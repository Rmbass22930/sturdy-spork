"""Lightweight SOC-style event, alert, and case management."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from uuid import uuid4

from .alerts import AlertEvent, AlertLevel, AlertManager
from .audit import AuditLogger
from .models import (
    SocAlertRecord,
    SocAlertStatus,
    SocAlertUpdate,
    SocCaseCreate,
    SocCaseRecord,
    SocCaseStatus,
    SocCaseUpdate,
    SocEventIngest,
    SocEventRecord,
    SocSeverity,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _severity_to_alert_level(severity: SocSeverity) -> AlertLevel:
    if severity in {SocSeverity.high, SocSeverity.critical}:
        return AlertLevel.critical if severity is SocSeverity.critical else AlertLevel.warning
    return AlertLevel.info


class SecurityOperationsManager:
    def __init__(
        self,
        *,
        event_log_path: str | Path,
        alert_store_path: str | Path,
        case_store_path: str | Path,
        audit_logger: AuditLogger,
        alert_manager: AlertManager,
    ) -> None:
        self._event_log_path = Path(event_log_path)
        self._alert_store_path = Path(alert_store_path)
        self._case_store_path = Path(case_store_path)
        self._audit = audit_logger
        self._alerts = alert_manager
        self._lock = Lock()
        for path in (self._event_log_path, self._alert_store_path, self._case_store_path):
            path.parent.mkdir(parents=True, exist_ok=True)

    def ingest_event(self, payload: SocEventIngest) -> "SocIngestResult":
        created_at = _utc_now()
        event_id = f"evt-{uuid4().hex[:12]}"
        alert_record: SocAlertRecord | None = None
        if payload.severity in {SocSeverity.high, SocSeverity.critical}:
            alert_record = self._build_alert_for_event(payload, event_id=event_id, created_at=created_at)

        event = SocEventRecord(
            **payload.model_dump(),
            event_id=event_id,
            created_at=created_at,
            linked_alert_id=alert_record.alert_id if alert_record else None,
        )
        with self._lock:
            if alert_record is not None:
                alerts = self._read_records(self._alert_store_path, SocAlertRecord)
                alerts.append(alert_record)
                self._write_records(self._alert_store_path, alerts)
            self._append_event(event)

        self._audit.log(
            "soc.event.ingested",
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": event.severity.value,
                "linked_alert_id": event.linked_alert_id,
            },
        )
        if alert_record is not None:
            self._alerts.emit(
                AlertEvent(
                    level=_severity_to_alert_level(payload.severity),
                    title=f"SOC alert: {payload.title}",
                    message=payload.summary,
                    context={"event_id": event.event_id, "alert_id": alert_record.alert_id, "source": payload.source},
                )
            )
        return SocIngestResult(event=event, alert=alert_record)

    def list_events(
        self,
        *,
        limit: int = 50,
        severity: SocSeverity | None = None,
        event_type: str | None = None,
    ) -> list[SocEventRecord]:
        if limit < 1:
            raise ValueError("limit must be positive")
        if not self._event_log_path.exists():
            return []
        events: list[SocEventRecord] = []
        for raw in self._event_log_path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                event = SocEventRecord.model_validate_json(raw)
            except Exception:
                continue
            if severity is not None and event.severity is not severity:
                continue
            if event_type is not None and event.event_type != event_type:
                continue
            events.append(event)
        events.sort(key=lambda item: item.created_at, reverse=True)
        return events[:limit]

    def list_alerts(self, *, status: SocAlertStatus | None = None) -> list[SocAlertRecord]:
        alerts = self._read_records(self._alert_store_path, SocAlertRecord)
        if status is not None:
            alerts = [item for item in alerts if item.status is status]
        alerts.sort(key=lambda item: item.updated_at, reverse=True)
        return alerts

    def get_alert(self, alert_id: str) -> SocAlertRecord:
        for alert in self.list_alerts():
            if alert.alert_id == alert_id:
                return alert
        raise KeyError(f"Alert not found: {alert_id}")

    def update_alert(self, alert_id: str, payload: SocAlertUpdate) -> SocAlertRecord:
        with self._lock:
            alerts = self._read_records(self._alert_store_path, SocAlertRecord)
            for index, existing in enumerate(alerts):
                if existing.alert_id != alert_id:
                    continue
                notes = list(existing.notes)
                if payload.note:
                    notes.append(payload.note)
                updated = existing.model_copy(
                    update={
                        "status": payload.status or existing.status,
                        "assignee": payload.assignee if payload.assignee is not None else existing.assignee,
                        "notes": notes,
                        "updated_at": _utc_now(),
                    }
                )
                alerts[index] = updated
                self._write_records(self._alert_store_path, alerts)
                self._audit.log(
                    "soc.alert.updated",
                    {"alert_id": alert_id, "status": updated.status.value, "assignee": updated.assignee},
                )
                return updated
        raise KeyError(f"Alert not found: {alert_id}")

    def create_case(self, payload: SocCaseCreate) -> SocCaseRecord:
        created_at = _utc_now()
        case = SocCaseRecord(
            **payload.model_dump(),
            case_id=f"case-{uuid4().hex[:12]}",
            created_at=created_at,
            updated_at=created_at,
        )
        with self._lock:
            cases = self._read_records(self._case_store_path, SocCaseRecord)
            cases.append(case)
            self._write_records(self._case_store_path, cases)
        self._audit.log(
            "soc.case.created",
            {
                "case_id": case.case_id,
                "severity": case.severity.value,
                "source_event_ids": case.source_event_ids,
                "linked_alert_ids": case.linked_alert_ids,
            },
        )
        return case

    def list_cases(self, *, status: SocCaseStatus | None = None) -> list[SocCaseRecord]:
        cases = self._read_records(self._case_store_path, SocCaseRecord)
        if status is not None:
            cases = [item for item in cases if item.status is status]
        cases.sort(key=lambda item: item.updated_at, reverse=True)
        return cases

    def get_case(self, case_id: str) -> SocCaseRecord:
        for case in self.list_cases():
            if case.case_id == case_id:
                return case
        raise KeyError(f"Case not found: {case_id}")

    def update_case(self, case_id: str, payload: SocCaseUpdate) -> SocCaseRecord:
        with self._lock:
            cases = self._read_records(self._case_store_path, SocCaseRecord)
            for index, existing in enumerate(cases):
                if existing.case_id != case_id:
                    continue
                notes = list(existing.notes)
                if payload.note:
                    notes.append(payload.note)
                updated = existing.model_copy(
                    update={
                        "status": payload.status or existing.status,
                        "assignee": payload.assignee if payload.assignee is not None else existing.assignee,
                        "notes": notes,
                        "updated_at": _utc_now(),
                    }
                )
                cases[index] = updated
                self._write_records(self._case_store_path, cases)
                self._audit.log(
                    "soc.case.updated",
                    {"case_id": case_id, "status": updated.status.value, "assignee": updated.assignee},
                )
                return updated
        raise KeyError(f"Case not found: {case_id}")

    def overview(self) -> dict[str, object]:
        events = self.list_events(limit=250)
        alerts = self.list_alerts()
        cases = self.list_cases()
        return {
            "events_total": len(events),
            "alerts_total": len(alerts),
            "open_alerts": sum(1 for item in alerts if item.status is SocAlertStatus.open),
            "cases_total": len(cases),
            "open_cases": sum(1 for item in cases if item.status is not SocCaseStatus.closed),
            "recent_events": [event.model_dump(mode="json") for event in events[:10]],
        }

    def _build_alert_for_event(
        self,
        payload: SocEventIngest,
        *,
        event_id: str,
        created_at: datetime,
    ) -> SocAlertRecord:
        return SocAlertRecord(
            alert_id=f"alert-{uuid4().hex[:12]}",
            title=payload.title,
            summary=payload.summary,
            severity=payload.severity,
            status=SocAlertStatus.open,
            source_event_ids=[event_id],
            created_at=created_at,
            updated_at=created_at,
        )

    def _append_event(self, event: SocEventRecord) -> None:
        line = event.model_dump_json()
        with self._event_log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    @staticmethod
    def _read_records(path: Path, model_type: type[SocAlertRecord] | type[SocCaseRecord]) -> list:
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, list):
            return []
        records = []
        for item in payload:
            try:
                records.append(model_type.model_validate(item))
            except Exception:
                continue
        return records

    @staticmethod
    def _write_records(path: Path, records: list[SocAlertRecord] | list[SocCaseRecord]) -> None:
        payload = [record.model_dump(mode="json") for record in records]
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


@dataclass(frozen=True)
class SocIngestResult:
    event: SocEventRecord
    alert: SocAlertRecord | None
