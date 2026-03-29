"""Lightweight SOC-style event, alert, and case management."""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from threading import Lock
from uuid import uuid4

from .alerts import AlertEvent, AlertLevel, AlertManager
from .audit import AuditLogger
from .models import (
    SocAlertRecord,
    SocAlertPromoteCaseRequest,
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
            self._apply_correlation_rules(event)

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

    def query_alerts(
        self,
        *,
        status: SocAlertStatus | None = None,
        severity: SocSeverity | None = None,
        assignee: str | None = None,
        linked_case_state: str | None = None,
        sort: str = "updated_desc",
        limit: int = 100,
    ) -> list[SocAlertRecord]:
        alerts = self._read_records(self._alert_store_path, SocAlertRecord)
        if status is not None:
            alerts = [item for item in alerts if item.status is status]
        if severity is not None:
            alerts = [item for item in alerts if item.severity is severity]
        if assignee is not None:
            normalized_assignee = assignee.strip().casefold()
            if normalized_assignee == "unassigned":
                alerts = [item for item in alerts if not item.assignee]
            else:
                alerts = [
                    item
                    for item in alerts
                    if item.assignee is not None and item.assignee.casefold() == normalized_assignee
                ]
        if linked_case_state == "linked":
            alerts = [item for item in alerts if item.linked_case_id]
        elif linked_case_state == "unlinked":
            alerts = [item for item in alerts if not item.linked_case_id]
        self._sort_alerts(alerts, sort)
        return alerts[:limit]

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
                next_status = payload.status or existing.status
                updated = existing.model_copy(
                    update={
                        "status": next_status,
                        "assignee": payload.assignee if payload.assignee is not None else existing.assignee,
                        "acknowledged_by": (
                            payload.acted_by
                            if payload.acted_by is not None and next_status is SocAlertStatus.acknowledged
                            else existing.acknowledged_by
                        ),
                        "notes": notes,
                        "updated_at": _utc_now(),
                    }
                )
                alerts[index] = updated
                self._write_records(self._alert_store_path, alerts)
                self._audit.log(
                    "soc.alert.updated",
                    {
                        "alert_id": alert_id,
                        "status": updated.status.value,
                        "assignee": updated.assignee,
                        "acted_by": payload.acted_by,
                    },
                )
                return updated
        raise KeyError(f"Alert not found: {alert_id}")

    def create_case(self, payload: SocCaseCreate) -> SocCaseRecord:
        created_at = _utc_now()
        enriched_payload = payload.model_copy(
            update={
                "observables": self._merge_observables(
                    payload.observables,
                    self._extract_observables_for_case(
                        source_event_ids=payload.source_event_ids,
                        linked_alert_ids=payload.linked_alert_ids,
                    ),
                )
            }
        )
        case = SocCaseRecord(
            **enriched_payload.model_dump(),
            case_id=f"case-{uuid4().hex[:12]}",
            created_at=created_at,
            updated_at=created_at,
        )
        with self._lock:
            alerts = self._read_records(self._alert_store_path, SocAlertRecord)
            cases = self._read_records(self._case_store_path, SocCaseRecord)
            cases.append(case)
            self._write_records(self._case_store_path, cases)
            self._link_case_alerts(alerts, case, preserve_status=True)
            self._write_records(self._alert_store_path, alerts)
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

    def promote_alert_to_case(
        self,
        alert_id: str,
        payload: SocAlertPromoteCaseRequest,
    ) -> tuple[SocAlertRecord, SocCaseRecord]:
        with self._lock:
            alerts = self._read_records(self._alert_store_path, SocAlertRecord)
            alert_index = next((index for index, item in enumerate(alerts) if item.alert_id == alert_id), None)
            if alert_index is None:
                raise KeyError(f"Alert not found: {alert_id}")

            existing_alert = alerts[alert_index]
            if existing_alert.linked_case_id:
                raise ValueError(f"Alert already linked to case: {existing_alert.linked_case_id}")

            created_at = _utc_now()
            case = SocCaseRecord(
                case_id=f"case-{uuid4().hex[:12]}",
                title=payload.title or existing_alert.title,
                summary=payload.summary or existing_alert.summary,
                severity=payload.severity or existing_alert.severity,
                source_event_ids=list(existing_alert.source_event_ids),
                linked_alert_ids=[existing_alert.alert_id],
                observables=self._extract_observables_for_case(
                    source_event_ids=existing_alert.source_event_ids,
                    linked_alert_ids=[existing_alert.alert_id],
                ),
                assignee=payload.assignee if payload.assignee is not None else existing_alert.assignee,
                status=payload.case_status,
                notes=[payload.note] if payload.note else [],
                created_at=created_at,
                updated_at=created_at,
            )
            cases = self._read_records(self._case_store_path, SocCaseRecord)
            cases.append(case)
            self._link_case_alerts(
                alerts,
                case,
                preserve_status=False,
                alert_status=payload.alert_status,
                note=payload.note,
                escalated_by=payload.acted_by,
            )
            updated_alert = alerts[alert_index]
            self._write_records(self._case_store_path, cases)
            self._write_records(self._alert_store_path, alerts)

        self._audit.log(
            "soc.alert.promoted",
            {
                "alert_id": updated_alert.alert_id,
                "case_id": case.case_id,
                "alert_status": updated_alert.status.value,
                "case_status": case.status.value,
                "acted_by": payload.acted_by,
            },
        )
        return updated_alert, case

    def list_cases(self, *, status: SocCaseStatus | None = None) -> list[SocCaseRecord]:
        cases = self._read_records(self._case_store_path, SocCaseRecord)
        if status is not None:
            cases = [item for item in cases if item.status is status]
        cases.sort(key=lambda item: item.updated_at, reverse=True)
        return cases

    def query_cases(
        self,
        *,
        status: SocCaseStatus | None = None,
        severity: SocSeverity | None = None,
        assignee: str | None = None,
        sort: str = "updated_desc",
        limit: int = 100,
    ) -> list[SocCaseRecord]:
        cases = self._read_records(self._case_store_path, SocCaseRecord)
        if status is not None:
            cases = [item for item in cases if item.status is status]
        if severity is not None:
            cases = [item for item in cases if item.severity is severity]
        if assignee is not None:
            normalized_assignee = assignee.strip().casefold()
            if normalized_assignee == "unassigned":
                cases = [item for item in cases if not item.assignee]
            else:
                cases = [
                    item
                    for item in cases
                    if item.assignee is not None and item.assignee.casefold() == normalized_assignee
                ]
        self._sort_cases(cases, sort)
        return cases[:limit]

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
                observables = list(existing.observables)
                if payload.note:
                    notes.append(payload.note)
                if payload.observable and payload.observable not in observables:
                    observables.append(payload.observable)
                updated = existing.model_copy(
                    update={
                        "status": payload.status or existing.status,
                        "assignee": payload.assignee if payload.assignee is not None else existing.assignee,
                        "notes": notes,
                        "observables": observables,
                        "updated_at": _utc_now(),
                    }
                )
                cases[index] = updated
                self._write_records(self._case_store_path, cases)
                self._audit.log(
                    "soc.case.updated",
                    {
                        "case_id": case_id,
                        "status": updated.status.value,
                        "assignee": updated.assignee,
                        "observable_added": payload.observable,
                    },
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

    def dashboard(self) -> dict[str, object]:
        events = self.list_events(limit=500)
        alerts = self.list_alerts()
        cases = self.list_cases()
        now = _utc_now()
        alert_severity = Counter(item.severity.value for item in alerts)
        alert_status = Counter(item.status.value for item in alerts)
        case_status = Counter(item.status.value for item in cases)
        event_types = Counter(item.event_type for item in events[:100])
        correlation_alerts = [item for item in alerts if item.category == "correlation"]
        stale_cutoff = now - timedelta(hours=24)

        return {
            "summary": self.overview(),
            "alert_severity": dict(alert_severity),
            "alert_status": dict(alert_status),
            "case_status": dict(case_status),
            "top_event_types": dict(event_types.most_common(10)),
            "triage": {
                "unassigned_alerts": [
                    item.model_dump(mode="json")
                    for item in alerts
                    if not item.assignee and not item.linked_case_id
                ][:10],
                "stale_open_alerts": [
                    item.model_dump(mode="json")
                    for item in alerts
                    if item.status is SocAlertStatus.open
                    and item.updated_at < stale_cutoff
                    and not item.linked_case_id
                ][:10],
                "recent_correlations": [item.model_dump(mode="json") for item in correlation_alerts[:10]],
                "active_cases": [
                    item.model_dump(mode="json") for item in cases if item.status is not SocCaseStatus.closed
                ][:10],
            },
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
            category="event",
            status=SocAlertStatus.open,
            source_event_ids=[event_id],
            created_at=created_at,
            updated_at=created_at,
        )

    def _apply_correlation_rules(self, event: SocEventRecord) -> None:
        self._correlate_endpoint_high_risk_device(event)
        self._correlate_repeated_tracker_activity(event)

    def _correlate_endpoint_high_risk_device(self, event: SocEventRecord) -> None:
        device_id = event.details.get("device_id")
        if not isinstance(device_id, str) or not device_id:
            return
        relevant_types = {"endpoint.telemetry_posture", "policy.access_decision"}
        if event.event_type not in relevant_types:
            return
        window_start = event.created_at - timedelta(hours=24)
        related_events = [
            item
            for item in self.list_events(limit=250)
            if item.created_at >= window_start
            and item.details.get("device_id") == device_id
            and item.event_type in relevant_types
        ]
        event_types = {item.event_type for item in related_events}
        if event_types != relevant_types:
            return
        self._upsert_correlation_alert(
            rule="endpoint_high_risk_device",
            key=device_id,
            title=f"Correlated endpoint risk for {device_id}",
            summary="The same endpoint reported posture issues and also triggered a risky access workflow.",
            severity=SocSeverity.critical,
            related_events=related_events,
        )

    def _correlate_repeated_tracker_activity(self, event: SocEventRecord) -> None:
        if event.event_type != "privacy.tracker_block":
            return
        hostname = event.details.get("hostname")
        if not isinstance(hostname, str) or not hostname:
            return
        window_start = event.created_at - timedelta(hours=1)
        related_events = [
            item
            for item in self.list_events(limit=250)
            if item.created_at >= window_start
            and item.event_type == "privacy.tracker_block"
            and item.details.get("hostname") == hostname
        ]
        if len(related_events) < 3:
            return
        self._upsert_correlation_alert(
            rule="repeated_tracker_activity",
            key=hostname,
            title=f"Repeated tracker activity for {hostname}",
            summary="Multiple tracker-block events hit the same hostname within one hour.",
            severity=SocSeverity.high,
            related_events=related_events,
        )

    def _upsert_correlation_alert(
        self,
        *,
        rule: str,
        key: str,
        title: str,
        summary: str,
        severity: SocSeverity,
        related_events: list[SocEventRecord],
    ) -> None:
        alerts = self._read_records(self._alert_store_path, SocAlertRecord)
        for index, existing in enumerate(alerts):
            if (
                existing.category == "correlation"
                and existing.correlation_rule == rule
                and existing.correlation_key == key
                and existing.status is not SocAlertStatus.closed
            ):
                updated = existing.model_copy(
                    update={
                        "summary": summary,
                        "severity": severity,
                        "source_event_ids": sorted({*existing.source_event_ids, *(item.event_id for item in related_events)}),
                        "updated_at": _utc_now(),
                    }
                )
                alerts[index] = updated
                self._write_records(self._alert_store_path, alerts)
                self._audit.log(
                    "soc.alert.correlated",
                    {"alert_id": updated.alert_id, "rule": rule, "key": key, "event_count": len(updated.source_event_ids)},
                )
                return

        created_at = _utc_now()
        alert = SocAlertRecord(
            alert_id=f"alert-{uuid4().hex[:12]}",
            title=title,
            summary=summary,
            severity=severity,
            category="correlation",
            status=SocAlertStatus.open,
            source_event_ids=sorted({item.event_id for item in related_events}),
            correlation_rule=rule,
            correlation_key=key,
            created_at=created_at,
            updated_at=created_at,
        )
        alerts.append(alert)
        self._write_records(self._alert_store_path, alerts)
        self._audit.log(
            "soc.alert.correlated",
            {"alert_id": alert.alert_id, "rule": rule, "key": key, "event_count": len(alert.source_event_ids)},
        )
        self._alerts.emit(
            AlertEvent(
                level=_severity_to_alert_level(severity),
                title=f"SOC correlation: {title}",
                message=summary,
                context={"alert_id": alert.alert_id, "rule": rule, "key": key},
            )
        )

    def _link_case_alerts(
        self,
        alerts: list[SocAlertRecord],
        case: SocCaseRecord,
        *,
        preserve_status: bool,
        alert_status: SocAlertStatus = SocAlertStatus.acknowledged,
        note: str | None = None,
        escalated_by: str | None = None,
    ) -> None:
        linked_ids = set(case.linked_alert_ids)
        if not linked_ids:
            return

        now = _utc_now()
        for index, existing in enumerate(alerts):
            if existing.alert_id not in linked_ids:
                continue

            notes = list(existing.notes)
            if note:
                notes.append(note)
            updates: dict[str, object] = {
                "linked_case_id": case.case_id,
                "notes": notes,
                "updated_at": now,
            }
            if case.assignee is not None:
                updates["assignee"] = case.assignee
            if not preserve_status:
                updates["status"] = alert_status
                if alert_status is SocAlertStatus.acknowledged and escalated_by is not None:
                    updates["acknowledged_by"] = escalated_by
                if escalated_by is not None:
                    updates["escalated_by"] = escalated_by
            alerts[index] = existing.model_copy(update=updates)

    def _extract_observables_for_case(
        self,
        *,
        source_event_ids: list[str],
        linked_alert_ids: list[str],
    ) -> list[str]:
        observables: list[str] = []
        if source_event_ids:
            events_by_id = {event.event_id: event for event in self.list_events(limit=500)}
            for event_id in source_event_ids:
                event = events_by_id.get(event_id)
                if event is None:
                    continue
                observables.extend(self._extract_observables_from_mapping(event.details))
                observables.extend(self._extract_observables_from_text(event.summary))
                observables.extend(self._extract_observables_from_text(event.title))
                observables.extend(event.artifacts)

        if linked_alert_ids:
            alerts_by_id = {alert.alert_id: alert for alert in self.list_alerts()}
            for alert_id in linked_alert_ids:
                alert = alerts_by_id.get(alert_id)
                if alert is None:
                    continue
                observables.extend(self._extract_observables_from_text(alert.title))
                observables.extend(self._extract_observables_from_text(alert.summary))

        return self._merge_observables([], observables)

    @staticmethod
    def _merge_observables(existing: list[str], discovered: list[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for item in [*existing, *discovered]:
            candidate = item.strip()
            if not candidate:
                continue
            normalized = candidate.casefold()
            if normalized in seen:
                continue
            seen.add(normalized)
            merged.append(candidate)
        return merged[:64]

    @classmethod
    def _extract_observables_from_mapping(cls, payload: dict[str, object]) -> list[str]:
        observables: list[str] = []
        for key, value in payload.items():
            lowered = key.casefold()
            if isinstance(value, str):
                if lowered in {"hostname", "resource", "filename", "device_id", "url"}:
                    observables.append(value)
                observables.extend(cls._extract_observables_from_text(value))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        observables.extend(cls._extract_observables_from_text(item))
        return observables

    @staticmethod
    def _extract_observables_from_text(value: str) -> list[str]:
        observables: list[str] = []
        for token in re.findall(r"https?://[^\s,]+", value):
            observables.append(token.rstrip(").,;]"))
        for token in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value):
            try:
                observables.append(str(ip_address(token)))
            except ValueError:
                continue
        for token in re.findall(r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*\.[A-Za-z]{2,}\b", value):
            observables.append(token.rstrip(").,;]"))
        return observables

    @staticmethod
    def _sort_alerts(alerts: list[SocAlertRecord], sort: str) -> None:
        severity_rank = {
            SocSeverity.low: 0,
            SocSeverity.medium: 1,
            SocSeverity.high: 2,
            SocSeverity.critical: 3,
        }
        if sort == "updated_asc":
            alerts.sort(key=lambda item: item.updated_at)
        elif sort == "severity_desc":
            alerts.sort(key=lambda item: (severity_rank[item.severity], item.updated_at), reverse=True)
        elif sort == "severity_asc":
            alerts.sort(key=lambda item: (severity_rank[item.severity], item.updated_at))
        else:
            alerts.sort(key=lambda item: item.updated_at, reverse=True)

    @staticmethod
    def _sort_cases(cases: list[SocCaseRecord], sort: str) -> None:
        severity_rank = {
            SocSeverity.low: 0,
            SocSeverity.medium: 1,
            SocSeverity.high: 2,
            SocSeverity.critical: 3,
        }
        if sort == "updated_asc":
            cases.sort(key=lambda item: item.updated_at)
        elif sort == "severity_desc":
            cases.sort(key=lambda item: (severity_rank[item.severity], item.updated_at), reverse=True)
        elif sort == "severity_asc":
            cases.sort(key=lambda item: (severity_rank[item.severity], item.updated_at))
        else:
            cases.sort(key=lambda item: item.updated_at, reverse=True)

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
