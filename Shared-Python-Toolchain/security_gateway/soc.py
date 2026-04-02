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
from typing import Any, Callable, Mapping, Sequence, cast
from uuid import uuid4

from .alerts import AlertEvent, AlertLevel, AlertManager
from .audit import AuditLogger
from .config import settings
from .detection_engine import DetectionEngine
from .models import (
    SocAlertRecord,
    SocAlertPromoteCaseRequest,
    SocAlertStatus,
    SocCaseTelemetryClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocDashboardViewStateUpdate,
    SocCaseEndpointTimelineClusterCaseRequest,
    SocDetectionRuleRecord,
    SocDetectionRuleUpdate,
    SocAlertUpdate,
    SocCaseCreate,
    SocEndpointTimelineCaseRequest,
    SocNetworkEvidenceCaseRequest,
    SocPacketSessionCaseRequest,
    SocRemoteNodeCaseRequest,
    SocTelemetryClusterCaseRequest,
    SocCaseRecord,
    SocCaseStatus,
    SocCaseUpdate,
    SocEventIngest,
    SocEventRecord,
    SocSeverity,
)
from .platform import build_platform_profile
from .soc_store import SecurityOperationsStore


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _severity_to_alert_level(severity: SocSeverity) -> AlertLevel:
    if severity in {SocSeverity.high, SocSeverity.critical}:
        return AlertLevel.critical if severity is SocSeverity.critical else AlertLevel.warning
    return AlertLevel.info


def _alert_level_to_severity(level: AlertLevel) -> SocSeverity:
    if level is AlertLevel.critical:
        return SocSeverity.critical
    if level is AlertLevel.warning:
        return SocSeverity.high
    return SocSeverity.medium


class SecurityOperationsManager:
    _TELEMETRY_RETENTION_HOURS = {
        "network.telemetry.connection": "soc_network_telemetry_retention_hours",
        "packet.telemetry.session": "soc_packet_telemetry_retention_hours",
    }
    _HUNT_TELEMETRY_EVENT_TYPES = (
        "endpoint.telemetry.process",
        "endpoint.telemetry.file",
        "endpoint.telemetry.connection",
        "network.telemetry.connection",
        "packet.telemetry.session",
    )

    def __init__(
        self,
        *,
        event_log_path: str | Path | None = None,
        alert_store_path: str | Path | None = None,
        case_store_path: str | Path | None = None,
        audit_logger: AuditLogger,
        alert_manager: AlertManager,
        store: SecurityOperationsStore | None = None,
        detection_engine: DetectionEngine | None = None,
        platform_profile_builder: Callable[[], dict[str, object]] | None = None,
    ) -> None:
        if store is None:
            if event_log_path is None or alert_store_path is None or case_store_path is None:
                raise ValueError("event_log_path, alert_store_path, and case_store_path are required when store is not provided")
            store = SecurityOperationsStore.from_paths(
                event_log_path=event_log_path,
                event_index_path=settings.soc_event_index_path,
                alert_store_path=alert_store_path,
                case_store_path=case_store_path,
            )
        self._store = store
        self._event_log_path = self._store.event_store.path
        self._alert_store_path = self._store.alert_store.path
        self._case_store_path = self._store.case_store.path
        self._audit = audit_logger
        self._alerts = alert_manager
        self._detection_engine = detection_engine or DetectionEngine(settings.soc_detection_catalog_path)
        self._platform_profile_builder = platform_profile_builder or build_platform_profile
        self._lock = Lock()

    @staticmethod
    def _read_dashboard_view_state() -> dict[str, object]:
        path = Path(settings.soc_dashboard_view_state_path)
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        operational_reason_filter = str(payload.get("operational_reason_filter") or "").strip() or None
        hunt_cluster_mode = str(payload.get("hunt_cluster_mode") or "").strip()
        if hunt_cluster_mode not in {"remote_ip", "device_id", "process_guid"}:
            hunt_cluster_mode = "remote_ip"
        hunt_cluster_value = str(payload.get("hunt_cluster_value") or "").strip() or None
        hunt_cluster_key = str(payload.get("hunt_cluster_key") or "").strip() or None
        hunt_cluster_action = str(payload.get("hunt_cluster_action") or "").strip()
        if hunt_cluster_action not in {"events", "existing_case", "case", "details"}:
            hunt_cluster_action = "events"
        return {
            "operational_reason_filter": operational_reason_filter,
            "hunt_cluster_mode": hunt_cluster_mode,
            "hunt_cluster_value": hunt_cluster_value,
            "hunt_cluster_key": hunt_cluster_key,
            "hunt_cluster_action": hunt_cluster_action,
        }

    @staticmethod
    def _write_dashboard_view_state(payload: Mapping[str, object]) -> dict[str, object]:
        path = Path(settings.soc_dashboard_view_state_path)
        hunt_cluster_mode = str(payload.get("hunt_cluster_mode") or "").strip()
        if hunt_cluster_mode not in {"remote_ip", "device_id", "process_guid"}:
            hunt_cluster_mode = "remote_ip"
        hunt_cluster_action = str(payload.get("hunt_cluster_action") or "").strip()
        if hunt_cluster_action not in {"events", "existing_case", "case", "details"}:
            hunt_cluster_action = "events"
        normalized: dict[str, object] = {
            "operational_reason_filter": str(payload.get("operational_reason_filter") or "").strip() or None,
            "hunt_cluster_mode": hunt_cluster_mode,
            "hunt_cluster_value": str(payload.get("hunt_cluster_value") or "").strip() or None,
            "hunt_cluster_key": str(payload.get("hunt_cluster_key") or "").strip() or None,
            "hunt_cluster_action": hunt_cluster_action,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(normalized, indent=2, sort_keys=True), encoding="utf-8")
        return normalized

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
            self._prune_telemetry_events_locked()
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
        return self._store.event_index_store.query(
            severity=severity.value if severity is not None else None,
            event_type=event_type,
            sort="created_desc",
            limit=limit,
            event_store=self._store.event_store,
        )

    def query_events(
        self,
        *,
        severity: SocSeverity | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
        sort: str = "created_desc",
        limit: int = 100,
    ) -> list[SocEventRecord]:
        if limit < 1:
            raise ValueError("limit must be positive")
        events = self._store.event_index_store.query(
            severity=severity.value if severity is not None else None,
            event_type=event_type,
            source=source.strip() if source is not None else None,
            tag=tag.strip() if tag is not None else None,
            text=text,
            remote_ip=remote_ip.strip() if remote_ip is not None else None,
            hostname=hostname.strip() if hostname is not None else None,
            filename=filename.strip() if filename is not None else None,
            artifact_path=artifact_path.strip() if artifact_path is not None else None,
            session_key=session_key.strip() if session_key is not None else None,
            device_id=device_id.strip() if device_id is not None else None,
            process_name=process_name.strip() if process_name is not None else None,
            process_guid=process_guid.strip() if process_guid is not None else None,
            signer_name=signer_name.strip() if signer_name is not None else None,
            sha256=sha256.strip() if sha256 is not None else None,
            sort=sort,
            limit=max(limit * 2, limit),
            event_store=self._store.event_store,
        )
        normalized_start_at = self._normalize_query_datetime(start_at)
        normalized_end_at = self._normalize_query_datetime(end_at)
        if normalized_start_at is not None:
            events = [item for item in events if item.created_at >= normalized_start_at]
        if normalized_end_at is not None:
            events = [item for item in events if item.created_at <= normalized_end_at]
        if linked_alert_state == "linked":
            events = [item for item in events if item.linked_alert_id]
        elif linked_alert_state == "unlinked":
            events = [item for item in events if not item.linked_alert_id]
        self._sort_events(events, sort)
        return events[:limit]

    def get_event(self, event_id: str) -> SocEventRecord:
        event = self._store.event_index_store.get(event_id, event_store=self._store.event_store)
        if event is not None:
            return event
        for candidate in self._store.event_store.list():
            if candidate.event_id == event_id:
                return candidate
        raise KeyError(f"Event not found: {event_id}")

    def list_alerts(self, *, status: SocAlertStatus | None = None) -> list[SocAlertRecord]:
        alerts = self._store.alert_store.read()
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
        correlation_rule: str | None = None,
        linked_case_state: str | None = None,
        sort: str = "updated_desc",
        limit: int = 100,
    ) -> list[SocAlertRecord]:
        alerts = self._store.alert_store.read()
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
        if correlation_rule is not None:
            normalized_rule = correlation_rule.strip().casefold()
            alerts = [
                item
                for item in alerts
                if item.correlation_rule is not None and item.correlation_rule.casefold() == normalized_rule
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
            alerts = self._store.alert_store.read()
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
                self._store.alert_store.write(alerts)
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
            alerts = self._store.alert_store.read()
            cases = self._store.case_store.read()
            cases.append(case)
            self._store.case_store.write(cases)
            self._link_case_alerts(alerts, case, preserve_status=True)
            self._store.alert_store.write(alerts)
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

    def create_case_from_packet_session(
        self,
        session_payload: dict[str, object],
        payload: SocPacketSessionCaseRequest | None = None,
    ) -> SocCaseRecord:
        case_payload = self.build_packet_session_case_payload(session_payload, payload=payload)
        return self.create_case(case_payload)

    def create_case_from_network_evidence(
        self,
        evidence_payload: dict[str, object],
        payload: SocNetworkEvidenceCaseRequest | None = None,
    ) -> SocCaseRecord:
        case_payload = self.build_network_evidence_case_payload(evidence_payload, payload=payload)
        return self.create_case(case_payload)

    def create_case_from_remote_node(
        self,
        node_payload: Mapping[str, Any],
        payload: SocRemoteNodeCaseRequest | None = None,
    ) -> SocCaseRecord:
        case_payload = self.build_remote_node_case_payload(node_payload, payload=payload)
        return self.create_case(case_payload)

    def create_case_from_endpoint_timeline(
        self,
        payload: SocEndpointTimelineCaseRequest,
    ) -> SocCaseRecord:
        case_payload = self.build_endpoint_timeline_case_payload(payload)
        return self.create_case(case_payload)

    def create_case_from_telemetry_cluster(
        self,
        payload: SocTelemetryClusterCaseRequest,
    ) -> SocCaseRecord:
        case_payload = self.build_telemetry_cluster_case_payload(payload)
        return self.create_case(case_payload)

    def create_case_from_case_endpoint_timeline_cluster(
        self,
        case_id: str,
        payload: SocCaseEndpointTimelineClusterCaseRequest,
    ) -> SocCaseRecord:
        case_payload = self.build_case_endpoint_timeline_cluster_case_payload(case_id, payload)
        return self.create_case(case_payload)

    def create_case_from_case_rule_alert_group(
        self,
        case_id: str,
        payload: SocCaseRuleGroupCaseRequest,
    ) -> SocCaseRecord:
        case_payload = self.build_case_rule_alert_group_case_payload(case_id, payload)
        return self.create_case(case_payload)

    def create_case_from_case_rule_evidence_group(
        self,
        case_id: str,
        payload: SocCaseRuleGroupCaseRequest,
    ) -> SocCaseRecord:
        case_payload = self.build_case_rule_evidence_group_case_payload(case_id, payload)
        return self.create_case(case_payload)

    def create_case_from_case_hunt_telemetry_cluster(
        self,
        case_id: str,
        payload: SocCaseTelemetryClusterCaseRequest,
    ) -> SocCaseRecord:
        case_payload = self.build_case_hunt_telemetry_cluster_case_payload(case_id, payload)
        return self.create_case(case_payload)

    def promote_alert_to_case(
        self,
        alert_id: str,
        payload: SocAlertPromoteCaseRequest,
    ) -> tuple[SocAlertRecord, SocCaseRecord]:
        with self._lock:
            alerts = self._store.alert_store.read()
            alert_index = next((index for index, item in enumerate(alerts) if item.alert_id == alert_id), None)
            if alert_index is None:
                raise KeyError(f"Alert not found: {alert_id}")

            existing_alert = alerts[alert_index]
            if existing_alert.linked_case_id:
                raise ValueError(f"Alert already linked to case: {existing_alert.linked_case_id}")

            cases = self._store.case_store.read()
            if payload.existing_case_id:
                case_index = next((index for index, item in enumerate(cases) if item.case_id == payload.existing_case_id), None)
                if case_index is None:
                    raise KeyError(f"Case not found: {payload.existing_case_id}")
                existing_case = cases[case_index]
                linked_alert_ids = list(existing_case.linked_alert_ids)
                if existing_alert.alert_id not in linked_alert_ids:
                    linked_alert_ids.append(existing_alert.alert_id)
                source_event_ids = list(existing_case.source_event_ids)
                for event_id in existing_alert.source_event_ids:
                    if event_id not in source_event_ids:
                        source_event_ids.append(event_id)
                notes = list(existing_case.notes)
                if payload.note:
                    notes.append(payload.note)
                observables = self._merge_observables(
                    existing_case.observables,
                    self._extract_observables_for_case(
                        source_event_ids=existing_alert.source_event_ids,
                        linked_alert_ids=[existing_alert.alert_id],
                    ),
                )
                case = existing_case.model_copy(
                    update={
                        "source_event_ids": source_event_ids,
                        "linked_alert_ids": linked_alert_ids,
                        "observables": observables,
                        "assignee": payload.assignee if payload.assignee is not None else existing_case.assignee,
                        "status": payload.case_status,
                        "notes": notes,
                        "updated_at": _utc_now(),
                    }
                )
                cases[case_index] = case
            else:
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
            self._store.case_store.write(cases)
            self._store.alert_store.write(alerts)

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
        cases = self._store.case_store.read()
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
        cases = self._store.case_store.read()
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

    def resolve_case_linked_alerts(self, case_id: str) -> list[SocAlertRecord]:
        case = self.get_case(case_id)
        if not case.linked_alert_ids:
            return []
        alerts_by_id = {alert.alert_id: alert for alert in self.list_alerts()}
        return [alerts_by_id[alert_id] for alert_id in case.linked_alert_ids if alert_id in alerts_by_id]

    def resolve_case_source_events(self, case_id: str) -> list[SocEventRecord]:
        case = self.get_case(case_id)
        if not case.source_event_ids:
            return []
        events_by_id = {event.event_id: event for event in self.list_events(limit=1000)}
        return [events_by_id[event_id] for event_id in case.source_event_ids if event_id in events_by_id]

    def list_case_rule_alert_groups(self, case_id: str) -> list[dict[str, object]]:
        alerts = [alert for alert in self.resolve_case_linked_alerts(case_id) if alert.correlation_rule]
        return self._group_alert_records(alerts)

    def list_case_rule_evidence_groups(self, case_id: str) -> list[dict[str, object]]:
        source_events = [
            event
            for event in self.resolve_case_source_events(case_id)
            if event.event_type.startswith("endpoint.telemetry.")
        ]
        return self._group_evidence_records(source_events)

    def list_rule_alert_groups(self, rule_id: str) -> list[dict[str, object]]:
        alerts = self.query_alerts(correlation_rule=rule_id, limit=250)
        return self._group_alert_records(alerts)

    def list_rule_evidence_groups(self, rule_id: str) -> list[dict[str, object]]:
        alerts = self.query_alerts(correlation_rule=rule_id, limit=250)
        source_events = self._events_for_ids(
            [
                event_id
                for alert in alerts
                for event_id in alert.source_event_ids
            ]
        )
        return self._group_evidence_records(source_events)

    def list_case_endpoint_timeline_clusters(
        self,
        case_id: str,
        *,
        cluster_by: str = "process",
        limit: int = 200,
    ) -> dict[str, object]:
        case = self.get_case(case_id)
        source_events = self.resolve_case_source_events(case_id)
        filters = self._case_endpoint_timeline_filters(case, source_events, cluster_by=cluster_by)
        clusters = self.cluster_endpoint_timeline(cluster_by=cluster_by, limit=limit, **filters)
        return {
            "clusters": clusters,
            "filters": {
                "case_id": case_id,
                "cluster_by": cluster_by,
                "limit": limit,
                **filters,
            },
        }

    def list_case_hunt_telemetry_clusters(
        self,
        case_id: str,
        *,
        cluster_by: str = "remote_ip",
        limit: int = 200,
    ) -> dict[str, object]:
        case = self.get_case(case_id)
        source_events = self.resolve_case_source_events(case_id)
        filters = self._case_hunt_telemetry_filters(case, source_events, cluster_by=cluster_by)
        clusters = self.list_hunt_telemetry_clusters(cluster_by=cluster_by, limit=limit, **cast(dict[str, Any], filters))
        return {
            "clusters": clusters,
            "filters": {
                "case_id": case_id,
                "cluster_by": cluster_by,
                "limit": limit,
                **filters,
            },
        }

    def resolve_endpoint_timeline_cluster(
        self,
        *,
        cluster_by: str,
        cluster_key: str,
        limit: int = 500,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> dict[str, object]:
        clusters = self.cluster_endpoint_timeline(
            cluster_by=cluster_by,
            limit=limit,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
        )
        for cluster in clusters:
            if str(cluster.get("cluster_key") or "") == cluster_key:
                return cluster
        raise KeyError(f"Endpoint timeline cluster not found: {cluster_key}")

    def list_case_endpoint_timeline(
        self,
        case_id: str,
        *,
        limit: int = 200,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> dict[str, object]:
        case = self.get_case(case_id)
        source_events = self.resolve_case_source_events(case_id)
        filters = self._case_endpoint_timeline_filters(case, source_events)
        overrides = {
            "device_id": device_id,
            "process_name": process_name,
            "process_guid": process_guid,
            "remote_ip": remote_ip,
            "signer_name": signer_name,
            "sha256": sha256,
        }
        for key, value in overrides.items():
            if value:
                filters[key] = value
        events = [item.model_dump(mode="json") for item in self.list_endpoint_timeline(limit=limit, **filters)]
        return {
            "events": events,
            "filters": {
                "case_id": case_id,
                "limit": limit,
                **filters,
            },
        }

    def resolve_case_endpoint_timeline_cluster(
        self,
        case_id: str,
        *,
        cluster_by: str,
        cluster_key: str,
        limit: int = 500,
    ) -> dict[str, object]:
        payload = self.list_case_endpoint_timeline_clusters(case_id, cluster_by=cluster_by, limit=limit)
        for cluster in cast(list[dict[str, object]], payload.get("clusters") or []):
            if str(cluster.get("cluster_key") or "") == cluster_key:
                return cluster
        raise KeyError(f"Endpoint timeline cluster not found for case {case_id}: {cluster_key}")

    def resolve_case_hunt_telemetry_cluster(
        self,
        case_id: str,
        *,
        cluster_by: str,
        cluster_key: str,
        limit: int = 500,
    ) -> dict[str, object]:
        payload = self.list_case_hunt_telemetry_clusters(case_id, cluster_by=cluster_by, limit=limit)
        for cluster in cast(list[dict[str, object]], payload.get("clusters") or []):
            if str(cluster.get("cluster_key") or "") == cluster_key:
                detail = dict(cluster)
                detail["events"] = [
                    item.model_dump(mode="json")
                    for item in self._events_for_ids(cast(list[str], cluster.get("event_ids") or []))
                ]
                return detail
        raise KeyError(f"Hunt telemetry cluster not found for case {case_id}: {cluster_key}")

    def resolve_case_rule_alert_group(
        self,
        case_id: str,
        *,
        group_key: str,
    ) -> dict[str, object]:
        for group in self.list_case_rule_alert_groups(case_id):
            if str(group.get("group_key") or "") == group_key:
                return group
        raise KeyError(f"Rule alert group not found for case {case_id}: {group_key}")

    def resolve_rule_alert_group(
        self,
        rule_id: str,
        *,
        group_key: str,
    ) -> dict[str, object]:
        for group in self.list_rule_alert_groups(rule_id):
            if str(group.get("group_key") or "") == group_key:
                return group
        raise KeyError(f"Rule alert group not found for detection {rule_id}: {group_key}")

    def resolve_case_rule_evidence_group(
        self,
        case_id: str,
        *,
        group_key: str,
    ) -> dict[str, object]:
        for group in self.list_case_rule_evidence_groups(case_id):
            if str(group.get("group_key") or "") == group_key:
                return group
        raise KeyError(f"Rule evidence group not found for case {case_id}: {group_key}")

    def resolve_rule_evidence_group(
        self,
        rule_id: str,
        *,
        group_key: str,
    ) -> dict[str, object]:
        for group in self.list_rule_evidence_groups(rule_id):
            if str(group.get("group_key") or "") == group_key:
                return group
        raise KeyError(f"Rule evidence group not found for detection {rule_id}: {group_key}")

    def update_case(self, case_id: str, payload: SocCaseUpdate) -> SocCaseRecord:
        with self._lock:
            cases = self._store.case_store.read()
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
                self._store.case_store.write(cases)
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
        storage_stats = self._store.stats()
        platform = self._platform_profile_builder()
        return {
            "events_total": len(events),
            "alerts_total": len(alerts),
            "open_alerts": sum(1 for item in alerts if item.status is SocAlertStatus.open),
            "cases_total": len(cases),
            "open_cases": sum(1 for item in cases if item.status is not SocCaseStatus.closed),
            "recent_events": [event.model_dump(mode="json") for event in events[:10]],
            "platform": platform,
            "storage": {
                "backend": storage_stats.backend,
                "event_count": storage_stats.event_count,
                "alert_count": storage_stats.alert_count,
                "case_count": storage_stats.case_count,
                "event_index_backend": storage_stats.event_index_backend,
                "event_indexed_count": storage_stats.event_indexed_count,
                "event_index_token_count": storage_stats.event_index_token_count,
                "event_log_path": storage_stats.event_log_path,
                "event_index_path": storage_stats.event_index_path,
                "alert_store_path": storage_stats.alert_store_path,
                "case_store_path": storage_stats.case_store_path,
            },
        }

    def dashboard(self) -> dict[str, object]:
        events = self.list_events(limit=500)
        alerts = self.list_alerts()
        cases = self.list_cases()
        now = _utc_now()
        overview = self.overview()
        platform = cast(dict[str, object], overview["platform"])
        alert_severity = Counter(item.severity.value for item in alerts)
        alert_status = Counter(item.status.value for item in alerts)
        case_status = Counter(item.status.value for item in cases)
        event_types = Counter(item.event_type for item in events[:100])
        correlation_alerts = [item for item in alerts if item.category == "correlation"]
        stale_cutoff = now - timedelta(hours=settings.soc_stale_after_hours)
        assignee_workload = self._build_assignee_workload(alerts, cases, stale_cutoff=stale_cutoff)
        view_state = self._read_dashboard_view_state()

        return {
            "summary": overview,
            "platform": platform,
            "storage": cast(dict[str, object], overview["storage"]),
            "view_state": view_state,
            "alert_severity": dict(alert_severity),
            "alert_status": dict(alert_status),
            "case_status": dict(case_status),
            "top_event_types": dict(event_types.most_common(10)),
            "workload": {
                "stale_assigned_alerts": sum(
                    1
                    for item in alerts
                    if item.status is SocAlertStatus.open and item.updated_at < stale_cutoff and item.assignee
                ),
                "stale_active_cases": sum(
                    1
                    for item in cases
                    if item.status is not SocCaseStatus.closed and item.updated_at < stale_cutoff
                ),
            },
            "assignee_workload": assignee_workload[:10],
            "aging_buckets": {
                "alerts": self._build_aging_buckets(
                    [item for item in alerts if item.status is SocAlertStatus.open]
                ),
                "cases": self._build_aging_buckets(
                    [item for item in cases if item.status is not SocCaseStatus.closed]
                ),
            },
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
                    and not item.assignee
                ][:10],
                "assigned_stale_alerts": [
                    item.model_dump(mode="json")
                    for item in alerts
                    if item.status is SocAlertStatus.open
                    and item.updated_at < stale_cutoff
                    and item.assignee
                ][:10],
                "recent_correlations": [item.model_dump(mode="json") for item in correlation_alerts[:10]],
                "active_cases": [
                    item.model_dump(mode="json") for item in cases if item.status is not SocCaseStatus.closed
                ][:10],
                "stale_active_cases": [
                    item.model_dump(mode="json")
                    for item in cases
                    if item.status is not SocCaseStatus.closed and item.updated_at < stale_cutoff
                ][:10],
            },
        }

    def update_dashboard_view_state(self, payload: SocDashboardViewStateUpdate) -> dict[str, object]:
        normalized_payload = {
            "operational_reason_filter": payload.operational_reason_filter,
            "hunt_cluster_mode": payload.hunt_cluster_mode,
            "hunt_cluster_value": payload.hunt_cluster_value,
            "hunt_cluster_key": payload.hunt_cluster_key,
            "hunt_cluster_action": payload.hunt_cluster_action,
        }
        with self._lock:
            return self._write_dashboard_view_state(normalized_payload)

    def search(
        self,
        *,
        query: str,
        severity: SocSeverity | None = None,
        tag: str | None = None,
        limit: int = 25,
    ) -> dict[str, object]:
        normalized_query = query.strip().casefold()
        if not normalized_query:
            return {"query": query, "events": [], "alerts": [], "cases": []}

        events = self.query_events(
            severity=severity,
            tag=tag,
            text=normalized_query,
            limit=limit,
        )
        alerts = [
            item
            for item in self.list_alerts()
            if (severity is None or item.severity is severity)
            and self._alert_matches_text(item, normalized_query)
        ][:limit]
        cases = [
            item
            for item in self.list_cases()
            if (severity is None or item.severity is severity)
            and self._case_matches_text(item, normalized_query)
        ][:limit]
        return {
            "query": query,
            "events": [item.model_dump(mode="json") for item in events],
            "alerts": [item.model_dump(mode="json") for item in alerts],
            "cases": [item.model_dump(mode="json") for item in cases],
        }

    def hunt(
        self,
        *,
        query: str | None = None,
        severity: SocSeverity | None = None,
        tag: str | None = None,
        source: str | None = None,
        event_type: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        facet_limit: int = 5,
        limit: int = 50,
    ) -> dict[str, object]:
        expanded_limit = max(limit, 500)
        events = self.query_events(
            severity=severity,
            event_type=event_type,
            source=source,
            tag=tag,
            text=query,
            remote_ip=remote_ip,
            hostname=hostname,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            signer_name=signer_name,
            sha256=sha256,
            start_at=start_at,
            end_at=end_at,
            limit=expanded_limit,
        )
        storage = self._store.stats()
        normalized_start_at = self._normalize_query_datetime(start_at)
        normalized_end_at = self._normalize_query_datetime(end_at)
        return {
            "query": query or "",
            "filters": {
                "severity": severity.value if severity is not None else None,
                "tag": tag,
                "source": source,
                "event_type": event_type,
                "remote_ip": remote_ip,
                "hostname": hostname,
                "filename": filename,
                "artifact_path": artifact_path,
                "session_key": session_key,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "signer_name": signer_name,
                "sha256": sha256,
                "start_at": normalized_start_at.isoformat() if normalized_start_at is not None else None,
                "end_at": normalized_end_at.isoformat() if normalized_end_at is not None else None,
                "facet_limit": facet_limit,
                "limit": limit,
            },
            "index": {
                "backend": storage.event_index_backend,
                "indexed_event_count": storage.event_indexed_count,
                "token_count": storage.event_index_token_count,
                "path": storage.event_index_path,
            },
            "match_count": len(events),
            "facets": self._build_hunt_facets(events, limit=facet_limit),
            "timeline": self._build_hunt_timeline(events, start_at=normalized_start_at, end_at=normalized_end_at),
            "summaries": self._build_hunt_summaries(events),
            "events": [item.model_dump(mode="json") for item in events[:limit]],
        }

    @staticmethod
    def _normalize_query_datetime(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def _build_hunt_facets(self, events: Sequence[SocEventRecord], *, limit: int) -> dict[str, list[dict[str, object]]]:
        bounded_limit = max(limit, 1)
        event_type_counts = Counter(item.event_type for item in events)
        source_counts = Counter(item.source for item in events)
        severity_counts = Counter(item.severity.value for item in events)
        tag_counts = Counter(tag for item in events for tag in item.tags)
        document_type_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "document_type")
        )
        remote_ip_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "remote_ip")
        )
        device_id_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "device_id")
        )
        process_name_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "process_name")
        )
        return {
            "event_type": self._facet_bucket_payload(event_type_counts, limit=bounded_limit),
            "source": self._facet_bucket_payload(source_counts, limit=bounded_limit),
            "severity": self._facet_bucket_payload(severity_counts, limit=bounded_limit),
            "tag": self._facet_bucket_payload(tag_counts, limit=bounded_limit),
            "document_type": self._facet_bucket_payload(document_type_counts, limit=bounded_limit),
            "remote_ip": self._facet_bucket_payload(remote_ip_counts, limit=bounded_limit),
            "device_id": self._facet_bucket_payload(device_id_counts, limit=bounded_limit),
            "process_name": self._facet_bucket_payload(process_name_counts, limit=bounded_limit),
        }

    @staticmethod
    def _facet_bucket_payload(counter: Counter[str], *, limit: int) -> list[dict[str, object]]:
        return [
            {"value": value, "count": count}
            for value, count in counter.most_common(limit)
        ]

    @staticmethod
    def _collect_hunt_values(event: SocEventRecord, field: str) -> list[str]:
        value = event.details.get(field)
        if isinstance(value, str) and value:
            return [value]
        fallback = SecurityOperationsManager._event_detail_string(event, field)
        return [fallback] if fallback else []

    def _build_hunt_timeline(
        self,
        events: Sequence[SocEventRecord],
        *,
        start_at: datetime | None,
        end_at: datetime | None,
    ) -> dict[str, object]:
        if not events:
            return {
                "bucket_unit": "day",
                "start_at": start_at.isoformat() if start_at is not None else None,
                "end_at": end_at.isoformat() if end_at is not None else None,
                "buckets": [],
            }
        window_start = start_at or min(item.created_at for item in events)
        window_end = end_at or max(item.created_at for item in events)
        bucket_unit = "hour" if (window_end - window_start) <= timedelta(hours=48) else "day"
        counts: Counter[str] = Counter()
        for event in events:
            created_at = event.created_at.astimezone(UTC)
            if bucket_unit == "hour":
                bucket = created_at.replace(minute=0, second=0, microsecond=0).isoformat()
            else:
                bucket = created_at.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
            counts[bucket] += 1
        return {
            "bucket_unit": bucket_unit,
            "start_at": window_start.isoformat(),
            "end_at": window_end.isoformat(),
            "buckets": [
                {"start_at": bucket, "count": count}
                for bucket, count in sorted(counts.items())
            ],
        }

    def _build_hunt_summaries(self, events: Sequence[SocEventRecord]) -> dict[str, object]:
        document_type_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "document_type")
        )
        severity_counts = Counter(item.severity.value for item in events)
        device_id_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "device_id")
        )
        process_name_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "process_name")
        )
        remote_ip_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "remote_ip")
        )
        signer_name_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "signer_name")
        )
        filename_counts = Counter(
            value
            for item in events
            for value in self._collect_hunt_values(item, "filename")
        )
        return {
            "document_types": self._facet_bucket_payload(document_type_counts, limit=max(len(document_type_counts), 1)),
            "severities": self._facet_bucket_payload(severity_counts, limit=max(len(severity_counts), 1)),
            "device_ids": self._facet_bucket_payload(device_id_counts, limit=max(len(device_id_counts), 1)),
            "process_names": self._facet_bucket_payload(process_name_counts, limit=max(len(process_name_counts), 1)),
            "remote_ips": self._facet_bucket_payload(remote_ip_counts, limit=max(len(remote_ip_counts), 1)),
            "signers": self._facet_bucket_payload(signer_name_counts, limit=max(len(signer_name_counts), 1)),
            "filenames": self._facet_bucket_payload(filename_counts, limit=max(len(filename_counts), 1)),
        }

    def summarize_endpoint_telemetry(
        self,
        *,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        facet_limit: int = 5,
        limit: int = 250,
    ) -> dict[str, object]:
        return self._build_telemetry_summary(
            telemetry_kind="endpoint",
            event_types=(
                "endpoint.telemetry.process",
                "endpoint.telemetry.file",
                "endpoint.telemetry.connection",
            ),
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            filename=filename,
            artifact_path=artifact_path,
            start_at=start_at,
            end_at=end_at,
            facet_limit=facet_limit,
            limit=limit,
        )

    def summarize_network_telemetry(
        self,
        *,
        remote_ip: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        facet_limit: int = 5,
        limit: int = 250,
    ) -> dict[str, object]:
        return self._build_telemetry_summary(
            telemetry_kind="network",
            event_types=("network.telemetry.connection",),
            remote_ip=remote_ip,
            start_at=start_at,
            end_at=end_at,
            facet_limit=facet_limit,
            limit=limit,
            retention_hours=settings.soc_network_telemetry_retention_hours,
        )

    def summarize_packet_telemetry(
        self,
        *,
        remote_ip: str | None = None,
        session_key: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        facet_limit: int = 5,
        limit: int = 250,
    ) -> dict[str, object]:
        return self._build_telemetry_summary(
            telemetry_kind="packet",
            event_types=("packet.telemetry.session",),
            remote_ip=remote_ip,
            session_key=session_key,
            start_at=start_at,
            end_at=end_at,
            facet_limit=facet_limit,
            limit=limit,
            retention_hours=settings.soc_packet_telemetry_retention_hours,
        )

    def list_hunt_telemetry_clusters(
        self,
        *,
        cluster_by: str = "remote_ip",
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        limit: int = 200,
    ) -> list[dict[str, object]]:
        if cluster_by not in {"remote_ip", "device_id", "process_guid"}:
            raise ValueError("cluster_by must be 'remote_ip', 'device_id', or 'process_guid'")
        telemetry_events = self._query_events_across_types(
            event_types=self._HUNT_TELEMETRY_EVENT_TYPES,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            start_at=start_at,
            end_at=end_at,
            sort="created_asc",
            limit=min(max(limit * 4, limit), 500),
        )
        grouped: dict[str, dict[str, object]] = {}
        for event in telemetry_events:
            cluster_key = self._event_detail_string(event, cluster_by)
            if not cluster_key:
                continue
            entry = grouped.setdefault(
                cluster_key,
                {
                    "cluster_by": cluster_by,
                    "cluster_key": cluster_key,
                    "label": self._hunt_telemetry_cluster_label(event, cluster_by=cluster_by, cluster_key=cluster_key),
                    "event_count": 0,
                    "event_ids": [],
                    "event_types": {},
                    "document_types": {},
                    "telemetry_kinds": {},
                    "device_ids": [],
                    "process_names": [],
                    "process_guids": [],
                    "remote_ips": [],
                    "filenames": [],
                    "session_keys": [],
                    "signers": [],
                    "first_seen_at": event.created_at.isoformat(),
                    "last_seen_at": event.created_at.isoformat(),
                    "severity": event.severity.value,
                },
            )
            entry["event_count"] = self._int_field(entry.get("event_count")) + 1
            cast(list[str], entry["event_ids"]).append(event.event_id)
            event_types = cast(dict[str, int], entry["event_types"])
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            document_types = cast(dict[str, int], entry["document_types"])
            document_type = self._event_detail_string(event, "document_type")
            if document_type:
                document_types[document_type] = document_types.get(document_type, 0) + 1
            telemetry_kinds = cast(dict[str, int], entry["telemetry_kinds"])
            telemetry_kind = self._telemetry_kind_for_event(event)
            telemetry_kinds[telemetry_kind] = telemetry_kinds.get(telemetry_kind, 0) + 1
            self._append_unique_value(entry, "device_ids", self._event_detail_string(event, "device_id"))
            self._append_unique_value(entry, "process_names", self._event_detail_string(event, "process_name"))
            self._append_unique_value(entry, "process_guids", self._event_detail_string(event, "process_guid"))
            self._append_unique_value(entry, "remote_ips", self._event_detail_string(event, "remote_ip"))
            self._append_unique_value(entry, "filenames", self._event_detail_string(event, "filename"))
            self._append_unique_value(entry, "session_keys", self._event_detail_string(event, "session_key"))
            self._append_unique_value(entry, "signers", self._event_detail_string(event, "signer_name"))
            first_seen_at = str(entry["first_seen_at"])
            last_seen_at = str(entry["last_seen_at"])
            created_at = event.created_at.isoformat()
            if created_at < first_seen_at:
                entry["first_seen_at"] = created_at
            if created_at > last_seen_at:
                entry["last_seen_at"] = created_at
            entry["severity"] = self._max_severity(self._parse_severity(str(entry["severity"])), event.severity).value
        clusters: list[dict[str, object]] = []
        for entry in grouped.values():
            cluster_events = self._events_for_ids(cast(list[str], entry["event_ids"]))
            related_alert_ids = self.resolve_network_evidence_alert_ids(cluster_events)
            related_cases = self.resolve_network_evidence_cases(cluster_events)
            entry["related_alert_ids"] = related_alert_ids
            entry["related_case_ids"] = [case.case_id for case in related_cases]
            entry["open_case_ids"] = [case.case_id for case in related_cases if case.status is not SocCaseStatus.closed]
            entry["open_case_count"] = len(cast(list[str], entry["open_case_ids"]))
            clusters.append(entry)
        clusters.sort(
            key=lambda item: (
                str(item.get("last_seen_at") or ""),
                self._int_field(item.get("event_count")),
                str(item.get("cluster_key") or ""),
            ),
            reverse=True,
        )
        return clusters[:limit]

    def resolve_hunt_telemetry_cluster(
        self,
        *,
        cluster_by: str,
        cluster_key: str,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        limit: int = 500,
    ) -> dict[str, object]:
        clusters = self.list_hunt_telemetry_clusters(
            cluster_by=cluster_by,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            start_at=start_at,
            end_at=end_at,
            limit=limit,
        )
        for cluster in clusters:
            if str(cluster.get("cluster_key") or "") == cluster_key:
                detail = dict(cluster)
                detail["events"] = [
                    item.model_dump(mode="json")
                    for item in self._events_for_ids(cast(list[str], cluster.get("event_ids") or []))
                ]
                return detail
        raise KeyError(f"Telemetry cluster not found: {cluster_by}:{cluster_key}")

    def _build_telemetry_summary(
        self,
        *,
        telemetry_kind: str,
        event_types: Sequence[str],
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        facet_limit: int = 5,
        limit: int = 250,
        retention_hours: float | None = None,
    ) -> dict[str, object]:
        bounded_limit = max(limit, 1)
        events = self._query_events_across_types(
            event_types=event_types,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            start_at=start_at,
            end_at=end_at,
            limit=bounded_limit,
        )
        normalized_start_at = self._normalize_query_datetime(start_at)
        normalized_end_at = self._normalize_query_datetime(end_at)
        return {
            "telemetry": telemetry_kind,
            "event_types": list(event_types),
            "filters": {
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
                "filename": filename,
                "artifact_path": artifact_path,
                "session_key": session_key,
                "start_at": normalized_start_at.isoformat() if normalized_start_at is not None else None,
                "end_at": normalized_end_at.isoformat() if normalized_end_at is not None else None,
                "facet_limit": facet_limit,
                "limit": bounded_limit,
            },
            "match_count": len(events),
            "retention_hours": retention_hours,
            "facets": self._build_hunt_facets(events, limit=facet_limit),
            "timeline": self._build_hunt_timeline(events, start_at=normalized_start_at, end_at=normalized_end_at),
            "summaries": self._build_hunt_summaries(events),
        }

    def _query_events_across_types(
        self,
        *,
        event_types: Sequence[str],
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        sort: str = "created_desc",
        limit: int = 250,
    ) -> list[SocEventRecord]:
        deduped: dict[str, SocEventRecord] = {}
        per_type_limit = min(max(limit, 1), 500)
        for event_type in event_types:
            for event in self.query_events(
                event_type=event_type,
                device_id=device_id,
                process_name=process_name,
                process_guid=process_guid,
                remote_ip=remote_ip,
                signer_name=signer_name,
                sha256=sha256,
                filename=filename,
                artifact_path=artifact_path,
                session_key=session_key,
                start_at=start_at,
                end_at=end_at,
                sort=sort,
                limit=per_type_limit,
            ):
                deduped[event.event_id] = event
        events = list(deduped.values())
        self._sort_events(events, sort)
        return events[:limit]

    def build_telemetry_cluster_case_payload(
        self,
        payload: SocTelemetryClusterCaseRequest,
    ) -> SocCaseCreate:
        cluster = self.resolve_hunt_telemetry_cluster(
            cluster_by=payload.cluster_by,
            cluster_key=payload.cluster_key,
            device_id=payload.device_id,
            process_name=payload.process_name,
            process_guid=payload.process_guid,
            remote_ip=payload.remote_ip,
            signer_name=payload.signer_name,
            sha256=payload.sha256,
            filename=payload.filename,
            artifact_path=payload.artifact_path,
            session_key=payload.session_key,
            start_at=payload.start_at,
            end_at=payload.end_at,
        )
        events = [
            self.get_event(str(item.get("event_id")))
            for item in cast(list[dict[str, object]], cluster.get("events") or [])
            if str(item.get("event_id") or "")
        ]
        if not events:
            raise ValueError("No telemetry events matched the requested cluster.")
        related_alert_ids = self.resolve_network_evidence_alert_ids(events)
        observables = self._merge_observables(
            [],
            [
                f"cluster:{payload.cluster_by}:{payload.cluster_key}",
                *(f"device:{item}" for item in self._collect_endpoint_timeline_values(events, "device_id")),
                *(f"process_name:{item}" for item in self._collect_endpoint_timeline_values(events, "process_name")),
                *(f"process_guid:{item}" for item in self._collect_endpoint_timeline_values(events, "process_guid")),
                *(f"remote_ip:{item}" for item in self._collect_endpoint_timeline_values(events, "remote_ip")),
                *(f"filename:{item}" for item in self._collect_endpoint_timeline_values(events, "filename")),
                *(f"sha256:{item}" for item in self._collect_endpoint_timeline_values(events, "sha256")),
                *(f"signer:{item}" for item in self._collect_endpoint_timeline_values(events, "signer_name")),
                *(f"session:{item}" for item in self._collect_endpoint_timeline_values(events, "session_key")),
                *self._extract_observables_for_case(
                    source_event_ids=[item.event_id for item in events],
                    linked_alert_ids=related_alert_ids,
                ),
            ],
        )
        telemetry_kinds = cast(dict[str, int], cluster.get("telemetry_kinds") or {})
        kind_summary = ", ".join(sorted(telemetry_kinds)) if telemetry_kinds else "telemetry"
        first_seen_at = str(cluster.get("first_seen_at") or events[0].created_at.isoformat())
        last_seen_at = str(cluster.get("last_seen_at") or events[-1].created_at.isoformat())
        default_title = f"Investigate {payload.cluster_by} cluster {payload.cluster_key}"
        default_summary = (
            f"Investigate {len(events)} normalized telemetry records for {payload.cluster_by} "
            f"{payload.cluster_key}. Sources: {kind_summary}. Window: {first_seen_at} to {last_seen_at}."
        )
        return SocCaseCreate(
            title=payload.title or default_title,
            summary=payload.summary or default_summary,
            severity=payload.severity or self._endpoint_timeline_severity(events),
            source_event_ids=[item.event_id for item in events],
            linked_alert_ids=related_alert_ids,
            observables=observables,
            assignee=payload.assignee,
        )

    def list_endpoint_timeline(
        self,
        *,
        limit: int = 200,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> list[SocEventRecord]:
        event_types = (
            "endpoint.telemetry.process",
            "endpoint.telemetry.file",
            "endpoint.telemetry.connection",
        )
        candidate_limit = min(max(limit * 4, limit), 500)
        events: list[SocEventRecord] = []
        for event_type in event_types:
            events.extend(
                self.query_events(
                    event_type=event_type,
                    device_id=device_id,
                    remote_ip=remote_ip,
                    signer_name=signer_name,
                    sort="created_asc",
                    limit=candidate_limit,
                )
            )
        deduped = {event.event_id: event for event in events}
        identity_candidates: set[str] = set()
        if process_guid:
            normalized_guid = process_guid.strip()
            for event in deduped.values():
                event_process_guid = self._event_detail_string(event, "process_guid")
                if event_process_guid != normalized_guid:
                    continue
                for candidate in (
                    self._event_detail_string(event, "process_guid"),
                    self._event_detail_string(event, "sha256"),
                    self._event_detail_string(event, "process_name"),
                ):
                    if candidate:
                        identity_candidates.add(candidate.casefold())
        filtered = [
            event
            for event in deduped.values()
            if self._endpoint_timeline_matches_filters(
                event,
                process_name=process_name,
                process_guid=process_guid,
                sha256=sha256,
                identity_candidates=identity_candidates,
            )
        ]
        return sorted(filtered, key=lambda item: item.created_at)[:limit]

    def cluster_endpoint_timeline(
        self,
        *,
        cluster_by: str = "process",
        limit: int = 200,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> list[dict[str, object]]:
        if cluster_by not in {"process", "remote_ip"}:
            raise ValueError("cluster_by must be 'process' or 'remote_ip'")
        events = self.list_endpoint_timeline(
            limit=limit,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
        )
        grouped: dict[str, dict[str, object]] = {}
        process_aliases: dict[tuple[str, str], str] = {}
        if cluster_by == "process":
            for event in events:
                event_device_id = self._event_detail_string(event, "device_id")
                canonical_identity = (
                    self._event_detail_string(event, "process_guid")
                    or self._event_detail_string(event, "sha256")
                    or self._event_detail_string(event, "process_name")
                )
                if not event_device_id or not canonical_identity:
                    continue
                for candidate in self._endpoint_timeline_identity_candidates(event):
                    process_aliases.setdefault((event_device_id, candidate.casefold()), canonical_identity)
        for event in events:
            cluster_key = self._endpoint_timeline_cluster_key(
                event,
                cluster_by=cluster_by,
                process_aliases=process_aliases,
            )
            if not cluster_key:
                continue
            entry = grouped.setdefault(
                cluster_key,
                {
                    "cluster_by": cluster_by,
                    "cluster_key": cluster_key,
                    "label": self._endpoint_timeline_cluster_label(event, cluster_by=cluster_by),
                    "event_count": 0,
                    "event_ids": [],
                    "event_types": {},
                    "device_ids": [],
                    "process_names": [],
                    "process_guids": [],
                    "remote_ips": [],
                    "filenames": [],
                    "first_seen_at": event.created_at.isoformat(),
                    "last_seen_at": event.created_at.isoformat(),
                },
            )
            event_count = entry.get("event_count")
            entry["event_count"] = (event_count if isinstance(event_count, int) else 0) + 1
            cast(list[str], entry["event_ids"]).append(event.event_id)
            event_types = cast(dict[str, int], entry["event_types"])
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            self._append_unique_value(entry, "device_ids", self._event_detail_string(event, "device_id"))
            self._append_unique_value(entry, "process_names", self._event_detail_string(event, "process_name"))
            self._append_unique_value(entry, "process_guids", self._event_detail_string(event, "process_guid"))
            self._append_unique_value(entry, "remote_ips", self._event_detail_string(event, "remote_ip"))
            self._append_unique_value(entry, "filenames", self._event_detail_string(event, "filename"))
            first_seen_at = str(entry["first_seen_at"])
            last_seen_at = str(entry["last_seen_at"])
            created_at = event.created_at.isoformat()
            if created_at < first_seen_at:
                entry["first_seen_at"] = created_at
            if created_at > last_seen_at:
                entry["last_seen_at"] = created_at

        clusters: list[dict[str, object]] = []
        for entry in grouped.values():
            cluster_events = [self.get_event(event_id) for event_id in cast(list[str], entry["event_ids"])]
            related_alert_ids = self.resolve_network_evidence_alert_ids(cluster_events)
            related_cases = self.resolve_network_evidence_cases(cluster_events)
            entry["related_alert_ids"] = related_alert_ids
            entry["related_case_ids"] = [case.case_id for case in related_cases]
            entry["open_case_ids"] = [case.case_id for case in related_cases if case.status is not SocCaseStatus.closed]
            entry["open_case_count"] = len(cast(list[str], entry["open_case_ids"]))
            clusters.append(entry)
        clusters.sort(
            key=lambda item: (
                str(item.get("last_seen_at") or ""),
                item.get("event_count") if isinstance(item.get("event_count"), int) else 0,
                str(item.get("cluster_key") or ""),
            ),
            reverse=True,
        )
        return clusters[:limit]

    def list_detection_rules(self) -> list[SocDetectionRuleRecord]:
        return [self._enrich_detection_rule(rule) for rule in self._detection_engine.list_rules()]

    def get_detection_rule(self, rule_id: str) -> SocDetectionRuleRecord:
        return self._enrich_detection_rule(self._detection_engine.get_rule(rule_id))

    def update_detection_rule(self, rule_id: str, payload: SocDetectionRuleUpdate) -> SocDetectionRuleRecord:
        updated = self._detection_engine.update_rule(rule_id, payload)
        self._audit.log(
            "soc.detection_rule.updated",
            {
                "rule_id": updated.rule_id,
                "enabled": updated.enabled,
                "parameters": updated.parameters,
            },
        )
        return self._enrich_detection_rule(updated)

    def emit_operational_notifications(self, *, state_path: str | Path | None = None) -> dict[str, object]:
        dashboard = self.dashboard()
        routes = self._build_operational_routes(dashboard)
        path = Path(state_path or settings.soc_notification_state_path)
        previous = self._read_notification_state(path)
        current: dict[str, dict[str, object]] = {}
        emitted = 0

        for route in routes:
            route_id = str(route["route_id"])
            fingerprint = str(route["fingerprint"])
            current[route_id] = {"active": True, "fingerprint": fingerprint}
            prior = previous.get(route_id, {})
            if prior.get("active") and prior.get("fingerprint") == fingerprint:
                continue
            self._alerts.emit(
                AlertEvent(
                    level=cast(AlertLevel, route["level"]),
                    title=str(route["title"]),
                    message=str(route["message"]),
                    context=cast(dict[str, object], route["context"]),
                )
            )
            self._audit.log(
                "soc.operational.notification",
                {"route_id": route_id, "fingerprint": fingerprint, "context": route["context"]},
            )
            operational_alert = self._upsert_operational_route_alert(route)
            if bool(route.get("auto_case")):
                self._ensure_operational_route_case(route, operational_alert)
            emitted += 1

        for route_id, prior in previous.items():
            if not prior.get("active") or route_id in current:
                continue
            self._alerts.emit(
                AlertEvent(
                    level=AlertLevel.info,
                    title=f"Operational pressure resolved: {route_id}",
                    message="The previously escalated SOC workload condition has cleared.",
                    context={"route_id": route_id},
                )
            )
            self._audit.log("soc.operational.notification.resolved", {"route_id": route_id})
            self._close_operational_route_alert(route_id)
            current[route_id] = {"active": False, "fingerprint": str(prior.get("fingerprint", ""))}

        self._write_notification_state(path, current)
        return {"enabled": True, "routes": len(routes), "emitted": emitted}

    def _upsert_operational_route_alert(self, route: Mapping[str, object]) -> SocAlertRecord:
        route_id = str(route["route_id"])
        created_at = _utc_now()
        with self._lock:
            alerts = self._store.alert_store.read()
            for index, existing in enumerate(alerts):
                if (
                    existing.category == "operational"
                    and existing.correlation_rule == "operational_route"
                    and existing.correlation_key == route_id
                    and existing.status is not SocAlertStatus.closed
                ):
                    updated = existing.model_copy(
                        update={
                            "title": str(route["title"]),
                            "summary": str(route["message"]),
                            "severity": _alert_level_to_severity(cast(AlertLevel, route["level"])),
                            "updated_at": created_at,
                        }
                    )
                    alerts[index] = updated
                    self._store.alert_store.write(alerts)
                    self._audit.log(
                        "soc.alert.operational",
                        {"alert_id": updated.alert_id, "route_id": route_id, "updated": True},
                    )
                    return updated

            alert = SocAlertRecord(
                alert_id=f"alert-{uuid4().hex[:12]}",
                title=str(route["title"]),
                summary=str(route["message"]),
                severity=_alert_level_to_severity(cast(AlertLevel, route["level"])),
                category="operational",
                status=SocAlertStatus.open,
                source_event_ids=[],
                correlation_rule="operational_route",
                correlation_key=route_id,
                created_at=created_at,
                updated_at=created_at,
            )
            alerts.append(alert)
            self._store.alert_store.write(alerts)
        self._audit.log(
            "soc.alert.operational",
            {"alert_id": alert.alert_id, "route_id": route_id, "updated": False},
        )
        return alert

    def _close_operational_route_alert(self, route_id: str) -> None:
        with self._lock:
            alerts = self._store.alert_store.read()
            changed = False
            for index, existing in enumerate(alerts):
                if (
                    existing.category == "operational"
                    and existing.correlation_rule == "operational_route"
                    and existing.correlation_key == route_id
                    and existing.status is not SocAlertStatus.closed
                ):
                    notes = list(existing.notes)
                    notes.append("Operational pressure resolved automatically.")
                    alerts[index] = existing.model_copy(
                        update={
                            "status": SocAlertStatus.closed,
                            "notes": notes,
                            "updated_at": _utc_now(),
                        }
                    )
                    changed = True
            if changed:
                self._store.alert_store.write(alerts)

    def _ensure_operational_route_case(self, route: Mapping[str, object], alert: SocAlertRecord) -> SocCaseRecord | None:
        route_id = str(route["route_id"])
        with self._lock:
            for case in self._store.case_store.read():
                if alert.alert_id in case.linked_alert_ids and case.status is not SocCaseStatus.closed:
                    return case
        context = cast(dict[str, object], route.get("context") or {})
        node_name = str(context.get("node_name") or "").strip()
        if not node_name:
            return None
        try:
            node_payload = self._resolve_remote_node_by_name(node_name)
        except KeyError:
            return None
        case = self.create_case(
            self.build_remote_node_case_payload(
                node_payload,
                payload=SocRemoteNodeCaseRequest(
                    title=str(route["title"]),
                    summary=str(route["message"]),
                    severity=_alert_level_to_severity(cast(AlertLevel, route["level"])),
                ),
            ).model_copy(update={"linked_alert_ids": [alert.alert_id]})
        )
        self._audit.log(
            "soc.case.operational",
            {"case_id": case.case_id, "route_id": route_id, "alert_id": alert.alert_id},
        )
        return case

    def _resolve_remote_node_by_name(self, node_name: str) -> dict[str, object]:
        dashboard = self.dashboard()
        platform = cast(dict[str, object], dashboard.get("platform") or {})
        topology = cast(dict[str, object], platform.get("topology") or {})
        remote_nodes = cast(list[dict[str, object]], topology.get("remote_nodes") or [])
        for item in remote_nodes:
            if str(item.get("node_name") or "") == node_name:
                return item
        raise KeyError(f"Remote node not found: {node_name}")

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

    def build_packet_session_case_payload(
        self,
        session_payload: dict[str, object],
        *,
        payload: SocPacketSessionCaseRequest | None = None,
    ) -> SocCaseCreate:
        def _int_list(values: object, *, limit: int | None = None) -> list[int]:
            if not isinstance(values, list):
                return []
            converted: list[int] = []
            for item in values:
                if isinstance(item, bool):
                    continue
                if isinstance(item, int):
                    converted.append(item)
                elif isinstance(item, str):
                    try:
                        converted.append(int(item))
                    except ValueError:
                        continue
            return converted[:limit] if limit is not None else converted

        def _int_value(value: object) -> int:
            if isinstance(value, bool):
                return 0
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value)
                except ValueError:
                    return 0
            return 0

        remote_ip = str(session_payload.get("remote_ip") or "unknown-remote")
        session_key = str(session_payload.get("session_key") or f"packet-session:{remote_ip}")
        source_events = self.resolve_packet_session_events(session_payload)
        sensitive_ports = _int_list(session_payload.get("sensitive_ports"))
        default_severity = SocSeverity.critical if sensitive_ports else SocSeverity.high
        packet_count = _int_value(session_payload.get("total_packets")) or _int_value(session_payload.get("last_packet_count"))
        observables: list[str] = [remote_ip, session_key]
        observables.extend(f"protocol:{item}" for item in cast(list[object], session_payload.get("protocols") or []))
        observables.extend(f"local_port:{item}" for item in _int_list(session_payload.get("local_ports")))
        observables.extend(f"remote_port:{item}" for item in _int_list(session_payload.get("remote_ports"), limit=10))
        return SocCaseCreate(
            title=(payload.title if payload and payload.title else f"Investigate packet session {remote_ip}"),
            summary=(
                payload.summary
                if payload and payload.summary
                else f"Investigate compact packet session evidence for {remote_ip}. Total packets observed: {packet_count}."
            ),
            severity=payload.severity if payload and payload.severity is not None else default_severity,
            source_event_ids=[item.event_id for item in source_events],
            observables=observables,
            assignee=payload.assignee if payload else None,
        )

    def resolve_packet_session_events(self, session_payload: dict[str, object]) -> list[SocEventRecord]:
        remote_ip = str(session_payload.get("remote_ip") or "")
        session_key = str(session_payload.get("session_key") or "")
        if not remote_ip and not session_key:
            return []
        related_events: list[SocEventRecord] = []
        for item in self.list_events(limit=500):
            if item.event_type not in {
                "packet.monitor.finding",
                "packet.monitor.recovered",
                "network.monitor.finding",
                "network.monitor.recovered",
            }:
                continue
            details = item.details.get("details")
            if not isinstance(details, dict):
                continue
            if session_key and details.get("session_key") == session_key:
                related_events.append(item)
                continue
            if remote_ip and details.get("remote_ip") == remote_ip:
                related_events.append(item)
        return related_events

    def build_network_evidence_case_payload(
        self,
        evidence_payload: dict[str, object],
        *,
        payload: SocNetworkEvidenceCaseRequest | None = None,
    ) -> SocCaseCreate:
        def _int_value(value: object) -> int:
            if isinstance(value, bool):
                return 0
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value)
                except ValueError:
                    return 0
            return 0

        def _int_list(values: object, *, limit: int | None = None) -> list[int]:
            if not isinstance(values, list):
                return []
            converted: list[int] = []
            for item in values:
                if isinstance(item, bool):
                    continue
                if isinstance(item, int):
                    converted.append(item)
                elif isinstance(item, str):
                    try:
                        converted.append(int(item))
                    except ValueError:
                        continue
            return converted[:limit] if limit is not None else converted

        remote_ip = str(evidence_payload.get("remote_ip") or "unknown-remote")
        observation = cast(dict[str, object], evidence_payload.get("observation") or {})
        packet_session = cast(dict[str, object], evidence_payload.get("packet_session") or {})
        source_events = self.resolve_network_evidence_events(evidence_payload)
        linked_alert_ids = self.resolve_network_evidence_alert_ids(source_events)
        local_ports = _int_list(observation.get("local_ports"))
        remote_ports = _int_list(observation.get("remote_ports"), limit=10)
        sensitive_ports = _int_list(observation.get("sensitive_ports"))
        protocols = [str(item) for item in cast(list[object], packet_session.get("protocols") or [])]
        total_hits = _int_value(observation.get("total_hits"))
        total_packets = _int_value(packet_session.get("total_packets")) or _int_value(packet_session.get("last_packet_count"))
        default_severity = SocSeverity.critical if sensitive_ports else SocSeverity.high
        observables: list[str] = [remote_ip]
        session_key = str(packet_session.get("session_key") or "")
        if session_key:
            observables.append(session_key)
        observables.extend(f"local_port:{item}" for item in local_ports)
        observables.extend(f"remote_port:{item}" for item in remote_ports)
        observables.extend(f"sensitive_port:{item}" for item in sensitive_ports)
        observables.extend(f"protocol:{item}" for item in protocols)
        return SocCaseCreate(
            title=(payload.title if payload and payload.title else f"Investigate network evidence {remote_ip}"),
            summary=(
                payload.summary
                if payload and payload.summary
                else f"Investigate combined network evidence for {remote_ip}. Observation hits: {total_hits}. Packet count: {total_packets}."
            ),
            severity=payload.severity if payload and payload.severity is not None else default_severity,
            source_event_ids=[item.event_id for item in source_events],
            linked_alert_ids=linked_alert_ids,
            observables=observables,
            assignee=payload.assignee if payload else None,
        )

    def build_remote_node_case_payload(
        self,
        node_payload: Mapping[str, Any],
        *,
        payload: SocRemoteNodeCaseRequest | None = None,
    ) -> SocCaseCreate:
        node_name = str(node_payload.get("node_name") or "").strip()
        node_role = str(node_payload.get("node_role") or "unknown").strip() or "unknown"
        status = str(node_payload.get("status") or "unknown").strip() or "unknown"
        last_seen_at = str(node_payload.get("last_seen_at") or "")
        service_health = cast(dict[str, Any], node_payload.get("service_health") or {})
        services = cast(dict[str, Any], service_health.get("services") or {})
        degraded_services = [
            name
            for name, details in services.items()
            if isinstance(details, Mapping)
            and bool(details.get("enabled"))
            and str(details.get("status") or "") in {"degraded", "pending"}
        ]
        metadata = cast(dict[str, Any], node_payload.get("metadata") or {})
        default_summary = (
            f"Investigate remote node {node_name} with role {node_role}. "
            f"Current status is {status}. Last seen at {last_seen_at or 'unknown'}."
        )
        if degraded_services:
            default_summary += f" Affected services: {', '.join(sorted(degraded_services))}."
        acknowledged_by = str(metadata.get("acknowledged_by") or "").strip()
        if acknowledged_by:
            default_summary += f" Acknowledged by {acknowledged_by}."
        observables = [
            f"node:{node_name}",
            f"role:{node_role}",
            f"node_status:{status}",
        ]
        observables.extend(f"service:{name}" for name in sorted(degraded_services))
        return SocCaseCreate(
            title=payload.title if payload and payload.title else f"Investigate remote node {node_name}",
            summary=payload.summary if payload and payload.summary else default_summary,
            severity=(
                payload.severity
                if payload and payload.severity is not None
                else (SocSeverity.high if status in {"degraded", "stale"} else SocSeverity.medium)
            ),
            observables=observables,
            assignee=payload.assignee if payload else None,
        )

    def build_endpoint_timeline_case_payload(
        self,
        payload: SocEndpointTimelineCaseRequest,
    ) -> SocCaseCreate:
        events = self.list_endpoint_timeline(
            limit=payload.limit,
            device_id=payload.device_id,
            process_name=payload.process_name,
            process_guid=payload.process_guid,
            remote_ip=payload.remote_ip,
            signer_name=payload.signer_name,
            sha256=payload.sha256,
        )
        if not events:
            raise ValueError("No endpoint timeline events matched the requested slice.")
        related_alert_ids = self.resolve_network_evidence_alert_ids(events)
        observables = self._merge_observables(
            [],
            [
                *(f"device:{item}" for item in self._collect_endpoint_timeline_values(events, "device_id")),
                *(f"process_name:{item}" for item in self._collect_endpoint_timeline_values(events, "process_name")),
                *(f"process_guid:{item}" for item in self._collect_endpoint_timeline_values(events, "process_guid")),
                *(f"remote_ip:{item}" for item in self._collect_endpoint_timeline_values(events, "remote_ip")),
                *(f"filename:{item}" for item in self._collect_endpoint_timeline_values(events, "filename")),
                *(f"sha256:{item}" for item in self._collect_endpoint_timeline_values(events, "sha256")),
                *(f"signer:{item}" for item in self._collect_endpoint_timeline_values(events, "signer_name")),
                *self._extract_observables_for_case(
                    source_event_ids=[item.event_id for item in events],
                    linked_alert_ids=related_alert_ids,
                ),
            ],
        )
        first_seen_at = events[0].created_at.isoformat()
        last_seen_at = events[-1].created_at.isoformat()
        device_label = payload.device_id or next(iter(self._collect_endpoint_timeline_values(events, "device_id")), "unknown-device")
        process_label = (
            payload.process_guid
            or payload.process_name
            or payload.sha256
            or next(iter(self._collect_endpoint_timeline_values(events, "process_guid")), "")
            or next(iter(self._collect_endpoint_timeline_values(events, "process_name")), "")
            or next(iter(self._collect_endpoint_timeline_values(events, "sha256")), "")
        )
        remote_label = payload.remote_ip or next(iter(self._collect_endpoint_timeline_values(events, "remote_ip")), "")
        default_title = f"Investigate endpoint timeline {device_label}"
        if process_label:
            default_title = f"{default_title} / {process_label}"
        elif remote_label:
            default_title = f"{default_title} / {remote_label}"
        default_summary = (
            f"Investigate {len(events)} endpoint timeline records for {device_label}. "
            f"Window: {first_seen_at} to {last_seen_at}."
        )
        if process_label:
            default_summary += f" Process identity: {process_label}."
        if remote_label:
            default_summary += f" Remote IP: {remote_label}."
        return SocCaseCreate(
            title=payload.title or default_title,
            summary=payload.summary or default_summary,
            severity=payload.severity or self._endpoint_timeline_severity(events),
            source_event_ids=[item.event_id for item in events],
            linked_alert_ids=related_alert_ids,
            observables=observables,
            assignee=payload.assignee,
        )

    def build_case_endpoint_timeline_cluster_case_payload(
        self,
        case_id: str,
        payload: SocCaseEndpointTimelineClusterCaseRequest,
    ) -> SocCaseCreate:
        case = self.get_case(case_id)
        source_events = self.resolve_case_source_events(case_id)
        base_filters = self._case_endpoint_timeline_filters(case, source_events, cluster_by=payload.cluster_by)
        cluster = self.resolve_case_endpoint_timeline_cluster(
            case_id,
            cluster_by=payload.cluster_by,
            cluster_key=payload.cluster_key,
        )
        cluster_filters: dict[str, str] = {}
        device_ids = cast(list[str], cluster.get("device_ids") or [])
        process_guids = cast(list[str], cluster.get("process_guids") or [])
        process_names = cast(list[str], cluster.get("process_names") or [])
        remote_ips = cast(list[str], cluster.get("remote_ips") or [])
        if device_ids:
            cluster_filters["device_id"] = device_ids[0]
        if process_guids:
            cluster_filters["process_guid"] = process_guids[0]
        elif process_names:
            cluster_filters["process_name"] = process_names[0]
        if payload.cluster_by == "remote_ip" and remote_ips:
            cluster_filters["remote_ip"] = remote_ips[0]

        request_payload = SocEndpointTimelineCaseRequest(
            device_id=cluster_filters.get("device_id", base_filters.get("device_id")),
            process_name=cluster_filters.get("process_name", base_filters.get("process_name")),
            process_guid=cluster_filters.get("process_guid", base_filters.get("process_guid")),
            remote_ip=cluster_filters.get("remote_ip", base_filters.get("remote_ip")),
            signer_name=base_filters.get("signer_name"),
            sha256=base_filters.get("sha256"),
            limit=max(self._int_field(cluster.get("event_count", 0)), 1),
            title=payload.title,
            summary=payload.summary,
            severity=payload.severity,
            assignee=payload.assignee,
        )
        return self.build_endpoint_timeline_case_payload(request_payload)

    def build_case_rule_alert_group_case_payload(
        self,
        case_id: str,
        payload: SocCaseRuleGroupCaseRequest,
    ) -> SocCaseCreate:
        case = self.get_case(case_id)
        group = self.resolve_case_rule_alert_group(case_id, group_key=payload.group_key)
        alerts = cast(list[dict[str, object]], group.get("alerts") or [])
        source_event_ids = [
            str(event_id)
            for alert in alerts
            for event_id in cast(list[object], alert.get("source_event_ids") or [])
            if str(event_id)
        ]
        source_events = self._events_for_ids(source_event_ids)
        return self._build_case_rule_group_timeline_case_payload(
            case=case,
            group_key=payload.group_key,
            group_events=source_events,
            title=payload.title,
            summary=payload.summary,
            severity=payload.severity,
            assignee=payload.assignee,
        )

    def build_case_rule_evidence_group_case_payload(
        self,
        case_id: str,
        payload: SocCaseRuleGroupCaseRequest,
    ) -> SocCaseCreate:
        case = self.get_case(case_id)
        group = self.resolve_case_rule_evidence_group(case_id, group_key=payload.group_key)
        source_events = [
            self.get_event(str(item.get("event_id")))
            for item in cast(list[dict[str, object]], group.get("events") or [])
            if str(item.get("event_id") or "")
        ]
        return self._build_case_rule_group_timeline_case_payload(
            case=case,
            group_key=payload.group_key,
            group_events=source_events,
            title=payload.title,
            summary=payload.summary,
            severity=payload.severity,
            assignee=payload.assignee,
        )

    def build_case_hunt_telemetry_cluster_case_payload(
        self,
        case_id: str,
        payload: SocCaseTelemetryClusterCaseRequest,
    ) -> SocCaseCreate:
        case = self.get_case(case_id)
        source_events = self.resolve_case_source_events(case_id)
        filters = self._case_hunt_telemetry_filters(case, source_events, cluster_by=payload.cluster_by)
        cluster = self.resolve_case_hunt_telemetry_cluster(
            case_id,
            cluster_by=payload.cluster_by,
            cluster_key=payload.cluster_key,
        )
        request_payload = SocTelemetryClusterCaseRequest(
            cluster_by=payload.cluster_by,
            cluster_key=payload.cluster_key,
            device_id=filters.get("device_id"),
            process_name=filters.get("process_name"),
            process_guid=filters.get("process_guid"),
            remote_ip=filters.get("remote_ip"),
            signer_name=filters.get("signer_name"),
            sha256=filters.get("sha256"),
            filename=filters.get("filename"),
            artifact_path=filters.get("artifact_path"),
            session_key=filters.get("session_key"),
            title=payload.title or f"Investigate {payload.cluster_by} cluster {cluster.get('label', payload.cluster_key)}",
            summary=payload.summary or f"Investigate case-linked hunt telemetry cluster {cluster.get('label', payload.cluster_key)}.",
            severity=payload.severity,
            assignee=payload.assignee,
        )
        return self.build_telemetry_cluster_case_payload(request_payload)

    def _build_case_rule_group_timeline_case_payload(
        self,
        *,
        case: SocCaseRecord,
        group_key: str,
        group_events: Sequence[SocEventRecord],
        title: str | None,
        summary: str | None,
        severity: SocSeverity | None,
        assignee: str | None,
    ) -> SocCaseCreate:
        if not group_events:
            raise ValueError("No endpoint timeline events matched the requested case rule group.")
        filters = self._case_endpoint_timeline_filters(case, group_events)
        timeline_limit = max(len(group_events), 25)
        request_payload = SocEndpointTimelineCaseRequest(
            device_id=filters.get("device_id"),
            process_name=filters.get("process_name"),
            process_guid=filters.get("process_guid"),
            remote_ip=filters.get("remote_ip"),
            signer_name=filters.get("signer_name"),
            sha256=filters.get("sha256"),
            limit=timeline_limit,
            title=title or f"Investigate endpoint timeline {group_key}",
            summary=summary or f"Investigate endpoint-backed case rule group {group_key}.",
            severity=severity,
            assignee=assignee,
        )
        return self.build_endpoint_timeline_case_payload(request_payload)

    def _case_endpoint_timeline_filters(
        self,
        case: SocCaseRecord,
        source_events: Sequence[SocEventRecord],
        *,
        cluster_by: str | None = None,
    ) -> dict[str, str]:
        filters = self._endpoint_timeline_filters_from_case_record(case, source_events)
        if cluster_by != "remote_ip" and any(filters.get(key) for key in ("process_guid", "process_name", "sha256")):
            filters.pop("remote_ip", None)
        return filters

    def _case_hunt_telemetry_filters(
        self,
        case: SocCaseRecord,
        source_events: Sequence[SocEventRecord],
        *,
        cluster_by: str | None = None,
    ) -> dict[str, str]:
        filters = self._endpoint_timeline_filters_from_case_record(case, source_events)
        observable_fields = {
            "filename": "filename",
            "artifact_path": "artifact_path",
            "session": "session_key",
            "session_key": "session_key",
        }
        for observable in case.observables:
            candidate = observable.strip()
            if not candidate:
                continue
            prefix, separator, raw_value = candidate.partition(":")
            if not separator:
                continue
            target_field = observable_fields.get(prefix.strip().casefold())
            field_value = raw_value.strip()
            if target_field and field_value and target_field not in filters:
                filters[target_field] = field_value
        for event in source_events:
            for field in ("device_id", "process_name", "process_guid", "remote_ip", "signer_name", "sha256", "filename", "artifact_path", "session_key"):
                if field in filters:
                    continue
                value = self._event_detail_string(event, field)
                if value:
                    filters[field] = value
        if cluster_by == "remote_ip":
            remote_ip = filters.get("remote_ip")
            filters = {key: value for key, value in {"remote_ip": remote_ip}.items() if value}
        elif cluster_by == "device_id":
            device_id = filters.get("device_id")
            filters = {key: value for key, value in {"device_id": device_id}.items() if value}
        elif any(filters.get(key) for key in ("process_guid", "process_name", "sha256")):
            filters.pop("remote_ip", None)
        return filters

    def resolve_network_evidence_events(self, evidence_payload: dict[str, object]) -> list[SocEventRecord]:
        remote_ip = str(evidence_payload.get("remote_ip") or "")
        packet_session = cast(dict[str, object], evidence_payload.get("packet_session") or {})
        session_key = str(packet_session.get("session_key") or "")
        if not remote_ip and not session_key:
            return []
        related_events: list[SocEventRecord] = []
        for item in self.list_events(limit=500):
            if item.event_type not in {
                "packet.monitor.finding",
                "packet.monitor.recovered",
                "network.monitor.finding",
                "network.monitor.recovered",
            }:
                continue
            details = item.details.get("details")
            if not isinstance(details, dict):
                continue
            if session_key and details.get("session_key") == session_key:
                related_events.append(item)
                continue
            if remote_ip and details.get("remote_ip") == remote_ip:
                related_events.append(item)
        return related_events

    def resolve_network_evidence_alert_ids(self, source_events: list[SocEventRecord]) -> list[str]:
        source_event_ids = {item.event_id for item in source_events}
        if not source_event_ids:
            return []
        linked_ids: list[str] = []
        for item in self.list_alerts():
            if source_event_ids.intersection(item.source_event_ids):
                linked_ids.append(item.alert_id)
        return linked_ids

    def resolve_network_evidence_cases(self, source_events: list[SocEventRecord]) -> list[SocCaseRecord]:
        source_event_ids = {item.event_id for item in source_events}
        if not source_event_ids:
            return []
        return [item for item in self.list_cases() if source_event_ids.intersection(item.source_event_ids)]

    def resolve_remote_node_cases(self, node_payload: Mapping[str, Any]) -> list[SocCaseRecord]:
        observables = {
            f"node:{str(node_payload.get('node_name') or '-').strip()}",
            f"role:{str(node_payload.get('node_role') or '-').strip()}",
        }
        related: list[SocCaseRecord] = []
        for item in self.list_cases():
            case_observables = {str(candidate) for candidate in item.observables}
            if observables.intersection(case_observables):
                related.append(item)
        return related

    @staticmethod
    def _event_detail_string(event: SocEventRecord, field: str) -> str | None:
        value = event.details.get(field)
        if field == "process_name" and (not isinstance(value, str) or not value):
            value = event.details.get("actor_process_name")
        elif field == "sha256" and (not isinstance(value, str) or not value):
            value = event.details.get("actor_process_sha256")
        return value if isinstance(value, str) and value else None

    @staticmethod
    def _append_unique_value(entry: dict[str, object], key: str, value: str | None) -> None:
        if not value:
            return
        bucket = cast(list[str], entry[key])
        if value not in bucket:
            bucket.append(value)

    def _endpoint_timeline_cluster_key(
        self,
        event: SocEventRecord,
        *,
        cluster_by: str,
        process_aliases: Mapping[tuple[str, str], str],
    ) -> str | None:
        if cluster_by == "remote_ip":
            return self._event_detail_string(event, "remote_ip")
        device_id = self._event_detail_string(event, "device_id")
        process_identity = None
        if device_id:
            for candidate in self._endpoint_timeline_identity_candidates(event):
                process_identity = process_aliases.get((device_id, candidate.casefold()))
                if process_identity:
                    break
        if not process_identity:
            process_identity = self._endpoint_timeline_process_identity(event)
        if not device_id or not process_identity:
            return None
        return f"{device_id}:{process_identity}"

    def _endpoint_timeline_cluster_label(self, event: SocEventRecord, *, cluster_by: str) -> str:
        if cluster_by == "remote_ip":
            return self._event_detail_string(event, "remote_ip") or "unknown-remote"
        device_id = self._event_detail_string(event, "device_id") or "unknown-device"
        process_label = (
            self._event_detail_string(event, "process_name")
            or self._event_detail_string(event, "process_guid")
            or self._event_detail_string(event, "sha256")
            or "unknown-process"
        )
        return f"{device_id} / {process_label}"

    def _endpoint_timeline_process_identity(self, event: SocEventRecord) -> str | None:
        return (
            self._event_detail_string(event, "sha256")
            or self._event_detail_string(event, "process_guid")
            or self._event_detail_string(event, "process_name")
        )

    def _endpoint_timeline_identity_candidates(self, event: SocEventRecord) -> list[str]:
        candidates = [
            self._event_detail_string(event, "process_guid"),
            self._event_detail_string(event, "sha256"),
            self._event_detail_string(event, "process_name"),
        ]
        seen: set[str] = set()
        ordered: list[str] = []
        for candidate in candidates:
            if not candidate:
                continue
            normalized = candidate.casefold()
            if normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(candidate)
        return ordered

    def _endpoint_timeline_matches_filters(
        self,
        event: SocEventRecord,
        *,
        process_name: str | None,
        process_guid: str | None,
        sha256: str | None,
        identity_candidates: set[str],
    ) -> bool:
        if process_name:
            event_process_name = self._event_detail_string(event, "process_name")
            if event_process_name is None or event_process_name.casefold() != process_name.strip().casefold():
                return False
        if process_guid:
            event_process_guid = self._event_detail_string(event, "process_guid")
            if event_process_guid != process_guid:
                event_identity = self._endpoint_timeline_process_identity(event)
                if not identity_candidates or event_identity is None or event_identity.casefold() not in identity_candidates:
                    return False
        if sha256:
            event_sha256 = self._event_detail_string(event, "sha256")
            if event_sha256 is None or event_sha256.casefold() != sha256.strip().casefold():
                return False
        return True

    @staticmethod
    def _collect_endpoint_timeline_values(events: list[SocEventRecord], field: str) -> list[str]:
        values: list[str] = []
        seen: set[str] = set()
        for event in events:
            value = event.details.get(field)
            if not isinstance(value, str) or not value:
                continue
            normalized = value.casefold()
            if normalized in seen:
                continue
            seen.add(normalized)
            values.append(value)
        return values

    @staticmethod
    def _endpoint_timeline_severity(events: list[SocEventRecord]) -> SocSeverity:
        for event in events:
            verdict = str(event.details.get("verdict") or "").casefold()
            if verdict in {"malicious", "quarantined"}:
                return SocSeverity.critical
            reputation = str(event.details.get("reputation") or "").casefold()
            if reputation == "malicious":
                return SocSeverity.critical
            risk_flags = event.details.get("risk_flags")
            if isinstance(risk_flags, list) and risk_flags:
                return SocSeverity.high
        return SocSeverity.high if any(item.event_type == "endpoint.telemetry.connection" for item in events) else SocSeverity.medium

    @staticmethod
    def _max_severity(left: SocSeverity, right: SocSeverity) -> SocSeverity:
        severity_rank = {
            SocSeverity.low: 0,
            SocSeverity.medium: 1,
            SocSeverity.high: 2,
            SocSeverity.critical: 3,
        }
        return left if severity_rank[left] >= severity_rank[right] else right

    @staticmethod
    def _parse_severity(value: str) -> SocSeverity:
        try:
            return SocSeverity(value)
        except ValueError:
            return SocSeverity.low

    @staticmethod
    def _telemetry_kind_for_event(event: SocEventRecord) -> str:
        if event.event_type.startswith("endpoint.telemetry."):
            return "endpoint"
        if event.event_type.startswith("network.telemetry."):
            return "network"
        if event.event_type.startswith("packet.telemetry."):
            return "packet"
        return "other"

    def _hunt_telemetry_cluster_label(
        self,
        event: SocEventRecord,
        *,
        cluster_by: str,
        cluster_key: str,
    ) -> str:
        if cluster_by == "device_id":
            process_name = self._event_detail_string(event, "process_name")
            return f"{cluster_key} / {process_name}" if process_name else cluster_key
        if cluster_by == "process_guid":
            device_id = self._event_detail_string(event, "device_id")
            process_name = self._event_detail_string(event, "process_name")
            prefix = f"{device_id} / " if device_id else ""
            suffix = f" ({process_name})" if process_name else ""
            return f"{prefix}{cluster_key}{suffix}"
        return cluster_key

    def _enrich_detection_rule(self, rule: SocDetectionRuleRecord) -> SocDetectionRuleRecord:
        correlated_alerts = [
            item
            for item in self._store.alert_store.read()
            if item.category == "correlation" and item.correlation_rule == rule.rule_id
        ]
        last_match_at = max((item.updated_at for item in correlated_alerts), default=None)
        return rule.model_copy(
            update={
                "hit_count": len(correlated_alerts),
                "open_alert_count": sum(1 for item in correlated_alerts if item.status is not SocAlertStatus.closed),
                "last_match_at": last_match_at,
            }
        )

    def _apply_correlation_rules(self, event: SocEventRecord) -> None:
        findings = self._detection_engine.evaluate(
            event=event,
            list_events=lambda limit: self.list_events(limit=limit),
        )
        for finding in findings:
            self._upsert_correlation_alert(
                rule=finding.rule_id,
                key=finding.key,
                title=finding.title,
                summary=finding.summary,
                severity=finding.severity,
                related_events=list(finding.related_events),
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

    def _endpoint_timeline_filters_from_case_record(
        self,
        case: SocCaseRecord,
        source_events: Sequence[SocEventRecord],
    ) -> dict[str, str]:
        filters: dict[str, str] = {}
        observable_fields = {
            "device": "device_id",
            "process_name": "process_name",
            "process_guid": "process_guid",
            "remote_ip": "remote_ip",
            "signer": "signer_name",
            "sha256": "sha256",
        }
        for observable in case.observables:
            candidate = observable.strip()
            if not candidate:
                continue
            prefix, separator, raw_value = candidate.partition(":")
            if separator:
                target_field = observable_fields.get(prefix.strip().casefold())
                field_value = raw_value.strip()
                if target_field and field_value and target_field not in filters:
                    filters[target_field] = field_value
                    continue
            try:
                remote_ip = str(ip_address(candidate))
            except ValueError:
                continue
            filters.setdefault("remote_ip", remote_ip)
        for event in source_events:
            if not event.event_type.startswith("endpoint.telemetry."):
                continue
            for field in ("device_id", "process_guid", "process_name", "remote_ip", "signer_name", "sha256"):
                if field in filters:
                    continue
                value = self._event_detail_string(event, field)
                if value:
                    filters[field] = value
        return filters

    def _group_alert_records(self, alerts: Sequence[SocAlertRecord]) -> list[dict[str, object]]:
        grouped: dict[str, dict[str, object]] = {}
        for alert in alerts:
            group_key = self._rule_alert_group_key(alert)
            entry = grouped.setdefault(
                group_key,
                {
                    "group_key": group_key,
                    "alert_count": 0,
                    "severity": alert.severity.value,
                    "title": group_key,
                    "alerts": [],
                    "related_case_ids": [],
                    "open_case_ids": [],
                    "open_case_count": 0,
                },
            )
            alert_count = entry.get("alert_count", 0)
            entry["alert_count"] = (alert_count if isinstance(alert_count, int) else 0) + 1
            cast(list[dict[str, object]], entry["alerts"]).append(alert.model_dump(mode="json"))
            if self._severity_rank(alert.severity.value) > self._severity_rank(str(entry.get("severity", "low"))):
                entry["severity"] = alert.severity.value
            related_case_ids = sorted(
                {
                    item.linked_case_id
                    for item in alerts
                    if item.linked_case_id and self._rule_alert_group_key(item) == group_key
                }
            )
            open_case_ids = [
                case_id
                for case_id in related_case_ids
                if self.get_case(case_id).status is not SocCaseStatus.closed
            ]
            entry["related_case_ids"] = related_case_ids
            entry["open_case_ids"] = open_case_ids
            entry["open_case_count"] = len(open_case_ids)
            entry["title"] = f"{group_key} (open cases: {len(open_case_ids)})" if open_case_ids else group_key
        groups = list(grouped.values())
        groups.sort(
            key=lambda item: (
                -self._severity_rank(str(item.get("severity", "low"))),
                -self._int_field(item.get("alert_count", 0)),
                str(item.get("group_key", "")),
            )
        )
        return groups

    def _group_evidence_records(self, source_events: Sequence[SocEventRecord]) -> list[dict[str, object]]:
        grouped: dict[str, dict[str, object]] = {}
        for event in source_events:
            group_key = self._rule_evidence_group_key(event)
            entry = grouped.setdefault(
                group_key,
                {
                    "group_key": group_key,
                    "event_count": 0,
                    "severity": event.severity.value,
                    "title": event.title,
                    "events": [],
                    "related_case_ids": [],
                    "open_case_ids": [],
                    "open_case_count": 0,
                },
            )
            event_count = entry.get("event_count", 0)
            entry["event_count"] = (event_count if isinstance(event_count, int) else 0) + 1
            cast(list[dict[str, object]], entry["events"]).append(event.model_dump(mode="json"))
            if self._severity_rank(event.severity.value) > self._severity_rank(str(entry.get("severity", "low"))):
                entry["severity"] = event.severity.value
            group_events = [self.get_event(event_id) for event_id in [str(item.get("event_id")) for item in cast(list[dict[str, object]], entry["events"])] if event_id]
            related_cases = self.resolve_network_evidence_cases(group_events)
            entry["related_case_ids"] = [case.case_id for case in related_cases]
            entry["open_case_ids"] = [case.case_id for case in related_cases if case.status is not SocCaseStatus.closed]
            entry["open_case_count"] = len(cast(list[str], entry["open_case_ids"]))
            entry["title"] = f"{group_key} (open cases: {entry['open_case_count']})" if entry["open_case_count"] else group_key
        groups = list(grouped.values())
        groups.sort(
            key=lambda item: (
                -self._severity_rank(str(item.get("severity", "low"))),
                -self._int_field(item.get("event_count", 0)),
                str(item.get("group_key", "")),
            )
        )
        return groups

    @staticmethod
    def _rule_alert_group_key(alert: SocAlertRecord) -> str:
        return alert.correlation_key or alert.linked_case_id or alert.correlation_rule or alert.alert_id or "ungrouped"

    @staticmethod
    def _int_field(value: object) -> int:
        return value if isinstance(value, int) else 0

    def _events_for_ids(self, event_ids: Sequence[str]) -> list[SocEventRecord]:
        if not event_ids:
            return []
        events_by_id = {event.event_id: event for event in self.list_events(limit=1000)}
        return [events_by_id[event_id] for event_id in event_ids if event_id in events_by_id]

    @staticmethod
    def _rule_evidence_group_key(event: SocEventRecord) -> str:
        details = event.details
        nested = details.get("details") if isinstance(details, dict) else None
        if isinstance(nested, dict):
            for key in ("remote_ip", "hostname", "filename", "artifact_path", "session_key", "key"):
                value = nested.get(key)
                if isinstance(value, str) and value:
                    return value
        if isinstance(details, dict):
            for key in ("source_ip", "hostname", "filename", "device_id", "resource"):
                value = details.get(key)
                if isinstance(value, str) and value:
                    return value
        return event.event_type or "ungrouped"

    @staticmethod
    def _severity_rank(value: str) -> int:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return order.get(value.casefold(), 0)

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

    @staticmethod
    def _build_aging_buckets(records: list[SocAlertRecord] | list[SocCaseRecord]) -> dict[str, int]:
        now = _utc_now()
        buckets = {"0-4h": 0, "4-24h": 0, "24-72h": 0, "72h+": 0}
        for record in records:
            age = now - record.updated_at
            if age < timedelta(hours=4):
                buckets["0-4h"] += 1
            elif age < timedelta(hours=24):
                buckets["4-24h"] += 1
            elif age < timedelta(hours=72):
                buckets["24-72h"] += 1
            else:
                buckets["72h+"] += 1
        return buckets

    @staticmethod
    def _build_assignee_workload(
        alerts: list[SocAlertRecord],
        cases: list[SocCaseRecord],
        *,
        stale_cutoff: datetime,
    ) -> list[dict[str, object]]:
        assignee_names = {
            (item.assignee or "unassigned")
            for item in alerts
            if item.status is SocAlertStatus.open
        } | {
            (item.assignee or "unassigned")
            for item in cases
            if item.status is not SocCaseStatus.closed
        }
        rows: list[dict[str, object]] = []
        for assignee in assignee_names:
            open_alerts = [
                item for item in alerts if item.status is SocAlertStatus.open and (item.assignee or "unassigned") == assignee
            ]
            active_cases = [
                item
                for item in cases
                if item.status is not SocCaseStatus.closed and (item.assignee or "unassigned") == assignee
            ]
            rows.append(
                {
                    "assignee": assignee,
                    "open_alerts": len(open_alerts),
                    "active_cases": len(active_cases),
                    "stale_alerts": sum(1 for item in open_alerts if item.updated_at < stale_cutoff),
                    "stale_cases": sum(1 for item in active_cases if item.updated_at < stale_cutoff),
                }
            )
        rows.sort(
            key=lambda item: (
                SecurityOperationsManager._coerce_int(item["stale_alerts"])
                + SecurityOperationsManager._coerce_int(item["stale_cases"]),
                SecurityOperationsManager._coerce_int(item["open_alerts"])
                + SecurityOperationsManager._coerce_int(item["active_cases"]),
                str(item["assignee"]) != "unassigned",
                str(item["assignee"]),
            ),
            reverse=True,
        )
        return rows

    def _build_operational_routes(self, dashboard: dict[str, object]) -> list[dict[str, object]]:
        workload = cast(dict[str, object], dashboard.get("workload") or {})
        assignee_workload = cast(list[dict[str, object]], dashboard.get("assignee_workload") or [])
        platform = cast(dict[str, object], dashboard.get("platform") or {})
        topology = cast(dict[str, object], platform.get("topology") or {})
        remote_nodes = cast(list[dict[str, object]], topology.get("remote_nodes") or [])
        routes: list[dict[str, object]] = []
        stale_assigned = self._coerce_int(workload.get("stale_assigned_alerts", 0))
        stale_cases = self._coerce_int(workload.get("stale_active_cases", 0))
        top_stale_assignees = [
            str(item["assignee"])
            for item in assignee_workload
            if self._coerce_int(item.get("stale_alerts", 0)) > 0 or self._coerce_int(item.get("stale_cases", 0)) > 0
        ][:3]
        if stale_assigned > 0:
            routes.append(
                {
                    "route_id": "handoff-stale-alerts",
                    "fingerprint": f"{stale_assigned}|{'/'.join(top_stale_assignees)}",
                    "level": AlertLevel.warning,
                    "title": "SOC handoff required",
                    "message": f"{stale_assigned} assigned alerts are stale and need analyst handoff.",
                    "context": {"count": stale_assigned, "assignees": top_stale_assignees},
                }
            )
        if stale_cases > 0:
            routes.append(
                {
                    "route_id": "stale-active-cases",
                    "fingerprint": f"{stale_cases}|{'/'.join(top_stale_assignees)}",
                    "level": AlertLevel.warning,
                    "title": "SOC case escalation needed",
                    "message": f"{stale_cases} active cases are stale and require escalation review.",
                    "context": {"count": stale_cases, "assignees": top_stale_assignees},
                }
            )
        for item in assignee_workload:
            assignee = str(item["assignee"])
            if assignee == "unassigned":
                continue
            open_alerts = self._coerce_int(item.get("open_alerts", 0))
            active_cases = self._coerce_int(item.get("active_cases", 0))
            if (
                open_alerts < settings.soc_assignee_open_alert_threshold
                and active_cases < settings.soc_assignee_active_case_threshold
            ):
                continue
            routes.append(
                {
                    "route_id": f"assignee-pressure:{assignee}",
                    "fingerprint": (
                        f"{open_alerts}|{active_cases}|"
                        f"{self._coerce_int(item.get('stale_alerts', 0))}|{self._coerce_int(item.get('stale_cases', 0))}"
                    ),
                    "level": AlertLevel.info,
                    "title": f"SOC workload pressure: {assignee}",
                    "message": f"{assignee} is carrying {open_alerts} open alerts and {active_cases} active cases.",
                    "context": item,
                }
            )
        for item in remote_nodes:
            node_name = str(item.get("node_name") or "").strip()
            node_status = str(item.get("status") or "unknown")
            if not node_name:
                continue
            action_failures = [str(action) for action in cast(list[object], item.get("action_failures") or []) if str(action)]
            suppression = cast(dict[str, object], item.get("suppression") or {})
            active_scopes = {str(scope) for scope in cast(list[object], suppression.get("active_scopes") or []) if str(scope)}
            routes.extend(self._build_remote_node_action_pattern_routes(item, active_scopes=active_scopes))
            if action_failures and "remote_node_action_failed" not in active_scopes:
                routes.append(
                    {
                        "route_id": f"remote-node:action-failed:{node_name}",
                        "fingerprint": "|".join([node_name, *sorted(action_failures)]),
                        "level": AlertLevel.warning,
                        "auto_case": True,
                        "title": f"Remote node action failed: {node_name}",
                        "message": f"Remote node {node_name} failed to execute: {', '.join(sorted(action_failures))}.",
                        "context": {
                            "node_name": node_name,
                            "node_role": str(item.get("node_role") or "unknown"),
                            "status": node_status,
                            "action_failures": sorted(action_failures),
                        },
                    }
                )
            if node_status not in {"degraded", "stale"}:
                continue
            maintenance = cast(dict[str, object], item.get("maintenance") or {})
            drain = cast(dict[str, object], item.get("drain") or {})
            route_scope = "remote_node_degraded" if node_status == "degraded" else "remote_node_stale"
            health_scope = "remote_node_health"
            maintenance_services = {
                str(service)
                for service in cast(list[object], maintenance.get("maintenance_services") or [])
                if str(service)
            }
            service_health = cast(dict[str, object], item.get("service_health") or {})
            services = cast(dict[str, dict[str, object]], service_health.get("services") or {})
            degraded_services = {
                name
                for name, details in services.items()
                if bool(details.get("enabled")) and str(details.get("status") or "") in {"degraded", "pending"}
            }
            maintenance_covers_route = bool(maintenance.get("active")) and node_status == "degraded" and (
                not maintenance_services or degraded_services.issubset(maintenance_services)
            )
            if route_scope in active_scopes or health_scope in active_scopes or maintenance_covers_route or bool(drain.get("active")):
                continue
            role = str(item.get("node_role") or "unknown")
            last_seen_at = str(item.get("last_seen_at") or "-")
            route_level = AlertLevel.warning if node_status == "degraded" else AlertLevel.info
            message = (
                f"Remote node {node_name} ({role}) is reporting degraded service health."
                if node_status == "degraded"
                else f"Remote node {node_name} ({role}) has gone stale."
            )
            routes.append(
                {
                    "route_id": f"remote-node:{route_scope}:{node_name}",
                    "fingerprint": f"{route_scope}|{node_status}|{last_seen_at}|{service_health.get('overall_status', 'unknown')}",
                    "level": route_level,
                    "title": f"Remote node {node_status}: {node_name}",
                    "message": message,
                    "context": {
                        "node_name": node_name,
                        "node_role": role,
                        "status": node_status,
                        "last_seen_at": last_seen_at,
                        "service_health": service_health,
                        "suppression": suppression,
                        "maintenance": maintenance,
                        "drain": drain,
                        "route_scope": route_scope,
                    },
                }
            )
        return routes

    def _build_remote_node_action_pattern_routes(
        self,
        item: dict[str, object],
        *,
        active_scopes: set[str],
    ) -> list[dict[str, object]]:
        node_name = str(item.get("node_name") or "").strip()
        if not node_name:
            return []
        node_role = str(item.get("node_role") or "unknown")
        now = _utc_now()
        history_cutoff = now - timedelta(hours=max(settings.soc_remote_node_action_history_window_hours, 0.0))
        recent_history = [
            entry
            for entry in self._remote_node_action_history(item)
            if (timestamp := self._parse_datetime(entry.get("at"))) is not None and timestamp >= history_cutoff
        ]
        routes: list[dict[str, object]] = []

        repeated_failures: list[tuple[str, int]] = []
        failure_threshold = max(settings.soc_remote_node_action_failure_repeat_threshold, 1)
        failed_counts = Counter(
            str(entry.get("action") or "").strip()
            for entry in recent_history
            if str(entry.get("transition") or "").strip().casefold() == "failed"
            and str(entry.get("action") or "").strip()
        )
        repeated_failures = sorted(
            [(action, count) for action, count in failed_counts.items() if count >= failure_threshold],
            key=lambda item: (-item[1], item[0]),
        )
        if repeated_failures and "remote_node_action_repeated_failures" not in active_scopes:
            failure_labels = [f"{action} x{count}" for action, count in repeated_failures]
            routes.append(
                {
                    "route_id": f"remote-node:action-failure-pattern:{node_name}",
                    "fingerprint": "|".join(
                        [node_name, *(f"{action}:{count}" for action, count in repeated_failures)]
                    ),
                    "level": AlertLevel.warning,
                    "auto_case": True,
                    "title": f"Remote node repeated action failures: {node_name}",
                    "message": f"Remote node {node_name} has repeated action failures: {', '.join(failure_labels)}.",
                    "context": {
                        "node_name": node_name,
                        "node_role": node_role,
                        "failure_counts": {action: count for action, count in repeated_failures},
                        "history_window_hours": settings.soc_remote_node_action_history_window_hours,
                    },
                }
            )

        retry_threshold = max(settings.soc_remote_node_action_retry_threshold, 1)
        retried_counts = Counter(
            str(entry.get("action") or "").strip()
            for entry in recent_history
            if str(entry.get("transition") or "").strip().casefold() == "retried"
            and str(entry.get("action") or "").strip()
        )
        retry_pressure = sorted(
            [(action, count) for action, count in retried_counts.items() if count >= retry_threshold],
            key=lambda item: (-item[1], item[0]),
        )
        if retry_pressure and "remote_node_action_retry_pressure" not in active_scopes:
            retry_labels = [f"{action} x{count}" for action, count in retry_pressure]
            routes.append(
                {
                    "route_id": f"remote-node:action-retry-pressure:{node_name}",
                    "fingerprint": "|".join([node_name, *(f"{action}:{count}" for action, count in retry_pressure)]),
                    "level": AlertLevel.info,
                    "title": f"Remote node retry pressure: {node_name}",
                    "message": f"Remote node {node_name} has repeated action retries: {', '.join(retry_labels)}.",
                    "context": {
                        "node_name": node_name,
                        "node_role": node_role,
                        "retry_counts": {action: count for action, count in retry_pressure},
                        "history_window_hours": settings.soc_remote_node_action_history_window_hours,
                    },
                }
            )

        stuck_actions = self._collect_stuck_remote_node_actions(item, now=now)
        if stuck_actions and "remote_node_action_stuck" not in active_scopes:
            stuck_labels = [f"{entry['action']} ({entry['status']}, {entry['age_minutes']}m)" for entry in stuck_actions]
            routes.append(
                {
                    "route_id": f"remote-node:action-stuck:{node_name}",
                    "fingerprint": "|".join(
                        [
                            node_name,
                            *(f"{entry['action']}:{entry['status']}:{entry['age_minutes']}" for entry in stuck_actions),
                        ]
                    ),
                    "level": AlertLevel.warning,
                    "auto_case": True,
                    "title": f"Remote node action stuck: {node_name}",
                    "message": f"Remote node {node_name} has overdue actions: {', '.join(stuck_labels)}.",
                    "context": {
                        "node_name": node_name,
                        "node_role": node_role,
                        "stuck_actions": stuck_actions,
                        "stuck_minutes_threshold": settings.soc_remote_node_action_stuck_minutes,
                    },
                }
            )
        return routes

    def _collect_stuck_remote_node_actions(
        self,
        item: dict[str, object],
        *,
        now: datetime,
    ) -> list[dict[str, object]]:
        threshold = max(settings.soc_remote_node_action_stuck_minutes, 0.0)
        candidates = [
            ("refresh", cast(dict[str, object], item.get("refresh") or {})),
            ("maintenance", cast(dict[str, object], item.get("maintenance") or {})),
            ("drain", cast(dict[str, object], item.get("drain") or {})),
        ]
        stuck_actions: list[dict[str, object]] = []
        for action_name, payload in candidates:
            status = str(payload.get("status") or "").strip().casefold()
            if status not in {"requested", "acknowledged"}:
                continue
            started_at = self._parse_datetime(payload.get(f"{action_name}_acknowledged_at")) or self._parse_datetime(
                payload.get(f"{action_name}_requested_at")
            )
            if started_at is None:
                continue
            age_minutes = round((now - started_at).total_seconds() / 60.0, 1)
            if age_minutes < threshold:
                continue
            stuck_actions.append(
                {
                    "action": action_name,
                    "status": status,
                    "age_minutes": age_minutes,
                    "requested_at": payload.get(f"{action_name}_requested_at"),
                    "acknowledged_at": payload.get(f"{action_name}_acknowledged_at"),
                }
            )
        stuck_actions.sort(key=lambda entry: (-cast(float, entry["age_minutes"]), str(entry["action"])))
        return stuck_actions

    @staticmethod
    def _remote_node_action_history(item: dict[str, object]) -> list[dict[str, object]]:
        direct_history = cast(list[object], item.get("action_history") or [])
        if direct_history:
            return [dict(entry) for entry in direct_history if isinstance(entry, Mapping)]
        metadata = cast(dict[str, object], item.get("metadata") or {})
        return [dict(entry) for entry in cast(list[object], metadata.get("action_history") or []) if isinstance(entry, Mapping)]

    @staticmethod
    def _read_notification_state(path: Path) -> dict[str, dict[str, object]]:
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _write_notification_state(path: Path, payload: dict[str, dict[str, object]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _coerce_int(value: object) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return 0
        return 0

    @staticmethod
    def _parse_datetime(value: object) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

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
    def _event_matches_text(event: SocEventRecord, query: str) -> bool:
        haystacks = [
            event.event_id,
            event.event_type,
            event.source,
            event.title,
            event.summary,
            *event.tags,
            *event.artifacts,
            json.dumps(event.details, sort_keys=True),
        ]
        return any(query in value.casefold() for value in haystacks)

    @staticmethod
    def _alert_matches_text(alert: SocAlertRecord, query: str) -> bool:
        haystacks = [
            alert.alert_id,
            alert.title,
            alert.summary,
            alert.category,
            alert.correlation_rule or "",
            alert.correlation_key or "",
            alert.assignee or "",
            alert.linked_case_id or "",
            *alert.source_event_ids,
            *alert.notes,
        ]
        return any(query in value.casefold() for value in haystacks)

    @staticmethod
    def _case_matches_text(case: SocCaseRecord, query: str) -> bool:
        haystacks = [
            case.case_id,
            case.title,
            case.summary,
            case.assignee or "",
            *case.source_event_ids,
            *case.linked_alert_ids,
            *case.observables,
            *case.notes,
        ]
        return any(query in value.casefold() for value in haystacks)

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
    def _sort_events(events: list[SocEventRecord], sort: str) -> None:
        severity_rank = {
            SocSeverity.low: 0,
            SocSeverity.medium: 1,
            SocSeverity.high: 2,
            SocSeverity.critical: 3,
        }
        if sort == "created_asc":
            events.sort(key=lambda item: item.created_at)
        elif sort == "severity_desc":
            events.sort(key=lambda item: (severity_rank[item.severity], item.created_at), reverse=True)
        elif sort == "severity_asc":
            events.sort(key=lambda item: (severity_rank[item.severity], item.created_at))
        else:
            events.sort(key=lambda item: item.created_at, reverse=True)

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
        self._store.event_store.append(event)
        self._store.event_index_store.append(event)

    def _prune_telemetry_events_locked(self) -> None:
        events = self._store.event_store.list()
        if not events:
            return
        now = _utc_now()
        kept_events: list[SocEventRecord] = []
        pruned = 0
        for event in events:
            retention_hours = self._retention_hours_for_event_type(event.event_type)
            if retention_hours is not None and event.created_at < now - timedelta(hours=retention_hours):
                pruned += 1
                continue
            kept_events.append(event)
        if pruned:
            self._store.replace_events(kept_events)
            self._audit.log("soc.telemetry.pruned", {"pruned_events": pruned})

    @classmethod
    def _retention_hours_for_event_type(cls, event_type: str) -> float | None:
        setting_name = cls._TELEMETRY_RETENTION_HOURS.get(event_type)
        if not setting_name:
            return None
        value = getattr(settings, setting_name, None)
        if value is None:
            return None
        return float(value)

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
