from __future__ import annotations

from datetime import UTC, datetime, timedelta

from security_gateway.audit import AuditLogger
from security_gateway.models import SocAlertRecord, SocAlertStatus, SocCaseRecord, SocCaseStatus, SocSeverity
from security_gateway.soc import SecurityOperationsManager


class DummyAlertManager:
    def __init__(self) -> None:
        self.events: list[object] = []

    def emit(self, event: object) -> None:
        self.events.append(event)


def _manager(tmp_path):
    alerts = DummyAlertManager()
    manager = SecurityOperationsManager(
        event_log_path=tmp_path / "soc_events.jsonl",
        alert_store_path=tmp_path / "soc_alerts.json",
        case_store_path=tmp_path / "soc_cases.json",
        audit_logger=AuditLogger(tmp_path / "audit.jsonl"),
        alert_manager=alerts,
    )
    return manager, alerts


def test_dashboard_includes_assignee_workload_and_aging_buckets(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    now = datetime.now(UTC)
    manager._write_records(  # type: ignore[attr-defined]
        manager._alert_store_path,  # type: ignore[attr-defined]
        [
            SocAlertRecord(
                alert_id="alert-1",
                title="Assigned stale alert",
                summary="Needs handoff",
                severity=SocSeverity.high,
                status=SocAlertStatus.open,
                assignee="tier1",
                created_at=now - timedelta(hours=30),
                updated_at=now - timedelta(hours=30),
            ),
            SocAlertRecord(
                alert_id="alert-2",
                title="Fresh unassigned alert",
                summary="New work",
                severity=SocSeverity.medium,
                status=SocAlertStatus.open,
                created_at=now - timedelta(hours=2),
                updated_at=now - timedelta(hours=2),
            ),
        ],
    )
    manager._write_records(  # type: ignore[attr-defined]
        manager._case_store_path,  # type: ignore[attr-defined]
        [
            SocCaseRecord(
                case_id="case-1",
                title="Investigating",
                summary="Needs follow-up",
                severity=SocSeverity.high,
                assignee="tier1",
                status=SocCaseStatus.investigating,
                created_at=now - timedelta(hours=80),
                updated_at=now - timedelta(hours=80),
            )
        ],
    )

    payload = manager.dashboard()

    assert payload["aging_buckets"]["alerts"]["24-72h"] == 1
    assert payload["aging_buckets"]["cases"]["72h+"] == 1
    assert payload["assignee_workload"][0]["assignee"] == "tier1"
    assert payload["assignee_workload"][0]["stale_alerts"] == 1
    assert payload["assignee_workload"][0]["stale_cases"] == 1


def test_emit_operational_notifications_deduplicates(tmp_path) -> None:
    manager, alerts = _manager(tmp_path)
    now = datetime.now(UTC)
    manager._write_records(  # type: ignore[attr-defined]
        manager._alert_store_path,  # type: ignore[attr-defined]
        [
            SocAlertRecord(
                alert_id="alert-1",
                title="Assigned stale alert",
                summary="Needs handoff",
                severity=SocSeverity.high,
                status=SocAlertStatus.open,
                assignee="tier1",
                created_at=now - timedelta(hours=30),
                updated_at=now - timedelta(hours=30),
            )
        ],
    )
    manager._write_records(  # type: ignore[attr-defined]
        manager._case_store_path,  # type: ignore[attr-defined]
        [
            SocCaseRecord(
                case_id="case-1",
                title="Investigating",
                summary="Needs escalation",
                severity=SocSeverity.high,
                assignee="tier1",
                status=SocCaseStatus.investigating,
                created_at=now - timedelta(hours=30),
                updated_at=now - timedelta(hours=30),
            )
        ],
    )
    state_path = tmp_path / "soc_operational_notifications.json"

    first = manager.emit_operational_notifications(state_path=state_path)
    second = manager.emit_operational_notifications(state_path=state_path)

    assert first["emitted"] >= 2
    assert second["emitted"] == 0
    assert len(alerts.events) == int(first["emitted"])
