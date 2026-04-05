from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from security_gateway.audit import AuditLogger
from security_gateway.config import settings
from security_gateway.detection_engine import DetectionEngine
from security_gateway.models import SocDetectionRuleUpdate
from security_gateway.models import (
    SocAlertRecord,
    SocAlertStatus,
    SocCaseCreate,
    SocCaseTelemetryClusterCaseRequest,
    SocCaseEndpointLineageClusterCaseRequest,
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocCaseRecord,
    SocCaseStatus,
    SocDashboardViewStateUpdate,
    SocEndpointLineageClusterCaseRequest,
    SocEndpointQueryCaseRequest,
    SocEndpointTimelineCaseRequest,
    SocEventRecord,
    SocEventIngest,
    SocSeverity,
    SocTelemetryClusterCaseRequest,
)
from security_gateway.platform import upsert_platform_node
from security_gateway.soc import SecurityOperationsManager


class DummyAlertManager:
    def __init__(self) -> None:
        self.events: list[object] = []

    def emit(self, event: object) -> None:
        self.events.append(event)


def _manager(tmp_path):
    alerts = DummyAlertManager()
    settings.soc_event_index_path = str(tmp_path / "soc_event_index.json")
    manager = SecurityOperationsManager(
        event_log_path=tmp_path / "soc_events.jsonl",
        alert_store_path=tmp_path / "soc_alerts.json",
        case_store_path=tmp_path / "soc_cases.json",
        audit_logger=AuditLogger(tmp_path / "audit.jsonl"),
        alert_manager=alerts,
        detection_engine=DetectionEngine(tmp_path / "soc_detection_catalog.json"),
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
    assert payload["platform"]["node_role"] == "standalone"
    assert payload["platform"]["service_health"]["enabled_services"] >= 1
    assert payload["platform"]["service_health"]["services"]["packet_monitor"]["enabled"] is True
    assert payload["storage"]["backend"] == "json-file"
    assert payload["storage"]["event_index_backend"] == "sqlite-event-index"
    assert payload["storage"]["event_count"] == 0
    assert payload["storage"]["event_indexed_count"] == 0
    assert payload["storage"]["alert_count"] == 2
    assert payload["storage"]["case_count"] == 1


def test_hunt_returns_index_stats_and_filtered_events(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.connection",
            source="sensor-a",
            severity=SocSeverity.high,
            title="Suspicious remote session",
            summary="Observed connection to 185.146.173.20 over tcp/443",
            details={"remote_ip": "185.146.173.20", "protocol": "tcp"},
            tags=["network", "session"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.posture",
            source="host-a",
            severity=SocSeverity.medium,
            title="Endpoint drift",
            summary="Agent policy drift detected",
            details={"hostname": "host-a"},
            tags=["endpoint"],
        )
    )

    payload = manager.hunt(query="185.146.173.20", source="sensor-a", limit=10)

    assert payload["index"]["backend"] == "sqlite-event-index"
    assert payload["index"]["indexed_event_count"] == 2
    assert payload["index"]["token_count"] >= 1
    assert payload["index"]["facet_source"] == "sqlite-event-index"
    assert payload["index"]["timeline_source"] == "sqlite-event-index"
    assert len(payload["events"]) == 1
    assert payload["facets"]["source"] == [{"value": "sensor-a", "count": 1}]
    assert payload["events"][0]["source"] == "sensor-a"
    assert payload["events"][0]["details"]["remote_ip"] == "185.146.173.20"


def test_event_index_status_and_rebuild_report_store_state(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="endpoint-a",
            severity=SocSeverity.medium,
            title="Process telemetry",
            summary="Process seen",
            details={"device_id": "device-11", "process_name": "powershell.exe"},
            tags=["endpoint"],
        )
    )

    status = manager.event_index_status()
    rebuilt = manager.rebuild_event_index()

    assert status["backend"] == "sqlite-event-index"
    assert status["event_count"] == 1
    assert status["indexed_event_count"] == 1
    assert status["stale"] is False
    assert status["indexed_at"] is not None
    assert status["dimension_counts"]["process_names"] >= 1
    assert rebuilt["rebuilt"] is True
    assert rebuilt["indexed_event_count"] == 1


def test_event_index_status_marks_signature_drift_as_stale(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    first_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="endpoint-a",
            severity=SocSeverity.medium,
            title="Process telemetry",
            summary="Process seen",
            details={"device_id": "device-stale", "process_name": "powershell.exe"},
            tags=["endpoint"],
        )
    ).event
    second_event = SocEventRecord(
        event_id="evt-stale-2",
        event_type="endpoint.telemetry.connection",
        source="endpoint-a",
        severity=SocSeverity.high,
        title="Connection telemetry",
        summary="Connection seen",
        details={"device_id": "device-stale", "process_name": "powershell.exe", "remote_ip": "198.51.100.201"},
        tags=["endpoint", "connection"],
        artifacts=[],
        created_at=datetime.now(UTC),
    )

    manager._store.event_store.write([first_event, second_event])  # type: ignore[attr-defined]

    status = manager.event_index_status()

    assert status["event_count"] == 2
    assert status["indexed_event_count"] == 1
    assert status["stale"] is True


def test_query_events_uses_indexed_time_window_and_link_state_filters(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    older = SocEventRecord(
        event_id="evt-query-index-older",
        event_type="endpoint.telemetry.process",
        source="endpoint-a",
        severity=SocSeverity.medium,
        title="Older process",
        summary="Older endpoint event",
        details={"device_id": "device-time", "process_name": "powershell.exe"},
        tags=["endpoint"],
        artifacts=[],
        created_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
        linked_alert_id="alert-linked-1",
    )
    newer = SocEventRecord(
        event_id="evt-query-index-newer",
        event_type="endpoint.telemetry.connection",
        source="endpoint-a",
        severity=SocSeverity.high,
        title="Newer connection",
        summary="Newer endpoint event",
        details={"device_id": "device-time", "process_name": "powershell.exe", "remote_ip": "198.51.100.202"},
        tags=["endpoint", "connection"],
        artifacts=[],
        created_at=datetime(2026, 4, 2, 0, 0, tzinfo=UTC),
        linked_alert_id=None,
    )

    manager._store.event_store.write([older, newer])  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild([older, newer], event_store=manager._store.event_store)  # type: ignore[attr-defined]

    linked_events = manager.query_events(linked_alert_state="linked", limit=10)
    windowed_events = manager.query_events(
        start_at=datetime(2026, 4, 1, 12, 0, tzinfo=UTC),
        end_at=datetime(2026, 4, 2, 12, 0, tzinfo=UTC),
        limit=10,
    )

    assert [item.event_id for item in linked_events] == ["evt-query-index-older"]
    assert [item.event_id for item in windowed_events] == ["evt-query-index-newer"]


def test_query_endpoint_telemetry_supports_advanced_filters(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="endpoint-a",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.dll",
            summary="Endpoint device-11 reported file activity for payload.dll.",
            details={
                "document_type": "endpoint_file",
                "device_id": "device-11",
                "filename": "payload.dll",
                "artifact_path": "C:/Temp/payload.dll",
                "operation": "write",
                "verdict": "suspicious",
                "file_extension": ".dll",
                "actor_process_name": "powershell.exe",
                "parent_process_name": "explorer.exe",
                "reputation": "unknown",
                "risk_flags": ["unsigned", "temp_path"],
            },
            tags=["endpoint", "telemetry", "file", "write", "unsigned"],
        )
    )

    payload = manager.query_endpoint_telemetry(
        device_id="device-11",
        document_type="endpoint_file",
        parent_process_name="explorer.exe",
        reputation="unknown",
        risk_flag="temp_path",
        verdict="suspicious",
        operation="write",
        file_extension=".dll",
        limit=20,
    )

    assert payload["match_count"] == 1
    assert payload["events"][0]["details"]["filename"] == "payload.dll"


def test_query_endpoint_telemetry_includes_lineage_joins(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="endpoint-a",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-join reported powershell execution.",
            details={
                "document_type": "endpoint_process",
                "device_id": "device-join",
                "process_name": "powershell.exe",
                "process_guid": "proc-join-a",
                "parent_process_name": "explorer.exe",
                "parent_process_guid": "parent-join-1",
                "sha256": "hash-join-a",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="endpoint-a",
            severity=SocSeverity.medium,
            title="Endpoint process telemetry: cmd.exe",
            summary="Endpoint device-join reported cmd execution.",
            details={
                "document_type": "endpoint_process",
                "device_id": "device-join",
                "process_name": "cmd.exe",
                "process_guid": "proc-join-b",
                "parent_process_name": "explorer.exe",
                "parent_process_guid": "parent-join-1",
                "sha256": "hash-join-b",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="endpoint-a",
            severity=SocSeverity.medium,
            title="Endpoint file telemetry: payload.dll",
            summary="Endpoint device-join wrote payload.dll.",
            details={
                "document_type": "endpoint_file",
                "device_id": "device-join",
                "filename": "payload.dll",
                "artifact_path": "C:/Temp/payload.dll",
                "actor_process_name": "powershell.exe",
                "actor_process_guid": "proc-join-a",
                "parent_process_name": "explorer.exe",
                "parent_process_guid": "parent-join-1",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    )

    payload = manager.query_endpoint_telemetry(device_id="device-join", limit=10)

    process_record = next(item for item in payload["events"] if item["event_id"] == process_event.event_id)

    assert payload["match_count"] == 3
    assert process_record["lineage"]["cluster_key"] == "device-join::parent-join-1::powershell.exe"
    assert process_record["lineage"]["parent_process_name"] == "explorer.exe"
    assert process_record["lineage"]["child_process_names"] == ["cmd.exe"]
    assert process_record["lineage"]["related_filenames"] == ["payload.dll"]


def test_create_case_from_endpoint_query_promotes_filtered_slice(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="endpoint-a",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-query-case reported powershell execution.",
            details={
                "document_type": "endpoint_process",
                "device_id": "device-query-case",
                "process_name": "powershell.exe",
                "process_guid": "proc-query-case",
                "parent_process_name": "explorer.exe",
                "sha256": "hash-query-case",
                "signer_name": "Unknown",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    file_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="endpoint-a",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.dll",
            summary="Endpoint device-query-case wrote payload.dll.",
            details={
                "document_type": "endpoint_file",
                "device_id": "device-query-case",
                "filename": "payload.dll",
                "artifact_path": "C:/Temp/payload.dll",
                "actor_process_name": "powershell.exe",
                "actor_process_guid": "proc-query-case",
                "parent_process_name": "explorer.exe",
                "operation": "write",
                "verdict": "suspicious",
                "file_extension": ".dll",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event

    case = manager.create_case_from_endpoint_query(
        SocEndpointQueryCaseRequest(
            device_id="device-query-case",
            parent_process_name="explorer.exe",
            operation="write",
            file_extension=".dll",
            assignee="tier2",
        )
    )

    assert case.assignee == "tier2"
    assert file_event.event_id in case.source_event_ids
    assert process_event.event_id not in case.source_event_ids
    assert "device:device-query-case" in case.observables
    assert "filename:payload.dll" in case.observables
    assert "artifact_path:C:/Temp/payload.dll" in case.observables


def test_hunt_supports_observable_filters(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.connection",
            source="sensor-a",
            severity=SocSeverity.high,
            title="Suspicious remote session",
            summary="Observed connection to 185.146.173.20 over tcp/443",
            details={"remote_ip": "185.146.173.20", "protocol": "tcp"},
            tags=["network", "session"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.malware_detected",
            source="host-a",
            severity=SocSeverity.critical,
            title="Malware detected on db-admin-01",
            summary="bad.exe matched and requires investigation.",
            details={
                "hostname": "db-admin-01",
                "filename": "bad.exe",
                "artifact_path": "C:/temp/bad.exe",
            },
            artifacts=["C:/temp/bad.exe"],
            tags=["endpoint", "malware"],
        )
    )

    payload = manager.hunt(hostname="db-admin-01", filename="bad.exe", artifact_path="C:/temp/bad.exe", limit=10)

    assert len(payload["events"]) == 1
    assert payload["events"][0]["event_type"] == "endpoint.malware_detected"


def test_hunt_supports_time_filters_and_facets(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    older = SocEventRecord(
        event_id="evt-old",
        event_type="network.telemetry.connection",
        source="sensor-a",
        severity=SocSeverity.medium,
        title="Older connection",
        summary="Observed connection to 198.51.100.10.",
        details={"remote_ip": "198.51.100.10", "device_id": "device-old", "process_name": "curl.exe"},
        tags=["network", "telemetry"],
        artifacts=[],
        created_at=datetime(2026, 3, 31, 0, 0, tzinfo=UTC),
        linked_alert_id=None,
    )
    newer = SocEventRecord(
        event_id="evt-new",
        event_type="endpoint.telemetry.process",
        source="sensor-b",
        severity=SocSeverity.high,
        title="Newer process",
        summary="Endpoint device-new reported process activity.",
        details={"device_id": "device-new", "process_name": "powershell.exe", "remote_ip": "203.0.113.55"},
        tags=["endpoint", "telemetry"],
        artifacts=[],
        created_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
        linked_alert_id=None,
    )
    manager._store.event_store.write([older, newer])  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild([older, newer])  # type: ignore[attr-defined]

    payload = manager.hunt(
        start_at=datetime(2026, 3, 31, 12, 0, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 12, 0, tzinfo=UTC),
        facet_limit=3,
        limit=10,
    )

    assert payload["match_count"] == 1
    assert payload["events"][0]["event_id"] == "evt-new"
    assert payload["filters"]["start_at"] == "2026-03-31T12:00:00+00:00"
    assert payload["filters"]["end_at"] == "2026-04-01T12:00:00+00:00"
    assert payload["filters"]["facet_limit"] == 3
    assert payload["facets"]["source"] == [{"value": "sensor-b", "count": 1}]
    assert payload["facets"]["event_type"] == [{"value": "endpoint.telemetry.process", "count": 1}]
    assert payload["facets"]["document_type"] == []
    assert payload["facets"]["device_id"] == [{"value": "device-new", "count": 1}]
    assert payload["timeline"]["bucket_unit"] == "hour"
    assert payload["timeline"]["buckets"] == [{"start_at": "2026-04-01T00:00:00+00:00", "count": 1}]
    assert payload["summaries"]["document_types"] == []
    assert payload["summaries"]["severities"] == [{"value": "high", "count": 1}]


def test_telemetry_summaries_include_facets_timeline_and_entity_breakdowns(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    events = [
        SocEventRecord(
            event_id="evt-endpoint-process",
            event_type="endpoint.telemetry.process",
            source="sensor-a",
            severity=SocSeverity.high,
            title="Endpoint process telemetry",
            summary="Endpoint device-summary reported process activity.",
            details={
                "document_type": "endpoint_process",
                "device_id": "device-summary",
                "process_name": "powershell.exe",
                "process_guid": "proc-summary",
                "signer_name": "Unknown",
            },
            tags=["endpoint", "telemetry", "process"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-endpoint-file",
            event_type="endpoint.telemetry.file",
            source="sensor-a",
            severity=SocSeverity.medium,
            title="Endpoint file telemetry",
            summary="Endpoint device-summary reported file activity.",
            details={
                "document_type": "endpoint_file",
                "device_id": "device-summary",
                "filename": "payload.dll",
                "signer_name": "Unknown",
            },
            tags=["endpoint", "telemetry", "file"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 1, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-network",
            event_type="network.telemetry.connection",
            source="sensor-b",
            severity=SocSeverity.medium,
            title="Network telemetry",
            summary="Observed connection to 203.0.113.77.",
            details={
                "document_type": "network_connection",
                "remote_ip": "203.0.113.77",
                "device_id": "sensor-b",
            },
            tags=["network", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 2, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-packet",
            event_type="packet.telemetry.session",
            source="sensor-c",
            severity=SocSeverity.low,
            title="Packet telemetry",
            summary="Packet monitor captured a normalized session document.",
            details={
                "document_type": "packet_session",
                "remote_ip": "203.0.113.77",
                "session_key": "packet-session:summary",
            },
            tags=["packet", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 3, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
    ]
    manager._store.event_store.write(events)  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    endpoint_summary = manager.summarize_endpoint_telemetry(
        device_id="device-summary",
        start_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 2, 0, tzinfo=UTC),
        facet_limit=3,
        limit=10,
    )
    network_summary = manager.summarize_network_telemetry(
        remote_ip="203.0.113.77",
        start_at=datetime(2026, 4, 1, 1, 30, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 2, 30, tzinfo=UTC),
        facet_limit=2,
        limit=10,
    )
    packet_summary = manager.summarize_packet_telemetry(
        session_key="packet-session:summary",
        start_at=datetime(2026, 4, 1, 2, 30, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 3, 30, tzinfo=UTC),
        facet_limit=2,
        limit=10,
    )

    assert endpoint_summary["telemetry"] == "endpoint"
    assert endpoint_summary["match_count"] == 2
    assert endpoint_summary["facets"]["document_type"] == [
        {"value": "endpoint_file", "count": 1},
        {"value": "endpoint_process", "count": 1},
    ]
    assert endpoint_summary["timeline"]["bucket_unit"] == "hour"
    assert endpoint_summary["summaries"]["device_ids"] == [{"value": "device-summary", "count": 2}]
    assert endpoint_summary["summaries"]["process_names"] == [{"value": "powershell.exe", "count": 1}]
    assert endpoint_summary["summaries"]["signers"] == [{"value": "Unknown", "count": 2}]
    assert network_summary["telemetry"] == "network"
    assert network_summary["match_count"] == 1
    assert network_summary["retention_hours"] == settings.soc_network_telemetry_retention_hours
    assert network_summary["facets"]["remote_ip"] == [{"value": "203.0.113.77", "count": 1}]
    assert packet_summary["telemetry"] == "packet"
    assert packet_summary["match_count"] == 1
    assert packet_summary["retention_hours"] == settings.soc_packet_telemetry_retention_hours
    assert packet_summary["summaries"]["remote_ips"] == [{"value": "203.0.113.77", "count": 1}]


def test_endpoint_lineage_summary_includes_cluster_facets_and_timeline(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    events = [
        SocEventRecord(
            event_id="evt-lineage-proc",
            event_type="endpoint.telemetry.process",
            source="sensor-a",
            severity=SocSeverity.high,
            title="Endpoint process telemetry",
            summary="Endpoint device-lineage reported process activity.",
            details={
                "document_type": "endpoint_process",
                "device_id": "device-lineage",
                "process_name": "powershell.exe",
                "process_guid": "proc-lineage",
                "sha256": "lineage-sha",
                "parent_process_name": "winword.exe",
                "parent_process_guid": "parent-lineage",
                "signer_name": "Unknown",
            },
            tags=["endpoint", "telemetry", "process"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-lineage-file",
            event_type="endpoint.telemetry.file",
            source="sensor-a",
            severity=SocSeverity.medium,
            title="Endpoint file telemetry",
            summary="Endpoint device-lineage reported file activity.",
            details={
                "document_type": "endpoint_file",
                "device_id": "device-lineage",
                "filename": "payload.dll",
                "artifact_path": "C:/Users/Public/payload.dll",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "lineage-sha",
            },
            tags=["endpoint", "telemetry", "file"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 1, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
    ]
    manager._store.event_store.write(events)  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    summary = manager.summarize_endpoint_lineage(
        device_id="device-lineage",
        start_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 2, 0, tzinfo=UTC),
        facet_limit=3,
        limit=10,
    )

    assert summary["telemetry"] == "endpoint_lineage"
    assert summary["match_count"] == 1
    assert summary["facets"]["lineage_root"] == [{"value": "parent-lineage", "count": 1}]
    assert summary["facets"]["filename"] == [{"value": "payload.dll", "count": 1}]
    assert summary["timeline"]["bucket_unit"] == "hour"
    assert summary["summaries"]["process_names"] == [{"value": "powershell.exe", "count": 1}]
    assert summary["clusters"][0]["cluster_key"] == "device-lineage::parent-lineage::proc-lineage"


def test_network_flow_docs_support_deeper_search_filters(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    events = [
        SocEventRecord(
            event_id="evt-network-conn",
            event_type="network.telemetry.connection",
            source="sensor-b",
            severity=SocSeverity.medium,
            title="Network telemetry",
            summary="Observed connection to 203.0.113.77.",
            details={
                "document_type": "network_connection",
                "remote_ip": "203.0.113.77",
                "local_ports": [8443],
                "remote_ports": [51000],
                "states": ["ESTABLISHED"],
            },
            tags=["network", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 2, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-network-flow",
            event_type="network.telemetry.flow",
            source="sensor-b",
            severity=SocSeverity.low,
            title="Network flow telemetry",
            summary="Observed inbound flow from 203.0.113.77 to 10.0.0.5:8443.",
            details={
                "schema": "network_flow_v1",
                "document_type": "network_flow",
                "flow_id": "flow:tcp:203.0.113.77:51000:10.0.0.5:8443:na",
                "remote_ip": "203.0.113.77",
                "remote_port": 51000,
                "local_ip": "10.0.0.5",
                "local_port": 8443,
                "protocol": "tcp",
                "service_name": "https-alt",
                "application_protocol": "https-alt",
                "transport_family": "tcp",
                "state": "ESTABLISHED",
                "direction": "inbound",
            },
            tags=["network", "telemetry", "flow", "tcp"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 2, 5, tzinfo=UTC),
            linked_alert_id=None,
        ),
    ]
    manager._store.event_store.write(events)  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    filtered = manager.query_events(
        event_type="network.telemetry.flow",
        remote_ip="203.0.113.77",
        flow_id="flow:tcp:203.0.113.77:51000:10.0.0.5:8443:na",
        service_name="https-alt",
        application_protocol="https-alt",
        local_ip="10.0.0.5",
        local_port="8443",
        remote_port="51000",
        protocol="tcp",
        state="ESTABLISHED",
        limit=10,
    )
    hunt_payload = manager.hunt(
        event_type="network.telemetry.flow",
        flow_id="flow:tcp:203.0.113.77:51000:10.0.0.5:8443:na",
        service_name="https-alt",
        application_protocol="https-alt",
        local_ip="10.0.0.5",
        local_port="8443",
        remote_port="51000",
        protocol="tcp",
        state="ESTABLISHED",
        limit=10,
    )
    network_summary = manager.summarize_network_telemetry(
        remote_ip="203.0.113.77",
        flow_id="flow:tcp:203.0.113.77:51000:10.0.0.5:8443:na",
        service_name="https-alt",
        application_protocol="https-alt",
        local_ip="10.0.0.5",
        local_port="8443",
        remote_port="51000",
        protocol="tcp",
        state="ESTABLISHED",
        start_at=datetime(2026, 4, 1, 2, 0, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 3, 0, tzinfo=UTC),
        facet_limit=3,
        limit=10,
    )

    assert [item.event_id for item in filtered] == ["evt-network-flow"]
    assert hunt_payload["events"][0]["event_id"] == "evt-network-flow"
    assert hunt_payload["filters"]["local_ip"] == "10.0.0.5"
    assert hunt_payload["facets"]["protocol"] == [{"value": "tcp", "count": 1}]
    assert hunt_payload["facets"]["service_name"] == [{"value": "https-alt", "count": 1}]
    assert hunt_payload["facets"]["local_port"] == [{"value": "8443", "count": 1}]
    assert hunt_payload["summaries"]["states"] == [{"value": "ESTABLISHED", "count": 1}]
    assert hunt_payload["summaries"]["application_protocols"] == [{"value": "https-alt", "count": 1}]
    assert network_summary["match_count"] == 1
    assert network_summary["facets"]["local_ip"] == [{"value": "10.0.0.5", "count": 1}]
    assert network_summary["facets"]["service_name"] == [{"value": "https-alt", "count": 1}]
    assert network_summary["summaries"]["protocols"] == [{"value": "tcp", "count": 1}]


def test_query_events_supports_close_reason_and_reject_code_filters(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    events = [
        SocEventRecord(
            event_id="evt-vpn-close",
            event_type="network.telemetry.vpn",
            source="sensor-auth",
            severity=SocSeverity.medium,
            title="VPN session closed",
            summary="VPN session closed because of idle timeout.",
            details={
                "schema": "network_vpn_v1",
                "document_type": "network_vpn",
                "username": "analyst",
                "hostname": "vpn-gateway-1",
                "close_reason": "idle-timeout",
                "session_event": "disconnect",
            },
            tags=["network", "telemetry", "vpn"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 4, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-radius-reject",
            event_type="network.telemetry.radius",
            source="sensor-auth",
            severity=SocSeverity.high,
            title="RADIUS reject",
            summary="RADIUS authentication rejected for analyst.",
            details={
                "schema": "network_radius_v1",
                "document_type": "network_radius",
                "username": "analyst",
                "hostname": "vpn-gateway-1",
                "reject_code": "access-reject",
                "outcome": "failure",
            },
            tags=["network", "telemetry", "radius"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 4, 5, tzinfo=UTC),
            linked_alert_id=None,
        ),
    ]
    manager._store.event_store.write(events)  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    vpn_filtered = manager.query_events(event_type="network.telemetry.vpn", close_reason="idle-timeout", limit=10)
    radius_filtered = manager.query_events(event_type="network.telemetry.radius", reject_code="access-reject", limit=10)
    hunt_payload = manager.hunt(source="sensor-auth", limit=10, facet_limit=5)

    assert [item.event_id for item in vpn_filtered] == ["evt-vpn-close"]
    assert [item.event_id for item in radius_filtered] == ["evt-radius-reject"]
    assert hunt_payload["facets"]["close_reason"] == [{"value": "idle-timeout", "count": 1}]
    assert hunt_payload["facets"]["reject_code"] == [{"value": "access-reject", "count": 1}]
    assert hunt_payload["summaries"]["close_reasons"] == [{"value": "idle-timeout", "count": 1}]
    assert hunt_payload["summaries"]["reject_codes"] == [{"value": "access-reject", "count": 1}]


def test_packet_session_docs_support_deeper_search_filters(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    event = SocEventRecord(
        event_id="evt-packet-session",
        event_type="packet.telemetry.session",
        source="sensor-c",
        severity=SocSeverity.low,
        title="Packet telemetry",
        summary="Packet monitor captured a normalized session document.",
        details={
            "schema": "packet_session_v1",
            "document_type": "packet_session",
            "session_key": "packet-session:cluster",
            "remote_ip": "203.0.113.88",
            "local_ip": "10.0.0.5",
            "local_port": 3389,
            "remote_port": 51000,
            "protocol": "tcp",
            "protocols": ["TCP"],
            "local_ips": ["10.0.0.5"],
            "local_ports": [3389],
            "remote_ports": [51000],
            "packet_count": 15,
            "sample_count": 1,
        },
        tags=["packet", "telemetry"],
        artifacts=[],
        created_at=datetime(2026, 4, 1, 2, 0, tzinfo=UTC),
        linked_alert_id=None,
    )
    manager._store.event_store.write([event])  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild([event])  # type: ignore[attr-defined]

    filtered = manager.query_events(
        event_type="packet.telemetry.session",
        session_key="packet-session:cluster",
        local_ip="10.0.0.5",
        local_port="3389",
        remote_port="51000",
        protocol="tcp",
        limit=10,
    )
    hunt_payload = manager.hunt(
        event_type="packet.telemetry.session",
        local_ip="10.0.0.5",
        local_port="3389",
        remote_port="51000",
        protocol="tcp",
        limit=10,
    )
    packet_summary = manager.summarize_packet_telemetry(
        session_key="packet-session:cluster",
        local_ip="10.0.0.5",
        local_port="3389",
        remote_port="51000",
        protocol="tcp",
        start_at=datetime(2026, 4, 1, 1, 30, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 2, 30, tzinfo=UTC),
        facet_limit=3,
        limit=10,
    )

    assert [item.event_id for item in filtered] == ["evt-packet-session"]
    assert hunt_payload["events"][0]["event_id"] == "evt-packet-session"
    assert hunt_payload["facets"]["protocol"] == [{"value": "tcp", "count": 1}]
    assert hunt_payload["facets"]["local_port"] == [{"value": "3389", "count": 1}]
    assert packet_summary["match_count"] == 1
    assert packet_summary["facets"]["local_ip"] == [{"value": "10.0.0.5", "count": 1}]
    assert packet_summary["summaries"]["protocols"] == [{"value": "tcp", "count": 1}]


def test_endpoint_lineage_clusters_join_process_and_file_activity(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    events = [
        SocEventRecord(
            event_id="evt-proc",
            event_type="endpoint.telemetry.process",
            source="sensor-a",
            severity=SocSeverity.high,
            title="Endpoint process telemetry",
            summary="Endpoint device-44 reported process activity.",
            details={
                "document_type": "endpoint_process",
                "device_id": "device-44",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-44",
                "parent_process_name": "winword.exe",
                "parent_process_guid": "parent-guid-44",
                "parent_chain": ["winword.exe", "explorer.exe"],
                "remote_ip": "203.0.113.144",
            },
            tags=["endpoint", "telemetry", "process"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-file",
            event_type="endpoint.telemetry.file",
            source="sensor-a",
            severity=SocSeverity.medium,
            title="Endpoint file telemetry",
            summary="Endpoint device-44 reported file activity.",
            details={
                "document_type": "endpoint_file",
                "device_id": "device-44",
                "filename": "payload.dll",
                "artifact_path": "C:/Users/Public/payload.dll",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": None,
                "remote_ip": "203.0.113.144",
            },
            tags=["endpoint", "telemetry", "file"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 0, 5, tzinfo=UTC),
            linked_alert_id=None,
        ),
    ]
    manager._store.event_store.write(events)  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    clusters = manager.list_endpoint_lineage_clusters(device_id="device-44", limit=10)
    detail = manager.resolve_endpoint_lineage_cluster(
        "device-44::parent-guid-44::proc-guid-44",
        device_id="device-44",
        limit=10,
    )

    assert len(clusters) == 1
    assert clusters[0]["cluster_key"] == "device-44::parent-guid-44::proc-guid-44"
    assert clusters[0]["lineage_root"] == "parent-guid-44"
    assert clusters[0]["lineage_process"] == "proc-guid-44"
    assert clusters[0]["event_count"] == 2
    assert clusters[0]["parent_process_names"] == ["winword.exe"]
    assert clusters[0]["actor_process_names"] == ["powershell.exe"]
    assert clusters[0]["filenames"] == ["payload.dll"]
    assert len(detail["events"]) == 2


def test_endpoint_lineage_cluster_case_promotion(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    events = [
        SocEventRecord(
            event_id="evt-proc",
            event_type="endpoint.telemetry.process",
            source="sensor-a",
            severity=SocSeverity.high,
            title="Endpoint process telemetry",
            summary="Endpoint device-45 reported process activity.",
            details={
                "document_type": "endpoint_process",
                "device_id": "device-45",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-45",
                "sha256": "ps4545",
                "parent_process_name": "winword.exe",
                "parent_process_guid": "parent-guid-45",
            },
            tags=["endpoint", "telemetry", "process"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-conn",
            event_type="endpoint.telemetry.connection",
            source="sensor-a",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry",
            summary="Endpoint device-45 reported a live connection.",
            details={
                "document_type": "endpoint_connection",
                "device_id": "device-45",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-45",
                "sha256": "ps4545",
                "remote_ip": "203.0.113.145",
            },
            tags=["endpoint", "telemetry", "connection"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 0, 1, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-file",
            event_type="endpoint.telemetry.file",
            source="sensor-a",
            severity=SocSeverity.high,
            title="Endpoint file telemetry",
            summary="Endpoint device-45 reported file activity.",
            details={
                "document_type": "endpoint_file",
                "device_id": "device-45",
                "filename": "payload.dll",
                "artifact_path": "C:/Users/Public/payload.dll",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps4545",
            },
            tags=["endpoint", "telemetry", "file"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 0, 2, tzinfo=UTC),
            linked_alert_id=None,
        ),
    ]
    manager._store.event_store.write(events)  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    promoted = manager.create_case_from_endpoint_lineage_cluster(
        SocEndpointLineageClusterCaseRequest(
            cluster_key="device-45::parent-guid-45::proc-guid-45",
            device_id="device-45",
            assignee="tier2",
        )
    )

    assert promoted.assignee == "tier2"
    assert promoted.source_event_ids == ["evt-proc", "evt-conn", "evt-file"]
    assert "device:device-45" in promoted.observables
    assert "process_guid:proc-guid-45" in promoted.observables
    assert "remote_ip:203.0.113.145" in promoted.observables
    assert "filename:payload.dll" in promoted.observables


def test_hunt_telemetry_clusters_and_case_promotion(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    events = [
        SocEventRecord(
            event_id="evt-endpoint-conn",
            event_type="endpoint.telemetry.connection",
            source="sensor-a",
            severity=SocSeverity.high,
            title="Endpoint connection telemetry",
            summary="Endpoint device-22 reported a live connection for powershell.exe.",
            details={
                "document_type": "endpoint_connection",
                "device_id": "device-22",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-22",
                "remote_ip": "203.0.113.88",
                "signer_name": "Unknown",
            },
            tags=["endpoint", "telemetry", "connection"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-network-conn",
            event_type="network.telemetry.connection",
            source="sensor-b",
            severity=SocSeverity.medium,
            title="Network telemetry",
            summary="Observed connection to 203.0.113.88.",
            details={"document_type": "network_connection", "remote_ip": "203.0.113.88", "device_id": "sensor-b"},
            tags=["network", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 1, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
        SocEventRecord(
            event_id="evt-packet-session",
            event_type="packet.telemetry.session",
            source="sensor-c",
            severity=SocSeverity.low,
            title="Packet telemetry",
            summary="Packet monitor captured a normalized session document.",
            details={
                "document_type": "packet_session",
                "remote_ip": "203.0.113.88",
                "session_key": "packet-session:cluster",
            },
            tags=["packet", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 2, 0, tzinfo=UTC),
            linked_alert_id=None,
        ),
    ]
    manager._store.event_store.write(events)  # type: ignore[attr-defined]
    manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    clusters = manager.list_hunt_telemetry_clusters(cluster_by="remote_ip", remote_ip="203.0.113.88", limit=10)
    detail = manager.resolve_hunt_telemetry_cluster(
        cluster_by="remote_ip",
        cluster_key="203.0.113.88",
        remote_ip="203.0.113.88",
        limit=10,
    )
    created = manager.create_case_from_telemetry_cluster(
        SocTelemetryClusterCaseRequest(
            cluster_by="remote_ip",
            cluster_key="203.0.113.88",
            remote_ip="203.0.113.88",
            assignee="tier2",
        )
    )

    assert len(clusters) == 1
    assert clusters[0]["cluster_key"] == "203.0.113.88"
    assert clusters[0]["event_count"] == 3
    assert clusters[0]["telemetry_kinds"] == {"endpoint": 1, "network": 1, "packet": 1}
    assert clusters[0]["open_case_count"] == 0
    assert len(detail["events"]) == 3
    assert created.assignee == "tier2"
    assert set(created.source_event_ids) == {"evt-endpoint-conn", "evt-network-conn", "evt-packet-session"}
    assert "remote_ip:203.0.113.88" in created.observables
    assert "session:packet-session:cluster" in created.observables


def test_dashboard_includes_persisted_view_state(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "soc_dashboard_view_state_path", str(tmp_path / "soc_dashboard_view_state.json"))
    Path(settings.soc_dashboard_view_state_path).write_text(
        json.dumps(
            {
                "operational_reason_filter": "stuck action",
                "hunt_cluster_mode": "device_id",
                "hunt_cluster_value": "device-11",
                "hunt_cluster_key": "cluster-11",
                "hunt_cluster_action": "details",
                "endpoint_timeline_cluster_mode": "remote_ip",
                "endpoint_timeline_cluster_key": "timeline-11",
                "endpoint_timeline_cluster_action": "case",
            }
        ),
        encoding="utf-8",
    )
    manager, _alerts = _manager(tmp_path)

    payload = manager.dashboard()

    assert payload["view_state"]["operational_reason_filter"] == "stuck action"
    assert payload["view_state"]["hunt_cluster_mode"] == "device_id"
    assert payload["view_state"]["hunt_cluster_value"] == "device-11"
    assert payload["view_state"]["hunt_cluster_key"] == "cluster-11"
    assert payload["view_state"]["hunt_cluster_action"] == "details"
    assert payload["view_state"]["endpoint_timeline_cluster_mode"] == "remote_ip"
    assert payload["view_state"]["endpoint_timeline_cluster_key"] == "timeline-11"
    assert payload["view_state"]["endpoint_timeline_cluster_action"] == "case"
    assert payload["summary_labels"]["toolchain_updates"] == "Toolchain Updates"
    assert payload["summary_labels"]["toolchain_security"] == "Toolchain Security"
    assert payload["summary_labels"]["toolchain_runtime"] == "Toolchain Runtime"
    assert payload["summary_labels"]["packet_sessions"] == "Packet Sessions"
    assert payload["summary_labels"]["network_evidence"] == "Network Evidence"
    assert payload["summary_labels"]["identity_correlations"] == "Identity Correlations"
    assert payload["summary_labels"]["network_dns"] == "DNS"
    assert payload["summary_labels"]["network_http"] == "HTTP"
    assert payload["summary_labels"]["network_tls"] == "TLS"
    assert payload["summary_labels"]["network_certificates"] == "Certificates"
    assert payload["summary_labels"]["network_proxy"] == "Proxy"
    assert payload["summary_labels"]["network_auth"] == "Auth"
    assert payload["summary_labels"]["network_vpn"] == "VPN"
    assert payload["summary_labels"]["network_dhcp"] == "DHCP"
    assert payload["summary_labels"]["network_directory_auth"] == "Directory Auth"
    assert payload["summary_labels"]["network_radius"] == "RADIUS"
    assert payload["summary_labels"]["network_nac"] == "NAC"
    assert "toolchain_runtime_status" in payload
    assert payload["summary_labels"]["hunt_clusters"] == "Hunt Clusters [device_id]"
    assert payload["summary_labels"]["endpoint_timeline_clusters"] == "Timeline Clusters [remote_ip]"
    assert payload["summary_labels"]["endpoint_lineage_clusters"] == "Endpoint Lineage"
    assert payload["summary_labels"]["operational_alerts"] == "Operational Alerts [stuck action]"
    assert payload["summary_labels"]["operational_cases"] == "Operational Cases [stuck action]"
    assert "toolchain_updates_status" in payload
    assert "toolchain_security_status" in payload


def test_dashboard_view_state_can_be_updated(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "soc_dashboard_view_state_path", str(tmp_path / "soc_dashboard_view_state.json"))
    manager, _alerts = _manager(tmp_path)

    view_state = manager.update_dashboard_view_state(
        SocDashboardViewStateUpdate(
            operational_reason_filter="action failed",
            hunt_cluster_mode="process_guid",
            hunt_cluster_value="proc-guid-1",
            hunt_cluster_key="cluster-22",
            hunt_cluster_action="case",
            endpoint_timeline_cluster_mode="process",
            endpoint_timeline_cluster_key="timeline-22",
            endpoint_timeline_cluster_action="details",
        )
    )

    assert view_state["operational_reason_filter"] == "action failed"
    assert view_state["hunt_cluster_mode"] == "process_guid"
    assert view_state["hunt_cluster_value"] == "proc-guid-1"
    assert view_state["hunt_cluster_key"] == "cluster-22"
    assert view_state["hunt_cluster_action"] == "case"
    assert view_state["endpoint_timeline_cluster_mode"] == "process"
    assert view_state["endpoint_timeline_cluster_key"] == "timeline-22"
    assert view_state["endpoint_timeline_cluster_action"] == "details"
    assert view_state["endpoint_lineage_cluster_mode"] == "device_id"
    assert view_state["endpoint_lineage_cluster_value"] is None
    assert view_state["endpoint_lineage_cluster_key"] is None
    assert view_state["endpoint_lineage_cluster_action"] == "events"
    assert json.loads(Path(settings.soc_dashboard_view_state_path).read_text(encoding="utf-8")) == {
        "operational_reason_filter": "action failed",
        "hunt_cluster_mode": "process_guid",
        "hunt_cluster_value": "proc-guid-1",
        "hunt_cluster_key": "cluster-22",
        "hunt_cluster_action": "case",
        "endpoint_timeline_cluster_mode": "process",
        "endpoint_timeline_cluster_key": "timeline-22",
        "endpoint_timeline_cluster_action": "details",
        "endpoint_lineage_cluster_mode": "device_id",
        "endpoint_lineage_cluster_value": None,
        "endpoint_lineage_cluster_key": None,
        "endpoint_lineage_cluster_action": "events",
    }


def test_platform_role_profile_changes_effective_service_health(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "sensor")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    manager, _alerts = _manager(tmp_path)

    payload = manager.overview()
    service_health = payload["platform"]["service_health"]

    assert payload["platform"]["node_role"] == "sensor"
    assert payload["platform"]["role_profile"]["services"]["packet_monitor"] is True
    assert payload["platform"]["role_profile"]["services"]["tracker_intel"] is False
    assert service_health["services"]["packet_monitor"]["enabled"] is True
    assert service_health["services"]["tracker_intel"]["enabled"] is False
    assert service_health["services"]["host_monitor"]["enabled"] is False
    assert payload["platform"]["topology"]["total_nodes"] == 1


def test_platform_topology_includes_registered_remote_nodes(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "healthy"},
            "last_seen_at": datetime.now(UTC).isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, _alerts = _manager(tmp_path)

    payload = manager.overview()
    topology = payload["platform"]["topology"]

    assert topology["remote_node_count"] == 1
    assert topology["total_nodes"] == 2
    assert topology["remote_nodes"][0]["node_name"] == "sensor-a"
    assert topology["remote_nodes"][0]["status"] == "healthy"


def test_emit_operational_notifications_includes_remote_node_pressure(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "degraded"},
            "last_seen_at": datetime.now(UTC).isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, alerts = _manager(tmp_path)

    result = manager.emit_operational_notifications(state_path=tmp_path / "notify.json")

    assert result["emitted"] >= 1
    assert any(getattr(event, "title", "").startswith("Remote node degraded: sensor-a") for event in alerts.events)


def test_emit_operational_notifications_skips_suppressed_remote_node_pressure(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "degraded"},
            "metadata": {
                "pressure_suppressions": [
                    {
                        "suppressed_by": "tier2",
                        "suppressed_until": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(),
                        "scopes": ["remote_node_degraded"],
                    }
                ],
            },
            "last_seen_at": datetime.now(UTC).isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, alerts = _manager(tmp_path)

    result = manager.emit_operational_notifications(state_path=tmp_path / "notify.json")

    assert result["emitted"] == 0
    assert not any(getattr(event, "title", "").startswith("Remote node degraded: sensor-a") for event in alerts.events)


def test_emit_operational_notifications_skips_maintained_remote_node_service_pressure(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {
                "overall_status": "degraded",
                "services": {"packet_monitor": {"status": "degraded", "enabled": True}},
            },
            "metadata": {
                "maintenance_by": "tier2",
                "maintenance_until": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(),
                "maintenance_services": ["packet_monitor"],
            },
            "last_seen_at": datetime.now(UTC).isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, alerts = _manager(tmp_path)

    result = manager.emit_operational_notifications(state_path=tmp_path / "notify.json")

    assert result["emitted"] == 0
    assert not any(getattr(event, "title", "").startswith("Remote node degraded: sensor-a") for event in alerts.events)


def test_emit_operational_notifications_skips_drained_remote_node_pressure(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {
                "overall_status": "degraded",
                "services": {"packet_monitor": {"status": "degraded", "enabled": True}},
            },
            "metadata": {
                "drain_at": datetime.now(UTC).isoformat(),
                "drained_by": "tier2",
                "drain_services": ["packet_monitor"],
            },
            "last_seen_at": datetime.now(UTC).isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, alerts = _manager(tmp_path)

    result = manager.emit_operational_notifications(state_path=tmp_path / "notify.json")

    assert result["emitted"] == 0
    assert not any(getattr(event, "title", "").startswith("Remote node degraded: sensor-a") for event in alerts.events)


def test_emit_operational_notifications_includes_failed_remote_node_actions(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {
                "overall_status": "healthy",
                "services": {"packet_monitor": {"status": "healthy", "enabled": True}},
            },
            "metadata": {
                "drain_at": datetime.now(UTC).isoformat(),
                "drain_failed_at": datetime.now(UTC).isoformat(),
                "drain_result": "failed",
                "drain_last_error": "packet monitor drain failed",
                "drain_retry_count": 1,
                "drain_retriable": True,
            },
            "last_seen_at": datetime.now(UTC).isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, alerts = _manager(tmp_path)

    result = manager.emit_operational_notifications(state_path=tmp_path / "notify.json")

    assert result["emitted"] == 1
    assert any(getattr(event, "title", "") == "Remote node action failed: sensor-a" for event in alerts.events)
    persisted_alerts = manager.list_alerts()
    persisted_cases = manager.list_cases()
    assert len(persisted_alerts) == 1
    assert persisted_alerts[0].category == "operational"
    assert persisted_alerts[0].correlation_rule == "operational_route"
    assert persisted_alerts[0].correlation_key == "remote-node:action-failed:sensor-a"
    assert len(persisted_cases) == 1
    assert persisted_cases[0].linked_alert_ids == [persisted_alerts[0].alert_id]
    assert any(item == "node:sensor-a" for item in persisted_cases[0].observables)


def test_emit_operational_notifications_includes_repeated_remote_node_action_failures(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    monkeypatch.setattr(settings, "soc_remote_node_action_failure_repeat_threshold", 2)
    now = datetime.now(UTC)
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "healthy"},
            "metadata": {
                "action_history": [
                    {"action": "drain", "transition": "failed", "at": (now - timedelta(minutes=30)).isoformat()},
                    {"action": "drain", "transition": "retried", "at": (now - timedelta(minutes=20)).isoformat()},
                    {"action": "drain", "transition": "failed", "at": (now - timedelta(minutes=10)).isoformat()},
                ]
            },
            "last_seen_at": now.isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, alerts = _manager(tmp_path)

    result = manager.emit_operational_notifications(state_path=tmp_path / "notify.json")

    assert result["emitted"] == 1
    assert any(getattr(event, "title", "") == "Remote node repeated action failures: sensor-a" for event in alerts.events)


def test_emit_operational_notifications_includes_remote_node_retry_pressure(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    monkeypatch.setattr(settings, "soc_remote_node_action_retry_threshold", 2)
    now = datetime.now(UTC)
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "healthy"},
            "metadata": {
                "action_history": [
                    {"action": "refresh", "transition": "requested", "at": (now - timedelta(minutes=40)).isoformat()},
                    {"action": "refresh", "transition": "retried", "at": (now - timedelta(minutes=30)).isoformat()},
                    {"action": "refresh", "transition": "retried", "at": (now - timedelta(minutes=10)).isoformat()},
                ]
            },
            "last_seen_at": now.isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, alerts = _manager(tmp_path)

    result = manager.emit_operational_notifications(state_path=tmp_path / "notify.json")

    assert result["emitted"] == 1
    assert any(getattr(event, "title", "") == "Remote node retry pressure: sensor-a" for event in alerts.events)


def test_emit_operational_notifications_includes_stuck_remote_node_actions(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    monkeypatch.setattr(settings, "soc_remote_node_action_stuck_minutes", 5.0)
    now = datetime.now(UTC)
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "healthy"},
            "metadata": {
                "refresh_pending": True,
                "refresh_requested_at": (now - timedelta(minutes=20)).isoformat(),
            },
            "last_seen_at": now.isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, alerts = _manager(tmp_path)

    result = manager.emit_operational_notifications(state_path=tmp_path / "notify.json")

    assert result["emitted"] == 1
    assert any(getattr(event, "title", "") == "Remote node action stuck: sensor-a" for event in alerts.events)


def test_emit_operational_notifications_deduplicates_persisted_operational_alerts_and_cases(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "healthy"},
            "metadata": {
                "refresh_pending": True,
                "refresh_requested_at": (datetime.now(UTC) - timedelta(minutes=20)).isoformat(),
            },
            "last_seen_at": datetime.now(UTC).isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, _alerts = _manager(tmp_path)
    state_path = tmp_path / "notify.json"

    first = manager.emit_operational_notifications(state_path=state_path)
    second = manager.emit_operational_notifications(state_path=state_path)

    assert first["emitted"] == 1
    assert second["emitted"] == 0
    assert len(manager.list_alerts()) == 1
    assert len(manager.list_cases()) == 1


def test_emit_operational_notifications_closes_resolved_operational_alert(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    now = datetime.now(UTC)
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "healthy"},
            "metadata": {
                "refresh_pending": True,
                "refresh_requested_at": (now - timedelta(minutes=20)).isoformat(),
            },
            "last_seen_at": now.isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )
    manager, _alerts = _manager(tmp_path)
    state_path = tmp_path / "notify.json"

    manager.emit_operational_notifications(state_path=state_path)
    upsert_platform_node(
        {
            "node_name": "sensor-a",
            "node_role": "sensor",
            "deployment_mode": "multi-node",
            "service_health": {"overall_status": "healthy"},
            "metadata": {
                "refresh_pending": False,
                "refresh_status": "completed",
            },
            "last_seen_at": now.isoformat(),
        },
        path=tmp_path / "platform_nodes.json",
    )

    resolved = manager.emit_operational_notifications(state_path=state_path)

    assert resolved["emitted"] == 0
    alerts_after = manager.list_alerts()
    assert len(alerts_after) == 1
    assert alerts_after[0].status is SocAlertStatus.closed
    assert "Operational pressure resolved automatically." in alerts_after[0].notes


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


def test_detection_engine_promotes_repeated_tracker_activity(tmp_path) -> None:
    manager, alerts = _manager(tmp_path)
    for _ in range(3):
        manager.ingest_event(
            SocEventIngest(
                event_type="privacy.tracker_block",
                source="tracker_intel",
                severity=SocSeverity.medium,
                title="Tracker blocked",
                summary="Blocked tracker beacon.example.",
                details={"hostname": "beacon.example"},
                tags=["privacy", "tracker"],
            )
        )
    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert len(correlation_alerts) == 1
    assert correlation_alerts[0].correlation_rule == "repeated_tracker_activity"
    assert correlation_alerts[0].correlation_key == "beacon.example"
    assert len(correlation_alerts[0].source_event_ids) == 3
    assert alerts.events


def test_detection_catalog_can_disable_rule(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    updated = manager.update_detection_rule(
        "repeated_tracker_activity",
        SocDetectionRuleUpdate(enabled=False),
    )
    for _ in range(3):
        manager.ingest_event(
            SocEventIngest(
                event_type="privacy.tracker_block",
                source="tracker_intel",
                severity=SocSeverity.medium,
                title="Tracker blocked",
                summary="Blocked tracker beacon.example.",
                details={"hostname": "beacon.example"},
                tags=["privacy", "tracker"],
            )
        )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert updated.enabled is False
    assert correlation_alerts == []


def test_detection_catalog_can_update_rule_parameters(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    updated = manager.update_detection_rule(
        "repeated_tracker_activity",
        SocDetectionRuleUpdate(parameters={"minimum_hits": 2}),
    )
    for _ in range(2):
        manager.ingest_event(
            SocEventIngest(
                event_type="privacy.tracker_block",
                source="tracker_intel",
                severity=SocSeverity.medium,
                title="Tracker blocked",
                summary="Blocked tracker beacon.example.",
                details={"hostname": "beacon.example"},
                tags=["privacy", "tracker"],
            )
        )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert updated.parameters["minimum_hits"] == 2
    assert len(correlation_alerts) == 1
    assert manager.get_detection_rule("repeated_tracker_activity").hit_count == 1


def test_detection_engine_promotes_repeated_malware_artifact(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    for _ in range(2):
        manager.ingest_event(
            SocEventIngest(
                event_type="endpoint.malware_detected",
                source="endpoint",
                severity=SocSeverity.critical,
                title="Malware detected",
                summary="bad.exe matched a malware rule.",
                details={"filename": "bad.exe", "verdict": "matched:test-rule"},
                tags=["endpoint", "malware"],
            )
        )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "repeated_malware_artifact" for item in correlation_alerts)


def test_detection_engine_promotes_suspicious_source_access(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.monitor.finding",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Suspicious remote IP observed",
            summary="A public remote IP repeatedly appeared against local listening ports.",
            details={
                "key": "suspicious-remote-ip:198.51.100.81",
                "resolved": False,
                "details": {
                    "remote_ip": "198.51.100.81",
                    "local_ports": [8443],
                    "remote_ports": [51000, 51001],
                    "hit_count": 3,
                    "finding_type": "suspicious_remote_ip",
                },
            },
            tags=["network"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="policy.access_decision",
            source="security_gateway",
            severity=SocSeverity.critical,
            title="Access deny for vpn-admin",
            summary="User operator-1 received a deny decision.",
            details={
                "user_id": "operator-1",
                "device_id": "device-1",
                "resource": "vpn-admin",
                "privilege_level": "admin",
                "source_ip": "198.51.100.81",
                "decision": "deny",
                "risk_score": 95.0,
                "reasons": ["blocked source"],
            },
            tags=["access", "deny"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "suspicious_source_access" for item in correlation_alerts)


def test_detection_engine_promotes_suspicious_source_access_from_telemetry_docs(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.low,
            title="Network telemetry for 198.51.100.82",
            summary="Network monitor captured a normalized remote-IP observation.",
            details={
                "schema": "network_connection_v1",
                "document_type": "network_connection",
                "remote_ip": "198.51.100.82",
                "local_ports": [3389],
                "remote_ports": [51000, 51001],
                "hit_count": 4,
                "sensitive_ports": [3389],
            },
            tags=["network", "telemetry", "connection"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="policy.access_decision",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Step-up required for admin console",
            summary="User operator-2 triggered a step-up decision.",
            details={
                "user_id": "operator-2",
                "device_id": "device-2",
                "resource": "admin-console",
                "privilege_level": "admin",
                "source_ip": "198.51.100.82",
                "decision": "step_up",
                "risk_score": 80.0,
                "reasons": ["network telemetry overlap"],
            },
            tags=["access", "step-up"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "suspicious_source_access" for item in correlation_alerts)
    assert any(item.correlation_key == "198.51.100.82" for item in correlation_alerts)


def test_detection_engine_promotes_packet_network_remote_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="packet.monitor.finding",
            source="security_gateway",
            severity=SocSeverity.critical,
            title="Suspicious packet activity observed: 198.51.100.91",
            summary="Packet metadata sampling observed a public remote IP against sensitive local ports.",
            details={
                "key": "packet-remote-ip:198.51.100.91",
                "resolved": False,
                "details": {
                    "session_key": "packet-session:198.51.100.91",
                    "remote_ip": "198.51.100.91",
                    "protocols": ["TCP"],
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "packet_count": 15,
                    "sensitive_ports": [3389],
                },
            },
            tags=["packet", "network"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.monitor.finding",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Suspicious remote IP observed",
            summary="A public remote IP repeatedly appeared against local listening ports.",
            details={
                "key": "suspicious-remote-ip:198.51.100.91",
                "resolved": False,
                "details": {
                    "remote_ip": "198.51.100.91",
                    "local_ports": [3389],
                    "remote_ports": [51000, 51001],
                    "hit_count": 3,
                    "finding_type": "suspicious_remote_ip",
                },
            },
            tags=["network"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "packet_network_remote_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "198.51.100.91" for item in correlation_alerts)


def test_detection_engine_promotes_packet_network_remote_overlap_from_telemetry_docs(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="packet.telemetry.session",
            source="security_gateway",
            severity=SocSeverity.low,
            title="Packet session telemetry for 198.51.100.91",
            summary="Packet monitor captured a normalized session document.",
            details={
                "schema": "packet_session_v1",
                "document_type": "packet_session",
                "session_key": "packet-session:198.51.100.91",
                "remote_ip": "198.51.100.91",
                "protocols": ["TCP"],
                "local_ports": [3389],
                "remote_ports": [51000],
                "packet_count": 15,
                "sensitive_ports": [3389],
            },
            tags=["packet", "telemetry", "session"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.low,
            title="Network telemetry for 198.51.100.91",
            summary="Network monitor captured a normalized remote-IP observation.",
            details={
                "schema": "network_connection_v1",
                "document_type": "network_connection",
                "remote_ip": "198.51.100.91",
                "local_ports": [3389],
                "remote_ports": [51000, 51001],
                "hit_count": 3,
                "sensitive_ports": [3389],
            },
            tags=["network", "telemetry", "connection"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "packet_network_remote_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "198.51.100.91" for item in correlation_alerts)


def test_detection_engine_promotes_endpoint_process_file_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-1 reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-1",
                "process_name": "powershell.exe",
                "process_path": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                "sha256": "abc123",
                "process_sha256": "abc123",
                "command_line": "powershell.exe -enc deadbeef",
                "risk_flags": ["encoded_command"],
                "remote_ips": ["198.51.100.83"],
            },
            tags=["endpoint", "telemetry", "process", "encoded_command"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.dll",
            summary="Endpoint device-ep-1 reported file activity for payload.dll.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-1",
                "filename": "payload.dll",
                "artifact_path": "C:/Users/Public/payload.dll",
                "sha256": "feedface",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "abc123",
                "risk_flags": ["startup_path"],
            },
            tags=["endpoint", "telemetry", "file", "created", "startup_path"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "endpoint_process_file_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "device-ep-1:abc123" for item in correlation_alerts)


def test_detection_engine_promotes_endpoint_unsigned_network_process(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: rundll32.exe",
            summary="Endpoint device-ep-2 reported process activity for rundll32.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-2",
                "process_name": "rundll32.exe",
                "process_guid": "proc-guid-1",
                "process_path": "C:/Windows/System32/rundll32.exe",
                "sha256": "deadbeef",
                "process_sha256": "deadbeef",
                "signer_name": "Unknown",
                "signer_status": "unsigned",
                "reputation": "suspicious",
                "risk_flags": ["remote_injection"],
                "remote_ips": ["198.51.100.90"],
                "network_connections": [
                    {"remote_ip": "198.51.100.90", "remote_port": 443, "protocol": "TCP"}
                ],
            },
            tags=["endpoint", "telemetry", "process", "remote_injection"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "endpoint_unsigned_network_process" for item in correlation_alerts)
    assert any(item.correlation_key == "device-ep-2:deadbeef" for item in correlation_alerts)


def test_detection_engine_promotes_endpoint_connection_network_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-3 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-3",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-3",
                "remote_ip": "198.51.100.95",
                "remote_port": 443,
                "protocol": "TCP",
                "signer_name": "Unknown",
                "risk_flags": ["encoded_command"],
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="packet.telemetry.session",
            source="security_gateway",
            severity=SocSeverity.low,
            title="Packet session telemetry for 198.51.100.95",
            summary="Packet monitor captured a normalized session document.",
            details={
                "schema": "packet_session_v1",
                "document_type": "packet_session",
                "session_key": "packet-session:198.51.100.95",
                "remote_ip": "198.51.100.95",
                "protocols": ["TCP"],
                "local_ports": [3389],
                "remote_ports": [443],
                "packet_count": 15,
                "sensitive_ports": [3389],
            },
            tags=["packet", "telemetry", "session"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "endpoint_connection_network_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "device-ep-3:powershell.exe:198.51.100.95" for item in correlation_alerts)


def test_detection_engine_promotes_network_dns_http_followup(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.dns",
            source="external_sensor",
            severity=SocSeverity.low,
            title="DNS telemetry for beacon.example",
            summary="External sensor submitted a normalized DNS record.",
            details={
                "schema": "network_dns_sensor_v1",
                "document_type": "network_dns",
                "remote_ip": "198.51.100.110",
                "hostname": "beacon.example",
                "record_type": "A",
                "answers": ["198.51.100.110"],
            },
            tags=["network", "telemetry", "dns"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.http",
            source="external_sensor",
            severity=SocSeverity.low,
            title="HTTP telemetry for beacon.example",
            summary="External sensor submitted a normalized HTTP record.",
            details={
                "schema": "network_http_sensor_v1",
                "document_type": "network_http",
                "remote_ip": "198.51.100.110",
                "hostname": "beacon.example",
                "method": "GET",
                "path": "/login",
                "status_code": 200,
            },
            tags=["network", "telemetry", "http"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_dns_http_followup" for item in correlation_alerts)
    assert any(item.correlation_key == "beacon.example" for item in correlation_alerts)


def test_detection_engine_promotes_network_tls_http_host_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.tls",
            source="external_sensor",
            severity=SocSeverity.low,
            title="TLS telemetry for beacon.example",
            summary="External sensor submitted a normalized TLS record.",
            details={
                "schema": "network_tls_sensor_v1",
                "document_type": "network_tls",
                "remote_ip": "198.51.100.111",
                "hostname": "beacon.example",
                "server_name": "beacon.example",
                "tls_version": "TLS1.3",
            },
            tags=["network", "telemetry", "tls"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.http",
            source="external_sensor",
            severity=SocSeverity.low,
            title="HTTP telemetry for beacon.example",
            summary="External sensor submitted a normalized HTTP record.",
            details={
                "schema": "network_http_sensor_v1",
                "document_type": "network_http",
                "remote_ip": "198.51.100.111",
                "hostname": "beacon.example",
                "method": "POST",
                "path": "/stage",
                "status_code": 503,
            },
            tags=["network", "telemetry", "http"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_tls_http_host_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "beacon.example:198.51.100.111" for item in correlation_alerts)


def test_detection_engine_promotes_network_certificate_tls_host_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.certificate",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Certificate telemetry for beacon.example",
            summary="External sensor submitted a normalized certificate record.",
            details={
                "schema": "network_certificate_sensor_v1",
                "document_type": "network_certificate",
                "remote_ip": "198.51.100.112",
                "hostname": "beacon.example",
                "sha256": "cert-sha256",
                "issuer": "CN=Beacon Issuer",
                "subject": "CN=beacon.example",
            },
            tags=["network", "telemetry", "certificate"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.tls",
            source="external_sensor",
            severity=SocSeverity.low,
            title="TLS telemetry for beacon.example",
            summary="External sensor submitted a normalized TLS record.",
            details={
                "schema": "network_tls_sensor_v1",
                "document_type": "network_tls",
                "remote_ip": "198.51.100.112",
                "hostname": "beacon.example",
                "server_name": "beacon.example",
                "tls_version": "TLS1.3",
            },
            tags=["network", "telemetry", "tls"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_certificate_tls_host_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "beacon.example:198.51.100.112" for item in correlation_alerts)


def test_detection_engine_promotes_network_certificate_http_host_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.certificate",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Certificate telemetry for beacon.example",
            summary="External sensor submitted a normalized certificate record.",
            details={
                "schema": "network_certificate_sensor_v1",
                "document_type": "network_certificate",
                "remote_ip": "198.51.100.113",
                "hostname": "beacon.example",
                "sha256": "cert-sha256",
                "issuer": "CN=Beacon Issuer",
                "subject": "CN=beacon.example",
            },
            tags=["network", "telemetry", "certificate"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.http",
            source="external_sensor",
            severity=SocSeverity.low,
            title="HTTP telemetry for beacon.example",
            summary="External sensor submitted a normalized HTTP record.",
            details={
                "schema": "network_http_sensor_v1",
                "document_type": "network_http",
                "remote_ip": "198.51.100.113",
                "hostname": "beacon.example",
                "method": "POST",
                "path": "/stage",
                "status_code": 503,
            },
            tags=["network", "telemetry", "http"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_certificate_http_host_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "beacon.example" for item in correlation_alerts)


def test_detection_rule_network_evidence_group_case_payload_uses_generic_network_case(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.dns",
            source="external_sensor",
            severity=SocSeverity.low,
            title="DNS telemetry for beacon.example",
            summary="External sensor submitted a normalized DNS record.",
            details={
                "schema": "network_dns_sensor_v1",
                "document_type": "network_dns",
                "remote_ip": "198.51.100.110",
                "hostname": "beacon.example",
                "record_type": "A",
                "answers": ["198.51.100.110"],
            },
            tags=["network", "telemetry", "dns"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.http",
            source="external_sensor",
            severity=SocSeverity.low,
            title="HTTP telemetry for beacon.example",
            summary="External sensor submitted a normalized HTTP record.",
            details={
                "schema": "network_http_sensor_v1",
                "document_type": "network_http",
                "remote_ip": "198.51.100.110",
                "hostname": "beacon.example",
                "method": "GET",
                "path": "/login",
                "status_code": 200,
            },
            tags=["network", "telemetry", "http"],
        )
    )

    case = manager.create_case_from_rule_evidence_group(
        "network_dns_http_followup",
        SocCaseRuleGroupCaseRequest(group_key="beacon.example", assignee="tier2"),
    )

    assert case.assignee == "tier2"
    assert "hostname:beacon.example" in case.observables
    assert "198.51.100.110" in case.observables
    assert len(case.source_event_ids) == 2


def test_detection_rule_network_alert_group_case_payload_uses_generic_network_case(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.tls",
            source="external_sensor",
            severity=SocSeverity.low,
            title="TLS telemetry for beacon.example",
            summary="External sensor submitted a normalized TLS record.",
            details={
                "schema": "network_tls_sensor_v1",
                "document_type": "network_tls",
                "remote_ip": "198.51.100.111",
                "hostname": "beacon.example",
                "server_name": "beacon.example",
                "tls_version": "TLS1.3",
            },
            tags=["network", "telemetry", "tls"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.http",
            source="external_sensor",
            severity=SocSeverity.low,
            title="HTTP telemetry for beacon.example",
            summary="External sensor submitted a normalized HTTP record.",
            details={
                "schema": "network_http_sensor_v1",
                "document_type": "network_http",
                "remote_ip": "198.51.100.111",
                "hostname": "beacon.example",
                "method": "POST",
                "path": "/stage",
                "status_code": 503,
            },
            tags=["network", "telemetry", "http"],
        )
    )

    case = manager.create_case_from_rule_alert_group(
        "network_tls_http_host_overlap",
        SocCaseRuleGroupCaseRequest(group_key="beacon.example:198.51.100.111", assignee="tier2"),
    )

    assert case.assignee == "tier2"
    assert "hostname:beacon.example" in case.observables
    assert "198.51.100.111" in case.observables
    assert len(case.linked_alert_ids) == 1


def test_detection_rule_certificate_network_group_case_payload_uses_generic_network_case(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.certificate",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Certificate telemetry for beacon.example",
            summary="External sensor submitted a normalized certificate record.",
            details={
                "schema": "network_certificate_sensor_v1",
                "document_type": "network_certificate",
                "remote_ip": "198.51.100.112",
                "hostname": "beacon.example",
                "sha256": "cert-sha256",
                "issuer": "CN=Beacon Issuer",
                "subject": "CN=beacon.example",
            },
            tags=["network", "telemetry", "certificate"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.tls",
            source="external_sensor",
            severity=SocSeverity.low,
            title="TLS telemetry for beacon.example",
            summary="External sensor submitted a normalized TLS record.",
            details={
                "schema": "network_tls_sensor_v1",
                "document_type": "network_tls",
                "remote_ip": "198.51.100.112",
                "hostname": "beacon.example",
                "server_name": "beacon.example",
                "tls_version": "TLS1.3",
            },
            tags=["network", "telemetry", "tls"],
        )
    )

    case = manager.create_case_from_rule_alert_group(
        "network_certificate_tls_host_overlap",
        SocCaseRuleGroupCaseRequest(group_key="beacon.example:198.51.100.112", assignee="tier2"),
    )

    assert case.assignee == "tier2"
    assert "hostname:beacon.example" in case.observables
    assert "198.51.100.112" in case.observables
    assert len(case.linked_alert_ids) == 1


def test_detection_engine_promotes_network_proxy_auth_user_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.proxy",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Proxy telemetry for beacon.example",
            summary="External sensor submitted a normalized proxy record.",
            details={
                "schema": "network_proxy_sensor_v1",
                "document_type": "network_proxy",
                "remote_ip": "198.51.100.114",
                "hostname": "beacon.example",
                "proxy_type": "http-connect",
                "action": "allowed",
                "username": "tier1",
            },
            tags=["network", "telemetry", "proxy"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.auth",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Auth telemetry for tier1",
            summary="External sensor submitted a normalized auth record.",
            details={
                "schema": "network_auth_sensor_v1",
                "document_type": "network_auth",
                "remote_ip": "198.51.100.114",
                "hostname": "beacon.example",
                "username": "tier1",
                "outcome": "success",
                "auth_protocol": "kerberos",
            },
            tags=["network", "telemetry", "auth"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_proxy_auth_user_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "tier1@beacon.example" for item in correlation_alerts)


def test_detection_engine_promotes_network_proxy_http_host_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.proxy",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Proxy telemetry for beacon.example",
            summary="External sensor submitted a normalized proxy record.",
            details={
                "schema": "network_proxy_sensor_v1",
                "document_type": "network_proxy",
                "remote_ip": "198.51.100.115",
                "hostname": "beacon.example",
                "proxy_type": "http-connect",
                "action": "allowed",
                "username": "tier1",
            },
            tags=["network", "telemetry", "proxy"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.http",
            source="external_sensor",
            severity=SocSeverity.low,
            title="HTTP telemetry for beacon.example",
            summary="External sensor submitted a normalized HTTP record.",
            details={
                "schema": "network_http_sensor_v1",
                "document_type": "network_http",
                "remote_ip": "198.51.100.115",
                "hostname": "beacon.example",
                "method": "POST",
                "path": "/stage",
                "status_code": 503,
            },
            tags=["network", "telemetry", "http"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_proxy_http_host_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "beacon.example" for item in correlation_alerts)


def test_detection_rule_proxy_network_group_case_payload_uses_generic_network_case(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.proxy",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Proxy telemetry for beacon.example",
            summary="External sensor submitted a normalized proxy record.",
            details={
                "schema": "network_proxy_sensor_v1",
                "document_type": "network_proxy",
                "remote_ip": "198.51.100.115",
                "hostname": "beacon.example",
                "proxy_type": "http-connect",
                "action": "allowed",
                "username": "tier1",
            },
            tags=["network", "telemetry", "proxy"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.http",
            source="external_sensor",
            severity=SocSeverity.low,
            title="HTTP telemetry for beacon.example",
            summary="External sensor submitted a normalized HTTP record.",
            details={
                "schema": "network_http_sensor_v1",
                "document_type": "network_http",
                "remote_ip": "198.51.100.115",
                "hostname": "beacon.example",
                "method": "POST",
                "path": "/stage",
                "status_code": 503,
            },
            tags=["network", "telemetry", "http"],
        )
    )

    case = manager.create_case_from_rule_alert_group(
        "network_proxy_http_host_overlap",
        SocCaseRuleGroupCaseRequest(group_key="beacon.example", assignee="tier2"),
    )

    assert case.assignee == "tier2"
    assert "hostname:beacon.example" in case.observables
    assert "198.51.100.115" in case.observables
    assert len(case.linked_alert_ids) == 1


def test_detection_engine_promotes_network_vpn_directory_auth_user_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.vpn",
            source="external_sensor",
            severity=SocSeverity.low,
            title="VPN telemetry for tier1",
            summary="External sensor submitted a normalized VPN record.",
            details={
                "schema": "network_vpn_sensor_v1",
                "document_type": "network_vpn",
                "remote_ip": "198.51.100.116",
                "hostname": "beacon.example",
                "username": "tier1",
                "tunnel_type": "wireguard",
                "assigned_ip": "10.8.0.5",
                "outcome": "connected",
            },
            tags=["network", "telemetry", "vpn"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.directory_auth",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Directory auth telemetry for tier1",
            summary="External sensor submitted a normalized directory auth record.",
            details={
                "schema": "network_directory_auth_sensor_v1",
                "document_type": "network_directory_auth",
                "remote_ip": "198.51.100.116",
                "hostname": "beacon.example",
                "username": "tier1",
                "directory_service": "active-directory",
                "outcome": "success",
                "realm": "EXAMPLE.LOCAL",
            },
            tags=["network", "telemetry", "directory-auth"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_vpn_directory_auth_user_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "tier1@beacon.example" for item in correlation_alerts)


def test_detection_engine_promotes_network_dhcp_auth_host_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.dhcp",
            source="external_sensor",
            severity=SocSeverity.low,
            title="DHCP telemetry for 10.0.0.25",
            summary="External sensor submitted a normalized DHCP record.",
            details={
                "schema": "network_dhcp_sensor_v1",
                "document_type": "network_dhcp",
                "remote_ip": "198.51.100.117",
                "hostname": "beacon.example",
                "assigned_ip": "10.0.0.25",
                "mac_address": "00:11:22:33:44:55",
                "lease_action": "ack",
            },
            tags=["network", "telemetry", "dhcp"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.auth",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Auth telemetry for tier1",
            summary="External sensor submitted a normalized auth record.",
            details={
                "schema": "network_auth_sensor_v1",
                "document_type": "network_auth",
                "remote_ip": "198.51.100.117",
                "hostname": "beacon.example",
                "username": "tier1",
                "outcome": "success",
                "auth_protocol": "kerberos",
            },
            tags=["network", "telemetry", "auth"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_dhcp_auth_host_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "beacon.example" for item in correlation_alerts)


def test_detection_rule_vpn_network_group_case_payload_uses_generic_network_case(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.vpn",
            source="external_sensor",
            severity=SocSeverity.low,
            title="VPN telemetry for tier1",
            summary="External sensor submitted a normalized VPN record.",
            details={
                "schema": "network_vpn_sensor_v1",
                "document_type": "network_vpn",
                "remote_ip": "198.51.100.116",
                "hostname": "beacon.example",
                "username": "tier1",
                "tunnel_type": "wireguard",
                "assigned_ip": "10.8.0.5",
                "outcome": "connected",
            },
            tags=["network", "telemetry", "vpn"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.directory_auth",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Directory auth telemetry for tier1",
            summary="External sensor submitted a normalized directory auth record.",
            details={
                "schema": "network_directory_auth_sensor_v1",
                "document_type": "network_directory_auth",
                "remote_ip": "198.51.100.116",
                "hostname": "beacon.example",
                "username": "tier1",
                "directory_service": "active-directory",
                "outcome": "success",
                "realm": "EXAMPLE.LOCAL",
            },
            tags=["network", "telemetry", "directory-auth"],
        )
    )

    case = manager.create_case_from_rule_alert_group(
        "network_vpn_directory_auth_user_overlap",
        SocCaseRuleGroupCaseRequest(group_key="tier1@beacon.example", assignee="tier2"),
    )

    assert case.assignee == "tier2"
    assert "hostname:beacon.example" in case.observables
    assert "198.51.100.116" in case.observables
    assert len(case.linked_alert_ids) == 1


def test_detection_engine_promotes_network_radius_directory_auth_user_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.radius",
            source="external_sensor",
            severity=SocSeverity.low,
            title="RADIUS telemetry for tier1",
            summary="External sensor submitted a normalized RADIUS record.",
            details={
                "schema": "network_radius_sensor_v1",
                "document_type": "network_radius",
                "remote_ip": "198.51.100.118",
                "hostname": "beacon.example",
                "username": "tier1",
                "outcome": "accept",
                "nas_identifier": "vpn-gateway-1",
                "realm": "EXAMPLE.LOCAL",
            },
            tags=["network", "telemetry", "radius"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.directory_auth",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Directory auth telemetry for tier1",
            summary="External sensor submitted a normalized directory auth record.",
            details={
                "schema": "network_directory_auth_sensor_v1",
                "document_type": "network_directory_auth",
                "remote_ip": "198.51.100.118",
                "hostname": "beacon.example",
                "username": "tier1",
                "directory_service": "active-directory",
                "outcome": "success",
                "realm": "EXAMPLE.LOCAL",
            },
            tags=["network", "telemetry", "directory-auth"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_radius_directory_auth_user_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "tier1@beacon.example" for item in correlation_alerts)


def test_detection_engine_promotes_network_nac_dhcp_host_overlap(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.nac",
            source="external_sensor",
            severity=SocSeverity.low,
            title="NAC telemetry for device-11",
            summary="External sensor submitted a normalized NAC record.",
            details={
                "schema": "network_nac_sensor_v1",
                "document_type": "network_nac",
                "remote_ip": "198.51.100.119",
                "hostname": "beacon.example",
                "device_id": "device-11",
                "mac_address": "00:11:22:33:44:55",
                "posture": "compliant",
                "action": "allow",
            },
            tags=["network", "telemetry", "nac"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.dhcp",
            source="external_sensor",
            severity=SocSeverity.low,
            title="DHCP telemetry for 10.0.0.25",
            summary="External sensor submitted a normalized DHCP record.",
            details={
                "schema": "network_dhcp_sensor_v1",
                "document_type": "network_dhcp",
                "remote_ip": "198.51.100.119",
                "hostname": "beacon.example",
                "assigned_ip": "10.0.0.25",
                "mac_address": "00:11:22:33:44:55",
                "lease_action": "ack",
            },
            tags=["network", "telemetry", "dhcp"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_nac_dhcp_host_overlap" for item in correlation_alerts)
    assert any(item.correlation_key == "beacon.example" for item in correlation_alerts)


def test_detection_rule_radius_network_group_case_payload_uses_generic_network_case(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.radius",
            source="external_sensor",
            severity=SocSeverity.low,
            title="RADIUS telemetry for tier1",
            summary="External sensor submitted a normalized RADIUS record.",
            details={
                "schema": "network_radius_sensor_v1",
                "document_type": "network_radius",
                "remote_ip": "198.51.100.118",
                "hostname": "beacon.example",
                "username": "tier1",
                "outcome": "accept",
                "nas_identifier": "vpn-gateway-1",
                "realm": "EXAMPLE.LOCAL",
            },
            tags=["network", "telemetry", "radius"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.directory_auth",
            source="external_sensor",
            severity=SocSeverity.low,
            title="Directory auth telemetry for tier1",
            summary="External sensor submitted a normalized directory auth record.",
            details={
                "schema": "network_directory_auth_sensor_v1",
                "document_type": "network_directory_auth",
                "remote_ip": "198.51.100.118",
                "hostname": "beacon.example",
                "username": "tier1",
                "directory_service": "active-directory",
                "outcome": "success",
                "realm": "EXAMPLE.LOCAL",
            },
            tags=["network", "telemetry", "directory-auth"],
        )
    )

    case = manager.create_case_from_rule_alert_group(
        "network_radius_directory_auth_user_overlap",
        SocCaseRuleGroupCaseRequest(group_key="tier1@beacon.example", assignee="tier2"),
    )

    assert case.assignee == "tier2"
    assert "hostname:beacon.example" in case.observables
    assert "198.51.100.118" in case.observables
    assert len(case.linked_alert_ids) == 1


def test_detection_engine_promotes_network_auth_failure_burst(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    for event_type, source in (
        ("network.telemetry.auth", "external_sensor"),
        ("network.telemetry.directory_auth", "external_sensor"),
        ("network.telemetry.radius", "external_sensor"),
    ):
        manager.ingest_event(
            SocEventIngest(
                event_type=event_type,
                source=source,
                severity=SocSeverity.low,
                title="Authentication failure",
                summary="External sensor submitted a failed auth record.",
                details={
                    "hostname": "beacon.example",
                    "username": "tier1",
                    "outcome": "failure",
                    "auth_protocol": "kerberos",
                    "directory_service": "active-directory",
                    "nas_identifier": "vpn-gateway-1",
                },
                tags=["network", "telemetry", "auth-failure"],
            )
        )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "network_auth_failure_burst" for item in correlation_alerts)
    assert any(item.correlation_key == "tier1@beacon.example" for item in correlation_alerts)


def test_detection_engine_promotes_network_vpn_disconnect_auth_failure_chain(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.vpn",
            source="external_sensor",
            severity=SocSeverity.low,
            title="VPN telemetry for tier1",
            summary="External sensor submitted a normalized VPN record.",
            details={
                "remote_ip": "198.51.100.120",
                "hostname": "beacon.example",
                "username": "tier1",
                "tunnel_type": "wireguard",
                "assigned_ip": "10.8.0.5",
                "outcome": "connected",
                "session_event": "disconnect",
                "close_reason": "idle-timeout",
            },
            tags=["network", "telemetry", "vpn"],
        )
    )
    for event_type in ("network.telemetry.auth", "network.telemetry.radius"):
        manager.ingest_event(
            SocEventIngest(
                event_type=event_type,
                source="external_sensor",
                severity=SocSeverity.low,
                title="Authentication failure",
                summary="External sensor submitted a failed auth record.",
                details={
                    "remote_ip": "198.51.100.120",
                    "hostname": "beacon.example",
                    "username": "tier1",
                    "outcome": "failure",
                    "auth_protocol": "kerberos",
                    "nas_identifier": "vpn-gateway-1",
                },
                tags=["network", "telemetry", "auth-failure"],
            )
        )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(
        item.correlation_rule == "network_vpn_disconnect_auth_failure_chain"
        and item.correlation_key == "tier1@beacon.example"
        and item.severity == SocSeverity.high
        for item in correlation_alerts
    )


def test_detection_engine_promotes_network_vpn_disconnect_auth_failure_chain_to_critical(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.vpn",
            source="external_sensor",
            severity=SocSeverity.low,
            title="VPN telemetry for tier1",
            summary="External sensor submitted a normalized VPN record.",
            details={
                "remote_ip": "198.51.100.120",
                "hostname": "beacon.example",
                "username": "tier1",
                "tunnel_type": "wireguard",
                "assigned_ip": "10.8.0.5",
                "outcome": "connected",
                "session_event": "disconnect",
                "close_reason": "policy-enforced",
            },
            tags=["network", "telemetry", "vpn"],
        )
    )
    for event_type in ("network.telemetry.auth", "network.telemetry.radius"):
        manager.ingest_event(
            SocEventIngest(
                event_type=event_type,
                source="external_sensor",
                severity=SocSeverity.low,
                title="Authentication failure",
                summary="External sensor submitted a failed auth record.",
                details={
                    "remote_ip": "198.51.100.120",
                    "hostname": "beacon.example",
                    "username": "tier1",
                    "outcome": "failure",
                    "auth_protocol": "kerberos",
                    "nas_identifier": "vpn-gateway-1",
                    "reject_code": "account-locked",
                },
                tags=["network", "telemetry", "auth-failure"],
            )
        )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(
        item.correlation_rule == "network_vpn_disconnect_auth_failure_chain"
        and item.correlation_key == "tier1@beacon.example"
        and item.severity == SocSeverity.critical
        for item in correlation_alerts
    )


def test_detection_rule_vpn_disconnect_auth_chain_case_payload_uses_generic_network_case(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.vpn",
            source="external_sensor",
            severity=SocSeverity.low,
            title="VPN telemetry for tier1",
            summary="External sensor submitted a normalized VPN record.",
            details={
                "remote_ip": "198.51.100.120",
                "hostname": "beacon.example",
                "username": "tier1",
                "tunnel_type": "wireguard",
                "assigned_ip": "10.8.0.5",
                "outcome": "connected",
                "session_event": "disconnect",
                "close_reason": "idle-timeout",
            },
            tags=["network", "telemetry", "vpn"],
        )
    )
    for event_type in ("network.telemetry.auth", "network.telemetry.radius"):
        manager.ingest_event(
            SocEventIngest(
                event_type=event_type,
                source="external_sensor",
                severity=SocSeverity.low,
                title="Authentication failure",
                summary="External sensor submitted a failed auth record.",
                details={
                    "remote_ip": "198.51.100.120",
                    "hostname": "beacon.example",
                    "username": "tier1",
                    "outcome": "failure",
                    "auth_protocol": "kerberos",
                    "nas_identifier": "vpn-gateway-1",
                },
                tags=["network", "telemetry", "auth-failure"],
            )
        )

    case = manager.create_case_from_rule_alert_group(
        "network_vpn_disconnect_auth_failure_chain",
        SocCaseRuleGroupCaseRequest(group_key="tier1@beacon.example", assignee="tier2"),
    )

    assert case.assignee == "tier2"
    assert "hostname:beacon.example" in case.observables
    assert "198.51.100.120" in case.observables
    assert len(case.linked_alert_ids) == 1


def test_detection_engine_promotes_network_radius_reject_burst(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    for _ in range(3):
        manager.ingest_event(
            SocEventIngest(
                event_type="network.telemetry.radius",
                source="external_sensor",
                severity=SocSeverity.low,
                title="RADIUS reject",
                summary="External sensor submitted a rejected RADIUS record.",
                details={
                    "remote_ip": "198.51.100.121",
                    "hostname": "beacon.example",
                    "username": "tier1",
                    "outcome": "reject",
                    "reject_code": "access-reject",
                    "nas_identifier": "vpn-gateway-1",
                },
                tags=["network", "telemetry", "radius-reject"],
            )
        )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(
        item.correlation_rule == "network_radius_reject_burst"
        and item.correlation_key == "tier1@beacon.example"
        and item.severity == SocSeverity.high
        for item in correlation_alerts
    )


def test_detection_engine_promotes_network_nac_posture_regression(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.nac",
            source="external_sensor",
            severity=SocSeverity.low,
            title="NAC posture change",
            summary="External sensor submitted a posture regression.",
            details={
                "remote_ip": "198.51.100.122",
                "hostname": "beacon.example",
                "device_id": "device-11",
                "mac_address": "00:11:22:33:44:55",
                "previous_posture": "compliant",
                "posture": "quarantined",
                "transition_reason": "malware-detected",
                "action": "isolate",
            },
            tags=["network", "telemetry", "nac"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(
        item.correlation_rule == "network_nac_posture_regression"
        and item.correlation_key == "device-11"
        and item.severity == SocSeverity.critical
        for item in correlation_alerts
    )


def test_detection_engine_promotes_network_radius_reject_burst_to_critical_for_lockout(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    for _ in range(3):
        manager.ingest_event(
            SocEventIngest(
                event_type="network.telemetry.radius",
                source="external_sensor",
                severity=SocSeverity.low,
                title="RADIUS reject",
                summary="External sensor submitted a rejected RADIUS record.",
                details={
                    "remote_ip": "198.51.100.121",
                    "hostname": "beacon.example",
                    "username": "tier1",
                    "outcome": "reject",
                    "reject_code": "account-locked",
                    "reject_reason": "user disabled by policy",
                    "nas_identifier": "vpn-gateway-1",
                },
                tags=["network", "telemetry", "radius-reject"],
            )
        )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(
        item.correlation_rule == "network_radius_reject_burst"
        and item.correlation_key == "tier1@beacon.example"
        and item.severity == SocSeverity.critical
        for item in correlation_alerts
    )


def test_detection_rule_radius_reject_burst_case_payload_uses_generic_network_case(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    for _ in range(3):
        manager.ingest_event(
            SocEventIngest(
                event_type="network.telemetry.radius",
                source="external_sensor",
                severity=SocSeverity.low,
                title="RADIUS reject",
                summary="External sensor submitted a rejected RADIUS record.",
                details={
                    "remote_ip": "198.51.100.121",
                    "hostname": "beacon.example",
                    "username": "tier1",
                    "outcome": "reject",
                    "reject_code": "access-reject",
                    "nas_identifier": "vpn-gateway-1",
                },
                tags=["network", "telemetry", "radius-reject"],
            )
        )

    case = manager.create_case_from_rule_alert_group(
        "network_radius_reject_burst",
        SocCaseRuleGroupCaseRequest(group_key="tier1@beacon.example", assignee="tier2"),
    )

    assert case.assignee == "tier2"
    assert "hostname:beacon.example" in case.observables
    assert "198.51.100.121" in case.observables
    assert len(case.linked_alert_ids) >= 1


def test_build_network_evidence_case_payload_includes_packet_enrichment(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    packet_event = manager.ingest_event(
        SocEventIngest(
            event_type="packet.monitor.finding",
            source="security_gateway",
            severity=SocSeverity.critical,
            title="Packet anomaly",
            summary="Packet session threshold exceeded.",
            details={"details": {"remote_ip": "198.51.100.95", "session_key": "packet-session:198.51.100.95"}},
            tags=["packet"],
        )
    ).event
    network_event = manager.ingest_event(
        SocEventIngest(
            event_type="network.monitor.finding",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Suspicious remote IP observed",
            summary="Repeated remote IP activity detected.",
            details={"details": {"remote_ip": "198.51.100.95", "local_ports": [3389], "remote_ports": [51000]}},
            tags=["network"],
        )
    ).event

    created = manager.build_network_evidence_case_payload(
        {
            "remote_ip": "198.51.100.95",
            "observation": {
                "remote_ip": "198.51.100.95",
                "total_hits": 3,
                "local_ports": [3389],
                "remote_ports": [51000],
                "sample_connections": [
                    {
                        "service_name": "rdp",
                        "application_protocol": "rdp",
                        "transport_family": "tcp",
                        "flow_id": "flow:tcp:198.51.100.95:51000:10.0.0.5:3389:na",
                    }
                ],
            },
            "packet_session": {
                "session_key": "packet-session:198.51.100.95",
                "protocols": ["TCP"],
                "service_names": ["rdp"],
                "application_protocols": ["rdp"],
                "transport_families": ["tcp"],
                "flow_ids": ["flow:tcp:198.51.100.95:51000:10.0.0.5:3389:na"],
                "protocol_evidence": {
                    "application_protocols": ["tls"],
                    "hostnames": ["example.com"],
                    "indicators": ["tls_handshake"],
                },
                "total_packets": 10,
            },
            "protocol_hosts": ["example.com"],
            "protocol_indicators": ["tls_handshake"],
        }
    )

    assert set(created.source_event_ids) == {packet_event.event_id, network_event.event_id}
    assert "service:rdp" in created.observables
    assert "application_protocol:rdp" in created.observables
    assert "application_protocol:tls" in created.observables
    assert "transport_family:tcp" in created.observables
    assert "flow_id:flow:tcp:198.51.100.95:51000:10.0.0.5:3389:na" in created.observables
    assert "host:example.com" in created.observables
    assert "protocol_indicator:tls_handshake" in created.observables
    assert "Services: rdp." in created.summary
    assert "Application protocols: rdp, tls." in created.summary
    assert "Hosts: example.com." in created.summary
    assert "Indicators: tls_handshake." in created.summary


def test_endpoint_timeline_clusters_group_by_process_and_remote_ip(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-4 reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-4",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-4",
                "sha256": "abc444",
                "signer_status": "unsigned",
                "reputation": "suspicious",
                "risk_flags": ["encoded_command"],
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-4 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-4",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-4",
                "remote_ip": "198.51.100.104",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    )
    manager.create_case(
        manager.build_endpoint_timeline_case_payload(
            SocEndpointTimelineCaseRequest(device_id="device-ep-4", process_guid="proc-guid-4")
        )
    )

    process_clusters = manager.cluster_endpoint_timeline(cluster_by="process", device_id="device-ep-4")
    remote_clusters = manager.cluster_endpoint_timeline(cluster_by="remote_ip", device_id="device-ep-4")

    assert process_clusters[0]["cluster_key"] == "device-ep-4:proc-guid-4"
    assert process_clusters[0]["event_count"] == 2
    assert process_event.event_id in process_clusters[0]["event_ids"]
    assert process_clusters[0]["open_case_count"] == 1
    assert remote_clusters[0]["cluster_key"] == "198.51.100.104"
    assert remote_clusters[0]["device_ids"] == ["device-ep-4"]


def test_create_case_from_endpoint_timeline_promotes_slice(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: cmd.exe",
            summary="Endpoint device-ep-5 reported process activity for cmd.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-5",
                "process_name": "cmd.exe",
                "process_guid": "proc-guid-5",
                "sha256": "cmd555",
                "signer_status": "unsigned",
                "risk_flags": ["suspicious_parent"],
                "remote_ips": ["198.51.100.105"],
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: cmd.exe",
            summary="Endpoint device-ep-5 reported a live connection for cmd.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-5",
                "process_name": "cmd.exe",
                "process_guid": "proc-guid-5",
                "remote_ip": "198.51.100.105",
                "state": "ESTABLISHED",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event

    case = manager.create_case_from_endpoint_timeline(
        SocEndpointTimelineCaseRequest(device_id="device-ep-5", process_guid="proc-guid-5", assignee="tier2")
    )

    assert case.assignee == "tier2"
    assert process_event.event_id in case.source_event_ids
    assert connection_event.event_id in case.source_event_ids
    assert "device:device-ep-5" in case.observables
    assert "process_guid:proc-guid-5" in case.observables
    assert "remote_ip:198.51.100.105" in case.observables


def test_case_context_exposes_rule_groups_and_endpoint_timeline_clusters(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-7 reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-7",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-7",
                "sha256": "ps777",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-7 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-7",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-7",
                "sha256": "ps777",
                "remote_ip": "198.51.100.107",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.critical,
            title="Endpoint file telemetry: payload.dll",
            summary="Endpoint device-ep-7 reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-7",
                "filename": "payload.dll",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps777",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    alert = next(item for item in manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))
    case = manager.create_case(
        SocCaseCreate(
            title="Endpoint investigation",
            summary="Investigate endpoint timeline activity.",
            severity=SocSeverity.high,
            linked_alert_ids=[alert.alert_id],
            source_event_ids=[process_event.event_id, connection_event.event_id, file_event.event_id],
            observables=["device:device-ep-7", "process_guid:proc-guid-7"],
        )
    )

    alert_groups = manager.list_case_rule_alert_groups(case.case_id)
    evidence_groups = manager.list_case_rule_evidence_groups(case.case_id)
    timeline_events = manager.list_case_endpoint_timeline(case.case_id, limit=20)
    timeline_clusters = manager.list_case_endpoint_timeline_clusters(case.case_id, cluster_by="process", limit=20)
    lineage_clusters = manager.list_case_endpoint_lineage_clusters(case.case_id, limit=20)

    assert alert_groups[0]["group_key"] == alert.correlation_key
    assert alert_groups[0]["alert_count"] >= 1
    assert evidence_groups[0]["event_count"] >= 1
    assert timeline_events["filters"]["case_id"] == case.case_id
    assert timeline_events["filters"]["process_guid"] == "proc-guid-7"
    assert timeline_events["events"]
    assert all(item["event_type"].startswith("endpoint.telemetry.") for item in timeline_events["events"])
    assert timeline_clusters["filters"]["case_id"] == case.case_id
    assert timeline_clusters["clusters"][0]["cluster_key"] == "device-ep-7:proc-guid-7"
    assert lineage_clusters["filters"]["case_id"] == case.case_id
    assert lineage_clusters["clusters"][0]["cluster_key"] == "device-ep-7::proc-guid-7::proc-guid-7"


def test_create_case_from_case_endpoint_timeline_cluster_promotes_slice(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-8 reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-8",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-8",
                "sha256": "ps888",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-8 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-8",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-8",
                "sha256": "ps888",
                "remote_ip": "198.51.100.108",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-ep-8 reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-8",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps888",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    alert = next(item for item in manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))
    case = manager.create_case(
        SocCaseCreate(
            title="Endpoint investigation",
            summary="Investigate endpoint timeline activity.",
            severity=SocSeverity.high,
            linked_alert_ids=[alert.alert_id],
            source_event_ids=[process_event.event_id, connection_event.event_id, file_event.event_id],
            observables=["device:device-ep-8", "process_guid:proc-guid-8"],
        )
    )

    promoted = manager.create_case_from_case_endpoint_timeline_cluster(
        case.case_id,
        SocCaseEndpointTimelineClusterCaseRequest(
            cluster_by="process",
            cluster_key="device-ep-8:proc-guid-8",
            assignee="tier2",
        ),
    )

    assert promoted.assignee == "tier2"
    assert process_event.event_id in promoted.source_event_ids
    assert connection_event.event_id in promoted.source_event_ids
    assert file_event.event_id in promoted.source_event_ids
    assert "device:device-ep-8" in promoted.observables
    assert "process_guid:proc-guid-8" in promoted.observables


def test_create_case_from_case_endpoint_lineage_cluster_promotes_slice(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-8b reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-8b",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-8b",
                "sha256": "ps88b",
                "parent_process_name": "winword.exe",
                "parent_process_guid": "parent-guid-8b",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-8b reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-8b",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-8b",
                "sha256": "ps88b",
                "remote_ip": "198.51.100.188",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-ep-8b reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-8b",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps88b",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    alert = next(item for item in manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))
    case = manager.create_case(
        SocCaseCreate(
            title="Endpoint lineage investigation",
            summary="Investigate endpoint lineage activity.",
            severity=SocSeverity.high,
            linked_alert_ids=[alert.alert_id],
            source_event_ids=[process_event.event_id, connection_event.event_id, file_event.event_id],
            observables=["device:device-ep-8b", "process_guid:proc-guid-8b"],
        )
    )

    promoted = manager.create_case_from_case_endpoint_lineage_cluster(
        case.case_id,
        SocCaseEndpointLineageClusterCaseRequest(
            cluster_key="device-ep-8b::parent-guid-8b::proc-guid-8b",
            assignee="tier2",
        ),
    )

    assert promoted.assignee == "tier2"
    assert process_event.event_id in promoted.source_event_ids
    assert connection_event.event_id in promoted.source_event_ids
    assert file_event.event_id in promoted.source_event_ids
    assert "device:device-ep-8b" in promoted.observables
    assert "process_guid:proc-guid-8b" in promoted.observables


def test_case_hunt_telemetry_clusters_and_case_promotion(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    endpoint_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-18 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-18",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-18",
                "remote_ip": "203.0.113.118",
                "signer_name": "Unknown",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    network_event = manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Network telemetry",
            summary="Observed connection to 203.0.113.118.",
            details={
                "schema": "network_connection_v1",
                "document_type": "network_connection",
                "remote_ip": "203.0.113.118",
                "device_id": "sensor-18",
            },
            tags=["network", "telemetry"],
        )
    ).event
    packet_event = manager.ingest_event(
        SocEventIngest(
            event_type="packet.telemetry.session",
            source="security_gateway",
            severity=SocSeverity.low,
            title="Packet telemetry",
            summary="Packet monitor captured a normalized session document.",
            details={
                "schema": "packet_session_v1",
                "document_type": "packet_session",
                "remote_ip": "203.0.113.118",
                "session_key": "packet-session:203.0.113.118",
            },
            tags=["packet", "telemetry"],
        )
    ).event
    case = manager.create_case(
        SocCaseCreate(
            title="Cross-telemetry investigation",
            summary="Investigate cross-telemetry activity.",
            severity=SocSeverity.high,
            source_event_ids=[endpoint_event.event_id, network_event.event_id, packet_event.event_id],
            observables=["device:device-ep-18", "process_guid:proc-guid-18", "remote_ip:203.0.113.118"],
        )
    )

    clusters = manager.list_case_hunt_telemetry_clusters(case.case_id, cluster_by="remote_ip", limit=20)
    detail = manager.resolve_case_hunt_telemetry_cluster(
        case.case_id,
        cluster_by="remote_ip",
        cluster_key="203.0.113.118",
    )
    promoted = manager.create_case_from_case_hunt_telemetry_cluster(
        case.case_id,
        SocCaseTelemetryClusterCaseRequest(
            cluster_by="remote_ip",
            cluster_key="203.0.113.118",
            assignee="tier2",
        ),
    )

    assert clusters["filters"]["case_id"] == case.case_id
    assert clusters["clusters"][0]["cluster_key"] == "203.0.113.118"
    assert detail["cluster_key"] == "203.0.113.118"
    assert len(detail["events"]) == 3
    assert promoted.assignee == "tier2"
    assert endpoint_event.event_id in promoted.source_event_ids
    assert network_event.event_id in promoted.source_event_ids
    assert packet_event.event_id in promoted.source_event_ids
    assert "remote_ip:203.0.113.118" in promoted.observables


def test_create_case_from_case_rule_alert_group_promotes_slice(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-9 reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-9",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-9",
                "sha256": "ps999",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-9 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-9",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-9",
                "sha256": "ps999",
                "remote_ip": "198.51.100.109",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-ep-9 reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-9",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps999",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    alert = next(item for item in manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))
    case = manager.create_case(
        SocCaseCreate(
            title="Endpoint investigation",
            summary="Investigate endpoint timeline activity.",
            severity=SocSeverity.high,
            linked_alert_ids=[alert.alert_id],
            source_event_ids=[process_event.event_id, connection_event.event_id, file_event.event_id],
            observables=["device:device-ep-9", "process_guid:proc-guid-9"],
        )
    )

    promoted = manager.create_case_from_case_rule_alert_group(
        case.case_id,
        SocCaseRuleGroupCaseRequest(group_key="device-ep-9:proc-guid-9", assignee="tier2"),
    )

    assert promoted.assignee == "tier2"
    assert process_event.event_id in promoted.source_event_ids
    assert connection_event.event_id in promoted.source_event_ids
    assert file_event.event_id in promoted.source_event_ids


def test_create_case_from_case_rule_evidence_group_promotes_slice(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-10 reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-10",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-10",
                "sha256": "ps1010",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-10 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-10",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-10",
                "sha256": "ps1010",
                "remote_ip": "198.51.100.110",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-ep-10 reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-10",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps1010",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    alert = next(item for item in manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))
    case = manager.create_case(
        SocCaseCreate(
            title="Endpoint investigation",
            summary="Investigate endpoint timeline activity.",
            severity=SocSeverity.high,
            linked_alert_ids=[alert.alert_id],
            source_event_ids=[process_event.event_id, connection_event.event_id, file_event.event_id],
            observables=["device:device-ep-10", "process_guid:proc-guid-10"],
        )
    )

    promoted = manager.create_case_from_case_rule_evidence_group(
        case.case_id,
        SocCaseRuleGroupCaseRequest(group_key="device-ep-10", assignee="tier2"),
    )

    assert promoted.assignee == "tier2"
    assert process_event.event_id in promoted.source_event_ids
    assert connection_event.event_id in promoted.source_event_ids
    assert file_event.event_id in promoted.source_event_ids


def test_create_case_from_rule_alert_group_promotes_slice(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-10b reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-10b",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-10b",
                "sha256": "ps1010b",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-10b reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-10b",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-10b",
                "sha256": "ps1010b",
                "remote_ip": "198.51.100.210",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-ep-10b reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-10b",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps1010b",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    next(item for item in manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))

    promoted = manager.create_case_from_rule_alert_group(
        "endpoint_timeline_execution_chain",
        SocCaseRuleGroupCaseRequest(group_key="device-ep-10b:proc-guid-10b", assignee="tier2"),
    )

    assert promoted.assignee == "tier2"
    assert process_event.event_id in promoted.source_event_ids
    assert connection_event.event_id in promoted.source_event_ids
    assert file_event.event_id in promoted.source_event_ids


def test_create_case_from_rule_evidence_group_promotes_slice(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    process_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-10c reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-10c",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-10c",
                "sha256": "ps1010c",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-10c reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-10c",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-10c",
                "sha256": "ps1010c",
                "remote_ip": "198.51.100.211",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-ep-10c reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-10c",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps1010c",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    next(item for item in manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))

    promoted = manager.create_case_from_rule_evidence_group(
        "endpoint_timeline_execution_chain",
        SocCaseRuleGroupCaseRequest(group_key="device-ep-10c", assignee="tier2"),
    )

    assert promoted.assignee == "tier2"
    assert process_event.event_id in promoted.source_event_ids
    assert connection_event.event_id in promoted.source_event_ids
    assert file_event.event_id in promoted.source_event_ids


def test_detection_engine_promotes_endpoint_timeline_execution_chain(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-ep-6 reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-ep-6",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-6",
                "sha256": "ps666",
                "command_line": "powershell.exe -enc ZGVhZGJlZWY=",
                "signer_status": "unsigned",
                "reputation": "suspicious",
                "risk_flags": ["encoded_command"],
            },
            tags=["endpoint", "telemetry", "process"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-ep-6 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-ep-6",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-6",
                "sha256": "ps666",
                "remote_ip": "198.51.100.106",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    )
    manager.ingest_event(
        SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-ep-6 reported file activity for payload.exe.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-ep-6",
                "filename": "payload.exe",
                "artifact_path": "C:/Users/Public/payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps666",
                "risk_flags": ["startup_path"],
            },
            tags=["endpoint", "telemetry", "file"],
        )
    )

    correlation_alerts = [item for item in manager.list_alerts() if item.category == "correlation"]

    assert any(item.correlation_rule == "endpoint_timeline_execution_chain" for item in correlation_alerts)
    assert any(item.correlation_key == "device-ep-6:proc-guid-6" for item in correlation_alerts)


def test_detection_rule_inventory_reports_alert_stats(tmp_path) -> None:
    manager, _alerts = _manager(tmp_path)
    for _ in range(2):
        manager.ingest_event(
            SocEventIngest(
                event_type="endpoint.malware_detected",
                source="endpoint",
                severity=SocSeverity.critical,
                title="Malware detected",
                summary="bad.exe matched a malware rule.",
                details={"filename": "bad.exe", "verdict": "matched:test-rule"},
                tags=["endpoint", "malware"],
            )
        )

    rule = manager.get_detection_rule("repeated_malware_artifact")

    assert rule.hit_count == 1
    assert rule.open_alert_count == 1
    assert rule.last_match_at is not None


def test_telemetry_retention_prunes_expired_network_and_packet_docs(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "soc_network_telemetry_retention_hours", 1.0)
    monkeypatch.setattr(settings, "soc_packet_telemetry_retention_hours", 1.0)
    manager, _alerts = _manager(tmp_path)
    old_timestamp = datetime.now(UTC) - timedelta(hours=5)
    manager._store.replace_events(  # type: ignore[attr-defined]
        [
            SocEventRecord(
                event_id="evt-old-network",
                event_type="network.telemetry.connection",
                source="security_gateway",
                severity=SocSeverity.low,
                title="Old network telemetry",
                summary="old",
                details={"schema": "network_connection_v1", "document_type": "network_connection", "remote_ip": "198.51.100.20"},
                artifacts=[],
                tags=["network", "telemetry"],
                created_at=old_timestamp,
                linked_alert_id=None,
            ),
            SocEventRecord(
                event_id="evt-old-packet",
                event_type="packet.telemetry.session",
                source="security_gateway",
                severity=SocSeverity.low,
                title="Old packet telemetry",
                summary="old",
                details={
                    "schema": "packet_session_v1",
                    "document_type": "packet_session",
                    "session_key": "packet-session:old",
                    "remote_ip": "198.51.100.21",
                },
                artifacts=[],
                tags=["packet", "telemetry"],
                created_at=old_timestamp,
                linked_alert_id=None,
            ),
        ]
    )

    manager.ingest_event(
        SocEventIngest(
            event_type="network.telemetry.connection",
            source="security_gateway",
            severity=SocSeverity.low,
            title="Fresh network telemetry",
            summary="fresh",
            details={"schema": "network_connection_v1", "document_type": "network_connection", "remote_ip": "198.51.100.22"},
            tags=["network", "telemetry"],
        )
    )

    events = manager.query_events(limit=20)

    assert all(item.event_id not in {"evt-old-network", "evt-old-packet"} for item in events)
