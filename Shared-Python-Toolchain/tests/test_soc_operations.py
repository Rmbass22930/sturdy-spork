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
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocCaseRecord,
    SocCaseStatus,
    SocDashboardViewStateUpdate,
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
    assert payload["storage"]["event_index_backend"] == "json-event-index"
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

    assert payload["index"]["backend"] == "json-event-index"
    assert payload["index"]["indexed_event_count"] == 2
    assert payload["index"]["token_count"] >= 1
    assert len(payload["events"]) == 1
    assert payload["events"][0]["source"] == "sensor-a"
    assert payload["events"][0]["details"]["remote_ip"] == "185.146.173.20"


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
        )
    )

    assert view_state["operational_reason_filter"] == "action failed"
    assert view_state["hunt_cluster_mode"] == "process_guid"
    assert view_state["hunt_cluster_value"] == "proc-guid-1"
    assert view_state["hunt_cluster_key"] == "cluster-22"
    assert view_state["hunt_cluster_action"] == "case"
    assert json.loads(Path(settings.soc_dashboard_view_state_path).read_text(encoding="utf-8")) == {
        "operational_reason_filter": "action failed",
        "hunt_cluster_mode": "process_guid",
        "hunt_cluster_value": "proc-guid-1",
        "hunt_cluster_key": "cluster-22",
        "hunt_cluster_action": "case",
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

    assert alert_groups[0]["group_key"] == alert.correlation_key
    assert alert_groups[0]["alert_count"] >= 1
    assert evidence_groups[0]["event_count"] >= 1
    assert timeline_events["filters"]["case_id"] == case.case_id
    assert timeline_events["filters"]["process_guid"] == "proc-guid-7"
    assert timeline_events["events"]
    assert all(item["event_type"].startswith("endpoint.telemetry.") for item in timeline_events["events"])
    assert timeline_clusters["filters"]["case_id"] == case.case_id
    assert timeline_clusters["clusters"][0]["cluster_key"] == "device-ep-7:proc-guid-7"


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
