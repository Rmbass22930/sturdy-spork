import json
import socket
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from security_gateway import service
from security_gateway.config import settings
from security_gateway.detection_engine import DetectionEngine
from security_gateway.ip_controls import IPBlocklistManager
from security_gateway.models import DeviceCompliance
from security_gateway.packet_monitor import PacketMonitor
from security_gateway.pam import VaultClient
from security_gateway.policy import PolicyEngine
from security_gateway.reports import SecurityReportBuilder
from security_gateway.soc import SecurityOperationsManager
from security_gateway.tor import ProxyRequestTimeoutError, ProxyResponse, ProxyResponseTooLargeError


class DummyAuditLogger:
    def __init__(self):
        self.events = []

    def log(self, event_type, data):
        self.events.append((event_type, data))


class DummyTraceRunner:
    def __init__(self):
        self.calls = []

    def trace(self, target, context=None):
        self.calls.append({"target": target, "context": context})
        return None


def _operator_headers(monkeypatch, token="test-operator-token"):
    monkeypatch.setattr(settings, "operator_bearer_token", token)
    monkeypatch.setattr(settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)
    return {"Authorization": f"Bearer {token}"}


def _operator_secret_headers(monkeypatch, token="test-operator-token", secret_name="operator-bearer-token"):
    monkeypatch.setattr(settings, "operator_bearer_token", "stale-fallback-token")
    monkeypatch.setattr(settings, "operator_bearer_secret_name", secret_name)
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)
    operator_vault = VaultClient(audit_logger=DummyAuditLogger(), master_key="test-master-key")
    operator_vault.store_secret(secret_name, token)
    monkeypatch.setattr(service, "vault", operator_vault)
    return {"Authorization": f"Bearer {token}"}


def _endpoint_headers(monkeypatch, token="test-endpoint-token"):
    monkeypatch.setattr(settings, "endpoint_bearer_token", token)
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", None)
    monkeypatch.setattr(settings, "endpoint_allow_loopback_without_token", False)
    return {"Authorization": f"Bearer {token}"}


def _endpoint_secret_headers(monkeypatch, token="test-endpoint-token", secret_name="endpoint-ingest-token"):
    monkeypatch.setattr(settings, "endpoint_bearer_token", "stale-endpoint-token")
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", secret_name)
    monkeypatch.setattr(settings, "endpoint_allow_loopback_without_token", False)
    service.vault.store_secret(secret_name, token)
    return {"Authorization": f"Bearer {token}"}


def _install_test_managers(monkeypatch, tmp_path):
    audit = DummyAuditLogger()
    operator_vault = VaultClient(audit_logger=audit, master_key="test-master-key")
    blocklist = IPBlocklistManager(path=tmp_path / "blocked_ips.json", audit_logger=audit)
    traceroute = DummyTraceRunner()
    report_dir = tmp_path / "reports"
    monkeypatch.setattr(settings, "report_output_dir", str(report_dir))
    monkeypatch.setattr(service, "audit_logger", audit)
    monkeypatch.setattr(service, "vault", operator_vault)
    monkeypatch.setattr(service, "ip_blocklist", blocklist)
    monkeypatch.setattr(
        service,
        "report_builder",
        SecurityReportBuilder(audit_log_path=tmp_path / "audit.jsonl", ip_blocklist_path=tmp_path / "blocked_ips.json"),
    )
    monkeypatch.setattr(settings, "soc_event_log_path", str(tmp_path / "soc_events.jsonl"))
    monkeypatch.setattr(settings, "soc_event_index_path", str(tmp_path / "soc_event_index.json"))
    monkeypatch.setattr(settings, "soc_alert_store_path", str(tmp_path / "soc_alerts.json"))
    monkeypatch.setattr(settings, "soc_case_store_path", str(tmp_path / "soc_cases.json"))
    monkeypatch.setattr(settings, "soc_detection_catalog_path", str(tmp_path / "soc_detection_catalog.json"))
    monkeypatch.setattr(settings, "soc_dashboard_view_state_path", str(tmp_path / "soc_dashboard_view_state.json"))
    monkeypatch.setattr(settings, "platform_node_registry_path", str(tmp_path / "platform_nodes.json"))
    monkeypatch.setattr(
        service.automation,
        "status",
        lambda: {
            "running": True,
            "last_run": "2026-03-31T12:00:00+00:00",
            "error_count": 0,
            "interval_seconds": 300.0,
            "tick_count": 4,
            "tracker_feed_refresh": {
                "enabled": True,
                "every_ticks": 12,
                "last_run": "2026-03-31T11:00:00+00:00",
                "last_result": "success",
                "last_error": None,
            },
            "malware_feed_refresh": {
                "enabled": False,
                "every_ticks": 12,
                "last_run": None,
                "last_result": None,
                "last_error": None,
            },
            "malware_rule_feed_refresh": {
                "enabled": False,
                "every_ticks": 12,
                "last_run": None,
                "last_result": None,
                "last_error": None,
            },
            "host_monitor": {
                "enabled": True,
                "every_ticks": 1,
                "last_run": "2026-03-31T11:59:00+00:00",
                "last_result": "success",
                "last_error": None,
            },
            "network_monitor": {
                "enabled": True,
                "every_ticks": 1,
                "last_run": "2026-03-31T11:59:00+00:00",
                "last_result": "success",
                "last_error": None,
            },
            "packet_monitor": {
                "enabled": True,
                "every_ticks": 1,
                "last_run": "2026-03-31T11:59:00+00:00",
                "last_result": "permission_denied",
                "last_error": "pktmon requires elevation",
            },
            "stream_monitor": {
                "enabled": True,
                "every_ticks": 1,
                "last_run": "2026-03-31T11:59:00+00:00",
                "last_result": "success",
                "last_error": None,
            },
        },
    )
    monkeypatch.setattr(
        service,
        "soc_manager",
        SecurityOperationsManager(
            event_log_path=tmp_path / "soc_events.jsonl",
            alert_store_path=tmp_path / "soc_alerts.json",
            case_store_path=tmp_path / "soc_cases.json",
            audit_logger=audit,
            alert_manager=service.alert_manager,
            detection_engine=DetectionEngine(tmp_path / "soc_detection_catalog.json"),
            platform_profile_builder=lambda: service.build_platform_profile(
                automation_status=service.automation.status(),
                tracker_health=service.tracker_intel.health_status(),
                malware_health=service.scanner.health_status(),
            ),
        ),
    )
    monkeypatch.setattr(
        service,
        "policy_engine",
        PolicyEngine(
            threat_responder=service.threat_responder,
            ip_blocklist=blocklist,
            traceroute_runner=traceroute,
        ),
    )
    monkeypatch.setattr(
        service,
        "packet_monitor",
        PacketMonitor(
            state_path=tmp_path / "packet_monitor_state.json",
            sample_seconds=settings.packet_monitor_sample_seconds,
            min_packet_count=settings.packet_monitor_min_packet_count,
            anomaly_multiplier=settings.packet_monitor_anomaly_multiplier,
            learning_samples=settings.packet_monitor_learning_samples,
            pkt_size=settings.packet_monitor_capture_bytes,
            sensitive_ports=settings.packet_monitor_sensitive_ports,
        ),
    )
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)
    service.public_rate_limiter.clear()
    service.auth_failure_rate_limiter.clear()
    return audit, blocklist, traceroute


def test_block_list_promote_unblock_api(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        created = client.post(
            "/network/blocked-ips",
            json={"ip": "203.0.113.30", "reason": "manual review", "duration_minutes": 15},
            headers=headers,
        )
        assert created.status_code == 200
        assert created.json()["entry"]["expires_at"] is not None

        listed = client.get("/network/blocked-ips", headers=headers)
        assert listed.status_code == 200
        assert listed.json()["blocked_ips"][0]["ip"] == "203.0.113.30"

        promoted = client.post(
            "/network/blocked-ips/203.0.113.30/promote",
            json={"reason": "confirmed attacker"},
            headers=headers,
        )
        assert promoted.status_code == 200
        assert promoted.json()["entry"]["expires_at"] is None
        assert promoted.json()["entry"]["reason"] == "confirmed attacker"

        removed = client.request(
            "DELETE",
            "/network/blocked-ips/203.0.113.30",
            json={"reason": "operator cleared"},
            headers=headers,
        )
        assert removed.status_code == 200


def test_packet_sessions_api_returns_compact_session_history(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    service.packet_monitor._write_state(  # type: ignore[attr-defined]
        {
            "session_history": {
                "packet-session:8.8.8.8": {
                    "session_key": "packet-session:8.8.8.8",
                    "remote_ip": "8.8.8.8",
                    "protocols": ["TCP"],
                    "local_ports": [3389],
                    "last_seen_at": "2026-03-29T21:00:00+00:00",
                    "sightings": 2,
                    "total_packets": 10,
                }
            }
        }
    )

    with TestClient(service.app) as client:
        response = client.get("/network/packet-sessions", headers=headers)
        filtered = client.get("/network/packet-sessions", params={"remote_ip": "8.8.8.8"}, headers=headers)

    assert response.status_code == 200
    assert response.json()["sessions"][0]["session_key"] == "packet-session:8.8.8.8"
    assert filtered.status_code == 200
    assert filtered.json()["sessions"][0]["remote_ip"] == "8.8.8.8"


def test_network_observations_and_evidence_api_return_combined_remote_ip_view(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    service.network_monitor._write_state(  # type: ignore[attr-defined]
        {
            "connection_history": {
                "8.8.8.8": {
                    "remote_ip": "8.8.8.8",
                    "states": ["ESTABLISHED"],
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "last_seen_at": "2026-03-29T21:30:00+00:00",
                    "sightings": 2,
                    "total_hits": 3,
                }
            }
        }
    )
    service.packet_monitor._write_state(  # type: ignore[attr-defined]
        {
            "session_history": {
                "packet-session:8.8.8.8": {
                    "session_key": "packet-session:8.8.8.8",
                    "remote_ip": "8.8.8.8",
                    "protocols": ["TCP"],
                    "local_ports": [3389],
                    "last_seen_at": "2026-03-29T21:00:00+00:00",
                    "sightings": 2,
                    "total_packets": 10,
                }
            }
        }
    )
    event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="network.monitor.finding",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Suspicious remote IP observed",
            summary="Repeated remote IP activity detected.",
            details={"details": {"remote_ip": "8.8.8.8"}},
            tags=["network"],
        )
    ).event
    service.soc_manager.create_case(
        service.SocCaseCreate(
            title="Investigate 8.8.8.8",
            summary="Open investigation for merged network evidence.",
            severity=service.SocSeverity.high,
            source_event_ids=[event.event_id],
        )
    )

    with TestClient(service.app) as client:
        observations = client.get("/network/observations", headers=headers)
        evidence = client.get("/network/evidence", headers=headers)

    assert observations.status_code == 200
    assert observations.json()["observations"][0]["remote_ip"] == "8.8.8.8"
    assert evidence.status_code == 200
    payload = evidence.json()["evidence"][0]
    assert payload["remote_ip"] == "8.8.8.8"
    assert payload["network_observation"]["total_hits"] == 3
    assert payload["packet_sessions"][0]["session_key"] == "packet-session:8.8.8.8"
    assert payload["related_case_ids"]
    assert payload["open_case_count"] == 1


def test_packet_session_case_api_creates_case_from_session_history(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    service.packet_monitor._write_state(  # type: ignore[attr-defined]
        {
            "session_history": {
                "packet-session:8.8.8.8": {
                    "session_key": "packet-session:8.8.8.8",
                    "remote_ip": "8.8.8.8",
                    "protocols": ["TCP"],
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "sensitive_ports": [3389],
                    "last_seen_at": "2026-03-29T21:00:00+00:00",
                    "sightings": 2,
                    "total_packets": 10,
                }
            }
        }
    )
    packet_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="packet.monitor.finding",
            source="security_gateway",
            severity=service.SocSeverity.critical,
            title="Suspicious packet activity observed: 8.8.8.8",
            summary="Packet metadata sampling observed a public remote IP against sensitive local ports.",
            details={
                "key": "packet-remote-ip:8.8.8.8",
                "resolved": False,
                "details": {
                    "session_key": "packet-session:8.8.8.8",
                    "remote_ip": "8.8.8.8",
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "sensitive_ports": [3389],
                },
            },
            tags=["packet", "network"],
        )
    ).event
    network_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="network.monitor.finding",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Suspicious remote IP observed",
            summary="A public remote IP repeatedly appeared against local listening ports.",
            details={
                "key": "suspicious-remote-ip:8.8.8.8",
                "resolved": False,
                "details": {
                    "remote_ip": "8.8.8.8",
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "finding_type": "suspicious_remote_ip",
                },
            },
            tags=["network"],
        )
    ).event

    with TestClient(service.app) as client:
        response = client.post(
            "/network/packet-sessions/case",
            json={"session_key": "packet-session:8.8.8.8", "assignee": "tier2"},
            headers=headers,
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["title"] == "Investigate packet session 8.8.8.8"
    assert payload["assignee"] == "tier2"
    assert "8.8.8.8" in payload["observables"]
    assert "packet-session:8.8.8.8" in payload["observables"]
    assert packet_event.event_id in payload["source_event_ids"]
    assert network_event.event_id in payload["source_event_ids"]


def test_create_case_from_network_evidence_api_promotes_remote_ip_context(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(
        service.packet_monitor,
        "list_recent_sessions",
        lambda limit=200, remote_ip=None: [
            {
                "session_key": "packet-session:8.8.8.8",
                "remote_ip": "8.8.8.8",
                "protocols": ["TCP"],
                "total_packets": 10,
            }
        ]
        if remote_ip in {None, "8.8.8.8"}
        else [],
    )
    packet_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="packet.monitor.finding",
            source="security_gateway",
            severity=service.SocSeverity.critical,
            title="Packet anomaly",
            summary="Packet session threshold exceeded.",
            details={"details": {"remote_ip": "8.8.8.8", "session_key": "packet-session:8.8.8.8"}},
            tags=["packet"],
        )
    ).event
    network_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="network.monitor.finding",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Suspicious remote IP observed",
            summary="A public remote IP repeatedly appeared against local listening ports.",
            details={"details": {"remote_ip": "8.8.8.8", "local_ports": [3389], "remote_ports": [51000], "sensitive_ports": [3389]}},
            tags=["network"],
        )
    ).event

    with TestClient(service.app) as client:
        response = client.post(
            "/network/evidence/case",
            json={"remote_ip": "8.8.8.8", "assignee": "tier2"},
            headers=headers,
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["title"] == "Investigate network evidence 8.8.8.8"
    assert payload["assignee"] == "tier2"
    assert "8.8.8.8" in payload["observables"]
    assert "packet-session:8.8.8.8" in payload["observables"]
    assert payload["linked_alert_ids"]
    assert packet_event.event_id in payload["source_event_ids"]
    assert network_event.event_id in payload["source_event_ids"]


def test_endpoint_timeline_cluster_and_case_api(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    process_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-11 reported process activity for powershell.exe.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-11",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-11",
                "sha256": "abc123",
                "signer_status": "unsigned",
                "risk_flags": ["encoded_command"],
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=service.SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-11 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-11",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-11",
                "sha256": "abc123",
                "remote_ip": "8.8.8.8",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint file telemetry: payload.dll",
            summary="Endpoint device-11 reported file activity for payload.dll.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-11",
                "filename": "payload.dll",
                "artifact_path": "C:/Users/Public/payload.dll",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "abc123",
                "risk_flags": ["startup_path"],
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event

    with TestClient(service.app) as client:
        clusters = client.get(
            "/endpoint/telemetry/timeline/clusters",
            params={"cluster_by": "process", "device_id": "device-11"},
            headers=headers,
        )
        case_response = client.post(
            "/endpoint/telemetry/timeline/case",
            json={"device_id": "device-11", "process_guid": "proc-guid-11", "assignee": "tier2"},
            headers=headers,
        )

    assert clusters.status_code == 200
    cluster_payload = clusters.json()["clusters"][0]
    assert cluster_payload["cluster_key"] == "device-11:proc-guid-11"
    assert cluster_payload["event_count"] == 3
    assert process_event.event_id in cluster_payload["event_ids"]

    assert case_response.status_code == 200
    case_payload = case_response.json()
    assert case_payload["assignee"] == "tier2"
    assert process_event.event_id in case_payload["source_event_ids"]
    assert connection_event.event_id in case_payload["source_event_ids"]
    assert file_event.event_id in case_payload["source_event_ids"]
    assert "device:device-11" in case_payload["observables"]
    assert "process_guid:proc-guid-11" in case_payload["observables"]
    assert "remote_ip:8.8.8.8" in case_payload["observables"]


def test_case_context_routes_expose_rule_groups_and_timeline_clusters(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    process_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-12 reported process activity.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-12",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-12",
                "sha256": "ps1212",
                "command_line": "powershell.exe -enc ZGVhZGJlZWY=",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=service.SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-12 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-12",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-12",
                "sha256": "ps1212",
                "remote_ip": "198.51.100.112",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=service.SocSeverity.critical,
            title="Endpoint file telemetry: payload.dll",
            summary="Endpoint device-12 reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-12",
                "filename": "payload.dll",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps1212",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    alert = next(item for item in service.soc_manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))
    case = service.soc_manager.create_case(
        service.SocCaseCreate(
            title="Endpoint investigation",
            summary="Investigate endpoint timeline activity.",
            severity=service.SocSeverity.high,
            linked_alert_ids=[alert.alert_id],
            source_event_ids=[process_event.event_id, connection_event.event_id, file_event.event_id],
            observables=["device:device-12", "process_guid:proc-guid-12"],
        )
    )

    with TestClient(service.app) as client:
        alert_groups = client.get(f"/soc/cases/{case.case_id}/rule-alert-groups", headers=headers)
        evidence_groups = client.get(f"/soc/cases/{case.case_id}/rule-evidence-groups", headers=headers)
        timeline_events = client.get(
            f"/soc/cases/{case.case_id}/endpoint-timeline",
            params={"limit": 20},
            headers=headers,
        )
        timeline_clusters = client.get(
            f"/soc/cases/{case.case_id}/endpoint-timeline/clusters",
            params={"cluster_by": "process", "limit": 20},
            headers=headers,
        )

    assert alert_groups.status_code == 200
    assert alert_groups.json()["groups"][0]["group_key"] == alert.correlation_key
    assert evidence_groups.status_code == 200
    assert evidence_groups.json()["groups"][0]["event_count"] >= 1
    assert timeline_events.status_code == 200
    assert timeline_events.json()["filters"]["case_id"] == case.case_id
    assert timeline_events.json()["filters"]["process_guid"] == "proc-guid-12"
    assert timeline_events.json()["events"]
    assert all(item["event_type"].startswith("endpoint.telemetry.") for item in timeline_events.json()["events"])
    assert timeline_clusters.status_code == 200
    assert timeline_clusters.json()["filters"]["case_id"] == case.case_id
    assert timeline_clusters.json()["clusters"][0]["cluster_key"] == "device-12:proc-guid-12"


def test_case_endpoint_timeline_cluster_case_route(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    process_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-13 reported process activity.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-13",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-13",
                "sha256": "ps1313",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=service.SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-13 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-13",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-13",
                "sha256": "ps1313",
                "remote_ip": "198.51.100.113",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-13 reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-13",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps1313",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    alert = next(item for item in service.soc_manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))
    case = service.soc_manager.create_case(
        service.SocCaseCreate(
            title="Endpoint investigation",
            summary="Investigate endpoint timeline activity.",
            severity=service.SocSeverity.high,
            linked_alert_ids=[alert.alert_id],
            source_event_ids=[process_event.event_id, connection_event.event_id, file_event.event_id],
            observables=["device:device-13", "process_guid:proc-guid-13"],
        )
    )

    with TestClient(service.app) as client:
        response = client.post(
            f"/soc/cases/{case.case_id}/endpoint-timeline/clusters/case",
            json={"cluster_by": "process", "cluster_key": "device-13:proc-guid-13", "assignee": "tier2"},
            headers=headers,
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["assignee"] == "tier2"
    assert process_event.event_id in payload["source_event_ids"]
    assert connection_event.event_id in payload["source_event_ids"]
    assert file_event.event_id in payload["source_event_ids"]
    assert "device:device-13" in payload["observables"]
    assert "process_guid:proc-guid-13" in payload["observables"]


def test_case_hunt_telemetry_cluster_routes(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    endpoint_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-19 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-19",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-19",
                "remote_ip": "203.0.113.119",
                "signer_name": "Unknown",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    network_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="network.telemetry.connection",
            source="security_gateway",
            severity=service.SocSeverity.medium,
            title="Network telemetry",
            summary="Observed connection to 203.0.113.119.",
            details={
                "schema": "network_connection_v1",
                "document_type": "network_connection",
                "remote_ip": "203.0.113.119",
                "device_id": "sensor-19",
            },
            tags=["network", "telemetry"],
        )
    ).event
    packet_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="packet.telemetry.session",
            source="security_gateway",
            severity=service.SocSeverity.low,
            title="Packet telemetry",
            summary="Packet monitor captured a normalized session document.",
            details={
                "schema": "packet_session_v1",
                "document_type": "packet_session",
                "remote_ip": "203.0.113.119",
                "session_key": "packet-session:203.0.113.119",
            },
            tags=["packet", "telemetry"],
        )
    ).event
    case = service.soc_manager.create_case(
        service.SocCaseCreate(
            title="Cross-telemetry investigation",
            summary="Investigate hunt telemetry clusters.",
            severity=service.SocSeverity.high,
            source_event_ids=[endpoint_event.event_id, network_event.event_id, packet_event.event_id],
            observables=["device:device-19", "process_guid:proc-guid-19", "remote_ip:203.0.113.119"],
        )
    )

    with TestClient(service.app) as client:
        listed = client.get(
            f"/soc/cases/{case.case_id}/hunt-telemetry/clusters",
            params={"cluster_by": "remote_ip", "limit": 20},
            headers=headers,
        )
        detail = client.get(
            f"/soc/cases/{case.case_id}/hunt-telemetry/clusters/203.0.113.119",
            params={"cluster_by": "remote_ip"},
            headers=headers,
        )
        created = client.post(
            f"/soc/cases/{case.case_id}/hunt-telemetry/clusters/case",
            json={"cluster_by": "remote_ip", "cluster_key": "203.0.113.119", "assignee": "tier2"},
            headers=headers,
        )

    assert listed.status_code == 200
    assert detail.status_code == 200
    assert created.status_code == 200
    assert listed.json()["filters"]["case_id"] == case.case_id
    assert listed.json()["clusters"][0]["cluster_key"] == "203.0.113.119"
    assert detail.json()["cluster"]["cluster_key"] == "203.0.113.119"
    assert len(detail.json()["cluster"]["events"]) == 3
    assert created.json()["assignee"] == "tier2"
    assert endpoint_event.event_id in created.json()["source_event_ids"]
    assert network_event.event_id in created.json()["source_event_ids"]
    assert packet_event.event_id in created.json()["source_event_ids"]


def test_case_rule_group_case_routes(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    process_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-14 reported process activity.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-14",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-14",
                "sha256": "ps1414",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    ).event
    connection_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=service.SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-14 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-14",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-14",
                "sha256": "ps1414",
                "remote_ip": "198.51.100.114",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    ).event
    file_event = service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-14 reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-14",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps1414",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    ).event
    alert = next(item for item in service.soc_manager.query_alerts(correlation_rule="endpoint_timeline_execution_chain", limit=10))
    case = service.soc_manager.create_case(
        service.SocCaseCreate(
            title="Endpoint investigation",
            summary="Investigate endpoint timeline activity.",
            severity=service.SocSeverity.high,
            linked_alert_ids=[alert.alert_id],
            source_event_ids=[process_event.event_id, connection_event.event_id, file_event.event_id],
            observables=["device:device-14", "process_guid:proc-guid-14"],
        )
    )

    with TestClient(service.app) as client:
        cluster_response = client.get(
            f"/soc/cases/{case.case_id}/endpoint-timeline/clusters/device-14:proc-guid-14",
            params={"cluster_by": "process"},
            headers=headers,
        )
        alert_group_response = client.get(
            f"/soc/cases/{case.case_id}/rule-alert-groups/device-14:proc-guid-14",
            headers=headers,
        )
        evidence_group_response = client.get(
            f"/soc/cases/{case.case_id}/rule-evidence-groups/device-14",
            headers=headers,
        )
        alert_response = client.post(
            f"/soc/cases/{case.case_id}/rule-alert-groups/case",
            json={"group_key": "device-14:proc-guid-14", "assignee": "tier2"},
            headers=headers,
        )
        evidence_response = client.post(
            f"/soc/cases/{case.case_id}/rule-evidence-groups/case",
            json={"group_key": "device-14", "assignee": "tier2"},
            headers=headers,
        )

    assert cluster_response.status_code == 200
    assert alert_group_response.status_code == 200
    assert evidence_group_response.status_code == 200
    assert alert_response.status_code == 200
    assert evidence_response.status_code == 200
    cluster_payload = cluster_response.json()["cluster"]
    alert_group_payload = alert_group_response.json()["group"]
    evidence_group_payload = evidence_group_response.json()["group"]
    alert_payload = alert_response.json()
    evidence_payload = evidence_response.json()
    assert cluster_payload["cluster_key"] == "device-14:proc-guid-14"
    assert alert_group_payload["group_key"] == "device-14:proc-guid-14"
    assert evidence_group_payload["group_key"] == "device-14"
    assert alert_payload["assignee"] == "tier2"
    assert evidence_payload["assignee"] == "tier2"
    assert process_event.event_id in alert_payload["source_event_ids"]
    assert connection_event.event_id in alert_payload["source_event_ids"]
    assert file_event.event_id in alert_payload["source_event_ids"]
    assert process_event.event_id in evidence_payload["source_event_ids"]
    assert connection_event.event_id in evidence_payload["source_event_ids"]
    assert file_event.event_id in evidence_payload["source_event_ids"]


def test_detection_rule_group_routes(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.process",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint process telemetry: powershell.exe",
            summary="Endpoint device-15 reported process activity.",
            details={
                "schema": "endpoint_process_v1",
                "document_type": "endpoint_process",
                "device_id": "device-15",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-15",
                "sha256": "ps1515",
                "signer_status": "unsigned",
                "reputation": "suspicious",
            },
            tags=["endpoint", "telemetry", "process"],
        )
    )
    service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.connection",
            source="security_gateway",
            severity=service.SocSeverity.medium,
            title="Endpoint connection telemetry: powershell.exe",
            summary="Endpoint device-15 reported a live connection for powershell.exe.",
            details={
                "schema": "endpoint_connection_v1",
                "document_type": "endpoint_connection",
                "device_id": "device-15",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-15",
                "sha256": "ps1515",
                "remote_ip": "198.51.100.115",
            },
            tags=["endpoint", "telemetry", "connection"],
        )
    )
    service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="endpoint.telemetry.file",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Endpoint file telemetry: payload.exe",
            summary="Endpoint device-15 reported suspicious file activity.",
            details={
                "schema": "endpoint_file_v1",
                "document_type": "endpoint_file",
                "device_id": "device-15",
                "filename": "payload.exe",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "ps1515",
            },
            tags=["endpoint", "telemetry", "file"],
        )
    )

    with TestClient(service.app) as client:
        alert_groups_response = client.get(
            "/soc/detections/endpoint_timeline_execution_chain/rule-alert-groups",
            headers=headers,
        )
        alert_group_response = client.get(
            "/soc/detections/endpoint_timeline_execution_chain/rule-alert-groups/device-15:proc-guid-15",
            headers=headers,
        )
        evidence_groups_response = client.get(
            "/soc/detections/endpoint_timeline_execution_chain/rule-evidence-groups",
            headers=headers,
        )
        evidence_group_response = client.get(
            "/soc/detections/endpoint_timeline_execution_chain/rule-evidence-groups/device-15",
            headers=headers,
        )

    assert alert_groups_response.status_code == 200
    assert alert_group_response.status_code == 200
    assert evidence_groups_response.status_code == 200
    assert evidence_group_response.status_code == 200
    assert alert_groups_response.json()["groups"][0]["group_key"] == "device-15:proc-guid-15"
    assert alert_group_response.json()["group"]["group_key"] == "device-15:proc-guid-15"
    assert evidence_groups_response.json()["groups"][0]["group_key"] == "device-15"
    assert evidence_group_response.json()["group"]["group_key"] == "device-15"


def test_soc_alerts_can_filter_by_correlation_rule(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    for _ in range(3):
        service.soc_manager.ingest_event(
            service.SocEventIngest(
                event_type="privacy.tracker_block",
                source="tracker_intel",
                severity=service.SocSeverity.medium,
                title="Tracker blocked",
                summary="Blocked tracker beacon.example.",
                details={"hostname": "beacon.example"},
                tags=["privacy", "tracker"],
            )
        )
    service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="packet.monitor.finding",
            source="security_gateway",
            severity=service.SocSeverity.critical,
            title="Suspicious packet activity observed: 8.8.8.8",
            summary="Packet metadata sampling observed a public remote IP against sensitive local ports.",
            details={
                "key": "packet-remote-ip:8.8.8.8",
                "resolved": False,
                "details": {
                    "session_key": "packet-session:8.8.8.8",
                    "remote_ip": "8.8.8.8",
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "sensitive_ports": [3389],
                },
            },
            tags=["packet", "network"],
        )
    )
    service.soc_manager.ingest_event(
        service.SocEventIngest(
            event_type="network.monitor.finding",
            source="security_gateway",
            severity=service.SocSeverity.high,
            title="Suspicious remote IP observed",
            summary="A public remote IP repeatedly appeared against local listening ports.",
            details={
                "key": "suspicious-remote-ip:8.8.8.8",
                "resolved": False,
                "details": {
                    "remote_ip": "8.8.8.8",
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "finding_type": "suspicious_remote_ip",
                },
            },
            tags=["network"],
        )
    )

    with TestClient(service.app) as client:
        response = client.get(
            "/soc/alerts",
            params={"correlation_rule": "packet_network_remote_overlap"},
            headers=headers,
        )

    assert response.status_code == 200
    alerts = response.json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["correlation_rule"] == "packet_network_remote_overlap"


def test_soc_hunt_and_events_support_time_filters_and_facets(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    older = service.SocEventRecord(
        event_id="evt-old",
        event_type="network.telemetry.connection",
        source="sensor-a",
        severity=service.SocSeverity.medium,
        title="Older connection",
        summary="Observed connection to 198.51.100.10.",
        details={"remote_ip": "198.51.100.10", "device_id": "device-old", "process_name": "curl.exe"},
        tags=["network", "telemetry"],
        artifacts=[],
        created_at=datetime(2026, 3, 31, 0, 0, tzinfo=timezone.utc),
        linked_alert_id=None,
    )
    newer = service.SocEventRecord(
        event_id="evt-new",
        event_type="endpoint.telemetry.process",
        source="sensor-b",
        severity=service.SocSeverity.high,
        title="Newer process",
        summary="Endpoint device-new reported process activity.",
        details={"device_id": "device-new", "process_name": "powershell.exe", "remote_ip": "203.0.113.55"},
        tags=["endpoint", "telemetry"],
        artifacts=[],
        created_at=datetime(2026, 4, 1, 0, 0, tzinfo=timezone.utc),
        linked_alert_id=None,
    )
    service.soc_manager._store.event_store.write([older, newer])  # type: ignore[attr-defined]
    service.soc_manager._store.event_index_store.rebuild([older, newer])  # type: ignore[attr-defined]

    with TestClient(service.app) as client:
        events_response = client.get(
            "/soc/events",
            params={
                "start_at": "2026-03-31T12:00:00+00:00",
                "end_at": "2026-04-01T12:00:00+00:00",
            },
            headers=headers,
        )
        hunt_response = client.get(
            "/soc/hunt",
            params={
                "start_at": "2026-03-31T12:00:00+00:00",
                "end_at": "2026-04-01T12:00:00+00:00",
                "facet_limit": 3,
            },
            headers=headers,
        )

    assert events_response.status_code == 200
    assert [item["event_id"] for item in events_response.json()["events"]] == ["evt-new"]
    assert hunt_response.status_code == 200
    hunt_payload = hunt_response.json()
    assert hunt_payload["match_count"] == 1
    assert hunt_payload["filters"]["facet_limit"] == 3
    assert hunt_payload["facets"]["source"] == [{"value": "sensor-b", "count": 1}]
    assert hunt_payload["timeline"]["bucket_unit"] == "hour"
    assert hunt_payload["timeline"]["buckets"] == [{"start_at": "2026-04-01T00:00:00+00:00", "count": 1}]
    assert hunt_payload["summaries"]["severities"] == [{"value": "high", "count": 1}]


def test_telemetry_summary_routes_return_facets_and_timeline(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    events = [
        service.SocEventRecord(
            event_id="evt-endpoint-process",
            event_type="endpoint.telemetry.process",
            source="sensor-a",
            severity=service.SocSeverity.high,
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
            created_at=datetime(2026, 4, 1, 0, 0, tzinfo=timezone.utc),
            linked_alert_id=None,
        ),
        service.SocEventRecord(
            event_id="evt-endpoint-file",
            event_type="endpoint.telemetry.file",
            source="sensor-a",
            severity=service.SocSeverity.medium,
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
            created_at=datetime(2026, 4, 1, 1, 0, tzinfo=timezone.utc),
            linked_alert_id=None,
        ),
        service.SocEventRecord(
            event_id="evt-network",
            event_type="network.telemetry.connection",
            source="sensor-b",
            severity=service.SocSeverity.medium,
            title="Network telemetry",
            summary="Observed connection to 203.0.113.77.",
            details={"document_type": "network_connection", "remote_ip": "203.0.113.77"},
            tags=["network", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 2, 0, tzinfo=timezone.utc),
            linked_alert_id=None,
        ),
        service.SocEventRecord(
            event_id="evt-packet",
            event_type="packet.telemetry.session",
            source="sensor-c",
            severity=service.SocSeverity.low,
            title="Packet telemetry",
            summary="Packet monitor captured a normalized session document.",
            details={
                "document_type": "packet_session",
                "remote_ip": "203.0.113.77",
                "session_key": "packet-session:summary",
            },
            tags=["packet", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 3, 0, tzinfo=timezone.utc),
            linked_alert_id=None,
        ),
    ]
    service.soc_manager._store.event_store.write(events)  # type: ignore[attr-defined]
    service.soc_manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    with TestClient(service.app) as client:
        endpoint_summary = client.get(
            "/endpoint/telemetry/summary",
            params={
                "device_id": "device-summary",
                "start_at": "2026-04-01T00:00:00+00:00",
                "end_at": "2026-04-01T02:00:00+00:00",
                "facet_limit": 3,
            },
            headers=headers,
        )
        network_summary = client.get(
            "/network/telemetry/summary",
            params={
                "remote_ip": "203.0.113.77",
                "start_at": "2026-04-01T01:30:00+00:00",
                "end_at": "2026-04-01T02:30:00+00:00",
                "facet_limit": 2,
            },
            headers=headers,
        )
        packet_summary = client.get(
            "/packet/telemetry/summary",
            params={
                "session_key": "packet-session:summary",
                "start_at": "2026-04-01T02:30:00+00:00",
                "end_at": "2026-04-01T03:30:00+00:00",
                "facet_limit": 2,
            },
            headers=headers,
        )

    assert endpoint_summary.status_code == 200
    endpoint_payload = endpoint_summary.json()
    assert endpoint_payload["telemetry"] == "endpoint"
    assert endpoint_payload["match_count"] == 2
    assert endpoint_payload["timeline"]["bucket_unit"] == "hour"
    assert endpoint_payload["summaries"]["device_ids"] == [{"value": "device-summary", "count": 2}]
    assert network_summary.status_code == 200
    network_payload = network_summary.json()
    assert network_payload["telemetry"] == "network"
    assert network_payload["match_count"] == 1
    assert network_payload["retention_hours"] == settings.soc_network_telemetry_retention_hours
    assert network_payload["facets"]["remote_ip"] == [{"value": "203.0.113.77", "count": 1}]
    assert packet_summary.status_code == 200
    packet_payload = packet_summary.json()
    assert packet_payload["telemetry"] == "packet"
    assert packet_payload["match_count"] == 1
    assert packet_payload["retention_hours"] == settings.soc_packet_telemetry_retention_hours
    assert packet_payload["summaries"]["remote_ips"] == [{"value": "203.0.113.77", "count": 1}]


def test_hunt_telemetry_cluster_routes_support_detail_and_case_promotion(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    events = [
        service.SocEventRecord(
            event_id="evt-endpoint-conn",
            event_type="endpoint.telemetry.connection",
            source="sensor-a",
            severity=service.SocSeverity.high,
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
            created_at=datetime(2026, 4, 1, 0, 0, tzinfo=timezone.utc),
            linked_alert_id=None,
        ),
        service.SocEventRecord(
            event_id="evt-network-conn",
            event_type="network.telemetry.connection",
            source="sensor-b",
            severity=service.SocSeverity.medium,
            title="Network telemetry",
            summary="Observed connection to 203.0.113.88.",
            details={"document_type": "network_connection", "remote_ip": "203.0.113.88"},
            tags=["network", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 1, 0, tzinfo=timezone.utc),
            linked_alert_id=None,
        ),
        service.SocEventRecord(
            event_id="evt-packet-session",
            event_type="packet.telemetry.session",
            source="sensor-c",
            severity=service.SocSeverity.low,
            title="Packet telemetry",
            summary="Packet monitor captured a normalized session document.",
            details={
                "document_type": "packet_session",
                "remote_ip": "203.0.113.88",
                "session_key": "packet-session:cluster",
            },
            tags=["packet", "telemetry"],
            artifacts=[],
            created_at=datetime(2026, 4, 1, 2, 0, tzinfo=timezone.utc),
            linked_alert_id=None,
        ),
    ]
    service.soc_manager._store.event_store.write(events)  # type: ignore[attr-defined]
    service.soc_manager._store.event_index_store.rebuild(events)  # type: ignore[attr-defined]

    with TestClient(service.app) as client:
        listed = client.get(
            "/soc/hunt/telemetry/clusters",
            params={"cluster_by": "remote_ip", "remote_ip": "203.0.113.88"},
            headers=headers,
        )
        detail = client.get(
            "/soc/hunt/telemetry/clusters/203.0.113.88",
            params={"cluster_by": "remote_ip", "remote_ip": "203.0.113.88"},
            headers=headers,
        )
        created = client.post(
            "/soc/hunt/telemetry/clusters/case",
            json={"cluster_by": "remote_ip", "cluster_key": "203.0.113.88", "remote_ip": "203.0.113.88", "assignee": "tier2"},
            headers=headers,
        )

    assert listed.status_code == 200
    clusters = listed.json()["clusters"]
    assert len(clusters) == 1
    assert clusters[0]["cluster_key"] == "203.0.113.88"
    assert clusters[0]["telemetry_kinds"] == {"endpoint": 1, "network": 1, "packet": 1}
    assert detail.status_code == 200
    assert len(detail.json()["cluster"]["events"]) == 3
    assert created.status_code == 200
    case_payload = created.json()
    assert case_payload["assignee"] == "tier2"
    assert set(case_payload["source_event_ids"]) == {"evt-endpoint-conn", "evt-network-conn", "evt-packet-session"}
    assert "remote_ip:203.0.113.88" in case_payload["observables"]


def test_api_docs_are_disabled_by_default(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)

    with TestClient(service.app) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404


def test_operator_and_endpoint_routes_fail_closed_when_tokens_are_unconfigured(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_token", None)
    monkeypatch.setattr(settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)
    monkeypatch.setattr(settings, "endpoint_bearer_token", None)
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", None)
    monkeypatch.setattr(settings, "endpoint_allow_loopback_without_token", False)

    payload = {
        "device_id": "device-123",
        "os": "Windows",
        "os_version": "11",
        "compliance": "compliant",
        "is_encrypted": True,
        "edr_active": True,
    }

    with TestClient(service.app) as client:
        operator_response = client.get("/automation/status")
        endpoint_response = client.post("/endpoint/telemetry", json=payload)

    assert operator_response.status_code == 503
    assert operator_response.json()["detail"] == "Operator bearer token is not configured for remote management."
    assert endpoint_response.status_code == 503
    assert endpoint_response.json()["detail"] == "Endpoint bearer token is not configured for remote ingestion."


def test_startup_fails_when_operator_token_backend_is_unavailable(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_token", "stale-static-token")
    monkeypatch.setattr(settings, "operator_bearer_secret_name", "operator-bearer-token")
    monkeypatch.setattr(service.vault, "retrieve_secret", lambda name: (_ for _ in ()).throw(RuntimeError("vault offline")))

    with pytest.raises(RuntimeError, match="Operator bearer token backend is unavailable during startup."):
        with TestClient(service.app):
            pass


def test_startup_fails_when_endpoint_token_backend_is_unavailable(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(settings, "endpoint_bearer_token", "stale-static-token")
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", "endpoint-ingest-token")
    monkeypatch.setattr(service.vault, "retrieve_secret", lambda name: (_ for _ in ()).throw(RuntimeError("vault offline")))

    with pytest.raises(RuntimeError, match="Endpoint bearer token backend is unavailable during startup."):
        with TestClient(service.app):
            pass


def test_security_health_reports_ready_auth_backends(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_secret_headers(monkeypatch, token="operator-token", secret_name="operator-bearer-token")
    monkeypatch.setattr(settings, "endpoint_bearer_token", None)
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", "endpoint-ingest-token")
    monkeypatch.setattr(settings, "endpoint_allow_loopback_without_token", False)
    service.vault.store_secret("endpoint-ingest-token", "endpoint-token")

    with TestClient(service.app) as client:
        response = client.get("/health/security", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["auth_backends"]["healthy"] is True
    assert payload["auth_backends"]["warnings"] == []
    assert payload["auth_backends"]["operator"]["status"] == "ready"
    assert payload["auth_backends"]["operator"]["source"] == "pam_secret"
    assert payload["auth_backends"]["endpoint"]["status"] == "ready"
    assert payload["auth_backends"]["endpoint"]["source"] == "pam_secret"
    assert payload["platform"]["service_health"]["overall_status"] == "degraded"
    assert payload["platform"]["service_health"]["services"]["packet_monitor"]["status"] == "degraded"
    assert payload["soc"]["events_total"] == 0
    assert payload["soc"]["alerts_total"] == 0


def test_security_health_applies_sensor_role_service_policy(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(settings, "platform_node_role", "sensor")

    with TestClient(service.app) as client:
        response = client.get("/health/security", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["platform"]["node_role"] == "sensor"
    assert payload["platform"]["role_profile"]["services"]["tracker_intel"] is False
    assert payload["platform"]["role_profile"]["services"]["packet_monitor"] is True
    assert payload["platform"]["service_health"]["services"]["tracker_intel"]["enabled"] is False
    assert payload["platform"]["service_health"]["services"]["network_monitor"]["enabled"] is True


def test_platform_node_heartbeat_updates_manager_topology(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")

    with TestClient(service.app) as client:
        created = client.post(
            "/platform/nodes/heartbeat",
            json={
                "node_name": "sensor-a",
                "node_role": "sensor",
                "deployment_mode": "multi-node",
                "service_health": {"overall_status": "healthy"},
                "metadata": {"site": "west"},
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            },
            headers=headers,
        )
        topology = client.get("/platform/nodes", headers=headers)

    assert created.status_code == 200
    created_payload = created.json()
    assert created_payload["node"]["node_name"] == "sensor-a"
    assert created_payload["topology"]["remote_node_count"] == 1
    assert topology.status_code == 200
    topology_payload = topology.json()
    assert topology_payload["platform"]["node_role"] == "manager"
    assert topology_payload["topology"]["remote_node_count"] == 1
    assert topology_payload["topology"]["healthy_nodes"] >= 1
    assert topology_payload["nodes"][1]["node_name"] == "sensor-a"
    assert topology_payload["nodes"][1]["status"] == "healthy"


def test_platform_node_detail_acknowledge_and_case_actions(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(settings, "platform_node_role", "manager")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")

    with TestClient(service.app) as client:
        heartbeat = client.post(
            "/platform/nodes/heartbeat",
            json={
                "node_name": "sensor-a",
                "node_role": "sensor",
                "deployment_mode": "multi-node",
                "service_health": {
                    "overall_status": "degraded",
                    "services": {"packet_monitor": {"status": "degraded", "enabled": True}},
                },
                "metadata": {"site": "west"},
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            },
            headers=headers,
        )
        detail = client.get("/platform/nodes/sensor-a", headers=headers)
        acknowledged = client.post(
            "/platform/nodes/sensor-a/acknowledge",
            json={"acknowledged_by": "tier2", "note": "Investigating packet monitor degradation"},
            headers=headers,
        )
        suppressed = client.post(
            "/platform/nodes/sensor-a/suppress",
            json={
                "suppressed_by": "tier2",
                "reason": "maintenance",
                "minutes": 30,
                "scopes": ["remote_node_degraded"],
            },
            headers=headers,
        )
        maintenance = client.post(
            "/platform/nodes/sensor-a/maintenance",
            json={"started_by": "tier2", "reason": "patching", "minutes": 45, "services": ["packet_monitor"]},
            headers=headers,
        )
        actions_after_maintenance = client.get("/platform/nodes/sensor-a/actions", headers=headers)
        acknowledged_maintenance = client.post(
            "/platform/nodes/sensor-a/actions/maintenance/acknowledge",
            json={"acted_by": "sensor-a", "note": "maintenance received"},
            headers=headers,
        )
        completed_maintenance = client.post(
            "/platform/nodes/sensor-a/actions/maintenance/complete",
            json={"acted_by": "sensor-a", "result": "success", "note": "maintenance active"},
            headers=headers,
        )
        refresh = client.post(
            "/platform/nodes/sensor-a/refresh",
            json={"requested_by": "tier2", "reason": "refresh health"},
            headers=headers,
        )
        actions_after_refresh = client.get("/platform/nodes/sensor-a/actions", headers=headers)
        acknowledged_refresh = client.post(
            "/platform/nodes/sensor-a/actions/refresh/acknowledge",
            json={"acted_by": "sensor-a", "note": "refresh received"},
            headers=headers,
        )
        completed_refresh = client.post(
            "/platform/nodes/sensor-a/actions/refresh/complete",
            json={"acted_by": "sensor-a", "result": "success", "note": "refresh complete"},
            headers=headers,
        )
        drained = client.post(
            "/platform/nodes/sensor-a/drain",
            json={"drained_by": "tier2", "reason": "patching", "services": ["packet_monitor"]},
            headers=headers,
        )
        completed_drain = client.post(
            "/platform/nodes/sensor-a/actions/drain/complete",
            json={"acted_by": "sensor-a", "result": "success", "note": "drain active"},
            headers=headers,
        )
        created_case = client.post(
            "/platform/nodes/sensor-a/case",
            json={"assignee": "tier2"},
            headers=headers,
        )
        detail_after_case = client.get("/platform/nodes/sensor-a", headers=headers)
        heartbeat_after_actions = client.post(
            "/platform/nodes/heartbeat",
            json={
                "node_name": "sensor-a",
                "node_role": "sensor",
                "deployment_mode": "multi-node",
                "service_health": {
                    "overall_status": "degraded",
                    "services": {"packet_monitor": {"status": "degraded", "enabled": True}},
                },
                "metadata": {"site": "west"},
                "last_seen_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            },
            headers=headers,
        )
        detail_after_heartbeat = client.get("/platform/nodes/sensor-a", headers=headers)
        cleared = client.post(
            "/platform/nodes/sensor-a/clear-suppression",
            json={"scopes": ["remote_node_degraded"]},
            headers=headers,
        )
        cleared_maintenance = client.post("/platform/nodes/sensor-a/clear-maintenance", headers=headers)
        ready = client.post("/platform/nodes/sensor-a/ready", headers=headers)

    assert heartbeat.status_code == 200
    assert detail.status_code == 200
    detail_payload = detail.json()["node"]
    assert detail_payload["node_name"] == "sensor-a"
    assert detail_payload["status"] == "degraded"
    assert detail_payload["open_case_count"] == 0

    assert acknowledged.status_code == 200
    acknowledged_payload = acknowledged.json()["node"]
    assert acknowledged_payload["metadata"]["acknowledged_by"] == "tier2"
    assert acknowledged_payload["metadata"]["acknowledgement_note"] == "Investigating packet monitor degradation"

    assert suppressed.status_code == 200
    suppressed_payload = suppressed.json()["node"]
    assert suppressed_payload["suppressed"] is True
    assert suppressed_payload["suppression"]["active_scopes"] == ["remote_node_degraded"]
    assert suppressed_payload["metadata"]["pressure_suppressions"][0]["suppressed_by"] == "tier2"
    assert suppressed_payload["metadata"]["pressure_suppressions"][0]["suppression_reason"] == "maintenance"

    assert maintenance.status_code == 200
    maintenance_payload = maintenance.json()["node"]
    assert maintenance_payload["maintenance"]["active"] is True
    assert maintenance_payload["maintenance"]["status"] == "requested"
    assert maintenance_payload["maintenance"]["maintenance_services"] == ["packet_monitor"]
    assert maintenance_payload["metadata"]["maintenance_by"] == "tier2"
    assert maintenance_payload["metadata"]["maintenance_reason"] == "patching"
    assert actions_after_maintenance.status_code == 200
    assert [item["action"] for item in actions_after_maintenance.json()["actions"]] == ["maintenance"]
    assert acknowledged_maintenance.status_code == 200
    acknowledged_maintenance_payload = acknowledged_maintenance.json()["node"]
    assert acknowledged_maintenance_payload["maintenance"]["status"] == "acknowledged"
    assert completed_maintenance.status_code == 200
    completed_maintenance_payload = completed_maintenance.json()["node"]
    assert completed_maintenance_payload["maintenance"]["status"] == "completed"
    assert completed_maintenance_payload["maintenance"]["maintenance_result"] == "success"

    assert refresh.status_code == 200
    refresh_payload = refresh.json()["node"]
    assert refresh_payload["refresh"]["pending"] is True
    assert refresh_payload["refresh"]["status"] == "requested"
    assert refresh_payload["metadata"]["refresh_requested_by"] == "tier2"
    assert refresh_payload["metadata"]["refresh_request_reason"] == "refresh health"
    assert actions_after_refresh.status_code == 200
    assert [item["action"] for item in actions_after_refresh.json()["actions"]] == ["refresh"]
    assert acknowledged_refresh.status_code == 200
    acknowledged_refresh_payload = acknowledged_refresh.json()["node"]
    assert acknowledged_refresh_payload["refresh"]["status"] == "acknowledged"
    assert completed_refresh.status_code == 200
    completed_refresh_payload = completed_refresh.json()["node"]
    assert completed_refresh_payload["refresh"]["pending"] is False
    assert completed_refresh_payload["refresh"]["status"] == "completed"

    assert drained.status_code == 200
    drained_payload = drained.json()["node"]
    assert drained_payload["drain"]["active"] is True
    assert drained_payload["drain"]["status"] == "requested"
    assert drained_payload["metadata"]["drained_by"] == "tier2"
    assert drained_payload["metadata"]["drain_reason"] == "patching"
    assert drained_payload["metadata"]["drain_services"] == ["packet_monitor"]
    assert completed_drain.status_code == 200
    completed_drain_payload = completed_drain.json()["node"]
    assert completed_drain_payload["drain"]["status"] == "completed"

    assert created_case.status_code == 200
    case_payload = created_case.json()
    assert case_payload["title"] == "Investigate remote node sensor-a"
    assert case_payload["assignee"] == "tier2"
    assert "node:sensor-a" in case_payload["observables"]
    assert "role:sensor" in case_payload["observables"]
    assert "service:packet_monitor" in case_payload["observables"]

    assert detail_after_case.status_code == 200
    after_case_payload = detail_after_case.json()["node"]
    assert after_case_payload["open_case_count"] == 1
    assert after_case_payload["open_case_ids"] == [case_payload["case_id"]]
    assert after_case_payload["suppressed"] is True
    assert after_case_payload["maintenance_active"] is True
    assert after_case_payload["drained"] is True

    assert heartbeat_after_actions.status_code == 200
    after_heartbeat_payload = detail_after_heartbeat.json()["node"]
    assert after_heartbeat_payload["metadata"]["acknowledged_by"] == "tier2"
    assert after_heartbeat_payload["suppressed"] is True
    assert after_heartbeat_payload["maintenance_active"] is True
    assert after_heartbeat_payload["maintenance"]["status"] == "completed"
    assert after_heartbeat_payload["drained"] is True
    assert after_heartbeat_payload["refresh"]["pending"] is False
    assert after_heartbeat_payload["refresh"]["status"] == "completed"
    assert after_heartbeat_payload["drain"]["status"] == "completed"
    assert after_heartbeat_payload["metadata"]["site"] == "west"

    assert cleared.status_code == 200
    cleared_payload = cleared.json()["node"]
    assert cleared_payload["suppressed"] is False
    assert cleared_maintenance.status_code == 200
    cleared_maintenance_payload = cleared_maintenance.json()["node"]
    assert cleared_maintenance_payload["maintenance_active"] is False
    assert ready.status_code == 200
    ready_payload = ready.json()["node"]
    assert ready_payload["drained"] is False
    assert ready_payload["drain"]["status"] == "completed"
    history = ready_payload["metadata"]["action_history"]
    assert [item["transition"] for item in history[:8]] == [
        "requested",
        "acknowledged",
        "completed",
        "requested",
        "acknowledged",
        "completed",
        "requested",
        "completed",
    ]
    assert [item["action"] for item in history[:8]] == [
        "maintenance",
        "maintenance",
        "maintenance",
        "refresh",
        "refresh",
        "refresh",
        "drain",
        "drain",
    ]


def test_platform_node_failed_action_state_is_exposed(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        heartbeat = client.post(
            "/platform/nodes/heartbeat",
            json={
                "node_name": "sensor-b",
                "node_role": "sensor",
                "deployment_mode": "multi-node",
                "service_health": {
                    "overall_status": "healthy",
                    "services": {"packet_monitor": {"status": "healthy", "enabled": True}},
                },
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            },
            headers=headers,
        )
        drain = client.post(
            "/platform/nodes/sensor-b/drain",
            json={"drained_by": "tier2", "reason": "testing", "services": ["packet_monitor"]},
            headers=headers,
        )
        failed = client.post(
            "/platform/nodes/sensor-b/actions/drain/complete",
            json={"acted_by": "sensor-b", "result": "failed", "note": "packet monitor drain failed"},
            headers=headers,
        )
        detail = client.get("/platform/nodes/sensor-b", headers=headers)

    assert heartbeat.status_code == 200
    assert drain.status_code == 200
    assert failed.status_code == 200
    payload = detail.json()["node"]
    assert payload["drain"]["status"] == "failed"
    assert payload["drain"]["active"] is False
    assert payload["drain"]["drain_result"] == "failed"
    assert payload["drain"]["drain_last_error"] == "packet monitor drain failed"
    assert payload["drain"]["drain_retry_count"] == 1
    assert payload["drain"]["drain_retriable"] is True
    assert payload["action_failures"] == ["drain"]
    assert payload["metadata"]["action_history"][-2]["transition"] == "requested"
    assert payload["metadata"]["action_history"][-1]["transition"] == "failed"

    with TestClient(service.app) as client:
        retried = client.post(
            "/platform/nodes/sensor-b/actions/drain/retry",
            json={"acted_by": "tier2"},
            headers=headers,
        )
        after_retry = client.get("/platform/nodes/sensor-b", headers=headers)
        actions = client.get("/platform/nodes/sensor-b/actions", headers=headers)

    assert retried.status_code == 200
    retried_payload = after_retry.json()["node"]
    assert retried_payload["drain"]["status"] == "requested"
    assert retried_payload["drain"]["active"] is True
    assert retried_payload["drain"]["drain_failed_at"] is None
    assert retried_payload["drain"]["drain_last_error"] is None
    assert retried_payload["action_failures"] == []
    assert [item["action"] for item in actions.json()["actions"]] == ["drain"]
    assert retried_payload["metadata"]["action_history"][-2]["transition"] == "retried"
    assert retried_payload["metadata"]["action_history"][-1]["transition"] == "requested"


def test_platform_node_pending_action_can_be_cancelled(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        heartbeat = client.post(
            "/platform/nodes/heartbeat",
            json={
                "node_name": "sensor-c",
                "node_role": "sensor",
                "deployment_mode": "multi-node",
                "service_health": {
                    "overall_status": "healthy",
                    "services": {"packet_monitor": {"status": "healthy", "enabled": True}},
                },
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            },
            headers=headers,
        )
        refresh = client.post(
            "/platform/nodes/sensor-c/refresh",
            json={"requested_by": "tier2", "reason": "refresh health"},
            headers=headers,
        )
        cancelled = client.post(
            "/platform/nodes/sensor-c/actions/refresh/cancel",
            json={"acted_by": "tier2"},
            headers=headers,
        )
        detail = client.get("/platform/nodes/sensor-c", headers=headers)
        actions = client.get("/platform/nodes/sensor-c/actions", headers=headers)

    assert heartbeat.status_code == 200
    assert refresh.status_code == 200
    assert cancelled.status_code == 200
    payload = detail.json()["node"]
    assert payload["refresh"]["status"] == "cancelled"
    assert payload["refresh"]["pending"] is False
    assert payload["refresh"]["refresh_cancelled_by"] == "tier2"
    assert payload["action_failures"] == []
    assert payload["action_pressure"]["retry_pressure"] == {}
    assert payload["action_pressure"]["stuck_actions"] == []
    assert actions.json()["actions"] == []
    assert payload["metadata"]["action_history"][-2]["transition"] == "requested"
    assert payload["metadata"]["action_history"][-1]["transition"] == "cancelled"


def test_list_platform_nodes_supports_action_history_filters(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        first = client.post(
            "/platform/nodes/heartbeat",
            json={
                "node_name": "sensor-a",
                "node_role": "sensor",
                "deployment_mode": "multi-node",
                "service_health": {"overall_status": "healthy", "services": {}},
                "metadata": {
                    "action_history": [
                        {"action": "refresh", "transition": "retried", "at": "2026-03-31T12:00:00+00:00"},
                        {"action": "refresh", "transition": "requested", "at": "2026-03-31T12:01:00+00:00"},
                    ]
                },
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            },
            headers=headers,
        )
        second = client.post(
            "/platform/nodes/heartbeat",
            json={
                "node_name": "sensor-b",
                "node_role": "sensor",
                "deployment_mode": "multi-node",
                "service_health": {"overall_status": "healthy", "services": {}},
                "metadata": {
                    "action_history": [
                        {"action": "drain", "transition": "cancelled", "at": "2026-03-31T12:02:00+00:00"},
                    ]
                },
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
            },
            headers=headers,
        )
        retried = client.get("/platform/nodes?transition=retried", headers=headers)
        cancelled = client.get("/platform/nodes?transition=cancelled", headers=headers)
        refresh_only = client.get("/platform/nodes?action=refresh", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert [item["node_name"] for item in retried.json()["nodes"]] == ["sensor-a"]
    assert [item["node_name"] for item in cancelled.json()["nodes"]] == ["sensor-b"]
    assert [item["node_name"] for item in refresh_only.json()["nodes"]] == ["sensor-a"]


def test_platform_node_detail_exposes_action_pressure(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "soc_remote_node_action_failure_repeat_threshold", 2)
    monkeypatch.setattr(settings, "soc_remote_node_action_retry_threshold", 2)
    monkeypatch.setattr(settings, "soc_remote_node_action_stuck_minutes", 5.0)
    headers = _operator_headers(monkeypatch)
    now = datetime.now(timezone.utc)

    with TestClient(service.app) as client:
        heartbeat = client.post(
            "/platform/nodes/heartbeat",
            json={
                "node_name": "sensor-pressure",
                "node_role": "sensor",
                "deployment_mode": "multi-node",
                "service_health": {"overall_status": "healthy", "services": {}},
                "metadata": {
                    "refresh_pending": True,
                    "refresh_requested_at": (now - timedelta(minutes=20)).isoformat(),
                    "action_history": [
                        {"action": "drain", "transition": "failed", "at": (now - timedelta(minutes=30)).isoformat()},
                        {"action": "drain", "transition": "failed", "at": (now - timedelta(minutes=10)).isoformat()},
                        {"action": "refresh", "transition": "retried", "at": (now - timedelta(minutes=25)).isoformat()},
                        {"action": "refresh", "transition": "retried", "at": (now - timedelta(minutes=5)).isoformat()},
                    ],
                },
                "last_seen_at": now.isoformat(),
            },
            headers=headers,
        )
        detail = client.get("/platform/nodes/sensor-pressure", headers=headers)
        listed = client.get("/platform/nodes", headers=headers)

    assert heartbeat.status_code == 200
    assert detail.status_code == 200
    payload = detail.json()["node"]
    assert payload["action_pressure"]["repeated_failures"] == {"drain": 2}
    assert payload["action_pressure"]["retry_pressure"] == {"refresh": 2}
    assert payload["action_pressure"]["stuck_actions"][0]["action"] == "refresh"
    listed_payload = next(
        item
        for item in listed.json()["nodes"]
        if item.get("node_name") == "sensor-pressure"
    )
    assert listed_payload["action_pressure"]["repeated_failure_active"] is True
    assert listed_payload["action_pressure"]["retry_pressure_active"] is True
    assert listed_payload["action_pressure"]["stuck_actions_active"] is True


def test_emit_platform_node_heartbeat_processes_returned_actions(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "platform_node_role", "sensor")
    monkeypatch.setattr(settings, "platform_deployment_mode", "multi-node")
    monkeypatch.setattr(settings, "platform_manager_url", "https://manager.local")
    monkeypatch.setattr(settings, "platform_manager_bearer_token", "token")
    monkeypatch.setattr(settings, "platform_manager_timeout_seconds", 3.0)
    monkeypatch.setattr(service, "_platform_node_heartbeat_enabled", lambda: True)
    monkeypatch.setattr(service, "_current_platform_profile", lambda: {"node_name": "sensor-a"})
    monkeypatch.setattr(service, "build_node_heartbeat_payload", lambda profile: {"node_name": "sensor-a"})
    class _Automation:
        def __init__(self) -> None:
            self.drained_services: list[str] = []

        def apply_drained_services(self, services: set[str]) -> None:
            self.drained_services = sorted(services)

    automation = _Automation()
    monkeypatch.setattr(service, "automation", automation)
    monkeypatch.setattr(
        service,
        "send_platform_node_heartbeat",
        lambda **kwargs: {
            "node": {"drain": {"active": True, "drain_services": ["packet_monitor"]}},
            "topology": {"remote_node_count": 1},
            "actions": [{"action": "refresh", "status": "requested"}],
        },
    )
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        service,
        "synchronize_platform_node_actions",
        lambda **kwargs: calls.append(dict(kwargs)) or {"actions": kwargs["actions"], "acknowledged": ["refresh"], "completed": ["refresh"]},
    )
    monkeypatch.setattr(
        service,
        "sync_local_platform_action_state",
        lambda **kwargs: {"drained_services": ["packet_monitor"]},
    )
    monkeypatch.setattr(
        service,
        "apply_local_platform_action",
        lambda *args, **kwargs: {"action": "refresh", "result": "success", "note": "local refresh cycle completed"},
    )

    result = service._emit_platform_node_heartbeat()

    assert result["result"] == "success"
    assert result["actions"]["completed"] == ["refresh"]
    assert result["local_action_state"]["drained_services"] == ["packet_monitor"]
    assert calls[0]["node_name"] == "sensor-a"
    assert calls[0]["acted_by"] == "sensor-a"
    assert calls[0]["actions"] == [{"action": "refresh", "status": "requested"}]
    assert automation.drained_services == ["packet_monitor"]


def test_security_health_reports_broken_auth_backend(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(settings, "endpoint_bearer_token", None)
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", "endpoint-ingest-token")
    monkeypatch.setattr(settings, "endpoint_allow_loopback_without_token", False)
    monkeypatch.setattr(service, "_validate_startup_security_dependencies", lambda: None)
    monkeypatch.setattr(service.vault, "retrieve_secret", lambda name: (_ for _ in ()).throw(RuntimeError("vault offline")))

    with TestClient(service.app) as client:
        response = client.get("/health/security", headers=headers)

    assert response.status_code == 200
    payload = response.json()
    assert payload["healthy"] is False
    assert "Endpoint bearer token backend is unavailable." in payload["warnings"]
    assert payload["auth_backends"]["healthy"] is False
    assert payload["auth_backends"]["endpoint"]["healthy"] is False
    assert payload["auth_backends"]["endpoint"]["status"] == "backend_unavailable"
    assert payload["auth_backends"]["endpoint"]["source"] == "pam_secret"
    assert payload["auth_backends"]["endpoint"]["error"] == (
        "Failed to resolve bearer token secret: endpoint-ingest-token"
    )


def test_soc_event_ingest_creates_alert_and_overview(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        created = client.post(
            "/soc/events",
            json={
                "event_type": "endpoint.malware_detected",
                "severity": "critical",
                "title": "Malware detected",
                "summary": "A scanned file matched malware rules.",
                "details": {"filename": "bad.exe", "verdict": "matched:test-rule"},
                "tags": ["endpoint", "malware"],
            },
            headers=headers,
        )
        listing = client.get("/soc/alerts", headers=headers)
        overview = client.get("/soc/overview", headers=headers)

    assert created.status_code == 200
    payload = created.json()
    assert payload["event"]["linked_alert_id"] is not None
    assert payload["alert"] is not None
    assert payload["alert"]["status"] == "open"
    assert listing.status_code == 200
    assert listing.json()["alerts"][0]["alert_id"] == payload["alert"]["alert_id"]
    assert overview.status_code == 200
    assert overview.json()["alerts_total"] == 1
    assert overview.json()["open_alerts"] == 1
    assert overview.json()["platform"]["service_health"]["services"]["automation"]["status"] == "healthy"


def test_soc_case_lifecycle(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        event_response = client.post(
            "/soc/events",
            json={
                "event_type": "policy.access_decision",
                "severity": "high",
                "title": "Access denied",
                "summary": "A high-risk access decision was denied.",
                "details": {"resource": "vpn-admin"},
            },
            headers=headers,
        )
        event_payload = event_response.json()
        created = client.post(
            "/soc/cases",
            json={
                "title": "Investigate denied access",
                "summary": "Analyst review required for denied privileged access.",
                "severity": "high",
                "source_event_ids": [event_payload["event"]["event_id"]],
                "linked_alert_ids": [event_payload["alert"]["alert_id"]],
                "assignee": "tier2-analyst",
            },
            headers=headers,
        )
        case_id = created.json()["case_id"]
        updated = client.patch(
            f"/soc/cases/{case_id}",
            json={
                "status": "investigating",
                "note": "Owner assigned and triage started.",
                "observable": "203.0.113.55",
            },
            headers=headers,
        )
        fetched = client.get(f"/soc/cases/{case_id}", headers=headers)
        fetched_alert = client.get(f"/soc/alerts/{event_payload['alert']['alert_id']}", headers=headers)

    assert created.status_code == 200
    assert updated.status_code == 200
    assert fetched.status_code == 200
    assert fetched_alert.status_code == 200
    assert updated.json()["status"] == "investigating"
    assert updated.json()["notes"] == ["Owner assigned and triage started."]
    assert "vpn-admin" in updated.json()["observables"]
    assert "203.0.113.55" in updated.json()["observables"]
    assert fetched.json()["assignee"] == "tier2-analyst"
    assert "vpn-admin" in fetched.json()["observables"]
    assert "203.0.113.55" in fetched.json()["observables"]
    assert fetched_alert.json()["linked_case_id"] == case_id


def test_soc_alert_can_be_promoted_to_case(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        event_response = client.post(
            "/soc/events",
            json={
                "event_type": "policy.access_decision",
                "severity": "high",
                "title": "Privileged access denied",
                "summary": "A privileged action was denied and needs triage.",
                "details": {"resource": "vpn-admin"},
            },
            headers=headers,
        )
        alert_id = event_response.json()["alert"]["alert_id"]
        promoted = client.post(
            f"/soc/alerts/{alert_id}/case",
            json={
                "assignee": "tier1-analyst",
                "note": "Promoted directly from the triage queue.",
                "acted_by": "tier1-analyst",
            },
            headers=headers,
        )
        refetch_alert = client.get(f"/soc/alerts/{alert_id}", headers=headers)
        dashboard = client.get("/soc/dashboard", headers=headers)

    assert promoted.status_code == 200
    payload = promoted.json()
    assert payload["alert"]["status"] == "acknowledged"
    assert payload["alert"]["linked_case_id"] == payload["case"]["case_id"]
    assert payload["alert"]["acknowledged_by"] == "tier1-analyst"
    assert payload["alert"]["escalated_by"] == "tier1-analyst"
    assert payload["case"]["status"] == "investigating"
    assert payload["case"]["linked_alert_ids"] == [alert_id]
    assert "vpn-admin" in payload["case"]["observables"]
    assert payload["case"]["notes"] == ["Promoted directly from the triage queue."]
    assert refetch_alert.status_code == 200
    assert refetch_alert.json()["linked_case_id"] == payload["case"]["case_id"]
    assert refetch_alert.json()["escalated_by"] == "tier1-analyst"
    assert dashboard.status_code == 200
    assert dashboard.json()["platform"]["service_health"]["services"]["packet_monitor"]["status"] == "degraded"
    assert dashboard.json()["triage"]["unassigned_alerts"] == []


def test_soc_alert_can_be_linked_to_existing_case(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        first_event = client.post(
            "/soc/events",
            json={
                "event_type": "policy.access_decision",
                "severity": "high",
                "title": "First privileged access denial",
                "summary": "Initial escalation target.",
                "details": {"resource": "vpn-admin"},
            },
            headers=headers,
        )
        first_alert_id = first_event.json()["alert"]["alert_id"]
        created_case = client.post(
            f"/soc/alerts/{first_alert_id}/case",
            json={"assignee": "tier1-analyst", "acted_by": "tier1-analyst"},
            headers=headers,
        )
        case_id = created_case.json()["case"]["case_id"]

        second_event = client.post(
            "/soc/events",
            json={
                "event_type": "policy.access_decision",
                "severity": "high",
                "title": "Second privileged access denial",
                "summary": "Follow-on escalation into the same case.",
                "details": {"resource": "db-admin", "hostname": "db-admin-01"},
            },
            headers=headers,
        )
        second_alert_id = second_event.json()["alert"]["alert_id"]
        promoted = client.post(
            f"/soc/alerts/{second_alert_id}/case",
            json={
                "existing_case_id": case_id,
                "note": "Linked into the existing investigation.",
                "acted_by": "tier2-analyst",
                "case_status": "investigating",
            },
            headers=headers,
        )
        fetched_case = client.get(f"/soc/cases/{case_id}", headers=headers)
        fetched_alert = client.get(f"/soc/alerts/{second_alert_id}", headers=headers)

    assert promoted.status_code == 200
    payload = promoted.json()
    assert payload["case"]["case_id"] == case_id
    assert first_alert_id in payload["case"]["linked_alert_ids"]
    assert second_alert_id in payload["case"]["linked_alert_ids"]
    assert "db-admin" in payload["case"]["observables"]
    assert "db-admin-01" in payload["case"]["observables"]
    assert payload["case"]["notes"][-1] == "Linked into the existing investigation."
    assert fetched_case.status_code == 200
    assert second_alert_id in fetched_case.json()["linked_alert_ids"]
    assert fetched_alert.status_code == 200
    assert fetched_alert.json()["linked_case_id"] == case_id
    assert fetched_alert.json()["escalated_by"] == "tier2-analyst"


def test_soc_alert_acknowledge_records_actor(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        event_response = client.post(
            "/soc/events",
            json={
                "event_type": "endpoint.malware_detected",
                "severity": "critical",
                "title": "Malware detected",
                "summary": "Manual acknowledgment check.",
                "details": {"filename": "bad.exe"},
            },
            headers=headers,
        )
        alert_id = event_response.json()["alert"]["alert_id"]
        updated = client.patch(
            f"/soc/alerts/{alert_id}",
            json={"status": "acknowledged", "acted_by": "tier2-analyst"},
            headers=headers,
        )

    assert updated.status_code == 200
    assert updated.json()["status"] == "acknowledged"
    assert updated.json()["acknowledged_by"] == "tier2-analyst"


def test_soc_alert_queries_support_filters_and_sort(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        for severity, title in [
            ("medium", "Medium tracker alert"),
            ("critical", "Critical malware alert"),
        ]:
            response = client.post(
                "/soc/events",
                json={
                    "event_type": "endpoint.malware_detected",
                    "severity": severity,
                    "title": title,
                    "summary": f"{title} summary.",
                    "details": {"filename": title.replace(" ", "_")},
                },
                headers=headers,
            )
            assert response.status_code == 200

        alerts = client.get("/soc/alerts", params={"sort": "severity_desc", "limit": 1}, headers=headers)
        critical_id = alerts.json()["alerts"][0]["alert_id"]
        promoted = client.post(
            f"/soc/alerts/{critical_id}/case",
            json={"assignee": "tier1-analyst"},
            headers=headers,
        )
        linked_only = client.get("/soc/alerts", params={"linked_case_state": "linked"}, headers=headers)
        unlinked_only = client.get("/soc/alerts", params={"linked_case_state": "unlinked"}, headers=headers)
        assigned_only = client.get("/soc/alerts", params={"assignee": "tier1-analyst"}, headers=headers)

    assert promoted.status_code == 200
    assert alerts.status_code == 200
    assert len(alerts.json()["alerts"]) == 1
    assert alerts.json()["alerts"][0]["severity"] == "critical"
    assert linked_only.status_code == 200
    assert [item["alert_id"] for item in linked_only.json()["alerts"]] == [critical_id]
    assert unlinked_only.status_code == 200
    assert all(item["linked_case_id"] is None for item in unlinked_only.json()["alerts"])
    assert assigned_only.status_code == 200
    assert [item["alert_id"] for item in assigned_only.json()["alerts"]] == [critical_id]


def test_soc_event_queries_support_filters_sort_and_get(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        created_one = client.post(
            "/soc/events",
            json={
                "event_type": "privacy.tracker_block",
                "source": "tracker_intel",
                "severity": "medium",
                "title": "Tracker blocked",
                "summary": "Blocked beacon.example from contacting the browser.",
                "details": {"hostname": "beacon.example"},
                "tags": ["tracker", "privacy"],
            },
            headers=headers,
        )
        created_two = client.post(
            "/soc/events",
            json={
                "event_type": "endpoint.malware_detected",
                "source": "endpoint",
                "severity": "critical",
                "title": "Malware detected",
                "summary": "bad.exe matched a malware rule.",
                "details": {"filename": "bad.exe"},
                "tags": ["endpoint", "malware"],
            },
            headers=headers,
        )
        listing = client.get(
            "/soc/events",
            params={"source": "tracker_intel", "tag": "privacy", "text": "beacon.example"},
            headers=headers,
        )
        sorted_listing = client.get(
            "/soc/events",
            params={"sort": "severity_desc"},
            headers=headers,
        )
        fetched = client.get(f"/soc/events/{created_two.json()['event']['event_id']}", headers=headers)

    assert created_one.status_code == 200
    assert created_two.status_code == 200
    assert listing.status_code == 200
    assert len(listing.json()["events"]) == 1
    assert listing.json()["events"][0]["source"] == "tracker_intel"
    assert sorted_listing.status_code == 200
    assert sorted_listing.json()["events"][0]["severity"] == "critical"
    assert fetched.status_code == 200
    assert fetched.json()["title"] == "Malware detected"


def test_soc_search_returns_events_alerts_and_cases(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        created = client.post(
            "/soc/events",
            json={
                "event_type": "endpoint.malware_detected",
                "severity": "critical",
                "title": "Malware detected on db-admin-01",
                "summary": "bad.exe matched and requires investigation.",
                "details": {"hostname": "db-admin-01", "filename": "bad.exe"},
                "tags": ["endpoint", "malware"],
            },
            headers=headers,
        )
        alert_id = created.json()["alert"]["alert_id"]
        created_case = client.post(
            f"/soc/alerts/{alert_id}/case",
            json={
                "title": "Investigate db-admin-01 malware",
                "summary": "Follow up on malware found on db-admin-01.",
                "acted_by": "tier2-analyst",
            },
            headers=headers,
        )
        search = client.get(
            "/soc/search",
            params={"q": "db-admin-01", "severity": "critical"},
            headers=headers,
        )

    assert created_case.status_code == 200
    assert search.status_code == 200
    payload = search.json()
    assert payload["events"][0]["title"] == "Malware detected on db-admin-01"
    assert payload["alerts"][0]["alert_id"] == alert_id
    assert payload["cases"][0]["title"] == "Investigate db-admin-01 malware"


def test_soc_hunt_returns_index_metadata_and_filtered_events(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        first = client.post(
            "/soc/events",
            json={
                "event_type": "network.connection",
                "source": "sensor-a",
                "severity": "high",
                "title": "Suspicious remote session",
                "summary": "Observed connection to 185.146.173.20 over tcp/443",
                "details": {"remote_ip": "185.146.173.20", "protocol": "tcp"},
                "tags": ["network", "session"],
            },
            headers=headers,
        )
        second = client.post(
            "/soc/events",
            json={
                "event_type": "endpoint.posture",
                "source": "host-a",
                "severity": "medium",
                "title": "Endpoint drift",
                "summary": "Agent policy drift detected",
                "details": {"hostname": "host-a"},
                "tags": ["endpoint"],
            },
            headers=headers,
        )
        hunted = client.get(
            "/soc/hunt",
            params={"q": "185.146.173.20", "source": "sensor-a", "limit": 10},
            headers=headers,
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert hunted.status_code == 200
    payload = hunted.json()
    assert payload["index"]["backend"] == "json-event-index"
    assert payload["index"]["indexed_event_count"] == 2
    assert payload["index"]["token_count"] >= 1
    assert len(payload["events"]) == 1
    assert payload["events"][0]["source"] == "sensor-a"
    assert payload["events"][0]["details"]["remote_ip"] == "185.146.173.20"


def test_soc_hunt_supports_observable_filters(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        created = client.post(
            "/soc/events",
            json={
                "event_type": "endpoint.malware_detected",
                "source": "host-a",
                "severity": "critical",
                "title": "Malware detected on db-admin-01",
                "summary": "bad.exe matched and requires investigation.",
                "details": {
                    "hostname": "db-admin-01",
                    "filename": "bad.exe",
                    "artifact_path": "C:/temp/bad.exe",
                },
                "artifacts": ["C:/temp/bad.exe"],
                "tags": ["endpoint", "malware"],
            },
            headers=headers,
        )
        hunted = client.get(
            "/soc/hunt",
            params={
                "hostname": "db-admin-01",
                "filename": "bad.exe",
                "artifact_path": "C:/temp/bad.exe",
                "limit": 10,
            },
            headers=headers,
        )

    assert created.status_code == 200
    assert hunted.status_code == 200
    payload = hunted.json()
    assert len(payload["events"]) == 1
    assert payload["events"][0]["event_type"] == "endpoint.malware_detected"


def test_soc_detection_catalog_endpoints(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        listed = client.get("/soc/detections", headers=headers)
        fetched = client.get("/soc/detections/repeated_tracker_activity", headers=headers)
        updated = client.patch(
            "/soc/detections/repeated_tracker_activity",
            json={"enabled": False, "parameters": {"minimum_hits": 4}},
            headers=headers,
        )

    assert listed.status_code == 200
    assert any(item["rule_id"] == "repeated_tracker_activity" for item in listed.json()["rules"])
    assert fetched.status_code == 200
    assert fetched.json()["rule_id"] == "repeated_tracker_activity"
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False
    assert updated.json()["parameters"]["minimum_hits"] == 4
    assert "hit_count" in fetched.json()
    assert "open_alert_count" in fetched.json()


def test_soc_case_queries_support_filters_and_sort(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        first = client.post(
            "/soc/cases",
            json={
                "title": "Medium case",
                "summary": "Initial review",
                "severity": "medium",
            },
            headers=headers,
        )
        second = client.post(
            "/soc/cases",
            json={
                "title": "Critical case",
                "summary": "Escalated review",
                "severity": "critical",
                "assignee": "tier2-analyst",
            },
            headers=headers,
        )
        sorted_cases = client.get("/soc/cases", params={"sort": "severity_desc", "limit": 1}, headers=headers)
        assigned_cases = client.get("/soc/cases", params={"assignee": "tier2-analyst"}, headers=headers)
        unassigned_cases = client.get("/soc/cases", params={"assignee": "unassigned"}, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert sorted_cases.status_code == 200
    assert sorted_cases.json()["cases"][0]["severity"] == "critical"
    assert assigned_cases.status_code == 200
    assert [item["title"] for item in assigned_cases.json()["cases"]] == ["Critical case"]
    assert unassigned_cases.status_code == 200
    assert [item["title"] for item in unassigned_cases.json()["cases"]] == ["Medium case"]


def test_access_deny_is_mirrored_into_soc_events(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    operator_headers = _operator_headers(monkeypatch)
    payload = {
        "user": {
            "user_id": "user-123",
            "email": "user@example.com",
            "groups": ["engineering"],
            "geo_lat": 37.7749,
            "geo_lon": -122.4194,
            "last_login": datetime.now(timezone.utc).isoformat(),
        },
        "device": {
            "device_id": "device-7",
            "os": "Windows",
            "os_version": "11",
            "compliance": "compromised",
            "is_encrypted": False,
            "edr_active": False,
        },
        "resource": "admin-portal",
        "privilege_level": "privileged",
        "source_ip": "203.0.113.45",
        "dns_secure": False,
        "threat_signals": {"credential_leak": 9.5},
    }

    with TestClient(service.app) as client:
        decision = client.post("/access/evaluate", json=payload)
        events = client.get("/soc/events", headers=operator_headers)

    assert decision.status_code == 200
    assert decision.json()["decision"] == "deny"
    assert events.status_code == 200
    assert events.json()["events"][0]["event_type"] == "policy.access_decision"
    assert events.json()["events"][0]["severity"] == "critical"


def test_soc_dashboard_reports_correlation_and_triage(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    (tmp_path / "soc_dashboard_view_state.json").write_text(
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

    with TestClient(service.app) as client:
        for _ in range(3):
            response = client.post(
                "/soc/events",
                json={
                    "event_type": "privacy.tracker_block",
                    "severity": "medium",
                    "title": "Tracker domain blocked",
                    "summary": "DNS resolution was denied because the hostname matched tracker intelligence.",
                    "details": {"hostname": "metrics.example.com", "target_type": "dns"},
                    "tags": ["privacy", "tracker"],
                },
                headers=headers,
            )
            assert response.status_code == 200

        dashboard = client.get("/soc/dashboard", headers=headers)

    assert dashboard.status_code == 200
    payload = dashboard.json()
    assert payload["summary"]["alerts_total"] >= 1
    assert payload["alert_status"]["open"] >= 1
    assert payload["triage"]["recent_correlations"]
    assert payload["triage"]["recent_correlations"][0]["correlation_rule"] == "repeated_tracker_activity"
    assert payload["triage"]["unassigned_alerts"]
    assert payload["view_state"]["operational_reason_filter"] == "stuck action"
    assert payload["view_state"]["hunt_cluster_mode"] == "device_id"
    assert payload["view_state"]["hunt_cluster_value"] == "device-11"
    assert payload["view_state"]["hunt_cluster_key"] == "cluster-11"
    assert payload["view_state"]["hunt_cluster_action"] == "details"


def test_soc_dashboard_view_state_update_api_persists_saved_filter(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        updated = client.post(
            "/soc/dashboard/view-state",
            json={
                "operational_reason_filter": "retry pressure",
                "hunt_cluster_mode": "process_guid",
                "hunt_cluster_value": "proc-guid-1",
                "hunt_cluster_key": "cluster-44",
                "hunt_cluster_action": "case",
            },
            headers=headers,
        )
        dashboard = client.get("/soc/dashboard", headers=headers)

    assert updated.status_code == 200
    assert updated.json()["view_state"]["operational_reason_filter"] == "retry pressure"
    assert updated.json()["view_state"]["hunt_cluster_mode"] == "process_guid"
    assert updated.json()["view_state"]["hunt_cluster_value"] == "proc-guid-1"
    assert updated.json()["view_state"]["hunt_cluster_key"] == "cluster-44"
    assert updated.json()["view_state"]["hunt_cluster_action"] == "case"
    assert dashboard.status_code == 200
    assert dashboard.json()["view_state"]["operational_reason_filter"] == "retry pressure"
    assert dashboard.json()["view_state"]["hunt_cluster_mode"] == "process_guid"
    assert dashboard.json()["view_state"]["hunt_cluster_value"] == "proc-guid-1"
    assert dashboard.json()["view_state"]["hunt_cluster_key"] == "cluster-44"
    assert dashboard.json()["view_state"]["hunt_cluster_action"] == "case"


def test_soc_correlates_endpoint_posture_and_access_decision(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    operator_headers = _operator_headers(monkeypatch)
    endpoint_headers = _endpoint_headers(monkeypatch)

    telemetry_payload = {
        "device_id": "device-corr-1",
        "os": "Windows",
        "os_version": "11",
        "compliance": "compromised",
        "is_encrypted": True,
        "edr_active": False,
    }
    access_payload = {
        "user": {
            "user_id": "user-123",
            "email": "user@example.com",
            "groups": ["engineering"],
            "geo_lat": 37.7749,
            "geo_lon": -122.4194,
            "last_login": datetime.now(timezone.utc).isoformat(),
        },
        "device": telemetry_payload,
        "resource": "admin-portal",
        "privilege_level": "privileged",
        "source_ip": "203.0.113.46",
        "dns_secure": False,
        "threat_signals": {"credential_leak": 9.5},
    }

    with TestClient(service.app) as client:
        telemetry = client.post("/endpoint/telemetry", json=telemetry_payload, headers=endpoint_headers)
        decision = client.post("/access/evaluate", json=access_payload)
        alerts = client.get("/soc/alerts", headers=operator_headers)
        dashboard = client.get("/soc/dashboard", headers=operator_headers)

    assert telemetry.status_code == 200
    assert decision.status_code == 200
    assert decision.json()["decision"] == "deny"
    correlation_alerts = [item for item in alerts.json()["alerts"] if item["category"] == "correlation"]
    assert correlation_alerts
    assert any(item["correlation_rule"] == "endpoint_high_risk_device" for item in correlation_alerts)
    assert dashboard.json()["triage"]["recent_correlations"]


def test_rejects_untrusted_host_headers(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(
        service.resolver,
        "resolve",
        lambda hostname, record_type: type("DummyResult", (), {"secure": True, "records": []})(),
    )

    with TestClient(service.app) as client:
        response = client.get(
            "/dns/resolve",
            params={"hostname": "example.com", "record_type": "A"},
            headers={"Host": "evil.example"},
        )

    assert response.status_code == 400


def test_http_responses_include_security_headers(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(
        service.resolver,
        "resolve",
        lambda hostname, record_type: type("DummyResult", (), {"secure": True, "records": []})(),
    )

    with TestClient(service.app) as client:
        response = client.get("/dns/resolve", params={"hostname": "example.com", "record_type": "A"})

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Permissions-Policy"] == "geolocation=(), camera=(), microphone=()"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_operator_auth_rate_limits_repeated_failures(monkeypatch, tmp_path):
    audit, _blocklist, _traceroute = _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_token", "expected-token")
    monkeypatch.setattr(settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)
    monkeypatch.setattr(settings, "operator_auth_max_failures_per_window", 1)
    monkeypatch.setattr(settings, "auth_failure_rate_limit_window_seconds", 60.0)

    with TestClient(service.app) as client:
        first = client.get("/automation/status")
        second = client.get("/automation/status")

    assert first.status_code == 401
    assert second.status_code == 429
    assert second.json()["detail"] == "Too many authentication failures; retry later."
    assert any(event_type == "operator.auth.rate_limit.exceeded" for event_type, _payload in audit.events)


def test_endpoint_auth_rate_limits_repeated_failures(monkeypatch, tmp_path):
    audit, _blocklist, _traceroute = _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "endpoint_bearer_token", "expected-endpoint-token")
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", None)
    monkeypatch.setattr(settings, "endpoint_allow_loopback_without_token", False)
    monkeypatch.setattr(settings, "endpoint_auth_max_failures_per_window", 1)
    monkeypatch.setattr(settings, "auth_failure_rate_limit_window_seconds", 60.0)

    payload = {
        "device_id": "device-123",
        "os": "Windows",
        "os_version": "11",
        "compliance": "compliant",
        "is_encrypted": True,
        "edr_active": True,
    }
    with TestClient(service.app) as client:
        first = client.post("/endpoint/telemetry", json=payload)
        second = client.post("/endpoint/telemetry", json=payload)

    assert first.status_code == 401
    assert second.status_code == 429
    assert second.json()["detail"] == "Too many authentication failures; retry later."
    assert any(event_type == "endpoint.auth.rate_limit.exceeded" for event_type, _payload in audit.events)


def test_rejects_oversized_non_multipart_request_bodies(monkeypatch, tmp_path):
    audit, _blocklist, _traceroute = _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "service_max_request_body_bytes", 32)

    with TestClient(service.app) as client:
        response = client.post("/tor/request", json={"url": "https://example.com/with-a-longer-path-than-the-limit"})

    assert response.status_code == 413
    assert response.text == "Request body too large."
    assert any(event_type == "http.request_too_large" for event_type, _payload in audit.events)


def test_access_evaluate_auto_block_message(monkeypatch, tmp_path):
    audit, blocklist, traceroute = _install_test_managers(monkeypatch, tmp_path)

    with TestClient(service.app) as client:
        response = client.post(
            "/access/evaluate",
            json={
                "user": {
                    "user_id": "user-123",
                    "email": "user@example.com",
                    "groups": ["engineering"],
                    "geo_lat": 37.7749,
                    "geo_lon": -122.4194,
                    "last_login": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
                },
                "device": {
                    "device_id": "device-1",
                    "os": "macOS",
                    "os_version": "15.0",
                    "compliance": DeviceCompliance.compromised.value,
                    "is_encrypted": False,
                    "edr_active": False,
                },
                "resource": "git",
                "privilege_level": "privileged",
                "dns_secure": False,
                "source_ip": "203.0.113.31",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "deny"
    assert any("auto-blocked" in reason for reason in payload["reasons"])
    assert payload["ip_block"]["status"] == "auto_blocked"
    assert payload["ip_block"]["ip"] == "203.0.113.31"
    assert blocklist.is_blocked("203.0.113.31") is True
    assert traceroute.calls
    assert any(event == "access.evaluate" for event, _ in audit.events)


def test_promote_missing_ip_returns_404(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        response = client.post(
            "/network/blocked-ips/203.0.113.40/promote",
            json={"reason": "confirmed attacker"},
            headers=headers,
        )

    assert response.status_code == 404


def test_unblock_missing_ip_returns_404(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        response = client.request(
            "DELETE",
            "/network/blocked-ips/203.0.113.41",
            json={"reason": "false positive"},
            headers=headers,
        )

    assert response.status_code == 404


def test_access_evaluate_denies_already_blocked_ip(monkeypatch, tmp_path):
    audit, blocklist, _ = _install_test_managers(monkeypatch, tmp_path)
    blocklist.block("203.0.113.42", reason="manual review", blocked_by="test")

    with TestClient(service.app) as client:
        response = client.post(
            "/access/evaluate",
            json={
                "user": {
                    "user_id": "user-123",
                    "email": "user@example.com",
                    "groups": ["engineering"],
                    "geo_lat": 37.7749,
                    "geo_lon": -122.4194,
                    "last_login": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
                },
                "device": {
                    "device_id": "device-1",
                    "os": "macOS",
                    "os_version": "15.0",
                    "compliance": DeviceCompliance.compliant.value,
                    "is_encrypted": True,
                    "edr_active": True,
                },
                "resource": "git",
                "privilege_level": "standard",
                "source_ip": "203.0.113.42",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "deny"
    assert any("blocked" in reason.lower() for reason in payload["reasons"])
    assert payload["ip_block"]["status"] == "existing"
    assert payload["ip_block"]["ip"] == "203.0.113.42"
    assert any(event == "access.evaluate" for event, _ in audit.events)


def test_access_evaluate_rate_limits_abusive_clients(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "access_evaluate_max_requests_per_window", 1)

    payload = {
        "user": {
            "user_id": "user-123",
            "email": "user@example.com",
            "groups": ["engineering"],
            "geo_lat": 37.7749,
            "geo_lon": -122.4194,
            "last_login": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        },
        "device": {
            "device_id": "device-1",
            "os": "macOS",
            "os_version": "15.0",
            "compliance": DeviceCompliance.compliant.value,
            "is_encrypted": True,
            "edr_active": True,
        },
        "resource": "git",
        "privilege_level": "standard",
        "source_ip": "203.0.113.10",
    }

    with TestClient(service.app) as client:
        first = client.post("/access/evaluate", json=payload)
        second = client.post("/access/evaluate", json=payload)

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"]


def test_access_evaluate_rejects_invalid_public_inputs(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)

    payload = {
        "user": {
            "user_id": "user-123",
            "email": "user@example.com",
            "groups": ["engineering"],
            "geo_lat": 37.7749,
            "geo_lon": -122.4194,
            "last_login": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        },
        "device": {
            "device_id": "device-1",
            "os": "macOS",
            "os_version": "15.0",
            "compliance": DeviceCompliance.compliant.value,
            "is_encrypted": True,
            "edr_active": True,
        },
        "resource": "git",
        "privilege_level": "standard",
        "source_ip": "not-an-ip",
    }

    with TestClient(service.app) as client:
        response = client.post("/access/evaluate", json=payload)

    assert response.status_code == 422


def test_reports_endpoints_list_and_fetch_saved_pdf(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        generated = client.get(
            "/reports/security-summary.pdf",
            params={"time_window_hours": 24, "min_risk_score": 50, "include_recent_events": False},
            headers=headers,
        )
        assert generated.status_code == 200
        assert generated.headers["content-type"] == "application/pdf"
        assert generated.content.startswith(b"%PDF")

        saved_path = service.report_builder.write_summary_pdf(max_events=5)
        listing = client.get("/reports", headers=headers)
        assert listing.status_code == 200
        payload = listing.json()
        assert payload["reports"]
        assert payload["reports"][0]["name"] == saved_path.name
        assert "path" not in payload["reports"][0]
        assert "report_output_dir" not in payload

        fetched = client.get(f"/reports/{saved_path.name}", headers=headers)
        assert fetched.status_code == 200
        assert fetched.headers["content-type"] == "application/pdf"
        assert fetched.content.startswith(b"%PDF")


def test_report_and_tracker_visibility_routes_require_operator_auth(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_token", "expected-token")
    monkeypatch.setattr(settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)

    with TestClient(service.app) as client:
        report = client.get("/reports/security-summary.pdf")
        listing = client.get("/reports")
        tracker_events = client.get("/privacy/tracker-events")
        proxy_health = client.get("/proxy/health")

    assert report.status_code == 401
    assert listing.status_code == 401
    assert tracker_events.status_code == 401
    assert proxy_health.status_code == 401


def test_report_and_tracker_routes_reject_pathological_query_values(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        report = client.get(
            "/reports/security-summary.pdf",
            params={"max_events": 10000, "time_window_hours": 100000.0, "min_risk_score": 200.0},
            headers=headers,
        )
        tracker_events = client.get("/privacy/tracker-events", params={"max_events": 10000}, headers=headers)

    assert report.status_code == 422
    assert tracker_events.status_code == 422


def test_dns_resolve_blocks_tracker_domains(monkeypatch, tmp_path):
    audit, _, _ = _install_test_managers(monkeypatch, tmp_path)

    with TestClient(service.app) as client:
        response = client.get("/dns/resolve", params={"hostname": "www.google-analytics.com", "record_type": "A"})

    assert response.status_code == 403
    assert "Tracker domain blocked" in response.json()["detail"]
    assert any(event == "privacy.tracker_block" for event, _ in audit.events)


def test_dns_resolve_rejects_invalid_inputs(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)

    with TestClient(service.app) as client:
        bad_host = client.get("/dns/resolve", params={"hostname": "bad host", "record_type": "A"})
        bad_type = client.get("/dns/resolve", params={"hostname": "example.com", "record_type": "AXFR"})

    assert bad_host.status_code == 400
    assert bad_type.status_code == 400


def test_dns_resolve_rate_limits_abusive_clients(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "dns_resolve_max_requests_per_window", 1)

    class DummyResult:
        secure = True
        records = []

    monkeypatch.setattr(service.resolver, "resolve", lambda hostname, record_type: DummyResult())

    with TestClient(service.app) as client:
        first = client.get("/dns/resolve", params={"hostname": "example.com", "record_type": "A"})
        second = client.get("/dns/resolve", params={"hostname": "example.com", "record_type": "A"})

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"]


def test_proxy_request_blocks_tracker_like_urls(monkeypatch, tmp_path):
    audit, _, _ = _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(settings, "audit_log_path", str(audit_path))

    with TestClient(service.app) as client:
        response = client.post(
            "/tor/request",
            json={"url": "https://metrics.example.com/collect?utm_source=email&gclid=abc123", "method": "GET", "via": "direct"},
            headers=headers,
        )

    assert response.status_code == 403
    assert "Tracker destination blocked" in response.json()["detail"]
    tracker_events = [data for event, data in audit.events if event == "privacy.tracker_block"]
    assert tracker_events
    assert tracker_events[0]["source"] == "heuristic"
    audit_path.write_text(
        json.dumps({"type": "privacy.tracker_block", "source": "heuristic", "hostname": "metrics.example.com"}) + "\n",
        encoding="utf-8",
    )

    with TestClient(service.app) as client:
        tracker_event_view = client.get("/privacy/tracker-events", headers=headers)

    assert tracker_event_view.status_code == 200
    assert tracker_event_view.json()["events"]


def test_proxy_request_rejects_private_destinations(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        response = client.post(
            "/tor/request",
            json={"url": "http://127.0.0.1/admin", "method": "GET", "via": "direct"},
            headers=headers,
        )

    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"].lower()


def test_proxy_request_rejects_disallowed_methods(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        response = client.post(
            "/tor/request",
            json={"url": "https://example.com/submit", "method": "POST", "via": "direct"},
            headers=headers,
        )

    assert response.status_code == 422
    assert "method must be one of" in response.text


def test_proxy_request_rate_limits_abusive_clients(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(settings, "proxy_request_max_requests_per_window", 1)
    monkeypatch.setattr(
        service.proxy,
        "_send_request",
        lambda method, url, **kwargs: ProxyResponse(
            status_code=200,
            headers={"content-type": "text/plain"},
            body="ok",
        ),
    )
    monkeypatch.setattr(
        "security_gateway.tor.socket.getaddrinfo",
        lambda host, port, type=0: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ],
    )

    with TestClient(service.app) as client:
        first = client.post(
            "/tor/request",
            json={"url": "https://example.com/health", "method": "GET", "via": "direct"},
            headers=headers,
        )
        second = client.post(
            "/tor/request",
            json={"url": "https://example.com/health", "method": "GET", "via": "direct"},
            headers=headers,
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"]


def test_proxy_request_allows_public_http_targets(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    monkeypatch.setattr(
        service.proxy,
        "_send_request",
        lambda method, url, **kwargs: ProxyResponse(
            status_code=200,
            headers={"content-type": "text/plain"},
            body="ok",
        ),
    )
    monkeypatch.setattr(
        "security_gateway.tor.socket.getaddrinfo",
        lambda host, port, type=0: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))
        ],
    )

    with TestClient(service.app) as client:
        response = client.post(
            "/tor/request",
            json={"url": "https://example.com/health", "method": "GET", "via": "direct"},
            headers=headers,
        )

    assert response.status_code == 200
    assert response.json()["status_code"] == 200
    assert response.json()["body"] == "ok"


def test_proxy_request_maps_response_too_large(monkeypatch, tmp_path):
    audit, _blocklist, _traceroute = _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(
        service.proxy,
        "request",
        lambda method, url, via="tor": (_ for _ in ()).throw(
            ProxyResponseTooLargeError("Proxy response exceeds the configured limit of 1048576 bytes.")
        ),
    )

    with TestClient(service.app) as client:
        response = client.post(
            "/tor/request",
            json={"url": "https://example.com/large", "method": "GET", "via": "direct"},
            headers=headers,
        )

    assert response.status_code == 413
    assert response.json()["detail"] == "Proxy response exceeded the configured size limit."
    assert any(event_type == "proxy.request.failure" for event_type, _payload in audit.events)


def test_proxy_request_maps_upstream_timeout(monkeypatch, tmp_path):
    audit, _blocklist, _traceroute = _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(
        service.proxy,
        "request",
        lambda method, url, via="tor": (_ for _ in ()).throw(
            ProxyRequestTimeoutError("Proxy request timed out after 10.0 seconds.")
        ),
    )

    with TestClient(service.app) as client:
        response = client.post(
            "/tor/request",
            json={"url": "https://example.com/slow", "method": "GET", "via": "direct"},
            headers=headers,
        )

    assert response.status_code == 504
    assert response.json()["detail"] == "Proxy request timed out."
    assert any(event_type == "proxy.request.failure" for event_type, _payload in audit.events)


def test_proxy_request_requires_operator_auth(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_token", "expected-token")
    monkeypatch.setattr(settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)

    with TestClient(service.app) as client:
        response = client.post(
            "/tor/request",
            json={"url": "https://example.com/health", "method": "GET", "via": "direct"},
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "Operator authentication required."


def test_tracker_feed_status_and_refresh_api(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    class DummyTrackerIntel:
        def feed_status(self):
            return {
                "cache_path": str(tmp_path / "tracker-feeds.json"),
                "domain_count": 0,
                "sources": [],
                "is_stale": True,
                "last_refresh_result": "failed",
                "failures": [{"url": "https://feed.local/example", "error": "timeout"}],
            }

        def refresh_feed_cache(self, urls=None):
            return {
                "cache_path": str(tmp_path / "tracker-feeds.json"),
                "domain_count": 25,
                "sources": [{"url": "https://feed.local/example", "domain_count": 25}],
                "last_refresh_result": "success",
                "failures": [],
            }

    monkeypatch.setattr(service, "tracker_intel", DummyTrackerIntel())

    with TestClient(service.app) as client:
        status = client.get("/privacy/tracker-feeds/status")
        assert status.status_code == 200
        assert status.json()["domain_count"] == 0
        assert status.json()["is_stale"] is True
        assert "cache_path" not in status.json()

        refreshed = client.post(
            "/privacy/tracker-feeds/refresh",
            json={"urls": ["https://feed.local/example"]},
            headers=headers,
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["domain_count"] == 25
        assert "cache_path" not in refreshed.json()


def test_tracker_feed_refresh_api_returns_502_on_failure(monkeypatch, tmp_path):
    audit, _blocklist, _traceroute = _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    class FailingTrackerIntel:
        def feed_status(self):
            return {"cache_path": str(tmp_path / "tracker-feeds.json"), "domain_count": 0, "sources": []}

        def refresh_feed_cache(self, urls=None):
            raise RuntimeError("upstream timeout")

    monkeypatch.setattr(service, "tracker_intel", FailingTrackerIntel())

    with TestClient(service.app) as client:
        refreshed = client.post(
            "/privacy/tracker-feeds/refresh",
            json={"urls": ["https://feed.local/example"]},
            headers=headers,
        )

    assert refreshed.status_code == 502
    assert refreshed.json()["detail"] == "Tracker feed refresh failed."
    assert any(event_type == "tracker.feed_refresh.failure" for event_type, _payload in audit.events)


def test_malware_feed_status_and_refresh_api(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    class DummyScanner:
        def feed_status(self):
            return {
                "cache_path": str(tmp_path / "malware-feeds.json"),
                "hash_count": 0,
                "sources": [],
                "is_stale": True,
                "last_refresh_result": "failed",
                "failures": [{"url": "https://feed.local/malware", "error": "timeout"}],
            }

        def refresh_feed_cache(self, urls=None):
            return {
                "cache_path": str(tmp_path / "malware-feeds.json"),
                "hash_count": 12,
                "sources": [{"url": "https://feed.local/malware", "hash_count": 12}],
                "last_refresh_result": "success",
                "failures": [],
            }

    monkeypatch.setattr(service, "scanner", DummyScanner())

    with TestClient(service.app) as client:
        status = client.get("/endpoint/malware-feeds/status")
        assert status.status_code == 200
        assert status.json()["hash_count"] == 0
        assert status.json()["is_stale"] is True
        assert "cache_path" not in status.json()

        refreshed = client.post(
            "/endpoint/malware-feeds/refresh",
            json={"urls": ["https://feed.local/malware"]},
            headers=headers,
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["hash_count"] == 12
        assert "cache_path" not in refreshed.json()


def test_malware_feed_refresh_api_returns_400_on_bad_config(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    class BadScanner:
        def feed_status(self):
            return {"cache_path": str(tmp_path / "malware-feeds.json"), "hash_count": 0, "sources": []}

        def refresh_feed_cache(self, urls=None):
            raise ValueError("No malware feed URLs configured.")

    monkeypatch.setattr(service, "scanner", BadScanner())

    with TestClient(service.app) as client:
        refreshed = client.post(
            "/endpoint/malware-feeds/refresh",
            json={"urls": ["https://feed.local/malware"]},
            headers=headers,
        )

    assert refreshed.status_code == 400
    assert "No malware feed URLs configured" in refreshed.json()["detail"]


def test_feed_management_routes_require_operator_auth(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_token", "expected-token")
    monkeypatch.setattr(settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)

    with TestClient(service.app) as client:
        refreshed = client.post("/privacy/tracker-feeds/refresh", json={"urls": ["https://feed.local/example"]})
        imported = client.post("/endpoint/malware-feeds/import", json={"source_path": "offline-hashes.txt"})

    assert refreshed.status_code == 401
    assert refreshed.json()["detail"] == "Operator authentication required."
    assert imported.status_code == 401
    assert imported.json()["detail"] == "Operator authentication required."


def test_operator_routes_require_auth_for_pam_and_network(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_token", "expected-token")
    monkeypatch.setattr(settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)

    with TestClient(service.app) as client:
        pam_metrics = client.get("/pam/metrics")
        block_list = client.get("/network/blocked-ips")
        automation_status = client.get("/automation/status")

    assert pam_metrics.status_code == 401
    assert block_list.status_code == 401
    assert automation_status.status_code == 401


def test_endpoint_ingest_routes_require_auth(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "endpoint_bearer_token", "expected-endpoint-token")
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", None)
    monkeypatch.setattr(settings, "endpoint_allow_loopback_without_token", False)

    with TestClient(service.app) as client:
        telemetry_write = client.post(
            "/endpoint/telemetry",
            json={
                "device_id": "device-42",
                "os": "Windows",
                "os_version": "11",
                "compliance": DeviceCompliance.compliant.value,
                "is_encrypted": True,
                "edr_active": True,
            },
        )
        scan = client.post(
            "/endpoint/scan",
            files={"file": ("sample.bin", b"hello", "application/octet-stream")},
        )

    assert telemetry_write.status_code == 401
    assert telemetry_write.json()["detail"] == "Endpoint authentication required."
    assert scan.status_code == 401
    assert scan.json()["detail"] == "Endpoint authentication required."


def test_pam_and_automation_routes_allow_operator_auth(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        stored = client.put("/pam/secret", json={"name": "db", "secret": "super-secret"}, headers=headers)
        assert stored.status_code == 200

        checked_out = client.post("/pam/checkout", json={"name": "db", "ttl_minutes": 5}, headers=headers)
        assert checked_out.status_code == 200
        assert checked_out.json()["secret"] == "super-secret"

        metrics = client.get("/pam/metrics", headers=headers)
        assert metrics.status_code == 200
        assert "rotation_count" in metrics.json()

        automation_status = client.get("/automation/status", headers=headers)
        assert automation_status.status_code == 200
        assert "running" in automation_status.json()

        proxy_health = client.get("/proxy/health", headers=headers)
        assert proxy_health.status_code == 200
        assert "tor" in proxy_health.json()


def test_pam_routes_reject_invalid_names_and_ttls(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        invalid_name = client.put("/pam/secret", json={"name": "../bad", "secret": "super-secret"}, headers=headers)
        empty_secret = client.put("/pam/secret", json={"name": "db", "secret": ""}, headers=headers)
        invalid_ttl = client.post("/pam/checkout", json={"name": "db", "ttl_minutes": 0}, headers=headers)

    assert invalid_name.status_code == 422
    assert empty_secret.status_code == 422
    assert invalid_ttl.status_code == 422


def test_operator_routes_accept_pam_secret_backed_token(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_secret_headers(monkeypatch, token="vault-backed-token")

    with TestClient(service.app) as client:
        metrics = client.get("/pam/metrics", headers=headers)
        stale_config_attempt = client.get(
            "/pam/metrics",
            headers={"Authorization": "Bearer stale-fallback-token"},
        )

    assert metrics.status_code == 200
    assert "rotation_count" in metrics.json()
    assert stale_config_attempt.status_code == 401


def test_operator_route_does_not_fall_back_to_static_token_when_pam_lookup_fails(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "operator_bearer_token", "stale-static-token")
    monkeypatch.setattr(settings, "operator_bearer_secret_name", "operator-bearer-token")
    monkeypatch.setattr(settings, "operator_allow_loopback_without_token", False)
    monkeypatch.setattr(service, "_validate_startup_security_dependencies", lambda: None)
    monkeypatch.setattr(service.vault, "retrieve_secret", lambda name: (_ for _ in ()).throw(RuntimeError("vault offline")))

    with TestClient(service.app) as client:
        response = client.get("/automation/status", headers={"Authorization": "Bearer stale-static-token"})

    assert response.status_code == 503
    assert response.json()["detail"] == "Operator bearer token backend is unavailable."


def test_network_monitor_auto_blocks_dos_candidate(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "auto_block_enabled", True)
    monkeypatch.setattr(settings, "auto_block_duration_minutes", 45)
    service.automation._ip_blocklist = service.ip_blocklist

    finding = {
        "key": "dos-candidate:198.51.100.80",
        "severity": "critical",
        "title": "Potential denial-of-service source observed: 198.51.100.80",
        "summary": "A public remote IP exceeded the abnormal inbound connection threshold.",
        "details": {
            "remote_ip": "198.51.100.80",
            "local_ports": [80, 443, 3389],
            "remote_ports": [50000, 50001, 50002],
            "hit_count": 14,
            "syn_received_count": 9,
            "finding_type": "dos_candidate",
        },
        "tags": ["network", "dos"],
    }

    service.automation._emit_network_monitor_finding(finding)

    assert service.ip_blocklist.is_blocked("198.51.100.80") is True
    assert finding["details"]["block_status"] == "blocked"
    events = service.soc_manager.list_events(limit=5)
    assert events[0].details["schema"] == "network_finding_v1"
    assert events[0].details["document_type"] == "network_finding"
    assert events[0].details["remote_ip"] == "198.51.100.80"
    assert events[0].details["details"]["block_status"] == "blocked"


def test_network_monitor_does_not_auto_block_generic_suspicious_ip(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "auto_block_enabled", True)
    service.automation._ip_blocklist = service.ip_blocklist

    finding = {
        "key": "suspicious-remote-ip:198.51.100.81",
        "severity": "high",
        "title": "Suspicious remote IP observed: 198.51.100.81",
        "summary": "A public remote IP repeatedly appeared against local listening ports.",
        "details": {
            "remote_ip": "198.51.100.81",
            "local_ports": [8443],
            "remote_ports": [51000, 51001, 51002],
            "hit_count": 3,
            "finding_type": "suspicious_remote_ip",
        },
        "tags": ["network"],
    }

    service.automation._emit_network_monitor_finding(finding)

    assert service.ip_blocklist.is_blocked("198.51.100.81") is False


def test_endpoint_ingest_secret_auth_and_operator_guarded_reads(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    endpoint_headers = _endpoint_secret_headers(monkeypatch, token="vault-endpoint-token")
    operator_headers = _operator_headers(monkeypatch, token="operator-token")

    with TestClient(service.app) as client:
        stored = client.post(
            "/endpoint/telemetry",
            json={
                "device_id": "device-7",
                "os": "Linux",
                "os_version": "6.8",
                "compliance": DeviceCompliance.compliant.value,
                "is_encrypted": True,
                "edr_active": True,
            },
            headers=endpoint_headers,
        )
        assert stored.status_code == 200
        assert stored.json()["signature"]

        scan = client.post(
            "/endpoint/scan",
            files={"file": ("sample.bin", b"hello", "application/octet-stream")},
            headers=endpoint_headers,
        )
        assert scan.status_code in {200, 503}
        if scan.status_code == 200:
            assert scan.json()["malicious"] is False
        else:
            assert "python-multipart" in scan.json()["detail"]

        unauthenticated_fetch = client.get("/endpoint/telemetry/device-7")
        operator_fetch = client.get("/endpoint/telemetry/device-7", headers=operator_headers)

    assert unauthenticated_fetch.status_code == 401
    assert unauthenticated_fetch.json()["detail"] == "Operator authentication required."
    assert operator_fetch.status_code == 200
    assert operator_fetch.json()["device_id"] == "device-7"


def test_endpoint_posture_event_uses_normalized_details(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    endpoint_headers = _endpoint_headers(monkeypatch)
    operator_headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        telemetry = client.post(
            "/endpoint/telemetry",
            json={
                "device_id": "device-9",
                "os": "Windows",
                "os_version": "11",
                "compliance": "compromised",
                "is_encrypted": True,
                "edr_active": False,
            },
            headers=endpoint_headers,
        )
        events = client.get("/soc/events", headers=operator_headers)
        hunted = client.get("/soc/hunt", params={"device_id": "device-9"}, headers=operator_headers)

    assert telemetry.status_code == 200
    event = events.json()["events"][0]
    assert event["event_type"] == "endpoint.telemetry_posture"
    assert event["details"]["schema"] == "endpoint_posture_v1"
    assert event["details"]["device_id"] == "device-9"
    assert event["details"]["document_type"] == "endpoint_posture"
    assert hunted.json()["events"][0]["details"]["device_id"] == "device-9"


def test_endpoint_malware_event_uses_normalized_details(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    endpoint_headers = _endpoint_headers(monkeypatch)
    operator_headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        scan = client.post(
            "/endpoint/scan",
            files={"file": ("bad.exe", b"bitcoin", "application/octet-stream")},
            headers=endpoint_headers,
        )
        if scan.status_code == 503:
            pytest.skip("python-multipart unavailable in this environment")
        events = client.get("/soc/events", headers=operator_headers)
        hunted = client.get("/soc/hunt", params={"filename": "bad.exe"}, headers=operator_headers)

    assert scan.status_code == 200
    event = events.json()["events"][0]
    assert event["event_type"] == "endpoint.malware_detected"
    assert event["details"]["schema"] == "endpoint_malware_v1"
    assert event["details"]["filename"] == "bad.exe"
    assert event["details"]["document_type"] == "endpoint_malware"
    assert hunted.json()["events"][0]["details"]["filename"] == "bad.exe"


def test_endpoint_process_and_file_telemetry_docs_are_searchable(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    endpoint_headers = _endpoint_headers(monkeypatch)
    operator_headers = _operator_headers(monkeypatch)

    with TestClient(service.app) as client:
        process_response = client.post(
            "/endpoint/telemetry/process",
            json={
                "device_id": "device-11",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-11",
                "process_path": "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                "process_sha256": "abc123",
                "parent_process_name": "winword.exe",
                "parent_process_guid": "parent-guid-11",
                "parent_chain": ["winword.exe", "explorer.exe"],
                "command_line": "powershell.exe -enc deadbeef",
                "signer_name": "Microsoft Corporation",
                "signer_status": "signed",
                "reputation": "trusted",
                "risk_flags": ["encoded_command"],
                "remote_ips": ["198.51.100.84"],
                "network_connections": [
                    {
                        "remote_ip": "198.51.100.84",
                        "remote_port": 443,
                        "protocol": "TCP",
                        "state": "ESTABLISHED",
                        "state_history": ["SYN_SENT", "ESTABLISHED"],
                        "connection_count": 2,
                        "observed_at": "2026-04-01T12:00:00+00:00",
                        "first_seen_at": "2026-04-01T11:58:00+00:00",
                        "last_seen_at": "2026-04-01T12:00:00+00:00",
                    }
                ],
            },
            headers=endpoint_headers,
        )
        file_response = client.post(
            "/endpoint/telemetry/file",
            json={
                "device_id": "device-11",
                "filename": "payload.dll",
                "artifact_path": "C:/Users/Public/payload.dll",
                "sha256": "feedface",
                "operation": "created",
                "verdict": "quarantined",
                "actor_process_name": "powershell.exe",
                "actor_process_sha256": "abc123",
                "signer_name": "Unknown",
                "signer_status": "unsigned",
                "reputation": "suspicious",
                "file_extension": ".dll",
                "risk_flags": ["startup_path"],
            },
            headers=endpoint_headers,
        )
        process_docs = client.get(
            "/endpoint/telemetry/processes",
            params={
                "device_id": "device-11",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-11",
                "signer_name": "Microsoft Corporation",
                "sha256": "abc123",
            },
            headers=operator_headers,
        )
        file_docs = client.get(
            "/endpoint/telemetry/files",
            params={
                "device_id": "device-11",
                "filename": "payload.dll",
                "signer_name": "Unknown",
                "sha256": "feedface",
            },
            headers=operator_headers,
        )
        connection_docs = client.get(
            "/endpoint/telemetry/connections",
            params={
                "device_id": "device-11",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-11",
                "remote_ip": "198.51.100.84",
                "signer_name": "Microsoft Corporation",
                "sha256": "abc123",
            },
            headers=operator_headers,
        )
        hunted = client.get(
            "/soc/hunt",
            params={
                "device_id": "device-11",
                "process_name": "powershell.exe",
                "process_guid": "proc-guid-11",
                "signer_name": "Microsoft Corporation",
                "sha256": "abc123",
            },
            headers=operator_headers,
        )
        timeline = client.get(
            "/endpoint/telemetry/timeline",
            params={
                "device_id": "device-11",
                "process_guid": "proc-guid-11",
                "remote_ip": "198.51.100.84",
            },
            headers=operator_headers,
        )
        full_timeline = client.get(
            "/endpoint/telemetry/timeline",
            params={
                "device_id": "device-11",
                "process_name": "powershell.exe",
            },
            headers=operator_headers,
        )

    assert process_response.status_code == 200
    assert file_response.status_code == 200
    assert process_docs.json()["processes"][0]["details"]["schema"] == "endpoint_process_v1"
    assert process_docs.json()["processes"][0]["details"]["process_name"] == "powershell.exe"
    assert process_docs.json()["processes"][0]["details"]["process_guid"] == "proc-guid-11"
    assert process_docs.json()["processes"][0]["details"]["signer_name"] == "Microsoft Corporation"
    assert process_docs.json()["processes"][0]["details"]["network_connections"][0]["remote_ip"] == "198.51.100.84"
    assert file_docs.json()["files"][0]["details"]["schema"] == "endpoint_file_v1"
    assert file_docs.json()["files"][0]["details"]["artifact_path"] == "C:/Users/Public/payload.dll"
    assert file_docs.json()["files"][0]["details"]["signer_status"] == "unsigned"
    assert file_docs.json()["files"][0]["details"]["file_extension"] == ".dll"
    assert connection_docs.json()["connections"][0]["details"]["schema"] == "endpoint_connection_v1"
    assert connection_docs.json()["connections"][0]["details"]["remote_ip"] == "198.51.100.84"
    assert connection_docs.json()["connections"][0]["details"]["process_guid"] == "proc-guid-11"
    assert connection_docs.json()["connections"][0]["details"]["state"] == "ESTABLISHED"
    assert connection_docs.json()["connections"][0]["details"]["state_history"] == ["SYN_SENT", "ESTABLISHED"]
    assert connection_docs.json()["connections"][0]["details"]["connection_count"] == 2
    assert connection_docs.json()["connections"][0]["details"]["first_seen_at"] == "2026-04-01T11:58:00+00:00"
    assert connection_docs.json()["connections"][0]["details"]["last_seen_at"] == "2026-04-01T12:00:00+00:00"
    assert any(
        item["details"].get("process_name") == "powershell.exe"
        for item in hunted.json()["events"]
    )
    assert timeline.status_code == 200
    assert [item["event_type"] for item in timeline.json()["timeline"]] == [
        "endpoint.telemetry.process",
        "endpoint.telemetry.connection",
    ]
    assert [item["event_type"] for item in full_timeline.json()["timeline"]] == [
        "endpoint.telemetry.process",
        "endpoint.telemetry.connection",
        "endpoint.telemetry.file",
    ]
    assert timeline.json()["timeline"][1]["recorded_at"] == "2026-04-01T12:00:00+00:00"
    assert timeline.json()["timeline"][1]["details"]["state_history"] == ["SYN_SENT", "ESTABLISHED"]


def test_network_snapshot_creates_normalized_connection_docs(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    service._record_network_monitor_snapshot(
        {
            "checked_at": "2026-04-01T12:00:00+00:00",
            "suspicious_observations": [
                {
                    "remote_ip": "198.51.100.81",
                    "states": ["ESTABLISHED"],
                    "state_counts": {"ESTABLISHED": 3},
                    "local_ports": [8443],
                    "remote_ports": [51000, 51001],
                    "hit_count": 3,
                    "sensitive_ports": [],
                    "sample_connections": [
                        {
                            "state": "ESTABLISHED",
                            "local_ip": "10.0.0.5",
                            "local_port": 8443,
                            "remote_ip": "198.51.100.81",
                            "remote_port": 51000,
                        }
                    ],
                }
            ],
        }
    )

    with TestClient(service.app) as client:
        events = client.get("/soc/events", params={"event_type": "network.telemetry.connection"}, headers=headers)
        hunted = client.get("/soc/hunt", params={"remote_ip": "198.51.100.81"}, headers=headers)

    event = events.json()["events"][0]
    assert event["details"]["schema"] == "network_connection_v1"
    assert event["details"]["document_type"] == "network_connection"
    assert event["details"]["remote_ip"] == "198.51.100.81"
    assert event["details"]["snapshot_at"] == "2026-04-01T12:00:00+00:00"
    assert hunted.json()["events"][0]["details"]["remote_ip"] == "198.51.100.81"


def test_packet_snapshot_creates_normalized_session_docs(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)

    service._record_packet_monitor_snapshot(
        {
            "checked_at": "2026-04-01T12:00:00+00:00",
            "capture_status": "fallback_socket_table",
            "evidence_mode": "socket_table",
            "session_observations": [
                {
                    "session_key": "packet-session:198.51.100.91",
                    "remote_ip": "198.51.100.91",
                    "protocols": ["TCP"],
                    "local_ips": ["10.0.0.5"],
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "packet_count": 15,
                    "sensitive_ports": [3389],
                    "sample_packet_endpoints": [
                        {
                            "protocol": "TCP",
                            "remote_ip": "198.51.100.91",
                            "remote_port": 51000,
                            "local_ip": "10.0.0.5",
                            "local_port": 3389,
                        }
                    ],
                }
            ],
        }
    )

    with TestClient(service.app) as client:
        events = client.get("/soc/events", params={"event_type": "packet.telemetry.session"}, headers=headers)
        hunted = client.get("/soc/hunt", params={"session_key": "packet-session:198.51.100.91"}, headers=headers)

    event = events.json()["events"][0]
    assert event["details"]["schema"] == "packet_session_v1"
    assert event["details"]["document_type"] == "packet_session"
    assert event["details"]["session_key"] == "packet-session:198.51.100.91"
    assert event["details"]["evidence_mode"] == "socket_table"
    assert hunted.json()["events"][0]["details"]["session_key"] == "packet-session:198.51.100.91"


def test_dedicated_network_and_packet_telemetry_routes(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(settings, "soc_network_telemetry_retention_hours", 24.0)
    monkeypatch.setattr(settings, "soc_packet_telemetry_retention_hours", 48.0)

    service._record_network_monitor_snapshot(
        {
            "checked_at": "2026-04-01T12:00:00+00:00",
            "suspicious_observations": [
                {
                    "remote_ip": "198.51.100.81",
                    "states": ["ESTABLISHED"],
                    "state_counts": {"ESTABLISHED": 3},
                    "local_ports": [8443],
                    "remote_ports": [51000],
                    "hit_count": 3,
                    "sensitive_ports": [],
                    "sample_connections": [],
                }
            ],
        }
    )
    service._record_packet_monitor_snapshot(
        {
            "checked_at": "2026-04-01T12:00:00+00:00",
            "capture_status": "fallback_socket_table",
            "evidence_mode": "socket_table",
            "session_observations": [
                {
                    "session_key": "packet-session:198.51.100.91",
                    "remote_ip": "198.51.100.91",
                    "protocols": ["TCP"],
                    "local_ips": ["10.0.0.5"],
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "packet_count": 15,
                    "sensitive_ports": [3389],
                    "sample_packet_endpoints": [],
                }
            ],
        }
    )

    with TestClient(service.app) as client:
        network_docs = client.get("/network/telemetry/connections", params={"remote_ip": "198.51.100.81"}, headers=headers)
        packet_docs = client.get("/packet/telemetry/sessions", params={"session_key": "packet-session:198.51.100.91"}, headers=headers)

    assert network_docs.status_code == 200
    assert packet_docs.status_code == 200
    assert network_docs.json()["retention_hours"] == 24.0
    assert packet_docs.json()["retention_hours"] == 48.0
    assert network_docs.json()["connections"][0]["details"]["remote_ip"] == "198.51.100.81"
    assert packet_docs.json()["sessions"][0]["details"]["session_key"] == "packet-session:198.51.100.91"


def test_endpoint_scan_rejects_oversized_upload(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _endpoint_headers(monkeypatch)
    monkeypatch.setattr(settings, "endpoint_scan_max_upload_bytes", 4)

    with TestClient(service.app) as client:
        response = client.post(
            "/endpoint/scan",
            files={"file": ("sample.bin", b"hello-world", "application/octet-stream")},
            headers=headers,
        )

    assert response.status_code in {413, 503}
    if response.status_code == 413:
        assert "configured limit" in response.json()["detail"]
    else:
        assert "python-multipart" in response.json()["detail"]


def test_security_health_and_rule_feed_routes(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
    headers = _operator_headers(monkeypatch)
    monkeypatch.setattr(settings, "endpoint_bearer_token", "endpoint-feed-token")
    monkeypatch.setattr(settings, "endpoint_bearer_secret_name", None)
    monkeypatch.setattr(settings, "endpoint_allow_loopback_without_token", False)

    class DummyTrackerIntel:
        def feed_status(self):
            return {"cache_path": str(tmp_path / "tracker-feeds.json"), "domain_count": 2, "sources": []}

        def health_status(self):
            return {"healthy": True, "warnings": [], "feed_status": self.feed_status()}

        def import_feed_cache(self, source_path):
            return {
                "cache_path": str(tmp_path / "tracker-feeds.json"),
                "domain_count": 2,
                "sources": [{"url": source_path, "domain_count": 2, "imported": True}],
                "last_refresh_result": "imported",
                "failures": [],
            }

    class DummyScanner:
        def feed_status(self):
            return {"cache_path": str(tmp_path / "malware-feeds.json"), "hash_count": 1, "sources": []}

        def rule_feed_status(self):
            return {"cache_path": str(tmp_path / "malware-rule-feeds.json"), "rule_count": 1, "sources": []}

        def health_status(self):
            return {
                "healthy": True,
                "warnings": [],
                "hash_feed_status": self.feed_status(),
                "rule_feed_status": self.rule_feed_status(),
            }

        def refresh_rule_feed_cache(self, urls=None):
            return {
                "cache_path": str(tmp_path / "malware-rule-feeds.json"),
                "rule_count": 3,
                "sources": [{"url": "https://feed.local/rules", "rule_count": 3}],
                "last_refresh_result": "success",
                "failures": [],
            }

        def import_rule_feed_cache(self, source_path):
            return {
                "cache_path": str(tmp_path / "malware-rule-feeds.json"),
                "rule_count": 2,
                "sources": [{"url": source_path, "rule_count": 2, "imported": True}],
                "last_refresh_result": "imported",
                "failures": [],
            }

    monkeypatch.setattr(service, "tracker_intel", DummyTrackerIntel())
    monkeypatch.setattr(service, "scanner", DummyScanner())

    with TestClient(service.app) as client:
        health = client.get("/health/security")
        assert health.status_code == 200
        assert health.json()["healthy"] is True
        assert "cache_path" not in health.text

        rule_status = client.get("/endpoint/malware-rule-feeds/status")
        assert rule_status.status_code == 200
        assert rule_status.json()["rule_count"] == 1
        assert "cache_path" not in rule_status.json()

        rule_refresh = client.post(
            "/endpoint/malware-rule-feeds/refresh",
            json={"urls": ["https://feed.local/rules"]},
            headers=headers,
        )
        assert rule_refresh.status_code == 200
        assert rule_refresh.json()["rule_count"] == 3
        assert "cache_path" not in rule_refresh.json()

        tracker_import = client.post(
            "/privacy/tracker-feeds/import",
            json={"source_path": "offline-tracker-list.txt"},
            headers=headers,
        )
        assert tracker_import.status_code == 200
        assert tracker_import.json()["last_refresh_result"] == "imported"
        assert "cache_path" not in tracker_import.json()

        rule_import = client.post(
            "/endpoint/malware-rule-feeds/import",
            json={"source_path": "offline-rules.txt"},
            headers=headers,
        )
        assert rule_import.status_code == 200
        assert "cache_path" not in rule_import.json()
        assert rule_import.json()["last_refresh_result"] == "imported"
