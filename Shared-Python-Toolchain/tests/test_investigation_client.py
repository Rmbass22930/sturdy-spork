from __future__ import annotations

import json
from typing import Any, cast

import httpx
import pytest

from security_gateway.investigation_client import RemoteSocInvestigationClient
from security_gateway.models import (
    SocAlertPromoteCaseRequest,
    SocAlertStatus,
    SocAlertUpdate,
    SocCaseEndpointLineageClusterCaseRequest,
    SocCaseEndpointTimelineClusterCaseRequest,
    SocEndpointQueryCaseRequest,
    SocNetworkEvidenceCaseRequest,
    SocPacketCaptureCaseRequest,
    SocPacketSessionCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocCaseStatus,
    SocCaseTelemetryClusterCaseRequest,
    SocCaseUpdate,
)


def test_remote_soc_investigation_client_connects_and_reads_dashboard() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            return httpx.Response(
                200,
                json={
                    "summary": {},
                    "view_state": {"operational_reason_filter": "stuck action"},
                    "summary_labels": {"operational_alerts": "Operational Alerts [stuck action]"},
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    dashboard = client.dashboard()
    state = client.dashboard_state()

    assert cast(dict[str, object], dashboard["view_state"])["operational_reason_filter"] == "stuck action"
    assert cast(dict[str, object], state["summary_labels"])["operational_alerts"] == "Operational Alerts [stuck action]"


def test_remote_soc_investigation_client_reads_toolchain_update_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            return httpx.Response(
                200,
                json={
                    "summary": {},
                    "toolchain_updates_status": {"count": 4, "new_count": 2, "applied_count": 1},
                    "view_state": {},
                    "summary_labels": {},
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    status = client.toolchain_updates_status()

    assert status["count"] == 4
    assert status["new_count"] == 2


def test_remote_soc_investigation_client_from_settings_uses_configured_manager(monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/alerts":
            return httpx.Response(
                200,
                json={
                    "alerts": [
                        {
                            "alert_id": "alert-11",
                            "title": "Endpoint timeline execution chain",
                            "summary": "Suspicious endpoint activity.",
                            "severity": "high",
                            "status": "open",
                            "source_event_ids": ["evt-11"],
                            "linked_case_id": "case-11",
                            "assignee": "tier2",
                            "correlation_rule": "endpoint_timeline_execution_chain",
                            "correlation_key": "device-11:proc-guid-11",
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:00:00+00:00",
                        }
                    ]
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    monkeypatch.setattr("security_gateway.investigation_client.settings.platform_manager_url", "https://manager.local")
    monkeypatch.setattr("security_gateway.investigation_client.settings.platform_manager_bearer_token", "operator-token")
    monkeypatch.setattr("security_gateway.investigation_client.settings.platform_manager_timeout_seconds", 7.5)

    client = RemoteSocInvestigationClient.from_settings(transport=httpx.MockTransport(handler))

    alerts = client.list_alerts()

    assert alerts[0]["alert_id"] == "alert-11"


def test_remote_soc_investigation_client_from_settings_requires_manager_url(monkeypatch) -> None:
    monkeypatch.setattr("security_gateway.investigation_client.settings.platform_manager_url", None)

    with pytest.raises(ValueError, match="No platform manager URL is configured."):
        RemoteSocInvestigationClient.from_settings()


def test_remote_soc_investigation_client_from_settings_requires_token_for_nonlocal_manager(monkeypatch) -> None:
    monkeypatch.setattr("security_gateway.investigation_client.settings.platform_manager_url", "https://manager.local")
    monkeypatch.setattr("security_gateway.investigation_client.settings.platform_manager_bearer_token", None)

    with pytest.raises(ValueError, match="Platform manager bearer token is required for non-local remote manager access."):
        RemoteSocInvestigationClient.from_settings()


def test_remote_soc_investigation_client_exposes_updates_and_group_promotions() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH" and request.url.path == "/soc/alerts/alert-11":
            return httpx.Response(
                200,
                json={
                    "alert_id": "alert-11",
                    "title": "Endpoint timeline execution chain",
                    "summary": "Suspicious endpoint activity.",
                    "severity": "high",
                    "status": "acknowledged",
                    "source_event_ids": ["evt-11"],
                    "linked_case_id": "case-11",
                    "assignee": "tier2",
                    "correlation_rule": "endpoint_timeline_execution_chain",
                    "correlation_key": "device-11:proc-guid-11",
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:05:00+00:00",
                },
            )
        if request.method == "PATCH" and request.url.path == "/soc/cases/case-11":
            return httpx.Response(
                200,
                json={
                    "case_id": "case-11",
                    "title": "Existing investigation",
                    "summary": "Investigate endpoint activity.",
                    "severity": "high",
                    "status": "investigating",
                    "linked_alert_ids": ["alert-11"],
                    "source_event_ids": ["evt-11"],
                    "observables": ["device:device-11"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:05:00+00:00",
                },
            )
        if request.method == "POST" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-alert-groups/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["group_key"] == "device-11:proc-guid-1"
            assert body["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-detection-alert-group-1",
                    "title": "Investigate endpoint timeline device-11:proc-guid-1",
                    "summary": "Endpoint timeline investigation",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "observables": [],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    updated_alert = client.update_alert("alert-11", SocAlertUpdate(status=SocAlertStatus.acknowledged, assignee="tier2"))
    updated_case = client.update_case("case-11", SocCaseUpdate(status=SocCaseStatus.investigating, assignee="tier2"))
    promoted = client.create_case_from_detection_rule_alert_group(
        "endpoint_timeline_execution_chain",
        SocCaseRuleGroupCaseRequest(group_key="device-11:proc-guid-1", assignee="tier2"),
    )

    assert updated_alert["status"] == "acknowledged"
    assert updated_case["status"] == "investigating"
    assert promoted["case_id"] == "case-detection-alert-group-1"


def test_remote_soc_investigation_client_exposes_event_index_endpoint_query_and_capture_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/events":
            assert request.url.params["close_reason"] == "idle-timeout"
            assert request.url.params["reject_code"] == "access-reject"
            return httpx.Response(
                200,
                json={
                    "events": [
                        {
                            "event_id": "evt-ops-11",
                            "event_type": "network.telemetry.vpn",
                            "source": "sensor-auth",
                            "severity": "high",
                            "title": "VPN session closed",
                            "summary": "VPN session closed because of idle timeout.",
                            "details": {"close_reason": "idle-timeout"},
                            "tags": ["network", "telemetry", "vpn"],
                            "artifacts": [],
                            "created_at": "2026-04-01T04:00:00+00:00",
                            "linked_alert_id": None,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/hunt":
            assert request.url.params["close_reason"] == "idle-timeout"
            assert request.url.params["reject_code"] == "access-reject"
            return httpx.Response(
                200,
                json={"events": [{"event_id": "evt-hunt-11"}], "match_count": 1, "facets": {}, "summaries": {}, "timeline": {"bucket_unit": "hour", "buckets": []}},
            )
        if request.method == "GET" and request.url.path == "/soc/events/index":
            return httpx.Response(200, json={"event_count": 9, "document_count": 9, "status": "ready"})
        if request.method == "POST" and request.url.path == "/soc/events/index/rebuild":
            return httpx.Response(200, json={"event_count": 9, "document_count": 9, "status": "rebuilt"})
        if request.method == "GET" and request.url.path == "/soc/alerts":
            assert request.url.params["limit"] == "10"
            return httpx.Response(
                200,
                json={
                    "alerts": [
                        {
                            "alert_id": "alert-identity-11",
                            "title": "Auth failure burst",
                            "summary": "Repeated auth failures",
                            "severity": "high",
                            "status": "open",
                            "source_event_ids": ["evt-ops-11"],
                            "linked_case_id": "case-11",
                            "assignee": None,
                            "correlation_rule": "network_auth_failure_burst",
                            "correlation_key": "tier1@example.test",
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:05:00+00:00",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/query":
            assert request.url.params["document_type"] == "endpoint.telemetry.file"
            assert request.url.params["parent_process_name"] == "cmd.exe"
            assert request.url.params["limit"] == "25"
            return httpx.Response(200, json={"match_count": 1, "events": [{"event_id": "evt-11"}]})
        if request.method == "POST" and request.url.path == "/endpoint/telemetry/query/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["artifact_path"] == "C:/Temp/payload.dll"
            assert body["operation"] == "write"
            assert body["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-endpoint-query-11",
                    "title": "endpoint query",
                    "summary": "endpoint query",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "observables": ["artifact_path:C:/Temp/payload.dll"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/network/telemetry/flows":
            assert request.url.params["process_name"] == "svchost.exe"
            return httpx.Response(200, json={"flows": [{"event_id": "flow-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/dns":
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(200, json={"dns_records": [{"event_id": "dns-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/http":
            assert request.url.params["hostname"] == "example.test"
            return httpx.Response(200, json={"http_records": [{"event_id": "http-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/tls":
            assert request.url.params["limit"] == "5"
            return httpx.Response(200, json={"tls_records": [{"event_id": "tls-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/certificates":
            assert request.url.params["hostname"] == "example.test"
            return httpx.Response(200, json={"certificate_records": [{"event_id": "cert-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/proxy":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"proxy_records": [{"event_id": "proxy-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/auth":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"auth_records": [{"event_id": "auth-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/vpn":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"vpn_records": [{"event_id": "vpn-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/dhcp":
            assert request.url.params["assigned_ip"] == "10.0.0.25"
            return httpx.Response(200, json={"dhcp_records": [{"event_id": "dhcp-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/directory-auth":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"directory_auth_records": [{"event_id": "dirauth-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/radius":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"radius_records": [{"event_id": "radius-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/nac":
            assert request.url.params["device_id"] == "device-11"
            return httpx.Response(200, json={"nac_records": [{"event_id": "nac-11"}]})
        if request.method == "GET" and request.url.path == "/packet/telemetry/captures":
            assert request.url.params["limit"] == "12"
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(200, json={"captures": [{"capture_id": "cap-11"}]})
        if request.method == "GET" and request.url.path == "/packet/telemetry/captures/cap-11":
            return httpx.Response(200, json={"capture": {"capture_id": "cap-11"}})
        if request.method == "GET" and request.url.path == "/packet/telemetry/captures/cap-11/text":
            return httpx.Response(200, json={"capture_id": "cap-11", "text": "packet text"})
        if request.method == "POST" and request.url.path == "/packet/telemetry/captures/cap-11/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["session_key"] == "packet-session:8.8.8.8"
            assert body["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-capture-11",
                    "title": "packet capture",
                    "summary": "packet capture",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "observables": ["packet_capture:cap-11"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        if request.method == "POST" and request.url.path == "/network/packet-sessions/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["session_key"] == "packet-session:8.8.8.8"
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"case_id": "case-session-11", "title": "packet session", "summary": "packet session", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        if request.method == "POST" and request.url.path == "/network/evidence/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["remote_ip"] == "8.8.8.8"
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"case_id": "case-evidence-11", "title": "network evidence", "summary": "network evidence", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        if request.method == "POST" and request.url.path == "/soc/alerts/alert-identity-11/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["assignee"] == "tier2"
            assert body["acted_by"] == "analyst"
            return httpx.Response(
                200,
                json={
                    "alert": {
                        "alert_id": "alert-identity-11",
                        "title": "Auth failure burst",
                        "summary": "Repeated auth failures",
                        "severity": "high",
                        "status": "acknowledged",
                        "source_event_ids": ["evt-ops-11"],
                        "linked_case_id": "case-identity-11",
                        "assignee": "tier2",
                        "correlation_rule": "network_auth_failure_burst",
                        "correlation_key": "tier1@example.test",
                        "created_at": "2026-03-31T00:00:00+00:00",
                        "updated_at": "2026-03-31T00:05:00+00:00",
                    },
                    "case": {
                        "case_id": "case-identity-11",
                        "title": "identity case",
                        "summary": "identity case",
                        "severity": "high",
                        "status": "investigating",
                        "linked_alert_ids": ["alert-identity-11"],
                        "source_event_ids": ["evt-ops-11"],
                        "observables": [],
                        "assignee": "tier2",
                        "notes": [],
                        "created_at": "2026-03-31T00:00:00+00:00",
                        "updated_at": "2026-03-31T00:00:00+00:00",
                    },
                },
            )
        if request.method == "GET" and request.url.path == "/network/packet-sessions":
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(200, json={"sessions": [{"session_key": "packet-session:8.8.8.8"}]})
        if request.method == "GET" and request.url.path == "/network/evidence":
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(200, json={"evidence": [{"remote_ip": "8.8.8.8", "title": "Network evidence for 8.8.8.8"}]})
        if request.method == "GET" and request.url.path == "/soc/cases":
            return httpx.Response(
                200,
                json={
                    "cases": [
                        {
                            "case_id": "case-11",
                            "title": "Identity case",
                            "summary": "Identity case",
                            "severity": "high",
                            "status": "investigating",
                            "linked_alert_ids": ["alert-identity-11"],
                            "source_event_ids": ["evt-ops-11"],
                            "observables": [],
                            "assignee": "tier2",
                            "notes": [],
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:00:00+00:00",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/events/evt-ops-11":
            return httpx.Response(200, json={"event_id": "evt-ops-11", "event_type": "network.telemetry.auth", "source": "sensor", "severity": "high", "title": "Auth failures", "summary": "Repeated auth failures", "details": {}, "artifacts": ["username:tier1"], "tags": ["identity"], "created_at": "2026-03-31T00:00:00+00:00", "linked_alert_id": "alert-identity-11"})
        if request.method == "POST" and request.url.path == "/soc/cases":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["source_event_ids"] == ["evt-ops-11"]
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"case_id": "case-event-11", "title": "Auth failures", "summary": "Repeated auth failures", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": ["evt-ops-11"], "observables": ["username:tier1"], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    events = client.query_events(close_reason="idle-timeout", reject_code="access-reject")
    hunt_payload = client.hunt(close_reason="idle-timeout", reject_code="access-reject")
    status = client.get_event_index_status()
    rebuilt = client.rebuild_event_index()
    endpoint_query = client.query_endpoint_telemetry(
        limit=25,
        document_type="endpoint.telemetry.file",
        parent_process_name="cmd.exe",
    )
    endpoint_case = client.create_case_from_endpoint_query(
        SocEndpointQueryCaseRequest(
            artifact_path="C:/Temp/payload.dll",
            operation="write",
            assignee="tier2",
        )
    )
    flows = client.list_network_telemetry_flows(process_name="svchost.exe")
    dns_records = client.list_network_telemetry_dns(remote_ip="8.8.8.8")
    http_records = client.list_network_telemetry_http(hostname="example.test")
    tls_records = client.list_network_telemetry_tls(limit=5)
    certificate_records = client.list_network_telemetry_certificates(hostname="example.test")
    proxy_records = client.list_network_telemetry_proxy(username="tier1")
    auth_records = client.list_network_telemetry_auth(username="tier1")
    vpn_records = client.list_network_telemetry_vpn(username="tier1")
    dhcp_records = client.list_network_telemetry_dhcp(assigned_ip="10.0.0.25")
    directory_auth_records = client.list_network_telemetry_directory_auth(username="tier1")
    radius_records = client.list_network_telemetry_radius(username="tier1")
    nac_records = client.list_network_telemetry_nac(device_id="device-11")
    packet_sessions = client.list_packet_sessions(remote_ip="8.8.8.8")
    network_evidence = client.list_network_evidence(remote_ip="8.8.8.8")
    identity_correlations = client.list_identity_correlations(limit=10, severity="high")
    event_payload = client.get_event("evt-ops-11")
    event_cases = client.list_cases_for_event("evt-ops-11")
    opened_event_case = client.open_event_case("evt-ops-11")
    captures = client.list_packet_capture_artifacts(limit=12, remote_ip="8.8.8.8")
    capture = client.get_packet_capture_artifact("cap-11")
    capture_text = client.get_packet_capture_text("cap-11")
    capture_case = client.create_case_from_packet_capture(
        "cap-11",
        SocPacketCaptureCaseRequest(session_key="packet-session:8.8.8.8", assignee="tier2"),
    )
    session_case = client.create_case_from_packet_session(
        {"session_key": "packet-session:8.8.8.8", "remote_ip": "8.8.8.8"},
        SocPacketSessionCaseRequest(session_key="packet-session:8.8.8.8", assignee="tier2"),
    )
    evidence_case = client.create_case_from_network_evidence(
        {"remote_ip": "8.8.8.8"},
        SocNetworkEvidenceCaseRequest(remote_ip="8.8.8.8", assignee="tier2"),
    )
    event_case = client.create_case_from_event("evt-ops-11", assignee="tier2")
    promoted = client.promote_alert_to_case(
        "alert-identity-11",
        SocAlertPromoteCaseRequest(assignee="tier2", acted_by="analyst"),
    )

    assert events[0]["event_id"] == "evt-ops-11"
    assert hunt_payload["match_count"] == 1
    assert status["status"] == "ready"
    assert rebuilt["status"] == "rebuilt"
    assert endpoint_query["match_count"] == 1
    assert endpoint_case["case_id"] == "case-endpoint-query-11"
    assert flows[0]["event_id"] == "flow-11"
    assert dns_records[0]["event_id"] == "dns-11"
    assert http_records[0]["event_id"] == "http-11"
    assert tls_records[0]["event_id"] == "tls-11"
    assert certificate_records[0]["event_id"] == "cert-11"
    assert proxy_records[0]["event_id"] == "proxy-11"
    assert auth_records[0]["event_id"] == "auth-11"
    assert vpn_records[0]["event_id"] == "vpn-11"
    assert dhcp_records[0]["event_id"] == "dhcp-11"
    assert directory_auth_records[0]["event_id"] == "dirauth-11"
    assert radius_records[0]["event_id"] == "radius-11"
    assert nac_records[0]["event_id"] == "nac-11"
    assert packet_sessions[0]["session_key"] == "packet-session:8.8.8.8"
    assert network_evidence[0]["remote_ip"] == "8.8.8.8"
    assert identity_correlations[0]["alert_id"] == "alert-identity-11"
    assert event_payload["event_id"] == "evt-ops-11"
    assert event_cases[0]["case_id"] == "case-11"
    assert opened_event_case["case_id"] == "case-11"
    assert cast(list[dict[str, Any]], captures["captures"])[0]["capture_id"] == "cap-11"
    assert cast(dict[str, Any], capture["capture"])["capture_id"] == "cap-11"
    assert capture_text["text"] == "packet text"
    assert capture_case["case_id"] == "case-capture-11"
    assert session_case["case_id"] == "case-session-11"
    assert evidence_case["case_id"] == "case-evidence-11"
    assert event_case["case_id"] == "case-event-11"
    assert cast(dict[str, Any], promoted["case"])["case_id"] == "case-identity-11"


def test_remote_soc_investigation_client_promotes_hunt_and_timeline_clusters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/hunt/telemetry/clusters/remote-ip-11":
            assert request.url.params["cluster_by"] == "remote_ip"
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_by": "remote_ip",
                        "cluster_key": "remote-ip-11",
                        "label": "8.8.8.8",
                        "event_count": 3,
                        "severity": "high",
                        "remote_ips": ["8.8.8.8"],
                        "device_ids": ["device-11"],
                        "process_guids": ["proc-guid-11"],
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/soc/hunt/telemetry/clusters/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["cluster_key"] == "remote-ip-11"
            assert body["cluster_by"] == "remote_ip"
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"case_id": "case-hunt-11", "title": "hunt", "summary": "hunt", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/timeline/clusters/timeline-11":
            assert request.url.params["cluster_by"] == "process"
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_by": "process",
                        "cluster_key": "timeline-11",
                        "label": "device-11:proc-guid-11",
                        "event_count": 4,
                        "device_ids": ["device-11"],
                        "process_names": ["powershell.exe"],
                        "process_guids": ["proc-guid-11"],
                        "remote_ips": ["8.8.8.8"],
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/endpoint/telemetry/timeline/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["device_id"] == "device-11"
            assert body["process_guid"] == "proc-guid-11"
            assert body["assignee"] == "tier2"
            assert body["limit"] == 4
            return httpx.Response(200, json={"case_id": "case-timeline-11", "title": "timeline", "summary": "timeline", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    hunt_case = client.promote_hunt_telemetry_cluster("remote-ip-11", cluster_by="remote_ip", assignee="tier2")
    timeline_case = client.promote_endpoint_timeline_cluster("timeline-11", cluster_by="process", assignee="tier2")

    assert hunt_case["case_id"] == "case-hunt-11"
    assert timeline_case["case_id"] == "case-timeline-11"


def test_remote_soc_investigation_client_promotes_lineage_cluster() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/lineage/clusters/lineage-11":
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_key": "lineage-11",
                        "label": "device-11:proc-guid-11",
                        "event_count": 5,
                        "severity": "high",
                        "device_ids": ["device-11"],
                        "process_names": ["powershell.exe"],
                        "process_guids": ["proc-guid-11"],
                        "remote_ips": ["8.8.8.8"],
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/endpoint/telemetry/lineage/clusters/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["cluster_key"] == "lineage-11"
            assert body["device_id"] == "device-11"
            assert body["process_guid"] == "proc-guid-11"
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"case_id": "case-lineage-11", "title": "lineage", "summary": "lineage", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    lineage_case = client.promote_endpoint_lineage_cluster("lineage-11", assignee="tier2")

    assert lineage_case["case_id"] == "case-lineage-11"


def test_remote_soc_investigation_client_exposes_case_cluster_workflows() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/endpoint-timeline/clusters":
            return httpx.Response(200, json={"clusters": [{"cluster_key": "timeline-11"}]})
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/endpoint-timeline/clusters/timeline-11":
            return httpx.Response(200, json={"cluster": {"cluster_key": "timeline-11"}})
        if request.method == "POST" and request.url.path == "/soc/cases/case-11/endpoint-timeline/clusters/case":
            return httpx.Response(200, json={"case_id": "case-timeline-22", "title": "timeline", "summary": "timeline", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/endpoint-lineage/clusters":
            return httpx.Response(200, json={"clusters": [{"cluster_key": "lineage-11"}]})
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/endpoint-lineage/clusters/lineage-11":
            return httpx.Response(200, json={"cluster": {"cluster_key": "lineage-11"}})
        if request.method == "POST" and request.url.path == "/soc/cases/case-11/endpoint-lineage/clusters/case":
            return httpx.Response(200, json={"case_id": "case-lineage-22", "title": "lineage", "summary": "lineage", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/hunt-telemetry/clusters":
            return httpx.Response(200, json={"clusters": [{"cluster_key": "hunt-11"}]})
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/hunt-telemetry/clusters/hunt-11":
            return httpx.Response(200, json={"cluster": {"cluster_key": "hunt-11"}})
        if request.method == "POST" and request.url.path == "/soc/cases/case-11/hunt-telemetry/clusters/case":
            return httpx.Response(200, json={"case_id": "case-hunt-22", "title": "hunt", "summary": "hunt", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    timeline_clusters = client.list_case_endpoint_timeline_clusters("case-11", cluster_by="process", limit=10)
    timeline_cluster = client.get_case_endpoint_timeline_cluster("case-11", cluster_by="process", cluster_key="timeline-11")
    timeline_case = client.create_case_from_case_endpoint_timeline_cluster(
        "case-11",
        SocCaseEndpointTimelineClusterCaseRequest(cluster_by="process", cluster_key="timeline-11", assignee="tier2"),
    )
    lineage_clusters = client.list_case_endpoint_lineage_clusters("case-11", limit=10)
    lineage_cluster = client.get_case_endpoint_lineage_cluster("case-11", cluster_key="lineage-11")
    lineage_case = client.create_case_from_case_endpoint_lineage_cluster(
        "case-11",
        SocCaseEndpointLineageClusterCaseRequest(cluster_key="lineage-11", assignee="tier2"),
    )
    hunt_clusters = client.list_case_hunt_telemetry_clusters("case-11", cluster_by="remote_ip", limit=10)
    hunt_cluster = client.get_case_hunt_telemetry_cluster("case-11", cluster_by="remote_ip", cluster_key="hunt-11")
    hunt_case = client.create_case_from_case_hunt_telemetry_cluster(
        "case-11",
        SocCaseTelemetryClusterCaseRequest(cluster_by="remote_ip", cluster_key="hunt-11", assignee="tier2"),
    )

    assert cast(list[dict[str, object]], timeline_clusters["clusters"])[0]["cluster_key"] == "timeline-11"
    assert timeline_cluster["cluster_key"] == "timeline-11"
    assert timeline_case["case_id"] == "case-timeline-22"
    assert cast(list[dict[str, object]], lineage_clusters["clusters"])[0]["cluster_key"] == "lineage-11"
    assert lineage_cluster["cluster_key"] == "lineage-11"
    assert lineage_case["case_id"] == "case-lineage-22"
    assert cast(list[dict[str, object]], hunt_clusters["clusters"])[0]["cluster_key"] == "hunt-11"
    assert hunt_cluster["cluster_key"] == "hunt-11"
    assert hunt_case["case_id"] == "case-hunt-22"


def test_remote_soc_investigation_client_exposes_case_group_and_lineage_event_reads() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/rule-alert-groups/alert-group-11":
            return httpx.Response(
                200,
                json={"group": {"group_key": "alert-group-11", "alerts": [{"alert_id": "alert-11"}]}},
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/rule-evidence-groups/evidence-group-11":
            return httpx.Response(
                200,
                json={"group": {"group_key": "evidence-group-11", "events": [{"event_id": "evt-11"}]}},
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-11/endpoint-lineage/clusters/lineage-11":
            return httpx.Response(
                200,
                json={"cluster": {"cluster_key": "lineage-11", "events": [{"event_id": "evt-lineage-11"}]}},
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    alerts = client.list_case_rule_alerts("case-11", "alert-group-11")
    events = client.list_case_rule_evidence_events("case-11", "evidence-group-11")
    lineage_events = client.list_case_endpoint_lineage_events("case-11", cluster_key="lineage-11")

    assert alerts[0]["alert_id"] == "alert-11"
    assert events[0]["event_id"] == "evt-11"
    assert lineage_events[0]["event_id"] == "evt-lineage-11"


def test_remote_soc_investigation_client_exposes_toolchain_runtime_project_and_job_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            return httpx.Response(
                200,
                json={
                    "summary": {"open_alerts": 0, "open_cases": 0},
                    "toolchain_runtime_status": {
                        "languages": {"count": 2},
                        "package_managers": {"count": 3},
                        "provisioning": {"pending_count": 1},
                    },
                    "view_state": {},
                    "summary_labels": {},
                },
            )
        if request.method == "GET" and request.url.path == "/toolchain/projects":
            assert request.url.params["root_path"] == "J:/workspace"
            return httpx.Response(
                200,
                json={
                    "projects": [
                        {
                            "project_id": "J:/workspace/python_app",
                            "title": "python_app",
                            "root_path": "J:/workspace/python_app",
                            "ecosystems": ["python"],
                            "manifest_files": ["pyproject.toml"],
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/toolchain/projects/J:/workspace/python_app":
            assert request.url.params["root_path"] == "J:/workspace"
            return httpx.Response(
                200,
                json={
                    "project": {
                        "project_id": "J:/workspace/python_app",
                        "title": "python_app",
                        "root_path": "J:/workspace/python_app",
                        "ecosystems": ["python"],
                        "manifest_files": ["pyproject.toml"],
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/toolchain/bootstrap/python":
            assert request.url.params["project_path"] == "J:/workspace"
            assert request.url.params["execute"] == "false"
            return httpx.Response(
                200,
                json={"target": {"target_id": "python", "status": "planned"}},
            )
        if request.method == "POST" and request.url.path == "/toolchain/provider-templates/docker/scaffold":
            assert request.url.params["target_dir"] == "J:/workspace/scaffold"
            return httpx.Response(
                200,
                json={"provider_id": "docker", "files": {"manifest.json": "{\"provider_id\": \"docker\"}"}, "write": False},
            )
        if request.method == "GET" and request.url.path == "/toolchain/jobs":
            return httpx.Response(
                200,
                json={"jobs": [{"job_id": "snapshot_report", "status": "idle"}]},
            )
        if request.method == "GET" and request.url.path == "/toolchain/jobs/snapshot_report":
            return httpx.Response(
                200,
                json={"job": {"job_id": "snapshot_report", "status": "idle"}},
            )
        if request.method == "POST" and request.url.path == "/toolchain/jobs/snapshot_report/run":
            return httpx.Response(
                200,
                json={"job": {"job_id": "snapshot_report", "status": "completed"}},
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    runtime_status = client.toolchain_runtime_status()
    projects = client.list_toolchain_projects(root_path="J:/workspace")
    project = client.get_toolchain_project("J:/workspace/python_app", root_path="J:/workspace")
    bootstrap = client.run_toolchain_bootstrap("python", project_path="J:/workspace")
    scaffold = client.scaffold_toolchain_provider_template("docker", target_dir="J:/workspace/scaffold")
    jobs = client.list_toolchain_jobs()
    job = client.get_toolchain_job("snapshot_report")
    job_run = client.run_toolchain_job("snapshot_report")

    assert cast(dict[str, Any], runtime_status["languages"])["count"] == 2
    assert projects[0]["title"] == "python_app"
    assert project["project_id"] == "J:/workspace/python_app"
    assert cast(dict[str, Any], bootstrap["target"])["status"] == "planned"
    assert cast(dict[str, Any], scaffold["files"])["manifest.json"] == "{\"provider_id\": \"docker\"}"
    assert jobs[0]["job_id"] == "snapshot_report"
    assert job["status"] == "idle"
    assert cast(dict[str, Any], job_run["job"])["status"] == "completed"


def test_remote_soc_investigation_client_exposes_toolchain_secret_lifecycle_and_schedule_runtime() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/toolchain/secret-resolution/platform_manager_bearer/set":
            assert request.url.params["persist"] == "override"
            return httpx.Response(200, json={"result": {"secret_id": "platform_manager_bearer", "source": "override_store", "status": "applied"}})
        if request.method == "POST" and request.url.path == "/toolchain/secret-resolution/platform_manager_bearer/clear":
            return httpx.Response(200, json={"result": {"secret_id": "platform_manager_bearer", "status": "cleared"}})
        if request.method == "GET" and request.url.path == "/toolchain/schedules/runtime":
            return httpx.Response(200, json={"runtime": {"running": False, "poll_seconds": 60.0}})
        if request.method == "POST" and request.url.path == "/toolchain/schedules/runtime/start":
            assert request.url.params["poll_seconds"] == "0.5"
            return httpx.Response(200, json={"runtime": {"running": True, "poll_seconds": 0.5}})
        if request.method == "POST" and request.url.path == "/toolchain/schedules/runtime/stop":
            return httpx.Response(200, json={"runtime": {"running": False, "poll_seconds": 0.5}})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    secret_set = client.set_toolchain_secret("platform_manager_bearer", "manager-secret", persist="override")
    runtime = client.get_toolchain_schedule_runtime()
    started = client.start_toolchain_schedule_runtime(poll_seconds=0.5)
    stopped = client.stop_toolchain_schedule_runtime()
    secret_clear = client.clear_toolchain_secret("platform_manager_bearer")

    assert secret_set["source"] == "override_store"
    assert runtime["running"] is False
    assert started["running"] is True
    assert stopped["running"] is False
    assert secret_clear["status"] == "cleared"


def test_remote_soc_investigation_client_exposes_toolchain_doctor() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/toolchain/doctor":
            return httpx.Response(200, json={"status": "ok", "summary": "healthy", "checks": [{"check_id": "manifest", "status": "ok"}]})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    result = client.toolchain_doctor()

    assert result["status"] == "ok"
    assert cast(list[dict[str, Any]], result["checks"])[0]["check_id"] == "manifest"


def test_remote_soc_investigation_client_can_repair_toolchain_doctor() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/toolchain/doctor/repair":
            assert request.url.params.get("force_reinstall") == "true"
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "summary": "repaired",
                    "force_reinstall": True,
                    "actions": [{"action_id": "environment_write", "status": "ok"}],
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSocInvestigationClient.connect(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    result = client.repair_toolchain_doctor(force_reinstall=True)

    assert result["status"] == "ok"
    assert result["force_reinstall"] is True
    assert cast(list[dict[str, Any]], result["actions"])[0]["action_id"] == "environment_write"
