import json
import socket
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from security_gateway import service
from security_gateway.config import settings
from security_gateway.ip_controls import IPBlocklistManager
from security_gateway.models import DeviceCompliance
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
    monkeypatch.setattr(settings, "soc_alert_store_path", str(tmp_path / "soc_alerts.json"))
    monkeypatch.setattr(settings, "soc_case_store_path", str(tmp_path / "soc_cases.json"))
    monkeypatch.setattr(
        service,
        "soc_manager",
        SecurityOperationsManager(
            event_log_path=tmp_path / "soc_events.jsonl",
            alert_store_path=tmp_path / "soc_alerts.json",
            case_store_path=tmp_path / "soc_cases.json",
            audit_logger=audit,
            alert_manager=service.alert_manager,
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
    assert payload["soc"]["events_total"] == 0
    assert payload["soc"]["alerts_total"] == 0


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
            json={"status": "investigating", "note": "Owner assigned and triage started."},
            headers=headers,
        )
        fetched = client.get(f"/soc/cases/{case_id}", headers=headers)

    assert created.status_code == 200
    assert updated.status_code == 200
    assert fetched.status_code == 200
    assert updated.json()["status"] == "investigating"
    assert updated.json()["notes"] == ["Owner assigned and triage started."]
    assert fetched.json()["assignee"] == "tier2-analyst"


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
