import json
import socket
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from security_gateway import service
from security_gateway.config import settings
from security_gateway.ip_controls import IPBlocklistManager
from security_gateway.models import DeviceCompliance
from security_gateway.pam import VaultClient
from security_gateway.policy import PolicyEngine
from security_gateway.reports import SecurityReportBuilder
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

    assert report.status_code == 401
    assert listing.status_code == 401
    assert tracker_events.status_code == 401


def test_dns_resolve_blocks_tracker_domains(monkeypatch, tmp_path):
    audit, _, _ = _install_test_managers(monkeypatch, tmp_path)

    with TestClient(service.app) as client:
        response = client.get("/dns/resolve", params={"hostname": "www.google-analytics.com", "record_type": "A"})

    assert response.status_code == 403
    assert "Tracker domain blocked" in response.json()["detail"]
    assert any(event == "privacy.tracker_block" for event, _ in audit.events)


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

    with TestClient(service.app) as client:
        response = client.post(
            "/tor/request",
            json={"url": "http://127.0.0.1/admin", "method": "GET", "via": "direct"},
        )

    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"].lower()


def test_proxy_request_rate_limits_abusive_clients(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
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
        )
        second = client.post(
            "/tor/request",
            json={"url": "https://example.com/health", "method": "GET", "via": "direct"},
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"]


def test_proxy_request_allows_public_http_targets(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)

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
        )

    assert response.status_code == 200
    assert response.json()["status_code"] == 200
    assert response.json()["body"] == "ok"


def test_proxy_request_maps_response_too_large(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
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
        )

    assert response.status_code == 413
    assert "configured limit" in response.json()["detail"]


def test_proxy_request_maps_upstream_timeout(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
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
        )

    assert response.status_code == 504
    assert "timed out" in response.json()["detail"]


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

        refreshed = client.post(
            "/privacy/tracker-feeds/refresh",
            json={"urls": ["https://feed.local/example"]},
            headers=headers,
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["domain_count"] == 25


def test_tracker_feed_refresh_api_returns_502_on_failure(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)
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
    assert "upstream timeout" in refreshed.json()["detail"]


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

        refreshed = client.post(
            "/endpoint/malware-feeds/refresh",
            json={"urls": ["https://feed.local/malware"]},
            headers=headers,
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["hash_count"] == 12


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

        rule_status = client.get("/endpoint/malware-rule-feeds/status")
        assert rule_status.status_code == 200
        assert rule_status.json()["rule_count"] == 1

        rule_refresh = client.post(
            "/endpoint/malware-rule-feeds/refresh",
            json={"urls": ["https://feed.local/rules"]},
            headers=headers,
        )
        assert rule_refresh.status_code == 200
        assert rule_refresh.json()["rule_count"] == 3

        tracker_import = client.post(
            "/privacy/tracker-feeds/import",
            json={"source_path": "offline-tracker-list.txt"},
            headers=headers,
        )
        assert tracker_import.status_code == 200
        assert tracker_import.json()["last_refresh_result"] == "imported"

        rule_import = client.post(
            "/endpoint/malware-rule-feeds/import",
            json={"source_path": "offline-rules.txt"},
            headers=headers,
        )
        assert rule_import.status_code == 200
        assert rule_import.json()["last_refresh_result"] == "imported"
