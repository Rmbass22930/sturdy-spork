from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from security_gateway import service
from security_gateway.config import settings
from security_gateway.ip_controls import IPBlocklistManager
from security_gateway.models import DeviceCompliance
from security_gateway.policy import PolicyEngine
from security_gateway.reports import SecurityReportBuilder


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


def _install_test_managers(monkeypatch, tmp_path):
    audit = DummyAuditLogger()
    blocklist = IPBlocklistManager(path=tmp_path / "blocked_ips.json", audit_logger=audit)
    traceroute = DummyTraceRunner()
    report_dir = tmp_path / "reports"
    monkeypatch.setattr(settings, "report_output_dir", str(report_dir))
    monkeypatch.setattr(service, "audit_logger", audit)
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
    return audit, blocklist, traceroute


def test_block_list_promote_unblock_api(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)

    with TestClient(service.app) as client:
        created = client.post(
            "/network/blocked-ips",
            json={"ip": "203.0.113.30", "reason": "manual review", "duration_minutes": 15},
        )
        assert created.status_code == 200
        assert created.json()["entry"]["expires_at"] is not None

        listed = client.get("/network/blocked-ips")
        assert listed.status_code == 200
        assert listed.json()["blocked_ips"][0]["ip"] == "203.0.113.30"

        promoted = client.post(
            "/network/blocked-ips/203.0.113.30/promote",
            json={"reason": "confirmed attacker"},
        )
        assert promoted.status_code == 200
        assert promoted.json()["entry"]["expires_at"] is None
        assert promoted.json()["entry"]["reason"] == "confirmed attacker"

        removed = client.request(
            "DELETE",
            "/network/blocked-ips/203.0.113.30",
            json={"reason": "operator cleared"},
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

    with TestClient(service.app) as client:
        response = client.post(
            "/network/blocked-ips/203.0.113.40/promote",
            json={"reason": "confirmed attacker"},
        )

    assert response.status_code == 404


def test_unblock_missing_ip_returns_404(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)

    with TestClient(service.app) as client:
        response = client.request(
            "DELETE",
            "/network/blocked-ips/203.0.113.41",
            json={"reason": "false positive"},
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


def test_reports_endpoints_list_and_fetch_saved_pdf(monkeypatch, tmp_path):
    _install_test_managers(monkeypatch, tmp_path)

    with TestClient(service.app) as client:
        generated = client.get(
            "/reports/security-summary.pdf",
            params={"time_window_hours": 24, "min_risk_score": 50, "include_recent_events": False},
        )
        assert generated.status_code == 200
        assert generated.headers["content-type"] == "application/pdf"
        assert generated.content.startswith(b"%PDF")

        saved_path = service.report_builder.write_summary_pdf(max_events=5)
        listing = client.get("/reports")
        assert listing.status_code == 200
        payload = listing.json()
        assert payload["reports"]
        assert payload["reports"][0]["name"] == saved_path.name

        fetched = client.get(f"/reports/{saved_path.name}")
        assert fetched.status_code == 200
        assert fetched.headers["content-type"] == "application/pdf"
        assert fetched.content.startswith(b"%PDF")
