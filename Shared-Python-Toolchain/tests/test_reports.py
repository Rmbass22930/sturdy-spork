import json
from pathlib import Path

from security_gateway.ip_controls import IPBlocklistManager
from security_gateway.config import settings
from security_gateway.reports import ReportFilters, SecurityReportBuilder


def _write_audit_events(path: Path) -> None:
    events = [
        {
            "ts": "2026-03-27T05:00:00+00:00",
            "type": "access.evaluate",
            "data": {
                "user_id": "alice",
                "resource": "git",
                "source_ip": "203.0.113.10",
                "decision": "deny",
                "risk_score": 82.0,
                "reasons": ["Privileged resource requested", "Risk above threshold"],
            },
        },
        {
            "ts": "2026-03-27T05:02:00+00:00",
            "type": "access.evaluate",
            "data": {
                "user_id": "alice",
                "resource": "git",
                "source_ip": "203.0.113.10",
                "decision": "deny",
                "risk_score": 78.0,
                "reasons": ["EDR agent inactive"],
            },
        },
        {
            "ts": "2026-03-27T05:04:00+00:00",
            "type": "access.evaluate",
            "data": {
                "user_id": "bob",
                "resource": "vpn",
                "source_ip": "198.51.100.22",
                "decision": "deny",
                "risk_score": 90.0,
                "reasons": ["Device reported as compromised"],
            },
        },
        {
            "ts": "2026-03-27T05:06:00+00:00",
            "type": "access.evaluate",
            "data": {
                "user_id": "carol",
                "resource": "wiki",
                "source_ip": "198.51.100.30",
                "decision": "deny",
                "risk_score": 20.0,
                "reasons": ["Step-up MFA required"],
            },
        },
        {
            "ts": "2026-03-27T05:08:00+00:00",
            "type": "privacy.tracker_block",
            "data": {
                "target_type": "proxy",
                "hostname": "metrics.example.com",
                "matched_domain": "metrics.example.com",
                "source": "heuristic",
                "confidence": "high",
                "reason": "Tracker-style host labels: metrics; Tracking query keys: client_id",
            },
        },
    ]
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")


def test_collect_summary_includes_blocked_and_potential_ips(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    blocklist_path = tmp_path / "blocked-ips.json"
    _write_audit_events(audit_path)
    manager = IPBlocklistManager(path=blocklist_path)
    manager.block("198.51.100.9", reason="confirmed attacker", blocked_by="operator")

    builder = SecurityReportBuilder(audit_log_path=audit_path, ip_blocklist_path=blocklist_path)
    summary = builder.collect_summary(filters=ReportFilters(max_events=10))

    blocked_ips = {entry["ip"] for entry in summary["blocked_ips"]}
    assert blocked_ips == {"198.51.100.9"}

    potential = {entry["ip"]: entry for entry in summary["potential_blocked_ips"]}
    assert "203.0.113.10" in potential
    assert "198.51.100.22" in potential
    assert "198.51.100.30" not in potential
    assert potential["203.0.113.10"]["count"] == 2
    assert "git" in potential["203.0.113.10"]["resources"]
    assert "Risk above threshold" in potential["203.0.113.10"]["reasons"]
    assert summary["tracker_block_events"][0]["hostname"] == "metrics.example.com"


def test_collect_summary_respects_filters(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    blocklist_path = tmp_path / "blocked-ips.json"
    _write_audit_events(audit_path)
    manager = IPBlocklistManager(path=blocklist_path)
    manager.block("198.51.100.9", reason="confirmed attacker", blocked_by="operator")

    builder = SecurityReportBuilder(audit_log_path=audit_path, ip_blocklist_path=blocklist_path)
    summary = builder.collect_summary(
        filters=ReportFilters(
            time_window_hours=100000.0,
            min_risk_score=85.0,
            include_blocked_ips=False,
            include_potential_blocked_ips=True,
            include_recent_events=False,
        )
    )

    assert summary["blocked_ips"] == []
    assert summary["recent_events"] == []
    potential = {entry["ip"]: entry for entry in summary["potential_blocked_ips"]}
    assert "198.51.100.22" in potential
    assert "203.0.113.10" not in potential


def test_write_summary_pdf_and_list_saved_reports(tmp_path: Path, monkeypatch) -> None:
    audit_path = tmp_path / "audit.jsonl"
    blocklist_path = tmp_path / "blocked-ips.json"
    report_path = tmp_path / "reports" / "security-summary.pdf"
    _write_audit_events(audit_path)
    monkeypatch.setattr(settings, "report_output_dir", str(tmp_path / "reports"))

    builder = SecurityReportBuilder(audit_log_path=audit_path, ip_blocklist_path=blocklist_path)
    written = builder.write_summary_pdf(report_path, max_events=10)

    assert written == report_path
    assert report_path.read_bytes().startswith(b"%PDF")

    reports = builder.list_saved_reports()
    assert len(reports) == 1
    assert reports[0]["name"] == "security-summary.pdf"
    assert reports[0]["blocked_ip_count"] == 0
    assert reports[0]["potential_blocked_ip_count"] == 2
    assert reports[0]["tracker_block_count"] == 1
    assert builder.resolve_saved_report() == report_path
