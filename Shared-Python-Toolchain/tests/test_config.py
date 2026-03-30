from __future__ import annotations

from security_gateway import config


def test_frozen_runtime_paths_use_localappdata(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(config.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    settings = config.Settings()  # type: ignore[call-arg]

    expected_root = tmp_path / "SecurityGateway"
    assert settings.audit_log_path == str(expected_root / "logs" / "audit.jsonl")
    assert settings.soc_event_log_path == str(expected_root / "logs" / "soc_events.jsonl")
    assert settings.soc_alert_store_path == str(expected_root / "logs" / "soc_alerts.json")
    assert settings.soc_case_store_path == str(expected_root / "logs" / "soc_cases.json")
    assert settings.ip_blocklist_path == str(expected_root / "logs" / "blocked_ips.json")
    assert settings.tracker_feed_cache_path == str(expected_root / "logs" / "tracker_feed_domains.json")
    assert settings.malware_feed_cache_path == str(expected_root / "logs" / "malware_feed_hashes.json")
    assert settings.malware_rule_feed_cache_path == str(expected_root / "logs" / "malware_rule_feed_rules.json")
    assert settings.report_output_dir == str(expected_root / "reports")
