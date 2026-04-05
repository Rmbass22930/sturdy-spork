from __future__ import annotations

import tempfile
from pathlib import Path

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
    assert config.get_runtime_data_dir() == expected_root
    assert config.get_runtime_logs_dir() == expected_root / "logs"


def test_runtime_data_override_wins_for_frozen_build(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(config.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("SECURITY_GATEWAY_RUNTIME_DATA_DIR", str(tmp_path / "runtime-root"))

    settings = config.Settings()  # type: ignore[call-arg]

    expected_root = tmp_path / "runtime-root"
    assert settings.audit_log_path == str(expected_root / "logs" / "audit.jsonl")
    assert settings.report_output_dir == str(expected_root / "reports")
    assert config.get_runtime_data_dir() == expected_root


def test_frozen_runtime_paths_fall_back_when_primary_root_is_not_writable(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(config.sys, "frozen", True, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    def fake_is_writable(path):
        return path == (Path(tempfile.gettempdir()) / "SecurityGateway-runtime")

    monkeypatch.setattr(config, "_runtime_root_is_writable", fake_is_writable)

    settings = config.Settings()  # type: ignore[call-arg]

    expected_root = Path(tempfile.gettempdir()) / "SecurityGateway-runtime"
    assert settings.audit_log_path == str(expected_root / "logs" / "audit.jsonl")
    assert settings.report_output_dir == str(expected_root / "reports")
    assert config.get_runtime_data_dir() == expected_root
