import json
from pathlib import Path
from datetime import UTC, datetime, timedelta

import pytest

from security_gateway.ip_controls import IPBlocklistManager


class DummyAuditLogger:
    def __init__(self):
        self.events = []

    def log(self, event_type, data):
        self.events.append((event_type, data))


def test_block_and_list_ip(tmp_path: Path) -> None:
    audit = DummyAuditLogger()
    manager = IPBlocklistManager(path=tmp_path / "blocked_ips.json", audit_logger=audit)

    entry = manager.block("203.0.113.10", reason="confirmed attack", blocked_by="test")

    assert entry.ip == "203.0.113.10"
    assert manager.is_blocked("203.0.113.10")
    assert manager.list_entries()[0].reason == "confirmed attack"
    assert any(event == "network.ip_block" for event, _ in audit.events)


def test_unblock_ip(tmp_path: Path) -> None:
    audit = DummyAuditLogger()
    manager = IPBlocklistManager(path=tmp_path / "blocked_ips.json", audit_logger=audit)
    manager.block("203.0.113.11", reason="operator hold", blocked_by="test")

    removed = manager.unblock("203.0.113.11", reason="false positive", unblocked_by="test")

    assert removed is True
    assert manager.is_blocked("203.0.113.11") is False
    assert any(event == "network.ip_unblock" for event, _ in audit.events)


def test_invalid_ip_is_rejected(tmp_path: Path) -> None:
    manager = IPBlocklistManager(path=tmp_path / "blocked_ips.json", audit_logger=DummyAuditLogger())

    with pytest.raises(ValueError):
        manager.block("not-an-ip", reason="bad")


def test_temporary_block_expires_automatically(tmp_path: Path) -> None:
    audit = DummyAuditLogger()
    manager = IPBlocklistManager(path=tmp_path / "blocked_ips.json", audit_logger=audit)
    manager.block("203.0.113.12", reason="temporary hold", blocked_by="test", duration_minutes=5)

    payload = {
        "203.0.113.12": {
            "ip": "203.0.113.12",
            "blocked_at": datetime.now(UTC).isoformat(),
            "reason": "temporary hold",
            "blocked_by": "test",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        }
    }
    (tmp_path / "blocked_ips.json").write_text(json.dumps(payload), encoding="utf-8")

    assert manager.is_blocked("203.0.113.12") is False
    assert manager.list_entries() == []
    assert any(event == "network.ip_unblock_expired" for event, _ in audit.events)


def test_promote_temporary_block_to_permanent(tmp_path: Path) -> None:
    audit = DummyAuditLogger()
    manager = IPBlocklistManager(path=tmp_path / "blocked_ips.json", audit_logger=audit)
    manager.block("203.0.113.14", reason="temporary hold", blocked_by="test", duration_minutes=10)

    entry = manager.promote_to_permanent("203.0.113.14", reason="confirmed attacker", promoted_by="test")

    assert entry is not None
    assert entry.expires_at is None
    assert entry.reason == "confirmed attacker"
    assert entry.blocked_by == "test"
    assert any(event == "network.ip_block_promote_permanent" for event, _ in audit.events)


def test_promote_missing_block_returns_none(tmp_path: Path) -> None:
    manager = IPBlocklistManager(path=tmp_path / "blocked_ips.json", audit_logger=DummyAuditLogger())

    entry = manager.promote_to_permanent("203.0.113.15", reason="confirmed attacker", promoted_by="test")

    assert entry is None
