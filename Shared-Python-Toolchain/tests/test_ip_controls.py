from pathlib import Path

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
