from datetime import timedelta

import pytest

from security_gateway.pam import VaultClient
from security_gateway.secret_backends import LocalMemoryBackend


class DummyAuditLogger:
    def __init__(self):
        self.events = []

    def log(self, event_type, data):
        self.events.append((event_type, data))


def test_secret_survives_forced_rotation():
    audit = DummyAuditLogger()
    vault = VaultClient(rotation_interval=timedelta(days=1), audit_logger=audit)
    vault.store_secret("db", "super-secret")
    lease = vault.checkout("db")
    assert lease.secret == "super-secret"
    vault.force_rotate()
    lease_after = vault.checkout("db")
    assert lease_after.secret == "super-secret"
    assert any(event for event, _ in audit.events if event.startswith("pam.rotate"))


def test_missing_secret_raises_key_error():
    vault = VaultClient(audit_logger=DummyAuditLogger())
    with pytest.raises(KeyError):
        vault.checkout("missing")


def test_metrics_increment_after_rotation():
    vault = VaultClient(rotation_interval=timedelta(days=1), audit_logger=DummyAuditLogger())
    vault.store_secret("db", "secret")
    before = vault.get_metrics()
    vault.force_rotate()
    after = vault.get_metrics()
    assert after["rotation_count"] == before["rotation_count"] + 1


def test_shared_master_key_recovers_secret_with_new_client():
    backend = LocalMemoryBackend()
    writer = VaultClient(backend=backend, audit_logger=DummyAuditLogger(), master_key="shared-master-key")
    writer.store_secret("db", "super-secret")

    reader = VaultClient(backend=backend, audit_logger=DummyAuditLogger(), master_key="shared-master-key")
    lease = reader.checkout("db")

    assert lease.secret == "super-secret"
