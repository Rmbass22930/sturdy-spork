"""Privileged access management utilities with automatic key rotation."""
from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Dict, List, Optional

from .audit import AuditLogger
from .config import settings
from .models import CredentialLease
from .secret_backends import HashicorpVaultBackend, LocalMemoryBackend, SecretBackend
from .utils import decrypt_secret, encrypt_secret

MAX_SECRET_NAME_LENGTH = 64
MAX_SECRET_VALUE_LENGTH = 8192
MIN_LEASE_TTL_MINUTES = 1
MAX_LEASE_TTL_MINUTES = 480
KEY_METADATA_SECRET_NAME = "__security_gateway_key_metadata__"
KEY_METADATA_VERSION = "v1"


class VaultClient:
    def __init__(
        self,
        rotation_interval: timedelta | None = None,
        backend: SecretBackend | None = None,
        audit_logger: AuditLogger | None = None,
        master_key: str | None = None,
    ):
        self._rotation_interval = rotation_interval or timedelta(days=1)
        self._root_master_key = master_key or settings.pam_master_key
        self._key_versions: Dict[str, str] = {}
        self._current_key_id: str = "v1"
        self._key_versions[self._current_key_id] = self._root_master_key
        self._backend = backend or self._select_backend()
        self._leases: Dict[str, CredentialLease] = {}
        self._last_rotation = datetime.now(UTC)
        self._rotation_count = 0
        self._audit = audit_logger or AuditLogger(settings.audit_log_path)
        self._load_key_metadata()

    def store_secret(self, name: str, plaintext: str) -> None:
        self._validate_secret_name(name)
        if not plaintext:
            raise ValueError("Secret value must not be empty.")
        if len(plaintext) > MAX_SECRET_VALUE_LENGTH:
            raise ValueError(f"Secret value exceeds the configured limit of {MAX_SECRET_VALUE_LENGTH} characters.")
        self.rotate_if_needed()
        version = self._current_key_id
        encrypted = encrypt_secret(self._key_versions[version], plaintext)
        self._backend.write(name, version, encrypted)
        self._audit.log(
            "pam.secret.store",
            {"name": name, "version": version, "backend": self.backend_name},
        )

    def retrieve_secret(self, name: str) -> Optional[str]:
        self._validate_secret_name(name)
        self.rotate_if_needed()
        for version in self._preferred_versions():
            encrypted = self._backend.read(name, version)
            if not encrypted:
                continue
            key = self._key_versions.get(version)
            if key:
                try:
                    return decrypt_secret(key, encrypted)
                except Exception:  # noqa: BLE001
                    continue
        return None

    def checkout(self, name: str, ttl_minutes: int = 15) -> CredentialLease:
        self._validate_secret_name(name)
        if ttl_minutes < MIN_LEASE_TTL_MINUTES or ttl_minutes > MAX_LEASE_TTL_MINUTES:
            raise ValueError(
                f"Lease TTL must be between {MIN_LEASE_TTL_MINUTES} and {MAX_LEASE_TTL_MINUTES} minutes."
            )
        secret = self.retrieve_secret(name)
        if not secret:
            raise KeyError(f"Secret {name} not found")
        lease_id = secrets.token_urlsafe(12)
        lease = CredentialLease(
            lease_id=lease_id,
            secret=secret,
            expires_at=datetime.now(UTC) + timedelta(minutes=ttl_minutes),
        )
        self._leases[lease_id] = lease
        self._audit.log("pam.secret.checkout", {"name": name, "lease_id": lease_id})
        return lease

    def get_lease(self, lease_id: str) -> Optional[CredentialLease]:
        lease = self._leases.get(lease_id)
        if lease and lease.expires_at > datetime.now(UTC):
            return lease
        return None

    def rotate_if_needed(self) -> None:
        if datetime.now(UTC) - self._last_rotation >= self._rotation_interval:
            self._rotate_keys(auto=True)

    def force_rotate(self) -> None:
        self._rotate_keys(auto=False)

    @property
    def current_key_id(self) -> str:
        return self._current_key_id

    def get_metrics(self) -> Dict[str, str | int]:
        return {
            "current_key": self._current_key_id,
            "rotation_count": self._rotation_count,
            "last_rotation": self._last_rotation.isoformat(),
            "backend": self.backend_name,
        }

    @property
    def backend_name(self) -> str:
        return type(self._backend).__name__

    def _rotate_keys(self, *, auto: bool) -> None:
        self._last_rotation = datetime.now(UTC)
        suffix = self._last_rotation.strftime("%Y%m%d%H%M")
        new_version = f"v{suffix}"
        self._key_versions[new_version] = secrets.token_urlsafe(32)
        self._current_key_id = new_version
        self._rotation_count += 1
        self._persist_key_metadata()
        expired = [lease_id for lease_id, lease in self._leases.items() if lease.expires_at <= datetime.now(UTC)]
        for lease_id in expired:
            del self._leases[lease_id]
        event_type = "pam.rotate.auto" if auto else "pam.rotate.manual"
        self._audit.log(event_type, {"current_key": self._current_key_id})

    def _preferred_versions(self) -> List[str]:
        ordered = [self._current_key_id]
        other_versions = sorted((v for v in self._key_versions if v != self._current_key_id), reverse=True)
        ordered.extend(other_versions)
        return ordered

    def _persist_key_metadata(self) -> None:
        payload = json.dumps(
            {
                "current_key_id": self._current_key_id,
                "key_versions": self._key_versions,
                "last_rotation": self._last_rotation.isoformat(),
                "rotation_count": self._rotation_count,
            },
            sort_keys=True,
        )
        encrypted = encrypt_secret(self._root_master_key, payload)
        self._backend.write(KEY_METADATA_SECRET_NAME, KEY_METADATA_VERSION, encrypted)

    def _load_key_metadata(self) -> None:
        encrypted = self._backend.read(KEY_METADATA_SECRET_NAME, KEY_METADATA_VERSION)
        if not encrypted:
            return
        payload = decrypt_secret(self._root_master_key, encrypted)
        data = json.loads(payload)
        key_versions = data.get("key_versions")
        current_key_id = data.get("current_key_id")
        if not isinstance(key_versions, dict) or not isinstance(current_key_id, str):
            raise RuntimeError("Stored PAM key metadata is invalid.")
        normalized_versions = {
            str(version): str(secret)
            for version, secret in key_versions.items()
            if str(version).strip() and str(secret).strip()
        }
        if "v1" not in normalized_versions:
            normalized_versions["v1"] = self._root_master_key
        self._key_versions = normalized_versions
        self._current_key_id = current_key_id if current_key_id in self._key_versions else "v1"
        last_rotation = data.get("last_rotation")
        if isinstance(last_rotation, str):
            self._last_rotation = datetime.fromisoformat(last_rotation)
        rotation_count = data.get("rotation_count")
        if isinstance(rotation_count, int):
            self._rotation_count = rotation_count

    def _select_backend(self) -> SecretBackend:
        if settings.hashicorp_vault_url and settings.hashicorp_vault_token:
            return HashicorpVaultBackend(
                settings.hashicorp_vault_url,
                settings.hashicorp_vault_token,
                settings.hashicorp_vault_mount,
                settings.hashicorp_vault_namespace,
                timeout_seconds=settings.hashicorp_vault_timeout_seconds,
                verify_tls=settings.hashicorp_vault_verify_tls,
            )
        return LocalMemoryBackend()

    @staticmethod
    def _validate_secret_name(name: str) -> None:
        if not name:
            raise ValueError("Secret name must not be empty.")
        if len(name) > MAX_SECRET_NAME_LENGTH:
            raise ValueError(
                f"Secret name exceeds the configured limit of {MAX_SECRET_NAME_LENGTH} characters."
            )
        if name[0] in "./" or name[-1] in "./":
            raise ValueError("Secret name must not start or end with '.' or '/'.")
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:/")
        if any(char not in allowed for char in name):
            raise ValueError("Secret name may only contain letters, numbers, '.', '_', '-', ':', and '/'.")
