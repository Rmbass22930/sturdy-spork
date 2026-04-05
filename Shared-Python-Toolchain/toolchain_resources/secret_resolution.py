"""Shared secret-resolution helpers for the toolchain."""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_gateway.config import Settings
from security_gateway.models import ToolchainSecretMutationRecord, ToolchainSecretResolutionRecord
from security_gateway.pam import VaultClient
from toolchain_resources.cache_store import ToolchainCacheStore
from toolchain_resources.secret_sources import ToolchainSecretSourceRegistry


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _mask_secret(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


class ToolchainSecretResolver:
    def __init__(
        self,
        settings: Settings,
        secret_sources: ToolchainSecretSourceRegistry,
        cache_store: ToolchainCacheStore,
        override_state_path: str | Path | None = None,
    ) -> None:
        self.settings = settings
        self.secret_sources = secret_sources
        self.cache_store = cache_store
        self._vault = VaultClient()
        self._override_state_path = Path(override_state_path or settings.toolchain_secret_override_state_path)

    def _read_overrides(self) -> dict[str, dict[str, Any]]:
        if not self._override_state_path.exists():
            return {}
        try:
            payload = json.loads(self._override_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        entries = payload.get("overrides")
        if not isinstance(entries, dict):
            return {}
        return {str(key): value for key, value in entries.items() if isinstance(value, dict)}

    def _write_overrides(self, overrides: dict[str, dict[str, Any]]) -> None:
        self._override_state_path.parent.mkdir(parents=True, exist_ok=True)
        self._override_state_path.write_text(json.dumps({"overrides": overrides}, indent=2, sort_keys=True), encoding="utf-8")

    def _get_override(self, secret_id: str) -> str | None:
        entry = self._read_overrides().get(secret_id)
        value = entry.get("value") if isinstance(entry, dict) else None
        return str(value) if isinstance(value, str) and value else None

    def _set_override(self, secret_id: str, value: str) -> None:
        overrides = self._read_overrides()
        overrides[secret_id] = {"value": value, "updated_at": _utc_now().isoformat()}
        self._write_overrides(overrides)

    def _clear_override(self, secret_id: str) -> bool:
        overrides = self._read_overrides()
        if secret_id not in overrides:
            return False
        del overrides[secret_id]
        self._write_overrides(overrides)
        return True

    def _vault_secret_name(self, secret_id: str) -> str | None:
        if secret_id == "operator_bearer":
            return self.settings.operator_bearer_secret_name or "operator-bearer-token"
        if secret_id == "endpoint_bearer":
            return self.settings.endpoint_bearer_secret_name or "endpoint-ingest-token"
        if secret_id == "platform_manager_bearer":
            return "platform-manager-bearer-token"
        if secret_id == "endpoint_telemetry_signing_key":
            return "endpoint-telemetry-signing-key"
        return None

    def _resolve_from_vault(self, secret_name: str | None) -> tuple[str, str | None]:
        if not secret_name:
            return "missing", None
        try:
            value = self._vault.retrieve_secret(secret_name)
        except Exception:
            return "vault_secret_ref", None
        return "vault_secret_ref", value

    def _resolve_raw(self, secret_id: str) -> tuple[str, str | None, dict[str, Any]]:
        override_value = self._get_override(secret_id)
        if override_value:
            return "override_store", override_value, {"override_path": str(self._override_state_path)}
        if secret_id == "operator_bearer":
            env_value = os.environ.get("SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN")
            value = self.settings.operator_bearer_token or env_value
            if not value:
                source, value = self._resolve_from_vault(self._vault_secret_name(secret_id))
            else:
                source = "env" if env_value else "static_config"
            return source, value, {
                "env_var": "SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN",
                "secret_name": self._vault_secret_name(secret_id),
            }
        if secret_id == "endpoint_bearer":
            env_value = os.environ.get("SECURITY_GATEWAY_ENDPOINT_BEARER_TOKEN")
            value = self.settings.endpoint_bearer_token or env_value
            if not value:
                source, value = self._resolve_from_vault(self._vault_secret_name(secret_id))
            else:
                source = "env" if env_value else "static_config"
            return source, value, {
                "env_var": "SECURITY_GATEWAY_ENDPOINT_BEARER_TOKEN",
                "secret_name": self._vault_secret_name(secret_id),
            }
        if secret_id == "platform_manager_bearer":
            env_value = os.environ.get("SECURITY_GATEWAY_PLATFORM_MANAGER_BEARER_TOKEN")
            value = self.settings.platform_manager_bearer_token or env_value
            if not value:
                source, value = self._resolve_from_vault(self._vault_secret_name(secret_id))
            else:
                source = "env" if env_value else "static_config"
            return (source, value, {"env_var": "SECURITY_GATEWAY_PLATFORM_MANAGER_BEARER_TOKEN", "secret_name": self._vault_secret_name(secret_id)})
        if secret_id == "vault_token":
            env_value = os.environ.get("SECURITY_GATEWAY_HASHICORP_VAULT_TOKEN")
            value = self.settings.hashicorp_vault_token or env_value
            return ("env" if env_value else "static_config", value, {"env_var": "SECURITY_GATEWAY_HASHICORP_VAULT_TOKEN"})
        if secret_id == "endpoint_telemetry_signing_key":
            env_value = os.environ.get("SECURITY_GATEWAY_ENDPOINT_TELEMETRY_SIGNING_KEY")
            value = self.settings.endpoint_telemetry_signing_key or env_value
            if not value:
                source, value = self._resolve_from_vault(self._vault_secret_name(secret_id))
            else:
                source = "env" if env_value else "static_config"
            return (source, value, {"env_var": "SECURITY_GATEWAY_ENDPOINT_TELEMETRY_SIGNING_KEY", "secret_name": self._vault_secret_name(secret_id)})
        if secret_id == "pam_master_key":
            value = os.environ.get("SECURITY_GATEWAY_PAM_MASTER_KEY") or self.settings.pam_master_key
            source = "env" if os.environ.get("SECURITY_GATEWAY_PAM_MASTER_KEY") else "generated_runtime"
            return source, value, {"env_var": "SECURITY_GATEWAY_PAM_MASTER_KEY"}
        return "missing", None, {}

    def list_resolutions(self) -> list[ToolchainSecretResolutionRecord]:
        records: list[ToolchainSecretResolutionRecord] = []
        for source_record in self.secret_sources.list_secret_sources():
            cached = self.cache_store.get_entry("secret_resolution", source_record.secret_id)
            cache_state = cached.status if cached is not None else "missing"
            records.append(self.resolve_secret(source_record.secret_id, cache_state=cache_state))
        return records

    def get_resolution(self, secret_id: str) -> ToolchainSecretResolutionRecord | None:
        if self.secret_sources.get_secret_source(secret_id) is None:
            return None
        cached = self.cache_store.get_entry("secret_resolution", secret_id)
        return self.resolve_secret(secret_id, cache_state=cached.status if cached is not None else "missing")

    def resolve_secret(self, secret_id: str, *, cache_state: str | None = None) -> ToolchainSecretResolutionRecord:
        source_record = self.secret_sources.get_secret_source(secret_id)
        title = source_record.title if source_record is not None else secret_id.replace("_", " ").title()
        source, value, metadata = self._resolve_raw(secret_id)
        resolved_at = _utc_now()
        if value:
            status = "resolved"
            summary = f"{title} resolved from {source}."
        else:
            status = "unresolved"
            source = "missing"
            summary = f"{title} could not be resolved from configured sources."
        record = ToolchainSecretResolutionRecord(
            secret_id=secret_id,
            title=title,
            source=source,
            status=status,
            summary=summary,
            masked_value=_mask_secret(value),
            resolved_at=resolved_at,
            metadata={**metadata, "cache_status": cache_state or "missing", "configured": bool(value)},
        )
        self.cache_store.set_entry(
            "secret_resolution",
            secret_id,
            source="resolver",
            summary=record.summary,
            ttl_seconds=1800.0,
            payload={"secret_id": secret_id, "source": record.source, "status": record.status, "masked_value": record.masked_value},
            metadata={"status": record.status, "source": record.source},
        )
        return record

    def set_secret(self, secret_id: str, value: str, *, persist: str = "auto") -> ToolchainSecretMutationRecord:
        source_record = self.secret_sources.get_secret_source(secret_id)
        if source_record is None:
            return ToolchainSecretMutationRecord(
                secret_id=secret_id,
                title=secret_id.replace("_", " ").title(),
                action="set",
                source="missing",
                status="not_found",
                summary="Toolchain secret was not found.",
                updated_at=_utc_now(),
            )
        title = source_record.title
        target = persist
        if target == "auto":
            target = "vault" if self._vault_secret_name(secret_id) else "override"
        if target == "vault":
            secret_name = self._vault_secret_name(secret_id)
            if not secret_name:
                target = "override"
            else:
                self._vault.store_secret(secret_name, value)
                self.cache_store.delete_entry("secret_resolution", secret_id)
                resolution = self.resolve_secret(secret_id)
                return ToolchainSecretMutationRecord(
                    secret_id=secret_id,
                    title=title,
                    action="set",
                    source="vault_secret_ref",
                    status="applied",
                    summary=f"{title} was stored in Vault as '{secret_name}'.",
                    updated_at=_utc_now(),
                    masked_value=resolution.masked_value,
                    metadata={"persist": "vault", "secret_name": secret_name},
                )
        self._set_override(secret_id, value)
        self.cache_store.delete_entry("secret_resolution", secret_id)
        resolution = self.resolve_secret(secret_id)
        return ToolchainSecretMutationRecord(
            secret_id=secret_id,
            title=title,
            action="set",
            source="override_store",
            status="applied",
            summary=f"{title} was stored in the toolchain override store.",
            updated_at=_utc_now(),
            masked_value=resolution.masked_value,
            metadata={"persist": "override", "override_path": str(self._override_state_path)},
        )

    def clear_secret(self, secret_id: str) -> ToolchainSecretMutationRecord:
        source_record = self.secret_sources.get_secret_source(secret_id)
        if source_record is None:
            return ToolchainSecretMutationRecord(
                secret_id=secret_id,
                title=secret_id.replace("_", " ").title(),
                action="clear",
                source="missing",
                status="not_found",
                summary="Toolchain secret was not found.",
                updated_at=_utc_now(),
            )
        cleared_override = self._clear_override(secret_id)
        self.cache_store.delete_entry("secret_resolution", secret_id)
        return ToolchainSecretMutationRecord(
            secret_id=secret_id,
            title=source_record.title,
            action="clear",
            source="override_store" if cleared_override else "missing",
            status="cleared",
            summary=(
                f"{source_record.title} override and cached resolution were cleared."
                if cleared_override
                else f"{source_record.title} cached resolution was cleared."
            ),
            updated_at=_utc_now(),
            metadata={"override_cleared": cleared_override},
        )
