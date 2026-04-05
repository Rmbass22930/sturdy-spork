"""Shared secret-source diagnostics for the toolchain."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from security_gateway.config import Settings
from security_gateway.models import ToolchainSecretSourceRecord


class ToolchainSecretSourceRegistry:
    def __init__(self, settings: Settings, override_state_path: str | Path | None = None) -> None:
        self.settings = settings
        self._override_state_path = Path(override_state_path or settings.toolchain_secret_override_state_path)

    def _load_overrides(self) -> dict[str, dict[str, Any]]:
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

    def list_secret_sources(self) -> list[ToolchainSecretSourceRecord]:
        vault_configured = bool(self.settings.hashicorp_vault_url and self.settings.hashicorp_vault_token)
        overrides = self._load_overrides()
        records = [
            self._record_for_token(
                secret_id="operator_bearer",
                title="Operator Bearer Token",
                env_var="SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN",
                static_value=self.settings.operator_bearer_token,
                secret_name=self.settings.operator_bearer_secret_name,
                vault_configured=vault_configured,
                override_entry=overrides.get("operator_bearer"),
            ),
            self._record_for_token(
                secret_id="endpoint_bearer",
                title="Endpoint Bearer Token",
                env_var="SECURITY_GATEWAY_ENDPOINT_BEARER_TOKEN",
                static_value=self.settings.endpoint_bearer_token,
                secret_name=self.settings.endpoint_bearer_secret_name,
                vault_configured=vault_configured,
                override_entry=overrides.get("endpoint_bearer"),
            ),
            self._record_for_token(
                secret_id="platform_manager_bearer",
                title="Platform Manager Bearer Token",
                env_var="SECURITY_GATEWAY_PLATFORM_MANAGER_BEARER_TOKEN",
                static_value=self.settings.platform_manager_bearer_token,
                secret_name=None,
                vault_configured=vault_configured,
                override_entry=overrides.get("platform_manager_bearer"),
            ),
            self._record_for_token(
                secret_id="vault_token",
                title="HashiCorp Vault Token",
                env_var="SECURITY_GATEWAY_HASHICORP_VAULT_TOKEN",
                static_value=self.settings.hashicorp_vault_token,
                secret_name=None,
                vault_configured=vault_configured,
                override_entry=overrides.get("vault_token"),
            ),
            self._record_for_token(
                secret_id="endpoint_telemetry_signing_key",
                title="Endpoint Telemetry Signing Key",
                env_var="SECURITY_GATEWAY_ENDPOINT_TELEMETRY_SIGNING_KEY",
                static_value=self.settings.endpoint_telemetry_signing_key,
                secret_name=None,
                vault_configured=vault_configured,
                override_entry=overrides.get("endpoint_telemetry_signing_key"),
            ),
            self._record_for_token(
                secret_id="pam_master_key",
                title="PAM Master Key",
                env_var="SECURITY_GATEWAY_PAM_MASTER_KEY",
                static_value=self.settings.pam_master_key,
                secret_name=None,
                vault_configured=vault_configured,
                generated_runtime=not bool(os.environ.get("SECURITY_GATEWAY_PAM_MASTER_KEY")),
                override_entry=overrides.get("pam_master_key"),
            ),
        ]
        return sorted(records, key=lambda item: item.secret_id)

    def _record_for_token(
        self,
        *,
        secret_id: str,
        title: str,
        env_var: str,
        static_value: str | None,
        secret_name: str | None,
        vault_configured: bool,
        generated_runtime: bool = False,
        override_entry: dict[str, Any] | None = None,
    ) -> ToolchainSecretSourceRecord:
        if override_entry and override_entry.get("value"):
            return ToolchainSecretSourceRecord(
                secret_id=secret_id,
                title=title,
                source="override_store",
                status="ok",
                summary=f"{title} is configured in the toolchain override store.",
                configured=True,
                metadata={"env_var": env_var, "override_path": str(self._override_state_path)},
            )
        if generated_runtime:
            return ToolchainSecretSourceRecord(
                secret_id=secret_id,
                title=title,
                source="generated_runtime",
                status="warning",
                summary=f"{title} is using a generated runtime value.",
                configured=True,
                metadata={"env_var": env_var},
            )
        if os.environ.get(env_var):
            return ToolchainSecretSourceRecord(
                secret_id=secret_id,
                title=title,
                source="env",
                status="ok",
                summary=f"{title} is configured via environment variable.",
                configured=True,
                metadata={"env_var": env_var},
            )
        if static_value:
            return ToolchainSecretSourceRecord(
                secret_id=secret_id,
                title=title,
                source="static_config",
                status="ok",
                summary=f"{title} is configured in settings.",
                configured=True,
                metadata={"env_var": env_var},
            )
        if secret_name:
            return ToolchainSecretSourceRecord(
                secret_id=secret_id,
                title=title,
                source="vault_secret_ref",
                status="ok" if vault_configured else "warning",
                summary=(
                    f"{title} is configured to resolve from Vault secret '{secret_name}'."
                    if vault_configured
                    else f"{title} references Vault secret '{secret_name}', but Vault is not fully configured."
                ),
                configured=True,
                metadata={"secret_name": secret_name, "env_var": env_var},
            )
        return ToolchainSecretSourceRecord(
            secret_id=secret_id,
            title=title,
            source="missing",
            status="error",
            summary=f"{title} is not configured.",
            configured=False,
            metadata={"env_var": env_var},
        )

    def get_secret_source(self, secret_id: str) -> ToolchainSecretSourceRecord | None:
        for record in self.list_secret_sources():
            if record.secret_id == secret_id:
                return record
        return None
