"""Shared health and diagnostics checks for toolchain-wide resources."""
from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from security_gateway.config import Settings, get_runtime_data_dir
from security_gateway.models import ToolchainHealthRecord
from toolchain_resources.linear_forms import LinearAsksFormRegistry
from toolchain_resources.updates import ToolchainUpdateRegistry


def _parent_writable(path_value: str | Path) -> bool:
    path = Path(path_value)
    target = path if path.is_dir() else path.parent
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(target, os.W_OK)


class ToolchainHealthRegistry:
    def __init__(
        self,
        settings: Settings,
        *,
        linear_forms: LinearAsksFormRegistry,
        updates: ToolchainUpdateRegistry,
    ) -> None:
        self.settings = settings
        self.linear_forms = linear_forms
        self.updates = updates

    def list_checks(self) -> list[ToolchainHealthRecord]:
        checked_at = datetime.now(UTC)
        runtime_dir = get_runtime_data_dir()
        forms = self.linear_forms.list_forms(include_disabled=True)
        update_records = self.updates.list_updates()
        checks = [
            ToolchainHealthRecord(
                check_id="runtime-storage",
                title="Runtime Storage",
                status="ok" if _parent_writable(runtime_dir) else "error",
                summary=(
                    f"Runtime directory is writable at {runtime_dir}."
                    if _parent_writable(runtime_dir)
                    else f"Runtime directory is not writable at {runtime_dir}."
                ),
                checked_at=checked_at,
                metadata={"runtime_dir": str(runtime_dir)},
            ),
            ToolchainHealthRecord(
                check_id="linear-forms",
                title="Linear Forms Registry",
                status="ok" if forms else "warning",
                summary=(
                    f"{len(forms)} Linear forms are registered."
                    if forms
                    else "Linear form registry is configured but no forms are registered."
                ),
                checked_at=checked_at,
                metadata={
                    "registry_path": str(self.settings.linear_asks_forms_path),
                    "form_count": len(forms),
                    "writable": _parent_writable(self.settings.linear_asks_forms_path),
                },
            ),
            ToolchainHealthRecord(
                check_id="toolchain-updates",
                title="Toolchain Update Feed",
                status="ok" if _parent_writable(self.settings.toolchain_updates_state_path) else "error",
                summary=(
                    f"Toolchain update state is writable with {len(update_records)} tracked updates."
                    if _parent_writable(self.settings.toolchain_updates_state_path)
                    else "Toolchain update state path is not writable."
                ),
                checked_at=checked_at,
                metadata={
                    "state_path": str(self.settings.toolchain_updates_state_path),
                    "update_count": len(update_records),
                },
            ),
            ToolchainHealthRecord(
                check_id="platform-manager",
                title="Platform Manager Configuration",
                status="ok" if self.settings.platform_manager_url else "warning",
                summary=(
                    f"Remote platform manager configured at {self.settings.platform_manager_url}."
                    if self.settings.platform_manager_url
                    else "Remote platform manager URL is not configured."
                ),
                checked_at=checked_at,
                metadata={
                    "manager_url": self.settings.platform_manager_url,
                    "bearer_token_configured": bool(self.settings.platform_manager_bearer_token),
                },
            ),
            ToolchainHealthRecord(
                check_id="hashicorp-vault",
                title="HashiCorp Vault Configuration",
                status=(
                    "ok"
                    if self.settings.hashicorp_vault_url and self.settings.hashicorp_vault_token
                    else "warning"
                ),
                summary=(
                    "Vault URL and token are configured."
                    if self.settings.hashicorp_vault_url and self.settings.hashicorp_vault_token
                    else "Vault configuration is partial or absent."
                ),
                checked_at=checked_at,
                metadata={
                    "vault_url": self.settings.hashicorp_vault_url,
                    "token_configured": bool(self.settings.hashicorp_vault_token),
                    "mount": self.settings.hashicorp_vault_mount,
                },
            ),
            ToolchainHealthRecord(
                check_id="operator-auth",
                title="Operator Access Configuration",
                status=(
                    "ok"
                    if self.settings.operator_bearer_token or self.settings.operator_allow_loopback_without_token
                    else "warning"
                ),
                summary=(
                    "Operator access is configured."
                    if self.settings.operator_bearer_token or self.settings.operator_allow_loopback_without_token
                    else "Operator access has no bearer token and loopback bypass is disabled."
                ),
                checked_at=checked_at,
                metadata={
                    "bearer_token_configured": bool(self.settings.operator_bearer_token),
                    "allow_loopback_without_token": self.settings.operator_allow_loopback_without_token,
                },
            ),
        ]
        return sorted(checks, key=lambda item: item.check_id)

    def get_check(self, check_id: str) -> ToolchainHealthRecord | None:
        for check in self.list_checks():
            if check.check_id == check_id:
                return check
        return None
