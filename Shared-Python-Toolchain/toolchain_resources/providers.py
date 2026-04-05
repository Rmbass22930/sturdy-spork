"""Shared provider catalog for toolchain-wide integrations."""
from __future__ import annotations

from pathlib import Path

from security_gateway.config import Settings
from security_gateway.models import ToolchainProviderRecord
from toolchain_resources.linear_forms import LinearAsksFormRegistry
from toolchain_resources.updates import ToolchainUpdateRegistry


def _path_writable_target(path_value: str | Path) -> bool:
    path = Path(path_value)
    target = path if path.is_dir() else path.parent
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return True


class ToolchainProviderRegistry:
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

    def list_providers(self) -> list[ToolchainProviderRecord]:
        enabled_forms = self.linear_forms.list_forms(include_disabled=False)
        all_forms = self.linear_forms.list_forms(include_disabled=True)
        update_records = self.updates.list_updates()
        docker_update_count = sum(1 for record in update_records if record.provider == "docker")
        linear_update_count = sum(1 for record in update_records if record.provider == "linear")

        providers = [
            ToolchainProviderRecord(
                provider_id="docker",
                title="Docker",
                category="catalog",
                description="Shared Docker product and workflow catalog for all programs.",
                capabilities=["resource_catalog", "portal", "updates"],
                configured=True,
                enabled=True,
                auto_loaded=True,
                update_source="toolchain_updates",
                status="ready",
                metadata={"resource_count": docker_update_count or 5},
            ),
            ToolchainProviderRecord(
                provider_id="linear",
                title="Linear",
                category="forms",
                description="Shared Linear intake-form registry and portal for all programs.",
                capabilities=["form_registry", "portal", "updates"],
                configured=_path_writable_target(self.settings.linear_asks_forms_path),
                enabled=True,
                auto_loaded=True,
                update_source="toolchain_updates",
                status="ready" if enabled_forms else "partial",
                metadata={
                    "form_count": len(all_forms),
                    "enabled_form_count": len(enabled_forms),
                    "registry_path": str(self.settings.linear_asks_forms_path),
                    "update_count": linear_update_count,
                },
            ),
            ToolchainProviderRecord(
                provider_id="toolchain_updates",
                title="Toolchain Updates",
                category="updates",
                description="Controlled shared update feed that syncs new vendor and catalog changes.",
                capabilities=["sync", "list", "detail", "mark_seen"],
                configured=_path_writable_target(self.settings.toolchain_updates_state_path),
                enabled=True,
                auto_loaded=True,
                update_source="internal_registry",
                status="ready",
                metadata={"update_count": len(update_records), "state_path": str(self.settings.toolchain_updates_state_path)},
            ),
            ToolchainProviderRecord(
                provider_id="platform_manager",
                title="Platform Manager",
                category="remote_control",
                description="Remote manager endpoint for cross-node dashboard and investigation workflows.",
                capabilities=["remote_dashboard", "remote_investigation", "node_control"],
                configured=bool(self.settings.platform_manager_url),
                enabled=bool(self.settings.platform_manager_url),
                auto_loaded=False,
                update_source=None,
                status="ready" if self.settings.platform_manager_url else "disabled",
                metadata={
                    "manager_url": self.settings.platform_manager_url,
                    "bearer_token_configured": bool(self.settings.platform_manager_bearer_token),
                },
            ),
            ToolchainProviderRecord(
                provider_id="hashicorp_vault",
                title="HashiCorp Vault",
                category="secrets",
                description="Shared secret backend configuration used for operator and endpoint credentials.",
                capabilities=["secret_lookup", "token_backing"],
                configured=bool(self.settings.hashicorp_vault_url and self.settings.hashicorp_vault_token),
                enabled=bool(self.settings.hashicorp_vault_url),
                auto_loaded=False,
                update_source=None,
                status="ready" if self.settings.hashicorp_vault_url and self.settings.hashicorp_vault_token else "partial",
                metadata={
                    "vault_url": self.settings.hashicorp_vault_url,
                    "mount": self.settings.hashicorp_vault_mount,
                    "namespace": self.settings.hashicorp_vault_namespace,
                },
            ),
        ]
        return sorted(providers, key=lambda item: item.provider_id)

    def get_provider(self, provider_id: str) -> ToolchainProviderRecord | None:
        for provider in self.list_providers():
            if provider.provider_id == provider_id:
                return provider
        return None
