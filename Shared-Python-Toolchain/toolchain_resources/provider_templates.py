"""Declarative provider-onboarding templates for the shared toolchain."""
from __future__ import annotations

from typing import Any

from security_gateway.models import ToolchainProviderTemplateRecord


_PROVIDER_TEMPLATES: dict[str, ToolchainProviderTemplateRecord] = {
    "docker": ToolchainProviderTemplateRecord(
        provider_id="docker",
        title="Docker",
        category="platform",
        description="Catalog and track Docker platform resources relevant to the shared toolchain.",
        capabilities=["catalog", "updates", "docs"],
        required_settings=[],
        optional_settings=["docker_context", "docker_registry"],
        update_source="docker-release-feed",
    ),
    "linear": ToolchainProviderTemplateRecord(
        provider_id="linear",
        title="Linear",
        category="workflow",
        description="Register Linear Asks/forms and workflow entry points for the shared toolchain.",
        capabilities=["forms", "portal", "updates"],
        required_settings=[],
        optional_settings=["linear_api_token", "linear_workspace_url"],
        update_source="linear-release-feed",
    ),
    "github": ToolchainProviderTemplateRecord(
        provider_id="github",
        title="GitHub",
        category="source_control",
        description="Expose repository, issue, pull-request, and automation workflows through the shared toolchain.",
        capabilities=["issues", "pull_requests", "automation", "updates"],
        required_settings=["github_app_installation"],
        optional_settings=["github_token", "github_webhook_secret"],
        update_source="github-changelog",
    ),
    "sentry": ToolchainProviderTemplateRecord(
        provider_id="sentry",
        title="Sentry",
        category="observability",
        description="Expose issue and event monitoring workflows through the shared toolchain.",
        capabilities=["issues", "events", "health"],
        required_settings=["sentry_auth_token"],
        optional_settings=["sentry_org", "sentry_project"],
        update_source="sentry-release-feed",
    ),
    "vault": ToolchainProviderTemplateRecord(
        provider_id="vault",
        title="HashiCorp Vault",
        category="secrets",
        description="Provide shared secret storage and retrieval integration for the toolchain.",
        capabilities=["secret_storage", "secret_resolution", "health"],
        required_settings=["hashicorp_vault_url", "hashicorp_vault_token"],
        optional_settings=["hashicorp_vault_namespace", "hashicorp_vault_mount"],
        update_source="vault-release-feed",
    ),
    "platform_manager": ToolchainProviderTemplateRecord(
        provider_id="platform_manager",
        title="Platform Manager",
        category="security",
        description="Connect remote manager services, investigations, and node-control workflows to the shared toolchain.",
        capabilities=["remote_control", "investigations", "dashboard"],
        required_settings=["platform_manager_url", "platform_manager_bearer_token"],
        optional_settings=["platform_manager_timeout_seconds"],
        update_source="security-gateway-release-feed",
    ),
}


class ToolchainProviderTemplateRegistry:
    def list_templates(self) -> list[ToolchainProviderTemplateRecord]:
        return sorted(_PROVIDER_TEMPLATES.values(), key=lambda item: item.provider_id)

    def get_template(self, provider_id: str) -> ToolchainProviderTemplateRecord | None:
        return _PROVIDER_TEMPLATES.get(provider_id)

    def render_template(self, provider_id: str) -> dict[str, Any] | None:
        template = self.get_template(provider_id)
        if template is None:
            return None
        return {
            "provider": template.model_dump(mode="json"),
            "manifest": {
                "provider_id": template.provider_id,
                "title": template.title,
                "category": template.category,
                "description": template.description,
                "capabilities": list(template.capabilities),
                "required_settings": list(template.required_settings),
                "optional_settings": list(template.optional_settings),
                "update_source": template.update_source,
            },
            "files": [
                f"toolchain_resources/{template.provider_id}_resources.py",
                f"tests/test_{template.provider_id}_toolchain.py",
            ],
        }
