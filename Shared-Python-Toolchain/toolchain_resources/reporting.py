"""Reporting/export helpers for the shared toolchain runtime."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from toolchain_resources.runtime import ToolchainRuntime


class ToolchainReportService:
    def __init__(self, runtime: ToolchainRuntime) -> None:
        self.runtime = runtime

    def snapshot(self) -> dict[str, Any]:
        providers = self.runtime.providers.list_providers()
        health = self.runtime.health.list_checks()
        security = self.runtime.security.list_checks()
        languages = self.runtime.languages.list_languages()
        package_managers = self.runtime.package_managers.list_package_managers()
        secret_sources = self.runtime.secret_sources.list_secret_sources()
        secret_resolutions = self.runtime.secret_resolver.list_resolutions()
        provisioning = self.runtime.provisioning.list_actions()
        policy = self.runtime.version_policy.evaluate()
        enforcement = self.runtime.policy_enforcement.evaluate()
        gates = self.runtime.policy_gates.evaluate()
        schedules = self.runtime.scheduler.list_schedules()
        cache_summary = self.runtime.cache_store.summary()
        return {
            "providers": [item.model_dump(mode="json") for item in providers],
            "health": [item.model_dump(mode="json") for item in health],
            "security": [item.model_dump(mode="json") for item in security],
            "languages": [item.model_dump(mode="json") for item in languages],
            "package_managers": [item.model_dump(mode="json") for item in package_managers],
            "secret_sources": [item.model_dump(mode="json") for item in secret_sources],
            "secret_resolutions": [item.model_dump(mode="json") for item in secret_resolutions],
            "provisioning": [item.model_dump(mode="json") for item in provisioning],
            "version_policy": [item.model_dump(mode="json") for item in policy],
            "policy_enforcement": [item.model_dump(mode="json") for item in enforcement],
            "policy_gates": [item.model_dump(mode="json") for item in gates],
            "schedules": [item.model_dump(mode="json") for item in schedules],
            "cache": cache_summary,
        }

    def render_markdown(self) -> str:
        snapshot = self.snapshot()
        return "\n".join(
            [
                "# Toolchain Report",
                "",
                f"- Providers: {len(snapshot['providers'])}",
                f"- Health checks: {len(snapshot['health'])}",
                f"- Security checks: {len(snapshot['security'])}",
                f"- Languages: {len(snapshot['languages'])}",
                f"- Package managers: {len(snapshot['package_managers'])}",
                f"- Secret sources: {len(snapshot['secret_sources'])}",
                f"- Secret resolutions: {len(snapshot['secret_resolutions'])}",
                f"- Provisioning actions: {len(snapshot['provisioning'])}",
                f"- Version policy results: {len(snapshot['version_policy'])}",
                f"- Enforcement decisions: {len(snapshot['policy_enforcement'])}",
                f"- Policy gates: {len(snapshot['policy_gates'])}",
                f"- Schedules: {len(snapshot['schedules'])}",
                f"- Cache entries: {snapshot['cache']['count']}",
            ]
        )
