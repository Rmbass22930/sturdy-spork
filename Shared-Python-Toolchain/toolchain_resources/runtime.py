"""Shared runtime bootstrap for toolchain resources."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import cast

from security_gateway.config import settings
from toolchain_resources.cache_store import ToolchainCacheStore
from toolchain_resources.bootstrap import ToolchainBootstrapExecutor
from toolchain_resources.health import ToolchainHealthRegistry
from toolchain_resources.jobs import ToolchainJobRunner
from toolchain_resources.language_health import ToolchainLanguageHealthRegistry
from toolchain_resources.languages import ToolchainLanguageRegistry
from toolchain_resources.linear_forms import LinearAsksFormRegistry
from toolchain_resources.package_managers import ToolchainPackageManagerRegistry
from toolchain_resources.package_operations import ToolchainPackageOperations
from toolchain_resources.policy_enforcement import ToolchainPolicyEnforcementRegistry
from toolchain_resources.policy_gates import ToolchainPolicyGateRegistry
from toolchain_resources.provisioning import ToolchainProvisioningRegistry
from toolchain_resources.provider_templates import ToolchainProviderTemplateRegistry
from toolchain_resources.provider_scaffold import ToolchainProviderScaffolder
from toolchain_resources.providers import ToolchainProviderRegistry
from toolchain_resources.projects import ToolchainProjectRegistry
from toolchain_resources.reporting import ToolchainReportService
from toolchain_resources.scheduler import ToolchainScheduler
from toolchain_resources.security import ToolchainSecurityRegistry
from toolchain_resources.secret_resolution import ToolchainSecretResolver
from toolchain_resources.secret_sources import ToolchainSecretSourceRegistry
from toolchain_resources.updates import ToolchainUpdateRegistry
from toolchain_resources.version_policy import ToolchainVersionPolicyRegistry


@dataclass(frozen=True)
class ToolchainRuntime:
    linear_forms: LinearAsksFormRegistry
    updates: ToolchainUpdateRegistry
    providers: ToolchainProviderRegistry
    health: ToolchainHealthRegistry
    security: ToolchainSecurityRegistry
    languages: ToolchainLanguageRegistry
    language_health: ToolchainLanguageHealthRegistry
    package_managers: ToolchainPackageManagerRegistry
    secret_sources: ToolchainSecretSourceRegistry
    cache_store: ToolchainCacheStore
    secret_resolver: ToolchainSecretResolver
    projects: ToolchainProjectRegistry
    provisioning: ToolchainProvisioningRegistry
    bootstrap: ToolchainBootstrapExecutor
    package_operations: ToolchainPackageOperations
    version_policy: ToolchainVersionPolicyRegistry
    provider_templates: ToolchainProviderTemplateRegistry
    provider_scaffolder: ToolchainProviderScaffolder
    reporting: ToolchainReportService
    policy_enforcement: ToolchainPolicyEnforcementRegistry
    policy_gates: ToolchainPolicyGateRegistry
    jobs: ToolchainJobRunner
    scheduler: ToolchainScheduler


@lru_cache(maxsize=1)
def get_toolchain_runtime() -> ToolchainRuntime:
    linear_forms = LinearAsksFormRegistry(settings.linear_asks_forms_path)
    updates = ToolchainUpdateRegistry(
        settings.toolchain_updates_state_path,
        linear_forms_path=settings.linear_asks_forms_path,
    )
    providers = ToolchainProviderRegistry(settings, linear_forms=linear_forms, updates=updates)
    health = ToolchainHealthRegistry(settings, linear_forms=linear_forms, updates=updates)
    security = ToolchainSecurityRegistry(settings)
    languages = ToolchainLanguageRegistry()
    language_health = ToolchainLanguageHealthRegistry(languages)
    package_managers = ToolchainPackageManagerRegistry()
    secret_sources = ToolchainSecretSourceRegistry(settings)
    cache_store = ToolchainCacheStore(settings.toolchain_cache_state_path)
    secret_resolver = ToolchainSecretResolver(settings, secret_sources, cache_store)
    projects = ToolchainProjectRegistry()
    provisioning = ToolchainProvisioningRegistry(languages, package_managers)
    bootstrap = ToolchainBootstrapExecutor(provisioning)
    package_operations = ToolchainPackageOperations(package_managers)
    version_policy = ToolchainVersionPolicyRegistry(languages, package_managers)
    provider_templates = ToolchainProviderTemplateRegistry()
    provider_scaffolder = ToolchainProviderScaffolder(provider_templates)
    policy_enforcement = ToolchainPolicyEnforcementRegistry(security, version_policy, provisioning)
    runtime = ToolchainRuntime(
        linear_forms=linear_forms,
        updates=updates,
        providers=providers,
        health=health,
        security=security,
        languages=languages,
        language_health=language_health,
        package_managers=package_managers,
        secret_sources=secret_sources,
        cache_store=cache_store,
        secret_resolver=secret_resolver,
        projects=projects,
        provisioning=provisioning,
        bootstrap=bootstrap,
        package_operations=package_operations,
        version_policy=version_policy,
        provider_templates=provider_templates,
        provider_scaffolder=provider_scaffolder,
        reporting=cast(ToolchainReportService, None),
        policy_enforcement=policy_enforcement,
        policy_gates=cast(ToolchainPolicyGateRegistry, None),
        jobs=cast(ToolchainJobRunner, None),
        scheduler=cast(ToolchainScheduler, None),
    )
    object.__setattr__(runtime, "reporting", ToolchainReportService(runtime))
    object.__setattr__(runtime, "jobs", ToolchainJobRunner(runtime))
    object.__setattr__(runtime, "policy_gates", ToolchainPolicyGateRegistry(policy_enforcement))
    object.__setattr__(runtime, "scheduler", ToolchainScheduler(settings.toolchain_scheduler_state_path, runtime.jobs))
    return runtime


def load_toolchain_runtime(*, sync_updates: bool = False, apply_safe_only: bool = True) -> ToolchainRuntime:
    runtime = get_toolchain_runtime()
    if sync_updates:
        runtime.updates.sync(apply_safe_only=apply_safe_only)
    gate = runtime.policy_gates.get_gate("startup")
    if gate is not None:
        runtime.cache_store.set_entry(
            "policy_gates",
            gate.gate_id,
            source="runtime",
            summary=gate.summary,
            payload=gate.model_dump(mode="json"),
            metadata={"gate_status": gate.status},
        )
        if settings.toolchain_policy_gate_fail_on_block and gate.status == "block":
            raise RuntimeError(gate.summary)
    if settings.toolchain_scheduler_run_on_startup:
        runtime.scheduler.run_due_jobs()
    if settings.toolchain_scheduler_background_enabled:
        runtime.scheduler.start_background_runner(poll_seconds=settings.toolchain_scheduler_poll_seconds)
    return runtime
