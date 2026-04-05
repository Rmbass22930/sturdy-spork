from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import cast

from security_gateway.config import settings
from toolchain_resources.cache_store import ToolchainCacheStore
from toolchain_resources.docker_resources import get_docker_resource, list_docker_resources
from toolchain_resources.doctor import ToolchainDoctor
from toolchain_resources.health import ToolchainHealthRegistry
from toolchain_resources.language_health import ToolchainLanguageHealthRegistry
from toolchain_resources.languages import ToolchainLanguageRegistry
from toolchain_resources.linear_forms import LinearAsksFormRegistry, LinearAsksFormUpsert
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
from toolchain_resources.runtime import ToolchainRuntime
from toolchain_resources.bootstrap import ToolchainBootstrapExecutor
from toolchain_resources.jobs import ToolchainJobRunner


def test_toolchain_resources_exposes_docker_catalog() -> None:
    resources = list_docker_resources()
    detail = get_docker_resource("sandboxes-2026-03-31")

    assert resources[0].resource_key == "offload-ga-2026-04-02"
    assert detail is not None
    assert detail.title == "Docker Sandboxes for agent execution"


def test_toolchain_resources_exposes_linear_registry(tmp_path: Path) -> None:
    registry = LinearAsksFormRegistry(tmp_path / "linear_forms.json")
    record = registry.upsert_form(
        LinearAsksFormUpsert(
            form_key="bug-report",
            title="Bug report",
            url="https://linear.app/example/forms/bug-report",
        )
    )

    assert registry.get_form("bug-report") is not None
    assert record.form_key == "bug-report"


def test_toolchain_resources_exposes_provider_registry(tmp_path: Path, monkeypatch) -> None:
    forms = LinearAsksFormRegistry(tmp_path / "linear_forms.json")
    forms.upsert_form(
        LinearAsksFormUpsert(
            form_key="bug-report",
            title="Bug report",
            url="https://linear.app/example/forms/bug-report",
        )
    )
    updates = ToolchainUpdateRegistry(tmp_path / "toolchain_updates.json", linear_forms_path=tmp_path / "linear_forms.json")
    updates.sync()
    monkeypatch.setattr(settings, "platform_manager_url", "https://manager.local")

    registry = ToolchainProviderRegistry(settings, linear_forms=forms, updates=updates)
    providers = registry.list_providers()
    linear = registry.get_provider("linear")

    assert any(provider.provider_id == "docker" for provider in providers)
    assert linear is not None
    assert linear.metadata["enabled_form_count"] == 1


def test_toolchain_resources_exposes_health_registry(tmp_path: Path, monkeypatch) -> None:
    forms = LinearAsksFormRegistry(tmp_path / "linear_forms.json")
    updates = ToolchainUpdateRegistry(tmp_path / "toolchain_updates.json", linear_forms_path=tmp_path / "linear_forms.json")
    updates.sync()
    monkeypatch.setattr(settings, "operator_bearer_token", "operator-token")

    health = ToolchainHealthRegistry(settings, linear_forms=forms, updates=updates)
    checks = health.list_checks()
    operator_auth = health.get_check("operator-auth")

    assert any(check.check_id == "toolchain-updates" for check in checks)
    assert operator_auth is not None
    assert operator_auth.status == "ok"


def test_toolchain_resources_exposes_security_registry(monkeypatch) -> None:
    monkeypatch.setattr(settings, "operator_bearer_token", "operator-token")
    monkeypatch.setattr(settings, "endpoint_bearer_token", "endpoint-token")
    monkeypatch.setattr(settings, "platform_manager_url", "https://manager.local")
    monkeypatch.setattr(settings, "platform_manager_bearer_token", "manager-token")
    monkeypatch.setattr(settings, "endpoint_telemetry_signing_key", "signing-key")
    monkeypatch.setattr(settings, "alert_webhook_url", "https://alerts.local/webhook")
    monkeypatch.setattr(settings, "alert_webhook_verify_tls", True)
    monkeypatch.setenv("SECURITY_GATEWAY_PAM_MASTER_KEY", "persisted-master-key")

    security = ToolchainSecurityRegistry(settings)
    checks = security.list_checks()
    operator_auth = security.get_check("operator-auth")
    pam_key = security.get_check("pam-master-key")

    assert any(check.check_id == "endpoint-telemetry-signing" for check in checks)
    assert operator_auth is not None
    assert operator_auth.status == "ok"
    assert pam_key is not None
    assert pam_key.status == "ok"


def test_toolchain_resources_exposes_language_registry() -> None:
    registry = ToolchainLanguageRegistry()
    languages = registry.list_languages()
    python = registry.get_language("python")

    assert any(language.language_id == "python" for language in languages)
    assert python is not None
    assert python.title == "Python"


def test_toolchain_resources_exposes_language_health_registry() -> None:
    registry = ToolchainLanguageRegistry()
    health = ToolchainLanguageHealthRegistry(registry)
    checks = health.list_checks()
    python = health.get_check("python")

    assert any(check.language_id == "python" for check in checks)
    assert python is not None
    assert python.title == "Python"


def test_toolchain_resources_exposes_package_manager_registry() -> None:
    registry = ToolchainPackageManagerRegistry()
    managers = registry.list_package_managers()
    pip_record = registry.get_package_manager("pip")

    assert any(manager.manager_id == "pip" for manager in managers)
    assert pip_record is not None
    assert "python" in pip_record.related_languages


def test_toolchain_resources_exposes_secret_source_registry(monkeypatch) -> None:
    monkeypatch.setattr(settings, "operator_bearer_token", "operator-token")
    monkeypatch.setattr(settings, "endpoint_bearer_token", "endpoint-token")
    monkeypatch.setattr(settings, "platform_manager_bearer_token", "manager-token")
    monkeypatch.setenv("SECURITY_GATEWAY_PAM_MASTER_KEY", "persisted-master-key")

    registry = ToolchainSecretSourceRegistry(settings)
    records = registry.list_secret_sources()
    operator_secret = registry.get_secret_source("operator_bearer")

    assert any(record.secret_id == "operator_bearer" for record in records)
    assert operator_secret is not None
    assert operator_secret.status == "ok"


def test_toolchain_resources_exposes_provisioning_registry() -> None:
    languages = ToolchainLanguageRegistry()
    package_managers = ToolchainPackageManagerRegistry()
    registry = ToolchainProvisioningRegistry(languages, package_managers)

    actions = registry.list_actions()
    python_action = registry.get_action("python")

    assert any(action.target_id == "python" for action in actions)
    assert python_action is not None
    assert python_action.target_type == "language"


def test_toolchain_resources_exposes_package_operations() -> None:
    operations = ToolchainPackageOperations(ToolchainPackageManagerRegistry())

    listed = operations.list_operations("pip")
    planned = operations.build_operation("pip", "install_deps")
    dry_run = operations.run_operation("pip", "install_deps", execute=False)

    assert any(item.manager_id == "pip" for item in listed)
    assert planned is not None
    assert planned.command[:2] == ["pip", "install"]
    assert dry_run["executed"] is False


def test_toolchain_resources_exposes_version_policy_registry() -> None:
    registry = ToolchainVersionPolicyRegistry(ToolchainLanguageRegistry(), ToolchainPackageManagerRegistry())

    results = registry.evaluate()
    python = registry.get_result("python")

    assert any(result.target_id == "python" for result in results)
    assert python is not None
    assert python.target_type == "language"


def test_toolchain_resources_exposes_cache_resolution_templates_reporting_and_enforcement(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(settings, "operator_bearer_token", "operator-token")
    monkeypatch.setattr(settings, "endpoint_bearer_token", "endpoint-token")
    monkeypatch.setattr(settings, "endpoint_telemetry_signing_key", "signing-key")
    monkeypatch.setenv("SECURITY_GATEWAY_PAM_MASTER_KEY", "persisted-master-key")

    cache_store = ToolchainCacheStore(tmp_path / "toolchain_cache.json")
    cache_record = cache_store.set_entry("updates", "docker", source="sync", summary="Docker feed cached.")
    secret_sources = ToolchainSecretSourceRegistry(settings)
    secret_resolver = ToolchainSecretResolver(settings, secret_sources, cache_store)
    resolution = secret_resolver.resolve_secret("operator_bearer")
    templates = ToolchainProviderTemplateRegistry()
    template = templates.get_template("docker")
    languages = ToolchainLanguageRegistry()
    package_managers = ToolchainPackageManagerRegistry()
    provisioning = ToolchainProvisioningRegistry(languages, package_managers)
    version_policy = ToolchainVersionPolicyRegistry(languages, package_managers)
    enforcement = ToolchainPolicyEnforcementRegistry(ToolchainSecurityRegistry(settings), version_policy, provisioning)
    provider_scaffolder = ToolchainProviderScaffolder(templates)
    runtime = ToolchainRuntime(
        linear_forms=LinearAsksFormRegistry(tmp_path / "linear_forms.json"),
        updates=ToolchainUpdateRegistry(tmp_path / "toolchain_updates.json", linear_forms_path=tmp_path / "linear_forms.json"),
        providers=ToolchainProviderRegistry(
            settings,
            linear_forms=LinearAsksFormRegistry(tmp_path / "linear_forms.json"),
            updates=ToolchainUpdateRegistry(tmp_path / "toolchain_updates_2.json", linear_forms_path=tmp_path / "linear_forms.json"),
        ),
        health=ToolchainHealthRegistry(
            settings,
            linear_forms=LinearAsksFormRegistry(tmp_path / "linear_forms.json"),
            updates=ToolchainUpdateRegistry(tmp_path / "toolchain_updates_3.json", linear_forms_path=tmp_path / "linear_forms.json"),
        ),
        security=ToolchainSecurityRegistry(settings),
        languages=languages,
        language_health=ToolchainLanguageHealthRegistry(languages),
        package_managers=package_managers,
        secret_sources=secret_sources,
        cache_store=cache_store,
        secret_resolver=secret_resolver,
        projects=ToolchainProjectRegistry(),
        provisioning=provisioning,
        bootstrap=ToolchainBootstrapExecutor(provisioning),
        package_operations=ToolchainPackageOperations(package_managers),
        version_policy=version_policy,
        provider_templates=templates,
        provider_scaffolder=provider_scaffolder,
        reporting=None,  # type: ignore[arg-type]
        policy_enforcement=enforcement,
        policy_gates=None,  # type: ignore[arg-type]
        jobs=None,  # type: ignore[arg-type]
        scheduler=None,  # type: ignore[arg-type]
    )
    object.__setattr__(runtime, "reporting", ToolchainReportService(runtime))
    object.__setattr__(runtime, "jobs", ToolchainJobRunner(runtime))
    object.__setattr__(runtime, "policy_gates", ToolchainPolicyGateRegistry(runtime.policy_enforcement))
    object.__setattr__(runtime, "scheduler", ToolchainScheduler(tmp_path / "toolchain_scheduler.json", runtime.jobs))
    report = runtime.reporting.snapshot()
    markdown = runtime.reporting.render_markdown()

    assert cache_record.namespace == "updates"
    assert resolution.status == "resolved"
    assert template is not None
    assert template.provider_id == "docker"
    assert any(result.policy_id == "security_baseline" for result in enforcement.evaluate())
    assert report["cache"]["count"] >= 1
    assert "Toolchain Report" in markdown
    assert json.loads(json.dumps(report))["cache"]["count"] >= 1


def test_toolchain_resources_exposes_projects_bootstrap_jobs_and_scaffolding(tmp_path: Path) -> None:
    project_root = tmp_path / "repo"
    python_project = project_root / "python_app"
    node_project = project_root / "node_app"
    python_project.mkdir(parents=True)
    node_project.mkdir(parents=True)
    (python_project / "pyproject.toml").write_text("[project]\nname='python-app'\n", encoding="utf-8")
    (node_project / "package.json").write_text('{"name":"node-app"}', encoding="utf-8")

    projects = ToolchainProjectRegistry()
    detected = projects.detect_projects(project_root)
    python_record = projects.get_project(str(python_project), root_path=project_root)

    provisioning = ToolchainProvisioningRegistry(ToolchainLanguageRegistry(), ToolchainPackageManagerRegistry())
    bootstrap = ToolchainBootstrapExecutor(provisioning)
    bootstrap_plan = bootstrap.run("python", execute=False, project_path=project_root)
    bootstrap_repair = bootstrap.run("python", mode="repair", execute=False, project_path=project_root)

    templates = ToolchainProviderTemplateRegistry()
    scaffolder = ToolchainProviderScaffolder(templates)
    scaffold = scaffolder.scaffold("docker", tmp_path / "scaffold", write=False)

    runtime = get_runtime_for_jobs(tmp_path)
    jobs = ToolchainJobRunner(runtime)
    scheduler = ToolchainScheduler(tmp_path / "toolchain_scheduler_jobs.json", jobs)
    job_list = jobs.list_jobs()
    job_result = jobs.run_job("snapshot_report")
    schedule = scheduler.upsert_schedule("snapshot_report", interval_minutes=30)
    due_run = scheduler.run_due_jobs(now=schedule.next_run_at)
    gates = ToolchainPolicyGateRegistry(runtime.policy_enforcement).evaluate()

    assert len(detected) >= 2
    assert python_record is not None
    assert "python" in python_record.ecosystems
    assert bootstrap_plan.status == "planned"
    assert bootstrap_repair.mode == "repair"
    assert scaffold is not None
    assert "manifest.json" in scaffold["files"]
    assert any(item.job_id == "snapshot_report" for item in job_list)
    assert cast(dict[str, object], job_result["job"])["status"] == "completed"
    assert schedule.schedule_id == "snapshot_report"
    assert due_run["ran"] == 1
    assert any(item.gate_id == "startup" for item in gates)


def test_toolchain_resources_exposes_bootstrap_execution_scheduler_runtime_and_secret_lifecycle(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(settings, "toolchain_secret_override_state_path", str(tmp_path / "toolchain_secret_overrides.json"))
    monkeypatch.setattr(settings, "platform_manager_bearer_token", None)
    provisioning = ToolchainProvisioningRegistry(ToolchainLanguageRegistry(), ToolchainPackageManagerRegistry())
    bootstrap = ToolchainBootstrapExecutor(provisioning)
    commands: list[tuple[object, bool]] = []

    def fake_run(command: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append((command, bool(kwargs.get("shell"))))
        return subprocess.CompletedProcess(["cmd"], 0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    executed = bootstrap.run("python", execute=True, verify_after=True, project_path=tmp_path)

    runtime = get_runtime_for_jobs(tmp_path)
    scheduler = ToolchainScheduler(tmp_path / "toolchain_scheduler_runtime.json", runtime.jobs)
    started = scheduler.start_background_runner(poll_seconds=0.5)
    runtime_status = scheduler.get_runtime_status()
    stopped = scheduler.stop_background_runner()

    secret_sources = ToolchainSecretSourceRegistry(settings, tmp_path / "toolchain_secret_overrides.json")
    secret_resolver = ToolchainSecretResolver(settings, secret_sources, runtime.cache_store, tmp_path / "toolchain_secret_overrides.json")
    secret_set = secret_resolver.set_secret("platform_manager_bearer", "manager-secret", persist="override")
    resolved = secret_resolver.resolve_secret("platform_manager_bearer")
    secret_clear = secret_resolver.clear_secret("platform_manager_bearer")

    assert executed.status == "executed"
    assert executed.verified is True
    assert executed.verify_returncode == 0
    assert len(commands) >= 2
    assert started.running is True
    assert runtime_status.running is True
    assert stopped.running is False
    assert secret_set.status == "applied"
    assert secret_set.source == "override_store"
    assert resolved.source == "override_store"
    assert resolved.status == "resolved"
    assert secret_clear.status == "cleared"


def test_toolchain_resources_exposes_machine_doctor(monkeypatch, tmp_path: Path) -> None:
    manifest = tmp_path / "toolchain_resources" / "global_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{}", encoding="utf-8")
    sitecustomize = tmp_path / "sitecustomize.py"
    sitecustomize.write_text("pass", encoding="utf-8")

    monkeypatch.setenv("SECURITY_GATEWAY_TOOLCHAIN_HOME", str(tmp_path))
    monkeypatch.setenv("SECURITY_GATEWAY_TOOLCHAIN_MANIFEST", str(manifest))
    monkeypatch.setenv("SECURITY_GATEWAY_TOOLCHAIN_CLI", "toolchain-resources")
    monkeypatch.setenv("SECURITY_GATEWAY_TOOLCHAIN_PYTHON_MODULE", "toolchain_resources.runtime")
    monkeypatch.setenv("SECURITY_GATEWAY_TOOLCHAIN_AUTOLOAD", "1")
    monkeypatch.setenv("SECURITY_GATEWAY_TOOLCHAIN_LOADED", "1")
    monkeypatch.setattr("toolchain_resources.doctor.which", lambda name: str(tmp_path / f"{name}.cmd"))
    monkeypatch.setattr("site.getusersitepackages", lambda: str(tmp_path))

    doctor = ToolchainDoctor(toolchain_home=tmp_path, manifest_path=manifest)
    monkeypatch.setattr(doctor, "_persisted_user_env", lambda: {
        "SECURITY_GATEWAY_TOOLCHAIN_HOME": str(tmp_path),
        "SECURITY_GATEWAY_TOOLCHAIN_MANIFEST": str(manifest),
        "SECURITY_GATEWAY_TOOLCHAIN_CLI": "toolchain-resources",
        "SECURITY_GATEWAY_TOOLCHAIN_PYTHON_MODULE": "toolchain_resources.runtime",
        "SECURITY_GATEWAY_TOOLCHAIN_AUTOLOAD": "1",
    })

    result = doctor.run()

    assert result["status"] == "ok"
    assert any(item["check_id"] == "manifest" for item in result["checks"])


def test_toolchain_resources_machine_doctor_can_repair_registration(monkeypatch, tmp_path: Path) -> None:
    manifest = tmp_path / "toolchain_resources" / "global_manifest.json"
    sitecustomize = tmp_path / "sitecustomize.py"
    persisted_env: dict[str, str] = {}

    monkeypatch.setenv("SECURITY_GATEWAY_TOOLCHAIN_LOADED", "1")
    monkeypatch.setattr("toolchain_resources.doctor.which", lambda _name: str(tmp_path / "script.cmd"))
    monkeypatch.setattr("site.getusersitepackages", lambda: str(tmp_path))

    doctor = ToolchainDoctor(toolchain_home=tmp_path, manifest_path=manifest)
    monkeypatch.setattr(doctor, "_persisted_user_env", lambda: dict(persisted_env))
    monkeypatch.setattr(doctor, "_write_user_env", lambda values: persisted_env.update(values))
    monkeypatch.setattr(doctor, "_broadcast_environment_change", lambda: True)
    monkeypatch.setattr(
        doctor,
        "_install_editable_package",
        lambda: doctor._action("editable_install", "Repair Editable Package Install", "skipped", "not needed"),
    )

    result = doctor.repair()

    assert result["status"] == "ok"
    assert manifest.exists()
    assert sitecustomize.exists()
    assert persisted_env["SECURITY_GATEWAY_TOOLCHAIN_HOME"] == str(tmp_path)
    assert any(item["action_id"] == "environment_write" for item in result["actions"])
    assert cast(dict[str, object], result["after"])["status"] == "ok"


def get_runtime_for_jobs(tmp_path: Path) -> ToolchainRuntime:
    forms = LinearAsksFormRegistry(tmp_path / "linear_forms_jobs.json")
    updates = ToolchainUpdateRegistry(tmp_path / "toolchain_updates_jobs.json", linear_forms_path=tmp_path / "linear_forms_jobs.json")
    providers = ToolchainProviderRegistry(settings, linear_forms=forms, updates=updates)
    health = ToolchainHealthRegistry(settings, linear_forms=forms, updates=updates)
    security = ToolchainSecurityRegistry(settings)
    languages = ToolchainLanguageRegistry()
    package_managers = ToolchainPackageManagerRegistry()
    secret_sources = ToolchainSecretSourceRegistry(settings)
    cache_store = ToolchainCacheStore(tmp_path / "toolchain_cache_jobs.json")
    secret_resolver = ToolchainSecretResolver(settings, secret_sources, cache_store)
    provisioning = ToolchainProvisioningRegistry(languages, package_managers)
    version_policy = ToolchainVersionPolicyRegistry(languages, package_managers)
    runtime = ToolchainRuntime(
        linear_forms=forms,
        updates=updates,
        providers=providers,
        health=health,
        security=security,
        languages=languages,
        language_health=ToolchainLanguageHealthRegistry(languages),
        package_managers=package_managers,
        secret_sources=secret_sources,
        cache_store=cache_store,
        secret_resolver=secret_resolver,
        projects=ToolchainProjectRegistry(),
        provisioning=provisioning,
        bootstrap=ToolchainBootstrapExecutor(provisioning),
        package_operations=ToolchainPackageOperations(package_managers),
        version_policy=version_policy,
        provider_templates=ToolchainProviderTemplateRegistry(),
        provider_scaffolder=ToolchainProviderScaffolder(ToolchainProviderTemplateRegistry()),
        reporting=None,  # type: ignore[arg-type]
        policy_enforcement=ToolchainPolicyEnforcementRegistry(security, version_policy, provisioning),
        policy_gates=None,  # type: ignore[arg-type]
        jobs=None,  # type: ignore[arg-type]
        scheduler=None,  # type: ignore[arg-type]
    )
    object.__setattr__(runtime, "reporting", ToolchainReportService(runtime))
    object.__setattr__(runtime, "jobs", ToolchainJobRunner(runtime))
    object.__setattr__(runtime, "policy_gates", ToolchainPolicyGateRegistry(runtime.policy_enforcement))
    object.__setattr__(runtime, "scheduler", ToolchainScheduler(tmp_path / "toolchain_scheduler_jobs.json", runtime.jobs))
    return runtime
