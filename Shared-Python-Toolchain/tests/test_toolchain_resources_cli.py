from __future__ import annotations

from typer.testing import CliRunner

from security_gateway.config import settings
from toolchain_resources import cli
from toolchain_resources.health import ToolchainHealthRegistry
from toolchain_resources.language_health import ToolchainLanguageHealthRegistry
from toolchain_resources.languages import ToolchainLanguageRegistry
from toolchain_resources.linear_forms import LinearAsksFormRegistry
from toolchain_resources.cache_store import ToolchainCacheStore
from toolchain_resources.bootstrap import ToolchainBootstrapExecutor
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
from toolchain_resources.jobs import ToolchainJobRunner
from toolchain_resources.runtime import ToolchainRuntime

runner = CliRunner()


def test_toolchain_resources_docker_cli_reads_catalog(monkeypatch) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    listed = runner.invoke(cli.app, ["docker", "list"])
    detail = runner.invoke(cli.app, ["docker", "get", "sandboxes-2026-03-31"])

    assert listed.exit_code == 0
    assert "offload-ga-2026-04-02" in listed.stdout
    assert detail.exit_code == 0
    assert "Docker Sandboxes for agent execution" in detail.stdout


def test_toolchain_resources_linear_cli_manages_registry(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    monkeypatch.setattr(cli, "linear_forms", LinearAsksFormRegistry(tmp_path / "linear_forms.json"))

    upsert = runner.invoke(
        cli.app,
        [
            "linear",
            "upsert",
            "bug-report",
            "https://linear.app/example/forms/bug-report",
            "--title",
            "Bug report",
        ],
    )
    listed = runner.invoke(cli.app, ["linear", "list"])
    removed = runner.invoke(cli.app, ["linear", "remove", "bug-report"])

    assert upsert.exit_code == 0
    assert "'form_key': 'bug-report'" in upsert.stdout
    assert listed.exit_code == 0
    assert "'title': 'Bug report'" in listed.stdout
    assert removed.exit_code == 0
    assert "'status': 'deleted'" in removed.stdout


def test_toolchain_resources_updates_cli_reads_registry(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    updates = ToolchainUpdateRegistry(
        tmp_path / "toolchain_updates.json",
        linear_forms_path=tmp_path / "linear_forms.json",
    )
    monkeypatch.setattr(cli, "updates", updates)

    synced = runner.invoke(cli.app, ["updates", "sync"])
    listed = runner.invoke(cli.app, ["updates", "list", "--provider", "docker"])
    detail = runner.invoke(cli.app, ["updates", "get", "docker:offload-ga-2026-04-02"])

    assert synced.exit_code == 0
    assert "'discovered':" in synced.stdout
    assert listed.exit_code == 0
    assert "docker:offload-ga-2026-04-02" in listed.stdout
    assert detail.exit_code == 0
    assert "Docker Offload now generally available" in detail.stdout


def test_toolchain_resources_providers_cli_reads_registry(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    updates = ToolchainUpdateRegistry(
        tmp_path / "toolchain_updates.json",
        linear_forms_path=tmp_path / "linear_forms.json",
    )
    updates.sync()
    monkeypatch.setattr(
        cli,
        "providers",
        ToolchainProviderRegistry(settings, linear_forms=LinearAsksFormRegistry(tmp_path / "linear_forms.json"), updates=updates),
    )

    listed = runner.invoke(cli.app, ["providers", "list"])
    detail = runner.invoke(cli.app, ["providers", "get", "docker"])

    assert listed.exit_code == 0
    assert "'provider_id': 'docker'" in listed.stdout
    assert detail.exit_code == 0
    assert "'title': 'Docker'" in detail.stdout


def test_toolchain_resources_health_cli_reads_registry(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    updates = ToolchainUpdateRegistry(
        tmp_path / "toolchain_updates.json",
        linear_forms_path=tmp_path / "linear_forms.json",
    )
    updates.sync()
    monkeypatch.setattr(
        cli,
        "health",
        ToolchainHealthRegistry(settings, linear_forms=LinearAsksFormRegistry(tmp_path / "linear_forms.json"), updates=updates),
    )

    listed = runner.invoke(cli.app, ["health", "list"])
    detail = runner.invoke(cli.app, ["health", "get", "toolchain-updates"])

    assert listed.exit_code == 0
    assert "'check_id': 'toolchain-updates'" in listed.stdout
    assert detail.exit_code == 0
    assert "'title': 'Toolchain Update Feed'" in detail.stdout


def test_toolchain_resources_security_cli_reads_registry(monkeypatch) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    monkeypatch.setattr(settings, "operator_bearer_token", "operator-token")
    monkeypatch.setattr(
        cli,
        "security",
        ToolchainSecurityRegistry(settings),
    )

    listed = runner.invoke(cli.app, ["security", "list", "--status", "ok"])
    detail = runner.invoke(cli.app, ["security", "get", "operator-auth"])

    assert listed.exit_code == 0
    assert "'check_id': 'operator-auth'" in listed.stdout
    assert detail.exit_code == 0
    assert "'title': 'Operator Bearer Authentication'" in detail.stdout


def test_toolchain_resources_languages_cli_reads_registry(monkeypatch) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    monkeypatch.setattr(cli, "languages", ToolchainLanguageRegistry())
    monkeypatch.setattr(cli, "language_health", ToolchainLanguageHealthRegistry(cli.languages))

    listed = runner.invoke(cli.app, ["languages", "list"])
    detail = runner.invoke(cli.app, ["languages", "get", "python"])
    health = runner.invoke(cli.app, ["languages", "health"])
    health_detail = runner.invoke(cli.app, ["languages", "health-get", "python"])

    assert listed.exit_code == 0
    assert "'language_id': 'python'" in listed.stdout
    assert detail.exit_code == 0
    assert "'title': 'Python'" in detail.stdout
    assert health.exit_code == 0
    assert "'language_id': 'python'" in health.stdout
    assert health_detail.exit_code == 0
    assert "'title': 'Python'" in health_detail.stdout


def test_toolchain_resources_packages_cli_reads_registry(monkeypatch) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    monkeypatch.setattr(cli, "package_managers", ToolchainPackageManagerRegistry())

    listed = runner.invoke(cli.app, ["packages", "list"])
    detail = runner.invoke(cli.app, ["packages", "get", "pip"])

    assert listed.exit_code == 0
    assert "'manager_id': 'pip'" in listed.stdout
    assert detail.exit_code == 0
    assert "'title': 'pip'" in detail.stdout


def test_toolchain_resources_secrets_cli_reads_registry(monkeypatch) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    monkeypatch.setattr(settings, "operator_bearer_token", "operator-token")
    monkeypatch.setattr(cli, "secret_sources", ToolchainSecretSourceRegistry(settings))

    listed = runner.invoke(cli.app, ["secrets", "list", "--status", "ok"])
    detail = runner.invoke(cli.app, ["secrets", "get", "operator_bearer"])

    assert listed.exit_code == 0
    assert "'secret_id': 'operator_bearer'" in listed.stdout
    assert detail.exit_code == 0
    assert "'title': 'Operator Bearer Token'" in detail.stdout


def test_toolchain_resources_provision_cli_reads_registry(monkeypatch) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    monkeypatch.setattr(
        cli,
        "provisioning",
        ToolchainProvisioningRegistry(ToolchainLanguageRegistry(), ToolchainPackageManagerRegistry()),
    )

    listed = runner.invoke(cli.app, ["provision", "list"])
    detail = runner.invoke(cli.app, ["provision", "get", "python"])

    assert listed.exit_code == 0
    assert "'target_id': 'python'" in listed.stdout
    assert detail.exit_code == 0
    assert "'title': 'Python'" in detail.stdout


def test_toolchain_resources_ops_cli_reads_registry(monkeypatch) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    monkeypatch.setattr(cli, "package_operations", ToolchainPackageOperations(ToolchainPackageManagerRegistry()))

    listed = runner.invoke(cli.app, ["ops", "list", "--manager", "pip"])
    detail = runner.invoke(cli.app, ["ops", "plan", "pip", "install_deps"])
    dry_run = runner.invoke(cli.app, ["ops", "run", "pip", "install_deps"])

    assert listed.exit_code == 0
    assert "'manager_id': 'pip'" in listed.stdout
    assert detail.exit_code == 0
    assert "'operation': 'install_deps'" in detail.stdout
    assert dry_run.exit_code == 0
    assert "'executed': False" in dry_run.stdout


def test_toolchain_resources_policy_cli_reads_registry(monkeypatch) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    monkeypatch.setattr(
        cli,
        "version_policy",
        ToolchainVersionPolicyRegistry(ToolchainLanguageRegistry(), ToolchainPackageManagerRegistry()),
    )

    listed = runner.invoke(cli.app, ["policy", "evaluate"])
    detail = runner.invoke(cli.app, ["policy", "get", "python"])

    assert listed.exit_code == 0
    assert "'target_id': 'python'" in listed.stdout
    assert detail.exit_code == 0
    assert "'title': 'Python'" in detail.stdout


def test_toolchain_resources_extended_cli_reads_registry(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    cache_store = ToolchainCacheStore(tmp_path / "toolchain_cache.json")
    cache_store.set_entry("updates", "docker", source="sync", summary="Docker feed cached.")
    monkeypatch.setattr(settings, "operator_bearer_token", "operator-token")
    secret_sources = ToolchainSecretSourceRegistry(settings)
    secret_resolver = ToolchainSecretResolver(settings, secret_sources, cache_store)
    provider_templates = ToolchainProviderTemplateRegistry()
    languages = ToolchainLanguageRegistry()
    package_managers = ToolchainPackageManagerRegistry()
    version_policy = ToolchainVersionPolicyRegistry(languages, package_managers)
    monkeypatch.setattr(cli, "cache_store", cache_store)
    monkeypatch.setattr(cli, "secret_resolver", secret_resolver)
    monkeypatch.setattr(cli, "provider_templates", provider_templates)
    monkeypatch.setattr(
        cli,
        "reporting",
        ToolchainReportService(_build_cli_runtime(tmp_path)),
    )
    monkeypatch.setattr(
        cli,
        "policy_enforcement",
        ToolchainPolicyEnforcementRegistry(
            ToolchainSecurityRegistry(settings),
            version_policy,
            ToolchainProvisioningRegistry(languages, package_managers),
        ),
    )

    cache_list = runner.invoke(cli.app, ["cache", "list"])
    resolution = runner.invoke(cli.app, ["resolve", "run", "operator_bearer"])
    template = runner.invoke(cli.app, ["templates", "render", "docker"])
    report = runner.invoke(cli.app, ["report", "markdown"])
    enforcement = runner.invoke(cli.app, ["enforce", "evaluate"])

    assert cache_list.exit_code == 0
    assert "'namespace': 'updates'" in cache_list.stdout
    assert resolution.exit_code == 0
    assert "'status': 'resolved'" in resolution.stdout
    assert template.exit_code == 0
    assert "'provider_id': 'docker'" in template.stdout
    assert report.exit_code == 0
    assert "Toolchain Report" in report.stdout
    assert enforcement.exit_code == 0
    assert "'policy_id': 'security_baseline'" in enforcement.stdout


def test_toolchain_resources_projects_bootstrap_jobs_and_scaffold_cli(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "load_toolchain_runtime", lambda **kwargs: cli.toolchain_runtime)
    project_root = tmp_path / "repo"
    project_root.mkdir()
    (project_root / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")
    monkeypatch.setattr(cli, "projects", ToolchainProjectRegistry())
    provisioning = ToolchainProvisioningRegistry(ToolchainLanguageRegistry(), ToolchainPackageManagerRegistry())
    monkeypatch.setattr(cli, "bootstrap", ToolchainBootstrapExecutor(provisioning))
    monkeypatch.setattr(cli, "provider_scaffolder", ToolchainProviderScaffolder(ToolchainProviderTemplateRegistry()))
    runtime = _build_cli_runtime(tmp_path)
    monkeypatch.setattr(cli, "jobs", ToolchainJobRunner(runtime))
    monkeypatch.setattr(cli, "scheduler", ToolchainScheduler(tmp_path / "toolchain_scheduler_cli.json", cli.jobs))
    monkeypatch.setattr(cli, "policy_gates", ToolchainPolicyGateRegistry(runtime.policy_enforcement))

    listed = runner.invoke(cli.app, ["projects", "list", "--root-path", str(project_root)])
    bootstrap_plan = runner.invoke(cli.app, ["bootstrap", "plan", "python", "--project-path", str(project_root)])
    bootstrap_repair = runner.invoke(cli.app, ["bootstrap", "repair", "python", "--project-path", str(project_root)])
    scaffold = runner.invoke(cli.app, ["templates", "scaffold", "docker", "--target-dir", str(tmp_path / "scaffold")])
    jobs = runner.invoke(cli.app, ["jobs", "run", "snapshot_report"])
    schedule = runner.invoke(cli.app, ["jobs", "schedules", "set", "snapshot_report", "--every-minutes", "30"])
    schedule_start = runner.invoke(cli.app, ["jobs", "schedules", "start", "--poll-seconds", "0.5"])
    schedule_runtime = runner.invoke(cli.app, ["jobs", "schedules", "runtime"])
    schedule_stop = runner.invoke(cli.app, ["jobs", "schedules", "stop"])
    schedule_run = runner.invoke(cli.app, ["jobs", "schedules", "run-due"])
    gates = runner.invoke(cli.app, ["gates", "evaluate"])
    secret_set = runner.invoke(
        cli.app,
        ["resolve", "set", "platform_manager_bearer", "--value", "manager-secret", "--persist", "override"],
    )
    secret_clear = runner.invoke(cli.app, ["resolve", "clear", "platform_manager_bearer"])

    assert listed.exit_code == 0
    assert "'title': 'repo'" in listed.stdout or "'title': 'sample'" in listed.stdout
    assert bootstrap_plan.exit_code == 0
    assert "'status': 'planned'" in bootstrap_plan.stdout
    assert bootstrap_repair.exit_code == 0
    assert "'mode': 'repair'" in bootstrap_repair.stdout
    assert scaffold.exit_code == 0
    assert "'provider_id': 'docker'" in scaffold.stdout
    assert jobs.exit_code == 0
    assert "'status': 'completed'" in jobs.stdout
    assert schedule.exit_code == 0
    assert "'schedule_id': 'snapshot_report'" in schedule.stdout
    assert schedule_start.exit_code == 0
    assert "'running': True" in schedule_start.stdout
    assert schedule_runtime.exit_code == 0
    assert "'poll_seconds': 0.5" in schedule_runtime.stdout
    assert schedule_stop.exit_code == 0
    assert "'running': False" in schedule_stop.stdout
    assert schedule_run.exit_code == 0
    assert "'ran':" in schedule_run.stdout
    assert gates.exit_code == 0
    assert "'gate_id': 'startup'" in gates.stdout
    assert secret_set.exit_code == 0
    assert "'source': 'override_store'" in secret_set.stdout
    assert secret_clear.exit_code == 0
    assert "'status': 'cleared'" in secret_clear.stdout


def test_toolchain_resources_doctor_cli_reads_machine_state(monkeypatch, tmp_path) -> None:
    class StubDoctor:
        def run(self) -> dict[str, object]:
            return {"status": "ok", "summary": "healthy", "checks": [{"check_id": "manifest", "status": "ok"}]}

    monkeypatch.setattr(cli, "doctor", StubDoctor())
    result = runner.invoke(cli.app, ["doctor", "run"])

    assert result.exit_code == 0
    assert "'status': 'ok'" in result.stdout
    assert "'check_id': 'manifest'" in result.stdout


def test_toolchain_resources_doctor_cli_repairs_machine_state(monkeypatch) -> None:
    class StubDoctor:
        def repair(self, *, force_reinstall: bool = False) -> dict[str, object]:
            return {
                "status": "ok",
                "summary": "repaired",
                "force_reinstall": force_reinstall,
                "actions": [{"action_id": "environment_write", "status": "ok"}],
            }

    monkeypatch.setattr(cli, "doctor", StubDoctor())
    result = runner.invoke(cli.app, ["doctor", "repair", "--force-reinstall"])

    assert result.exit_code == 0
    assert "'status': 'ok'" in result.stdout
    assert "'force_reinstall': True" in result.stdout
    assert "'action_id': 'environment_write'" in result.stdout


def _build_cli_runtime(tmp_path) -> ToolchainRuntime:
    forms = LinearAsksFormRegistry(tmp_path / "linear_forms_rt.json")
    updates = ToolchainUpdateRegistry(tmp_path / "toolchain_updates_rt.json", linear_forms_path=tmp_path / "linear_forms_rt.json")
    providers = ToolchainProviderRegistry(settings, linear_forms=forms, updates=updates)
    health = ToolchainHealthRegistry(settings, linear_forms=forms, updates=updates)
    security = ToolchainSecurityRegistry(settings)
    languages = ToolchainLanguageRegistry()
    package_managers = ToolchainPackageManagerRegistry()
    secret_sources = ToolchainSecretSourceRegistry(settings)
    cache_store = ToolchainCacheStore(tmp_path / "toolchain_cache_rt.json")
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
    object.__setattr__(runtime, "scheduler", ToolchainScheduler(tmp_path / "toolchain_scheduler_rt.json", runtime.jobs))
    return runtime
