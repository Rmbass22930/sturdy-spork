"""CLI for shared toolchain resources."""
from __future__ import annotations

import json
from pathlib import Path

from rich import print
import typer

from toolchain_resources.docker_resources import get_docker_resource, list_docker_resources
from toolchain_resources.doctor import ToolchainDoctor
from toolchain_resources.linear_forms import LinearAsksFormUpsert
from toolchain_resources.runtime import load_toolchain_runtime

app = typer.Typer(help="Interact with shared toolchain resources.")
docker_app = typer.Typer(help="Inspect built-in Docker resources.")
linear_app = typer.Typer(help="Manage shared Linear Asks forms.")
updates_app = typer.Typer(help="Inspect and sync the shared update feed.")
providers_app = typer.Typer(help="Inspect shared provider configuration across the toolchain.")
health_app = typer.Typer(help="Inspect shared health and diagnostics across the toolchain.")
security_app = typer.Typer(help="Inspect shared security validation across the toolchain.")
languages_app = typer.Typer(help="Inspect installed programming language toolchains across the toolchain.")
packages_app = typer.Typer(help="Inspect installed package-manager tools across the toolchain.")
secrets_app = typer.Typer(help="Inspect shared secret-source diagnostics across the toolchain.")
resolve_app = typer.Typer(help="Inspect shared secret resolution across the toolchain.")
cache_app = typer.Typer(help="Inspect shared cache metadata across the toolchain.")
projects_app = typer.Typer(help="Detect projects and dependency manifests across the toolchain.")
provision_app = typer.Typer(help="Inspect provisioning actions for missing toolchain components.")
bootstrap_app = typer.Typer(help="Plan or execute bootstrap actions for missing toolchain components.")
ops_app = typer.Typer(help="Plan or run shared package-manager operations.")
policy_app = typer.Typer(help="Evaluate version policy across languages and package managers.")
templates_app = typer.Typer(help="Inspect shared provider-onboarding templates.")
jobs_app = typer.Typer(help="Run shared toolchain jobs.")
schedules_app = typer.Typer(help="Manage persisted background schedules for toolchain jobs.")
report_app = typer.Typer(help="Render a shared toolchain report.")
enforce_app = typer.Typer(help="Evaluate policy enforcement decisions across the toolchain.")
gates_app = typer.Typer(help="Evaluate policy gates for startup, CI, and packaging.")
doctor_app = typer.Typer(help="Verify machine-level toolchain registration and availability.")

toolchain_runtime = load_toolchain_runtime(sync_updates=False)
linear_forms = toolchain_runtime.linear_forms
updates = toolchain_runtime.updates
providers = toolchain_runtime.providers
health = toolchain_runtime.health
security = toolchain_runtime.security
languages = toolchain_runtime.languages
language_health = toolchain_runtime.language_health
package_managers = toolchain_runtime.package_managers
secret_sources = toolchain_runtime.secret_sources
secret_resolver = toolchain_runtime.secret_resolver
cache_store = toolchain_runtime.cache_store
projects = toolchain_runtime.projects
provisioning = toolchain_runtime.provisioning
bootstrap = toolchain_runtime.bootstrap
package_operations = toolchain_runtime.package_operations
version_policy = toolchain_runtime.version_policy
provider_templates = toolchain_runtime.provider_templates
provider_scaffolder = toolchain_runtime.provider_scaffolder
reporting = toolchain_runtime.reporting
policy_enforcement = toolchain_runtime.policy_enforcement
policy_gates = toolchain_runtime.policy_gates
jobs = toolchain_runtime.jobs
scheduler = toolchain_runtime.scheduler
doctor = ToolchainDoctor()


@app.callback()
def toolchain_resources_callback() -> None:
    load_toolchain_runtime(sync_updates=True, apply_safe_only=True)


@docker_app.command("list")
def docker_list() -> None:
    print({"resources": [resource.model_dump(mode="json") for resource in list_docker_resources()]})


@docker_app.command("get")
def docker_get(resource_key: str) -> None:
    resource = get_docker_resource(resource_key)
    if resource is None:
        typer.echo("Docker resource not found.", err=True)
        raise typer.Exit(code=1)
    print({"resource": resource.model_dump(mode="json")})


@linear_app.command("list")
def linear_list(include_disabled: bool = typer.Option(False, "--include-disabled", help="Include disabled forms.")) -> None:
    print(
        {
            "forms": [form.model_dump(mode="json") for form in linear_forms.list_forms(include_disabled=include_disabled)],
            "portal_path": "/linear/asks",
        }
    )


@linear_app.command("upsert")
def linear_upsert(
    form_key: str,
    url: str,
    title: str = typer.Option(..., "--title", help="Display title for the form."),
    description: str | None = typer.Option(None, "--description", help="Optional short description."),
    category: str | None = typer.Option(None, "--category", help="Optional grouping label."),
    team: str | None = typer.Option(None, "--team", help="Optional owning team."),
    enabled: bool = typer.Option(True, "--enabled/--disabled", help="Whether the form should appear in the portal."),
) -> None:
    record = linear_forms.upsert_form(
        LinearAsksFormUpsert(
            form_key=form_key,
            title=title,
            url=url,
            description=description,
            category=category,
            team=team,
            enabled=enabled,
        )
    )
    print({"form": record.model_dump(mode="json")})


@linear_app.command("remove")
def linear_remove(form_key: str) -> None:
    deleted = linear_forms.delete_form(form_key)
    if not deleted:
        typer.echo("Linear form not found.", err=True)
        raise typer.Exit(code=1)
    print({"status": "deleted", "form_key": form_key})


@updates_app.command("sync")
def updates_sync(
    apply_safe_only: bool = typer.Option(True, "--apply-safe-only/--no-apply-safe-only", help="Auto-apply safe catalog updates."),
) -> None:
    print(updates.sync(apply_safe_only=apply_safe_only))


@updates_app.command("list")
def updates_list(
    provider: str | None = typer.Option(None, "--provider", help="Optional provider filter."),
    status: str | None = typer.Option(None, "--status", help="Optional status filter."),
) -> None:
    print({"updates": [record.model_dump(mode="json") for record in updates.list_updates(provider=provider, status=status)]})


@updates_app.command("get")
def updates_get(update_id: str) -> None:
    record = updates.get_update(update_id)
    if record is None:
        typer.echo("Toolchain update not found.", err=True)
        raise typer.Exit(code=1)
    print({"update": record.model_dump(mode="json")})


@updates_app.command("mark-seen")
def updates_mark_seen(update_id: str) -> None:
    record = updates.mark_seen(update_id)
    if record is None:
        typer.echo("Toolchain update not found.", err=True)
        raise typer.Exit(code=1)
    print({"update": record.model_dump(mode="json")})


@providers_app.command("list")
def providers_list() -> None:
    print({"providers": [record.model_dump(mode="json") for record in providers.list_providers()]})


@providers_app.command("get")
def providers_get(provider_id: str) -> None:
    record = providers.get_provider(provider_id)
    if record is None:
        typer.echo("Toolchain provider not found.", err=True)
        raise typer.Exit(code=1)
    print({"provider": record.model_dump(mode="json")})


@health_app.command("list")
def health_list(
    status: str | None = typer.Option(None, "--status", help="Optional health status filter."),
) -> None:
    records = health.list_checks()
    if status:
        records = [record for record in records if record.status == status]
    print({"checks": [record.model_dump(mode="json") for record in records]})


@health_app.command("get")
def health_get(check_id: str) -> None:
    record = health.get_check(check_id)
    if record is None:
        typer.echo("Toolchain health check not found.", err=True)
        raise typer.Exit(code=1)
    print({"check": record.model_dump(mode="json")})


@security_app.command("list")
def security_list(
    status: str | None = typer.Option(None, "--status", help="Optional security status filter."),
    severity: str | None = typer.Option(None, "--severity", help="Optional security severity filter."),
) -> None:
    records = security.list_checks()
    if status:
        records = [record for record in records if record.status == status]
    if severity:
        records = [record for record in records if record.severity == severity]
    print({"checks": [record.model_dump(mode="json") for record in records]})


@security_app.command("get")
def security_get(check_id: str) -> None:
    record = security.get_check(check_id)
    if record is None:
        typer.echo("Toolchain security check not found.", err=True)
        raise typer.Exit(code=1)
    print({"check": record.model_dump(mode="json")})


@languages_app.command("list")
def languages_list(
    status: str | None = typer.Option(None, "--status", help="Optional language availability filter."),
) -> None:
    records = languages.list_languages()
    if status:
        records = [record for record in records if record.status == status]
    print({"languages": [record.model_dump(mode="json") for record in records]})


@languages_app.command("get")
def languages_get(language_id: str) -> None:
    record = languages.get_language(language_id)
    if record is None:
        typer.echo("Toolchain language not found.", err=True)
        raise typer.Exit(code=1)
    print({"language": record.model_dump(mode="json")})


@languages_app.command("health")
def languages_health(
    status: str | None = typer.Option(None, "--status", help="Optional language health status filter."),
) -> None:
    records = language_health.list_checks()
    if status:
        records = [record for record in records if record.status == status]
    print({"checks": [record.model_dump(mode="json") for record in records]})


@languages_app.command("health-get")
def languages_health_get(language_id: str) -> None:
    record = language_health.get_check(language_id)
    if record is None:
        typer.echo("Toolchain language health check not found.", err=True)
        raise typer.Exit(code=1)
    print({"check": record.model_dump(mode="json")})


@packages_app.command("list")
def packages_list(
    status: str | None = typer.Option(None, "--status", help="Optional package-manager availability filter."),
) -> None:
    records = package_managers.list_package_managers()
    if status:
        records = [record for record in records if record.status == status]
    print({"package_managers": [record.model_dump(mode="json") for record in records]})


@packages_app.command("get")
def packages_get(manager_id: str) -> None:
    record = package_managers.get_package_manager(manager_id)
    if record is None:
        typer.echo("Toolchain package manager not found.", err=True)
        raise typer.Exit(code=1)
    print({"package_manager": record.model_dump(mode="json")})


@secrets_app.command("list")
def secrets_list(
    status: str | None = typer.Option(None, "--status", help="Optional secret status filter."),
    source: str | None = typer.Option(None, "--source", help="Optional secret source filter."),
) -> None:
    records = secret_sources.list_secret_sources()
    if status:
        records = [record for record in records if record.status == status]
    if source:
        records = [record for record in records if record.source == source]
    print({"secret_sources": [record.model_dump(mode="json") for record in records]})


@secrets_app.command("get")
def secrets_get(secret_id: str) -> None:
    record = secret_sources.get_secret_source(secret_id)
    if record is None:
        typer.echo("Toolchain secret source not found.", err=True)
        raise typer.Exit(code=1)
    print({"secret_source": record.model_dump(mode="json")})


@resolve_app.command("list")
def resolve_list(
    status: str | None = typer.Option(None, "--status", help="Optional resolution status filter."),
    source: str | None = typer.Option(None, "--source", help="Optional resolution source filter."),
) -> None:
    records = secret_resolver.list_resolutions()
    if status:
        records = [record for record in records if record.status == status]
    if source:
        records = [record for record in records if record.source == source]
    print({"resolutions": [record.model_dump(mode="json") for record in records]})


@resolve_app.command("get")
def resolve_get(secret_id: str) -> None:
    record = secret_resolver.get_resolution(secret_id)
    if record is None:
        typer.echo("Toolchain secret resolution not found.", err=True)
        raise typer.Exit(code=1)
    print({"resolution": record.model_dump(mode="json")})


@resolve_app.command("run")
def resolve_run(secret_id: str) -> None:
    print({"resolution": secret_resolver.resolve_secret(secret_id).model_dump(mode="json")})


@resolve_app.command("set")
def resolve_set(
    secret_id: str,
    value: str = typer.Option(..., "--value", prompt=True, hide_input=True, help="Secret plaintext to store."),
    persist: str = typer.Option("auto", "--persist", help="Storage target: auto, vault, or override."),
) -> None:
    print({"result": secret_resolver.set_secret(secret_id, value, persist=persist).model_dump(mode="json")})


@resolve_app.command("clear")
def resolve_clear(secret_id: str) -> None:
    print({"result": secret_resolver.clear_secret(secret_id).model_dump(mode="json")})


@cache_app.command("list")
def cache_list(
    namespace: str | None = typer.Option(None, "--namespace", help="Optional cache namespace filter."),
    status: str | None = typer.Option(None, "--status", help="Optional cache status filter."),
) -> None:
    print({"entries": [record.model_dump(mode="json") for record in cache_store.list_entries(namespace, status)]})


@cache_app.command("get")
def cache_get(namespace: str, cache_key: str) -> None:
    record = cache_store.get_entry(namespace, cache_key)
    if record is None:
        typer.echo("Toolchain cache entry not found.", err=True)
        raise typer.Exit(code=1)
    print({"entry": record.model_dump(mode="json")})


@projects_app.command("list")
def projects_list(root_path: str = typer.Option(".", "--root-path", help="Root path to scan for projects.")) -> None:
    print({"projects": [record.model_dump(mode="json") for record in projects.detect_projects(root_path)]})


@projects_app.command("get")
def projects_get(project_id: str, root_path: str = typer.Option(".", "--root-path", help="Root path to scan for projects.")) -> None:
    record = projects.get_project(project_id, root_path=root_path)
    if record is None:
        typer.echo("Toolchain project not found.", err=True)
        raise typer.Exit(code=1)
    print({"project": record.model_dump(mode="json")})


@provision_app.command("list")
def provision_list(
    status: str | None = typer.Option(None, "--status", help="Optional provisioning status filter."),
) -> None:
    records = provisioning.list_actions()
    if status:
        records = [record for record in records if record.status == status]
    print({"actions": [record.model_dump(mode="json") for record in records]})


@provision_app.command("get")
def provision_get(target_id: str) -> None:
    record = provisioning.get_action(target_id)
    if record is None:
        typer.echo("Toolchain provisioning action not found.", err=True)
        raise typer.Exit(code=1)
    print({"action": record.model_dump(mode="json")})


@bootstrap_app.command("plan")
def bootstrap_plan(target_id: str, project_path: str = typer.Option(".", "--project-path", help="Working directory for execution.")) -> None:
    print({"result": bootstrap.run(target_id, execute=False, mode="install", project_path=project_path).model_dump(mode="json")})


@bootstrap_app.command("run")
def bootstrap_run(
    target_id: str,
    project_path: str = typer.Option(".", "--project-path", help="Working directory for execution."),
    execute: bool = typer.Option(False, "--execute", help="Run the bootstrap command instead of returning a plan."),
    verify_after: bool = typer.Option(True, "--verify-after/--no-verify-after", help="Run verification after execution."),
    timeout_seconds: float = typer.Option(300.0, "--timeout-seconds", help="Execution timeout in seconds."),
) -> None:
    print(
        {
            "result": bootstrap.run(
                target_id,
                mode="install",
                execute=execute,
                verify_after=verify_after,
                project_path=project_path,
                timeout_seconds=timeout_seconds,
            ).model_dump(mode="json")
        }
    )


@bootstrap_app.command("repair")
def bootstrap_repair(
    target_id: str,
    project_path: str = typer.Option(".", "--project-path", help="Working directory for execution."),
    execute: bool = typer.Option(False, "--execute", help="Run the repair command instead of returning a plan."),
    verify_after: bool = typer.Option(True, "--verify-after/--no-verify-after", help="Run verification after execution."),
    timeout_seconds: float = typer.Option(300.0, "--timeout-seconds", help="Execution timeout in seconds."),
) -> None:
    print(
        {
            "result": bootstrap.run(
                target_id,
                mode="repair",
                execute=execute,
                verify_after=verify_after,
                project_path=project_path,
                timeout_seconds=timeout_seconds,
            ).model_dump(mode="json")
        }
    )


@ops_app.command("list")
def ops_list(manager_id: str | None = typer.Option(None, "--manager", help="Optional package manager filter.")) -> None:
    print({"operations": [record.model_dump(mode="json") for record in package_operations.list_operations(manager_id)]})


@ops_app.command("plan")
def ops_plan(manager_id: str, operation: str) -> None:
    record = package_operations.build_operation(manager_id, operation)
    if record is None:
        typer.echo("Toolchain package operation not found.", err=True)
        raise typer.Exit(code=1)
    print({"operation": record.model_dump(mode="json")})


@ops_app.command("run")
def ops_run(
    manager_id: str,
    operation: str,
    project_path: str = typer.Option(".", "--project-path", help="Project working directory."),
    execute: bool = typer.Option(False, "--execute", help="Run the command instead of returning a dry-run plan."),
    timeout_seconds: float = typer.Option(60.0, "--timeout-seconds", help="Execution timeout in seconds."),
) -> None:
    print(
        package_operations.run_operation(
            manager_id,
            operation,
            project_path=project_path,
            execute=execute,
            timeout_seconds=timeout_seconds,
        )
    )


@policy_app.command("evaluate")
def policy_evaluate(
    status: str | None = typer.Option(None, "--status", help="Optional version-policy status filter."),
) -> None:
    records = version_policy.evaluate()
    if status:
        records = [record for record in records if record.status == status]
    print({"results": [record.model_dump(mode="json") for record in records]})


@policy_app.command("get")
def policy_get(target_id: str) -> None:
    record = version_policy.get_result(target_id)
    if record is None:
        typer.echo("Toolchain version-policy result not found.", err=True)
        raise typer.Exit(code=1)
    print({"result": record.model_dump(mode="json")})


@templates_app.command("list")
def templates_list() -> None:
    print({"templates": [record.model_dump(mode="json") for record in provider_templates.list_templates()]})


@templates_app.command("get")
def templates_get(provider_id: str) -> None:
    record = provider_templates.get_template(provider_id)
    if record is None:
        typer.echo("Toolchain provider template not found.", err=True)
        raise typer.Exit(code=1)
    print({"template": record.model_dump(mode="json")})


@templates_app.command("render")
def templates_render(provider_id: str) -> None:
    payload = provider_templates.render_template(provider_id)
    if payload is None:
        typer.echo("Toolchain provider template not found.", err=True)
        raise typer.Exit(code=1)
    print(payload)


@templates_app.command("scaffold")
def templates_scaffold(
    provider_id: str,
    target_dir: str = typer.Option(".", "--target-dir", help="Directory for scaffolded files."),
    write: bool = typer.Option(False, "--write", help="Write files to disk instead of returning a dry-run scaffold."),
) -> None:
    payload = provider_scaffolder.scaffold(provider_id, target_dir, write=write)
    if payload is None:
        typer.echo("Toolchain provider template not found.", err=True)
        raise typer.Exit(code=1)
    print(payload)


@jobs_app.command("list")
def jobs_list() -> None:
    print({"jobs": [record.model_dump(mode="json") for record in jobs.list_jobs()]})


@jobs_app.command("get")
def jobs_get(job_id: str) -> None:
    record = jobs.get_job(job_id)
    if record is None:
        typer.echo("Toolchain job not found.", err=True)
        raise typer.Exit(code=1)
    print({"job": record.model_dump(mode="json")})


@jobs_app.command("run")
def jobs_run(job_id: str) -> None:
    print(jobs.run_job(job_id))


@schedules_app.command("list")
def schedules_list() -> None:
    print({"schedules": [record.model_dump(mode="json") for record in scheduler.list_schedules()]})


@schedules_app.command("get")
def schedules_get(schedule_id: str) -> None:
    record = scheduler.get_schedule(schedule_id)
    if record is None:
        typer.echo("Toolchain schedule not found.", err=True)
        raise typer.Exit(code=1)
    print({"schedule": record.model_dump(mode="json")})


@schedules_app.command("set")
def schedules_set(
    job_id: str,
    every_minutes: int = typer.Option(..., "--every-minutes", help="How often to run the job."),
    enabled: bool = typer.Option(True, "--enabled/--paused", help="Whether the schedule should be active."),
) -> None:
    print({"schedule": scheduler.upsert_schedule(job_id, interval_minutes=every_minutes, enabled=enabled).model_dump(mode="json")})


@schedules_app.command("remove")
def schedules_remove(schedule_id: str) -> None:
    if not scheduler.remove_schedule(schedule_id):
        typer.echo("Toolchain schedule not found.", err=True)
        raise typer.Exit(code=1)
    print({"status": "deleted", "schedule_id": schedule_id})


@schedules_app.command("run-due")
def schedules_run_due() -> None:
    print(scheduler.run_due_jobs())


@schedules_app.command("runtime")
def schedules_runtime() -> None:
    print({"runtime": scheduler.get_runtime_status().model_dump(mode="json")})


@schedules_app.command("start")
def schedules_start(
    poll_seconds: float = typer.Option(60.0, "--poll-seconds", help="Background poll interval in seconds."),
) -> None:
    print({"runtime": scheduler.start_background_runner(poll_seconds=poll_seconds).model_dump(mode="json")})


@schedules_app.command("stop")
def schedules_stop() -> None:
    print({"runtime": scheduler.stop_background_runner().model_dump(mode="json")})


@report_app.command("json")
def report_json() -> None:
    print(reporting.snapshot())


@report_app.command("markdown")
def report_markdown() -> None:
    typer.echo(reporting.render_markdown())


@report_app.command("write")
def report_write(
    output_path: str,
    format: str = typer.Option("json", "--format", help="Output format: json or markdown."),
) -> None:
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if format == "markdown":
        target.write_text(reporting.render_markdown(), encoding="utf-8")
    else:
        target.write_text(json.dumps(reporting.snapshot(), indent=2, sort_keys=True), encoding="utf-8")
    print({"status": "written", "path": str(target), "format": format})


@enforce_app.command("evaluate")
def enforce_evaluate(
    status: str | None = typer.Option(None, "--status", help="Optional enforcement status filter."),
) -> None:
    records = policy_enforcement.evaluate()
    if status:
        records = [record for record in records if record.status == status]
    print({"results": [record.model_dump(mode="json") for record in records]})


@enforce_app.command("get")
def enforce_get(policy_id: str) -> None:
    record = policy_enforcement.get_result(policy_id)
    if record is None:
        typer.echo("Toolchain policy enforcement result not found.", err=True)
        raise typer.Exit(code=1)
    print({"result": record.model_dump(mode="json")})


@gates_app.command("evaluate")
def gates_evaluate(
    status: str | None = typer.Option(None, "--status", help="Optional gate status filter."),
) -> None:
    records = policy_gates.evaluate()
    if status:
        records = [record for record in records if record.status == status]
    print({"gates": [record.model_dump(mode="json") for record in records]})


@gates_app.command("get")
def gates_get(gate_id: str) -> None:
    record = policy_gates.get_gate(gate_id)
    if record is None:
        typer.echo("Toolchain policy gate not found.", err=True)
        raise typer.Exit(code=1)
    print({"gate": record.model_dump(mode="json")})


@doctor_app.command("run")
def doctor_run() -> None:
    print(doctor.run())


@doctor_app.command("repair")
def doctor_repair(
    force_reinstall: bool = typer.Option(
        False,
        "--force-reinstall",
        help="Force an editable user reinstall even if the script and module surface already look healthy.",
    ),
) -> None:
    print(doctor.repair(force_reinstall=force_reinstall))


app.add_typer(docker_app, name="docker")
app.add_typer(linear_app, name="linear")
app.add_typer(updates_app, name="updates")
app.add_typer(providers_app, name="providers")
app.add_typer(health_app, name="health")
app.add_typer(security_app, name="security")
app.add_typer(languages_app, name="languages")
app.add_typer(packages_app, name="packages")
app.add_typer(secrets_app, name="secrets")
app.add_typer(resolve_app, name="resolve")
app.add_typer(cache_app, name="cache")
app.add_typer(projects_app, name="projects")
app.add_typer(provision_app, name="provision")
app.add_typer(bootstrap_app, name="bootstrap")
app.add_typer(ops_app, name="ops")
app.add_typer(policy_app, name="policy")
app.add_typer(templates_app, name="templates")
app.add_typer(jobs_app, name="jobs")
jobs_app.add_typer(schedules_app, name="schedules")
app.add_typer(report_app, name="report")
app.add_typer(enforce_app, name="enforce")
app.add_typer(gates_app, name="gates")
app.add_typer(doctor_app, name="doctor")
