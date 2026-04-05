"""Typer CLI for the security gateway."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

if __package__ in {None, ""}:  # pragma: no cover - PyInstaller direct execution
    sys.path.append(str(Path(__file__).resolve().parent.parent))

import typer
from rich import print

from security_gateway.alerts import alert_manager, AlertEvent, AlertLevel
from security_gateway.audit import AuditLogger
from security_gateway.automation import AutomationSupervisor, run_forever
from security_gateway.config import settings
from security_gateway.dns import SecureDNSResolver
from security_gateway.endpoint import MalwareScanner
from security_gateway.host_monitor import HostMonitor
from security_gateway.ip_controls import IPBlocklistManager
from security_gateway.investigation_client import RemoteSocInvestigationClient
from security_gateway.models import (
    AccessRequest,
    SocAlertPromoteCaseRequest,
    LinearAsksFormUpsert,
    SocAlertStatus,
    SocAlertUpdate,
    SocCaseEndpointLineageClusterCaseRequest,
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocCaseStatus,
    SocCaseTelemetryClusterCaseRequest,
    SocCaseUpdate,
    SocEndpointQueryCaseRequest,
    SocNetworkEvidenceCaseRequest,
    SocPacketCaptureCaseRequest,
    SocPacketSessionCaseRequest,
    SocSeverity,
)
from security_gateway.pam import VaultClient
from security_gateway.platform import build_platform_profile
from security_gateway.policy import PolicyEngine
from security_gateway.report_browser import run_report_browser
from security_gateway.reports import SecurityReportBuilder
from security_gateway.soc_dashboard import run_remote_soc_dashboard, run_soc_dashboard
from security_gateway.state import dns_security_cache
from security_gateway.tracker_intel import TrackerIntel
from security_gateway.tor import OutboundProxy
from security_gateway.threat_response import ThreatResponseCoordinator
from toolchain_resources.docker_resources import get_docker_resource, list_docker_resources
from toolchain_resources.linear_forms import LinearAsksFormRegistry
from toolchain_resources.runtime import load_toolchain_runtime

app = typer.Typer(help="Interact with the security gateway modules locally.")
soc_remote_app = typer.Typer(help="Interact with a remote SOC manager without the Tk dashboard.")
linear_forms_app = typer.Typer(help="Manage configured Linear Asks web forms.")
docker_resources_app = typer.Typer(help="Inspect built-in Docker resources relevant to the toolchain.")
load_toolchain_runtime(sync_updates=False)

audit_logger = AuditLogger(settings.audit_log_path)
vault = VaultClient(audit_logger=audit_logger)
threat_responder = ThreatResponseCoordinator(vault, audit_logger, alert_manager)
ip_blocklist = IPBlocklistManager(audit_logger=audit_logger)
policy_engine = PolicyEngine(threat_responder=threat_responder, ip_blocklist=ip_blocklist)
resolver = SecureDNSResolver()
proxy = OutboundProxy()
scanner = MalwareScanner(
    feed_cache_path=settings.malware_feed_cache_path,
    feed_urls=settings.malware_feed_urls,
    stale_after_hours=settings.malware_feed_stale_hours,
    disabled_feed_urls=settings.malware_feed_disabled_urls,
    min_hashes_per_source=settings.malware_feed_min_hashes_per_source,
    min_total_hashes=settings.malware_feed_min_total_hashes,
    replace_ratio_floor=settings.malware_feed_replace_ratio_floor,
    verify_tls=settings.malware_feed_verify_tls,
    ca_bundle_path=settings.malware_feed_ca_bundle_path,
    rule_feed_cache_path=settings.malware_rule_feed_cache_path,
    rule_feed_urls=settings.malware_rule_feed_urls,
    rule_feed_stale_after_hours=settings.malware_rule_feed_stale_hours,
    disabled_rule_feed_urls=settings.malware_rule_feed_disabled_urls,
    min_rules_per_source=settings.malware_rule_feed_min_rules_per_source,
    min_total_rules=settings.malware_rule_feed_min_total_rules,
    rule_replace_ratio_floor=settings.malware_rule_feed_replace_ratio_floor,
    rule_feed_verify_tls=settings.malware_rule_feed_verify_tls,
    rule_feed_ca_bundle_path=settings.malware_rule_feed_ca_bundle_path,
)
report_builder = SecurityReportBuilder()
tracker_intel = TrackerIntel(
    extra_domains_path=settings.tracker_domain_list_path,
    feed_cache_path=settings.tracker_feed_cache_path,
    feed_urls=settings.tracker_feed_urls,
    stale_after_hours=settings.tracker_feed_stale_hours,
    disabled_feed_urls=settings.tracker_feed_disabled_urls,
    min_domains_per_source=settings.tracker_feed_min_domains_per_source,
    min_total_domains=settings.tracker_feed_min_total_domains,
    replace_ratio_floor=settings.tracker_feed_replace_ratio_floor,
    verify_tls=settings.tracker_feed_verify_tls,
    ca_bundle_path=settings.tracker_feed_ca_bundle_path,
)
host_monitor = HostMonitor(
    state_path=settings.host_monitor_state_path,
    system_drive=settings.host_monitor_system_drive,
    disk_free_percent_threshold=settings.host_monitor_disk_free_percent_threshold,
)
linear_forms = LinearAsksFormRegistry(settings.linear_asks_forms_path)


@app.callback()
def security_gateway_callback() -> None:
    load_toolchain_runtime(sync_updates=True, apply_safe_only=True)


def _seed_offline_feeds() -> None:
    if settings.tracker_offline_seed_path and not Path(settings.tracker_feed_cache_path).exists():
        tracker_intel.import_feed_cache(settings.tracker_offline_seed_path)
    if settings.malware_offline_hash_seed_path and not Path(settings.malware_feed_cache_path).exists():
        scanner.import_feed_cache(settings.malware_offline_hash_seed_path)
    if settings.malware_offline_rule_seed_path and not Path(settings.malware_rule_feed_cache_path).exists():
        scanner.import_rule_feed_cache(settings.malware_offline_rule_seed_path)


_seed_offline_feeds()


def _is_local_manager_url(url: str) -> bool:
    parsed = urlparse(url)
    hostname = parsed.hostname or (url.split("/", 1)[0].split(":", 1)[0] if "://" not in url else "")
    normalized = str(hostname or "").strip().strip("[]").casefold()
    return normalized in {"localhost", "127.0.0.1", "::1"}


@app.command()
def evaluate(policy_file: Path) -> None:
    """Evaluate a JSON access request file."""
    payload = json.loads(policy_file.read_text())
    decision = policy_engine.evaluate(AccessRequest.model_validate(payload))
    print({"decision": decision.decision.value, "risk_score": decision.risk_score, "reasons": decision.reasons})
    if decision.issued_challenge:
        print({"challenge_id": decision.issued_challenge})


@app.command()
def dns(hostname: str, record_type: str = "A") -> None:
    result = resolver.resolve(hostname, record_type)
    dns_security_cache.record(hostname, result.secure)
    print({"secure": result.secure, "records": [record.__dict__ for record in result.records]})


@app.command()
def pam_store(name: str, secret: str) -> None:
    vault.store_secret(name, secret)
    print({"status": "stored", "name": name, "metrics": vault.get_metrics()})


@app.command()
def pam_checkout(name: str, ttl_minutes: int = typer.Option(15, help="Lease duration in minutes")) -> None:
    lease = vault.checkout(name, ttl_minutes)
    print(lease.model_dump())


@app.command()
def pam_rotate() -> None:
    vault.force_rotate()
    print({"status": "rotated", "current_key": vault.current_key_id})


@app.command()
def pam_metrics() -> None:
    print(vault.get_metrics())


@app.command()
def proxy_request(url: str, via: str = typer.Option("tor", help="tor|warp|direct")) -> None:
    try:
        response = proxy.request("GET", url, via=via)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    print({"status_code": response.status_code, "preview": response.body[:120]})


@app.command()
def proxy_health() -> None:
    print(proxy.health())


@app.command("ip-block")
def ip_block(
    ip: str,
    reason: str = typer.Option("manual operator block", help="Why the IP is being blocked"),
    duration_minutes: int | None = typer.Option(None, help="Optional automatic expiry in minutes"),
) -> None:
    entry = ip_blocklist.block(ip, reason=reason, blocked_by="cli", duration_minutes=duration_minutes)
    print({"status": "blocked", "entry": entry.__dict__})


@app.command("ip-unblock")
def ip_unblock(ip: str, reason: str = typer.Option("operator review cleared", help="Why the IP is being unblocked")) -> None:
    removed = ip_blocklist.unblock(ip, reason=reason, unblocked_by="cli")
    if not removed:
        raise typer.Exit(code=1)
    print({"status": "unblocked", "ip": ip, "reason": reason})


@app.command("ip-list")
def ip_list() -> None:
    print({"blocked_ips": [entry.__dict__ for entry in ip_blocklist.list_entries()]})


@app.command("ip-promote")
def ip_promote(
    ip: str,
    reason: str = typer.Option("confirmed attacker - permanent block", help="Reason to convert the block to permanent"),
) -> None:
    entry = ip_blocklist.promote_to_permanent(ip, reason=reason, promoted_by="cli")
    if not entry:
        raise typer.Exit(code=1)
    print({"status": "promoted", "entry": entry.__dict__})


@app.command()
def scan(path: Path) -> None:
    malicious, verdict = scanner.scan_path(path)
    print({"malicious": malicious, "verdict": verdict})


@app.command("malware-feed-status")
def malware_feed_status() -> None:
    print(scanner.feed_status())


@app.command("malware-feed-refresh")
def malware_feed_refresh(
    url: list[str] | None = typer.Option(None, "--url", help="Override malware feed URLs for this refresh run"),
) -> None:
    try:
        result = scanner.refresh_feed_cache(url)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    print({"status": "refreshed", **result})


@app.command("malware-feed-import")
def malware_feed_import(path: Path) -> None:
    try:
        result = scanner.import_feed_cache(path)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    print({"status": "imported", **result})


@app.command("malware-rule-feed-status")
def malware_rule_feed_status() -> None:
    print(scanner.rule_feed_status())


@app.command("malware-rule-feed-refresh")
def malware_rule_feed_refresh(
    url: list[str] | None = typer.Option(None, "--url", help="Override malware rule feed URLs for this refresh run"),
) -> None:
    try:
        result = scanner.refresh_rule_feed_cache(url)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    print({"status": "refreshed", **result})


@app.command("malware-rule-feed-import")
def malware_rule_feed_import(path: Path) -> None:
    try:
        result = scanner.import_rule_feed_cache(path)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    print({"status": "imported", **result})


@app.command()
def automation_run() -> None:
    """Run automation supervisor in the foreground."""
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit_logger,
        alert_manager=alert_manager,
        tracker_intel=tracker_intel,
        malware_scanner=scanner,
        interval_seconds=settings.automation_interval_seconds,
        tracker_feed_refresh_enabled=settings.automation_tracker_feed_refresh_enabled,
        tracker_feed_refresh_every_ticks=settings.automation_tracker_feed_refresh_every_ticks,
        malware_feed_refresh_enabled=settings.automation_malware_feed_refresh_enabled,
        malware_feed_refresh_every_ticks=settings.automation_malware_feed_refresh_every_ticks,
        malware_rule_feed_refresh_enabled=settings.automation_malware_rule_feed_refresh_enabled,
        malware_rule_feed_refresh_every_ticks=settings.automation_malware_rule_feed_refresh_every_ticks,
        host_monitor=host_monitor,
        host_monitor_enabled=settings.host_monitor_enabled,
        host_monitor_every_ticks=settings.host_monitor_every_ticks,
    )
    print("Starting automation supervisor. Press Ctrl+C to stop.")
    run_forever(supervisor)


@app.command()
def alert_test(
    level: AlertLevel = typer.Option(AlertLevel.info, case_sensitive=False),
    title: str = "Test Alert",
    message: str = "SecurityGateway alert test",
) -> None:
    event = AlertEvent(level=level, title=title, message=message, context={"source": "cli"})
    alert_manager.emit(event)
    print("Alert dispatched.")


@app.command()
def mfa_register_webauthn(user_id: str, credential_id: str, public_key_b64: str) -> None:
    """Register a WebAuthn/Passkey credential (Ed25519 public key in base64)."""
    policy_engine.mfa_service.register_webauthn(user_id, credential_id, public_key_b64)
    print({"status": "registered", "user": user_id, "credential": credential_id})


@app.command("report-pdf")
def report_pdf(
    output: Path | None = typer.Option(None, help="Write the PDF to this path"),
    max_events: int = typer.Option(25, help="Number of recent audit events to include"),
    time_window_hours: float | None = typer.Option(None, help="Only include events from the last N hours"),
    min_risk_score: float = typer.Option(0.0, help="Only include access-evaluate entries at or above this risk score"),
    include_blocked_ips: bool = typer.Option(True, "--blocked/--no-blocked", help="Include the blocked IP section"),
    include_potential_blocked_ips: bool = typer.Option(True, "--potential/--no-potential", help="Include the potential blocked IP section"),
    include_recent_events: bool = typer.Option(True, "--events/--no-events", help="Include the recent audit events section"),
    open_file: bool = typer.Option(False, "--open", help="Open the PDF after generating it"),
) -> None:
    target = report_builder.write_summary_pdf(
        output,
        max_events=max_events,
        time_window_hours=time_window_hours,
        min_risk_score=min_risk_score,
        include_blocked_ips=include_blocked_ips,
        include_potential_blocked_ips=include_potential_blocked_ips,
        include_recent_events=include_recent_events,
    )
    print({"status": "written", "path": str(target)})
    if open_file:
        try:
            os.startfile(target)  # type: ignore[attr-defined]
        except OSError as exc:
            typer.echo(f"Unable to open generated report: {exc}", err=True)
            raise typer.Exit(code=1) from exc


@app.command("report-list")
def report_list() -> None:
    print({"reports": report_builder.list_saved_reports()})


@app.command("report-open")
def report_open(
    name: str | None = typer.Argument(None, help="Saved report file name. Defaults to the newest report."),
    print_after_open: bool = typer.Option(False, "--print", help="Send the report to the default printer instead of opening it"),
) -> None:
    action = "print" if print_after_open else "open"
    try:
        target = report_builder.open_saved_report(name, action=action)
    except FileNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    except OSError as exc:
        typer.echo(f"Unable to {action} report: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    print({"status": action, "path": str(target)})


@app.command("report-browser")
def report_browser() -> None:
    run_report_browser(report_builder)


def _resolve_dashboard_connection(
    *,
    remote: bool,
    manager_url: str | None,
    bearer_token: str | None,
    timeout_seconds: float | None,
) -> tuple[bool, str | None, str | None, float]:
    resolved_remote = remote or bool(manager_url) or bool(settings.platform_manager_url)
    resolved_url = manager_url or settings.platform_manager_url
    resolved_token = bearer_token or settings.platform_manager_bearer_token
    resolved_timeout = timeout_seconds if timeout_seconds is not None else settings.platform_manager_timeout_seconds
    if resolved_remote and not resolved_url:
        typer.echo(
            "Remote dashboard requested but no manager URL is configured. "
            "Set SECURITY_GATEWAY_PLATFORM_MANAGER_URL or pass --manager-url.",
            err=True,
        )
        raise typer.Exit(code=1)
    if resolved_remote and resolved_url and not _is_local_manager_url(resolved_url) and not resolved_token:
        typer.echo(
            "Remote dashboard requested for a non-local manager URL but no bearer token is configured. "
            "Set SECURITY_GATEWAY_PLATFORM_MANAGER_BEARER_TOKEN or pass --bearer-token.",
            err=True,
        )
        raise typer.Exit(code=1)
    return resolved_remote, resolved_url, resolved_token, resolved_timeout


def _open_configured_soc_dashboard(
    *,
    remote: bool = False,
    manager_url: str | None = None,
    bearer_token: str | None = None,
    timeout_seconds: float | None = None,
) -> None:
    resolved_remote, resolved_url, resolved_token, resolved_timeout = _resolve_dashboard_connection(
        remote=remote,
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    if resolved_remote:
        assert resolved_url is not None
        run_remote_soc_dashboard(
            base_url=resolved_url,
            bearer_token=resolved_token,
            timeout_seconds=resolved_timeout,
        )
        return
    run_soc_dashboard()


def _remote_investigation_client(
    *,
    manager_url: str | None = None,
    bearer_token: str | None = None,
    timeout_seconds: float | None = None,
) -> RemoteSocInvestigationClient:
    try:
        return RemoteSocInvestigationClient.from_settings(
            manager_url=manager_url,
            bearer_token=bearer_token,
            timeout_seconds=timeout_seconds,
        )
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


def _emit_remote_output(payload: Any, *, json_output: bool = False) -> None:
    if json_output:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return
    print(payload)


def _parse_cli_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


@app.command("soc-dashboard")
def soc_dashboard(
    remote: bool = typer.Option(
        False,
        "--remote",
        help="Open the dashboard against a remote manager. Defaults to the configured platform manager when present.",
    ),
    manager_url: str | None = typer.Option(
        None,
        "--manager-url",
        help="Remote manager base URL. Defaults to SECURITY_GATEWAY_PLATFORM_MANAGER_URL.",
    ),
    bearer_token: str | None = typer.Option(
        None,
        "--bearer-token",
        help="Remote operator token. Defaults to SECURITY_GATEWAY_PLATFORM_MANAGER_BEARER_TOKEN.",
    ),
    timeout_seconds: float | None = typer.Option(
        None,
        "--timeout-seconds",
        min=0.1,
        help="Remote dashboard HTTP timeout in seconds. Defaults to SECURITY_GATEWAY_PLATFORM_MANAGER_TIMEOUT_SECONDS.",
    ),
) -> None:
    _open_configured_soc_dashboard(
        remote=remote,
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )


@soc_remote_app.command("dashboard")
def soc_remote_dashboard(
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.dashboard(), json_output=json_output)


@soc_remote_app.command("get-alert")
def soc_remote_get_alert(
    alert_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.get_alert(alert_id), json_output=json_output)


@soc_remote_app.command("list-alerts")
def soc_remote_list_alerts(
    status: SocAlertStatus | None = typer.Option(None, "--status", case_sensitive=False, help="Optional alert status filter."),
    severity: SocSeverity | None = typer.Option(None, "--severity", case_sensitive=False, help="Optional alert severity filter."),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional alert assignee filter."),
    correlation_rule: str | None = typer.Option(None, "--correlation-rule", help="Optional correlation rule filter."),
    linked_case_state: str | None = typer.Option(None, "--linked-case-state", help="linked|unlinked"),
    sort: str = typer.Option("updated_desc", "--sort", help="updated_desc|updated_asc|severity_desc|severity_asc"),
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of alerts to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_alerts(
            status=status,
            severity=severity,
            assignee=assignee,
            correlation_rule=correlation_rule,
            linked_case_state=linked_case_state,
            sort=sort,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("get-case")
def soc_remote_get_case(
    case_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.get_case(case_id), json_output=json_output)


@soc_remote_app.command("list-case-alerts")
def soc_remote_list_case_alerts(
    case_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.list_case_linked_alerts(case_id), json_output=json_output)


@soc_remote_app.command("list-case-events")
def soc_remote_list_case_events(
    case_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.list_case_source_events(case_id), json_output=json_output)


@soc_remote_app.command("list-case-rule-alerts")
def soc_remote_list_case_rule_alerts(
    case_id: str,
    group_key: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.list_case_rule_alerts(case_id, group_key), json_output=json_output)


@soc_remote_app.command("list-case-rule-evidence-events")
def soc_remote_list_case_rule_evidence_events(
    case_id: str,
    group_key: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.list_case_rule_evidence_events(case_id, group_key), json_output=json_output)


@soc_remote_app.command("list-cases")
def soc_remote_list_cases(
    status: SocCaseStatus | None = typer.Option(None, "--status", case_sensitive=False, help="Optional case status filter."),
    severity: SocSeverity | None = typer.Option(None, "--severity", case_sensitive=False, help="Optional case severity filter."),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional case assignee filter."),
    sort: str = typer.Option("updated_desc", "--sort", help="updated_desc|updated_asc|severity_desc|severity_asc"),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_cases(status=status, severity=severity, assignee=assignee, sort=sort),
        json_output=json_output,
    )


@soc_remote_app.command("list-case-timeline-events")
def soc_remote_list_case_timeline_events(
    case_id: str,
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of timeline rows to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_case_endpoint_timeline(
            case_id,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-case-lineage-events")
def soc_remote_list_case_lineage_events(
    case_id: str,
    cluster_key: str,
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of lineage events to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_case_endpoint_lineage_events(case_id, cluster_key=cluster_key, limit=limit),
        json_output=json_output,
    )


@soc_remote_app.command("get-rule")
def soc_remote_get_rule(
    rule_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.get_detection_rule(rule_id), json_output=json_output)


@soc_remote_app.command("list-rule-groups")
def soc_remote_list_rule_groups(
    rule_id: str,
    kind: str = typer.Option("alerts", "--kind", help="alerts|evidence"),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    normalized_kind = str(kind).strip().casefold()
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    if normalized_kind == "alerts":
        _emit_remote_output(client.list_detection_rule_alert_groups(rule_id), json_output=json_output)
        return
    if normalized_kind == "evidence":
        _emit_remote_output(client.list_detection_rule_evidence_groups(rule_id), json_output=json_output)
        return
    typer.echo("Rule group kind must be 'alerts' or 'evidence'.", err=True)
    raise typer.Exit(code=1)


@soc_remote_app.command("event-index-status")
def soc_remote_event_index_status(
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.get_event_index_status(), json_output=json_output)


@soc_remote_app.command("rebuild-event-index")
def soc_remote_rebuild_event_index(
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.rebuild_event_index(), json_output=json_output)


@soc_remote_app.command("query-events")
def soc_remote_query_events(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of SOC events to return."),
    severity: SocSeverity | None = typer.Option(None, "--severity", case_sensitive=False, help="Optional severity filter."),
    event_type: str | None = typer.Option(None, "--event-type", help="Optional event-type filter."),
    source: str | None = typer.Option(None, "--source", help="Optional source filter."),
    tag: str | None = typer.Option(None, "--tag", help="Optional tag filter."),
    text: str | None = typer.Option(None, "--text", help="Optional text filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    filename: str | None = typer.Option(None, "--filename", help="Optional filename filter."),
    artifact_path: str | None = typer.Option(None, "--artifact-path", help="Optional artifact-path filter."),
    session_key: str | None = typer.Option(None, "--session-key", help="Optional session-key filter."),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device-id filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    flow_id: str | None = typer.Option(None, "--flow-id", help="Optional flow-id filter."),
    service_name: str | None = typer.Option(None, "--service-name", help="Optional service-name filter."),
    application_protocol: str | None = typer.Option(None, "--application-protocol", help="Optional application-protocol filter."),
    local_ip: str | None = typer.Option(None, "--local-ip", help="Optional local IP filter."),
    local_port: str | None = typer.Option(None, "--local-port", help="Optional local port filter."),
    remote_port: str | None = typer.Option(None, "--remote-port", help="Optional remote port filter."),
    protocol: str | None = typer.Option(None, "--protocol", help="Optional protocol filter."),
    state: str | None = typer.Option(None, "--state", help="Optional state filter."),
    close_reason: str | None = typer.Option(None, "--close-reason", help="Optional VPN close-reason filter."),
    reject_code: str | None = typer.Option(None, "--reject-code", help="Optional RADIUS reject-code filter."),
    start_at: str | None = typer.Option(None, "--start-at", help="Optional ISO-8601 start time filter."),
    end_at: str | None = typer.Option(None, "--end-at", help="Optional ISO-8601 end time filter."),
    linked_alert_state: str | None = typer.Option(None, "--linked-alert-state", help="linked|unlinked"),
    sort: str = typer.Option("created_desc", "--sort", help="created_desc|created_asc|severity_desc|severity_asc"),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.query_events(
            limit=limit,
            severity=severity,
            event_type=event_type,
            source=source,
            tag=tag,
            text=text,
            remote_ip=remote_ip,
            hostname=hostname,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            signer_name=signer_name,
            sha256=sha256,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            close_reason=close_reason,
            reject_code=reject_code,
            start_at=start_at,
            end_at=end_at,
            linked_alert_state=linked_alert_state,
            sort=sort,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("hunt")
def soc_remote_hunt(
    query: str | None = typer.Option(None, "--query", help="Optional free-text hunt query."),
    severity: SocSeverity | None = typer.Option(None, "--severity", case_sensitive=False, help="Optional severity filter."),
    tag: str | None = typer.Option(None, "--tag", help="Optional tag filter."),
    source: str | None = typer.Option(None, "--source", help="Optional source filter."),
    event_type: str | None = typer.Option(None, "--event-type", help="Optional event-type filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    filename: str | None = typer.Option(None, "--filename", help="Optional filename filter."),
    artifact_path: str | None = typer.Option(None, "--artifact-path", help="Optional artifact-path filter."),
    session_key: str | None = typer.Option(None, "--session-key", help="Optional session-key filter."),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device-id filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    flow_id: str | None = typer.Option(None, "--flow-id", help="Optional flow-id filter."),
    service_name: str | None = typer.Option(None, "--service-name", help="Optional service-name filter."),
    application_protocol: str | None = typer.Option(None, "--application-protocol", help="Optional application-protocol filter."),
    local_ip: str | None = typer.Option(None, "--local-ip", help="Optional local IP filter."),
    local_port: str | None = typer.Option(None, "--local-port", help="Optional local port filter."),
    remote_port: str | None = typer.Option(None, "--remote-port", help="Optional remote port filter."),
    protocol: str | None = typer.Option(None, "--protocol", help="Optional protocol filter."),
    state: str | None = typer.Option(None, "--state", help="Optional state filter."),
    close_reason: str | None = typer.Option(None, "--close-reason", help="Optional VPN close-reason filter."),
    reject_code: str | None = typer.Option(None, "--reject-code", help="Optional RADIUS reject-code filter."),
    start_at: str | None = typer.Option(None, "--start-at", help="Optional ISO-8601 start time filter."),
    end_at: str | None = typer.Option(None, "--end-at", help="Optional ISO-8601 end time filter."),
    facet_limit: int = typer.Option(5, "--facet-limit", min=1, help="Maximum facet values per dimension."),
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum event rows to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.hunt(
            query=query,
            severity=severity,
            tag=tag,
            source=source,
            event_type=event_type,
            remote_ip=remote_ip,
            hostname=hostname,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            signer_name=signer_name,
            sha256=sha256,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            close_reason=close_reason,
            reject_code=reject_code,
            start_at=start_at,
            end_at=end_at,
            facet_limit=facet_limit,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("query-endpoint-telemetry")
def soc_remote_query_endpoint_telemetry(
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of endpoint telemetry records to return."),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    filename: str | None = typer.Option(None, "--filename", help="Optional filename filter."),
    artifact_path: str | None = typer.Option(None, "--artifact-path", help="Optional artifact-path filter."),
    local_ip: str | None = typer.Option(None, "--local-ip", help="Optional local IP filter."),
    local_port: str | None = typer.Option(None, "--local-port", help="Optional local port filter."),
    remote_port: str | None = typer.Option(None, "--remote-port", help="Optional remote port filter."),
    protocol: str | None = typer.Option(None, "--protocol", help="Optional protocol filter."),
    state: str | None = typer.Option(None, "--state", help="Optional state filter."),
    document_type: str | None = typer.Option(None, "--document-type", help="Optional endpoint document-type filter."),
    parent_process_name: str | None = typer.Option(None, "--parent-process-name", help="Optional parent-process filter."),
    reputation: str | None = typer.Option(None, "--reputation", help="Optional reputation filter."),
    risk_flag: str | None = typer.Option(None, "--risk-flag", help="Optional risk-flag filter."),
    verdict: str | None = typer.Option(None, "--verdict", help="Optional verdict filter."),
    operation: str | None = typer.Option(None, "--operation", help="Optional operation filter."),
    file_extension: str | None = typer.Option(None, "--file-extension", help="Optional file-extension filter."),
    start_at: str | None = typer.Option(None, "--start-at", help="Optional ISO-8601 start time filter."),
    end_at: str | None = typer.Option(None, "--end-at", help="Optional ISO-8601 end time filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.query_endpoint_telemetry(
            limit=limit,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            filename=filename,
            artifact_path=artifact_path,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            document_type=document_type,
            parent_process_name=parent_process_name,
            reputation=reputation,
            risk_flag=risk_flag,
            verdict=verdict,
            operation=operation,
            file_extension=file_extension,
            start_at=start_at,
            end_at=end_at,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("create-case-from-endpoint-query")
def soc_remote_create_case_from_endpoint_query(
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of endpoint telemetry records to promote."),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    filename: str | None = typer.Option(None, "--filename", help="Optional filename filter."),
    artifact_path: str | None = typer.Option(None, "--artifact-path", help="Optional artifact-path filter."),
    local_ip: str | None = typer.Option(None, "--local-ip", help="Optional local IP filter."),
    local_port: str | None = typer.Option(None, "--local-port", help="Optional local port filter."),
    remote_port: str | None = typer.Option(None, "--remote-port", help="Optional remote port filter."),
    protocol: str | None = typer.Option(None, "--protocol", help="Optional protocol filter."),
    state: str | None = typer.Option(None, "--state", help="Optional state filter."),
    document_type: str | None = typer.Option(None, "--document-type", help="Optional endpoint document-type filter."),
    parent_process_name: str | None = typer.Option(None, "--parent-process-name", help="Optional parent-process filter."),
    reputation: str | None = typer.Option(None, "--reputation", help="Optional reputation filter."),
    risk_flag: str | None = typer.Option(None, "--risk-flag", help="Optional risk-flag filter."),
    verdict: str | None = typer.Option(None, "--verdict", help="Optional verdict filter."),
    operation: str | None = typer.Option(None, "--operation", help="Optional operation filter."),
    file_extension: str | None = typer.Option(None, "--file-extension", help="Optional file-extension filter."),
    start_at: str | None = typer.Option(None, "--start-at", help="Optional ISO-8601 start time filter."),
    end_at: str | None = typer.Option(None, "--end-at", help="Optional ISO-8601 end time filter."),
    title: str | None = typer.Option(None, "--title", help="Optional case title override."),
    summary: str | None = typer.Option(None, "--summary", help="Optional case summary override."),
    severity: SocSeverity | None = typer.Option(None, "--severity", help="Optional case severity."),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional case assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.create_case_from_endpoint_query(
            SocEndpointQueryCaseRequest(
                limit=limit,
                device_id=device_id,
                process_name=process_name,
                process_guid=process_guid,
                remote_ip=remote_ip,
                signer_name=signer_name,
                sha256=sha256,
                filename=filename,
                artifact_path=artifact_path,
                local_ip=local_ip,
                local_port=local_port,
                remote_port=remote_port,
                protocol=protocol,
                state=state,
                document_type=document_type,
                parent_process_name=parent_process_name,
                reputation=reputation,
                risk_flag=risk_flag,
                verdict=verdict,
                operation=operation,
                file_extension=file_extension,
                start_at=_parse_cli_datetime(start_at),
                end_at=_parse_cli_datetime(end_at),
                title=title,
                summary=summary,
                severity=severity,
                assignee=assignee,
            )
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-flows")
def soc_remote_list_network_flows(
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    flow_id: str | None = typer.Option(None, "--flow-id", help="Optional stable flow ID filter."),
    service_name: str | None = typer.Option(None, "--service-name", help="Optional service-name filter."),
    application_protocol: str | None = typer.Option(None, "--application-protocol", help="Optional app protocol filter."),
    local_ip: str | None = typer.Option(None, "--local-ip", help="Optional local IP filter."),
    local_port: int | None = typer.Option(None, "--local-port", help="Optional local port filter."),
    remote_port: int | None = typer.Option(None, "--remote-port", help="Optional remote port filter."),
    protocol: str | None = typer.Option(None, "--protocol", help="Optional protocol filter."),
    state: str | None = typer.Option(None, "--state", help="Optional connection state filter."),
    limit: int = typer.Option(250, "--limit", min=1, help="Maximum number of flow records to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_flows(
            remote_ip=remote_ip,
            process_name=process_name,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-dns")
def soc_remote_list_network_dns(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of DNS telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_dns(limit=limit, remote_ip=remote_ip, hostname=hostname),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-http")
def soc_remote_list_network_http(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of HTTP telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_http(limit=limit, remote_ip=remote_ip, hostname=hostname),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-tls")
def soc_remote_list_network_tls(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of TLS telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_tls(limit=limit, remote_ip=remote_ip, hostname=hostname),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-certificates")
def soc_remote_list_network_certificates(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of certificate telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_certificates(limit=limit, remote_ip=remote_ip, hostname=hostname),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-proxy")
def soc_remote_list_network_proxy(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of proxy telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    username: str | None = typer.Option(None, "--username", help="Optional username filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_proxy(limit=limit, remote_ip=remote_ip, hostname=hostname, username=username),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-auth")
def soc_remote_list_network_auth(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of auth telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    username: str | None = typer.Option(None, "--username", help="Optional username filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_auth(limit=limit, remote_ip=remote_ip, username=username, hostname=hostname),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-vpn")
def soc_remote_list_network_vpn(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of VPN telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    username: str | None = typer.Option(None, "--username", help="Optional username filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_vpn(limit=limit, remote_ip=remote_ip, username=username, hostname=hostname),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-dhcp")
def soc_remote_list_network_dhcp(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of DHCP telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    assigned_ip: str | None = typer.Option(None, "--assigned-ip", help="Optional assigned IP filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_dhcp(limit=limit, remote_ip=remote_ip, hostname=hostname, assigned_ip=assigned_ip),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-directory-auth")
def soc_remote_list_network_directory_auth(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of directory-auth telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    username: str | None = typer.Option(None, "--username", help="Optional username filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_directory_auth(limit=limit, remote_ip=remote_ip, username=username, hostname=hostname),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-radius")
def soc_remote_list_network_radius(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of RADIUS telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    username: str | None = typer.Option(None, "--username", help="Optional username filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_radius(limit=limit, remote_ip=remote_ip, username=username, hostname=hostname),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-nac")
def soc_remote_list_network_nac(
    limit: int = typer.Option(100, "--limit", min=1, help="Maximum number of NAC telemetry records to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    hostname: str | None = typer.Option(None, "--hostname", help="Optional hostname filter."),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device ID filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_telemetry_nac(limit=limit, remote_ip=remote_ip, hostname=hostname, device_id=device_id),
        json_output=json_output,
    )


@soc_remote_app.command("list-packet-sessions")
def soc_remote_list_packet_sessions(
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of packet sessions to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_packet_sessions(limit=limit, remote_ip=remote_ip),
        json_output=json_output,
    )


@soc_remote_app.command("list-network-evidence")
def soc_remote_list_network_evidence(
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of network evidence rows to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_network_evidence(limit=limit, remote_ip=remote_ip),
        json_output=json_output,
    )


@soc_remote_app.command("summarize-network-telemetry")
def soc_remote_summarize_network_telemetry(
    limit: int = typer.Option(250, "--limit", min=1, help="Maximum number of records to summarize."),
    facet_limit: int = typer.Option(5, "--facet-limit", min=1, help="Maximum facet values per field."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    flow_id: str | None = typer.Option(None, "--flow-id", help="Optional flow ID filter."),
    service_name: str | None = typer.Option(None, "--service-name", help="Optional service-name filter."),
    application_protocol: str | None = typer.Option(None, "--application-protocol", help="Optional application-protocol filter."),
    local_ip: str | None = typer.Option(None, "--local-ip", help="Optional local IP filter."),
    local_port: str | None = typer.Option(None, "--local-port", help="Optional local port filter."),
    remote_port: str | None = typer.Option(None, "--remote-port", help="Optional remote port filter."),
    protocol: str | None = typer.Option(None, "--protocol", help="Optional protocol filter."),
    state: str | None = typer.Option(None, "--state", help="Optional state filter."),
    start_at: str | None = typer.Option(None, "--start-at", help="Optional ISO8601 start timestamp."),
    end_at: str | None = typer.Option(None, "--end-at", help="Optional ISO8601 end timestamp."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.summarize_network_telemetry(
            limit=limit,
            facet_limit=facet_limit,
            remote_ip=remote_ip,
            process_name=process_name,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            start_at=start_at,
            end_at=end_at,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-identity-correlations")
def soc_remote_list_identity_correlations(
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of identity-correlation alerts to return."),
    severity: str | None = typer.Option(None, "--severity", help="Optional severity filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_identity_correlations(limit=limit, severity=severity),
        json_output=json_output,
    )


@soc_remote_app.command("get-event")
def soc_remote_get_event(
    event_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.get_event(event_id), json_output=json_output)


@soc_remote_app.command("list-event-cases")
def soc_remote_list_event_cases(
    event_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.list_cases_for_event(event_id), json_output=json_output)


@soc_remote_app.command("open-event-case")
def soc_remote_open_event_case(
    event_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.open_event_case(event_id), json_output=json_output)


@soc_remote_app.command("create-case-from-event")
def soc_remote_create_case_from_event(
    event_id: str,
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    title: str | None = typer.Option(None, "--title", help="Optional case title override."),
    summary: str | None = typer.Option(None, "--summary", help="Optional case summary override."),
    severity: str | None = typer.Option(None, "--severity", help="Optional severity override."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.create_case_from_event(
            event_id,
            assignee=assignee,
            title=title,
            summary=summary,
            severity=severity,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("summarize-packet-telemetry")
def soc_remote_summarize_packet_telemetry(
    limit: int = typer.Option(250, "--limit", min=1, help="Maximum number of packet records to summarize."),
    facet_limit: int = typer.Option(5, "--facet-limit", min=1, help="Maximum facet values per field."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    session_key: str | None = typer.Option(None, "--session-key", help="Optional session-key filter."),
    local_ip: str | None = typer.Option(None, "--local-ip", help="Optional local IP filter."),
    local_port: str | None = typer.Option(None, "--local-port", help="Optional local port filter."),
    remote_port: str | None = typer.Option(None, "--remote-port", help="Optional remote port filter."),
    protocol: str | None = typer.Option(None, "--protocol", help="Optional protocol filter."),
    start_at: str | None = typer.Option(None, "--start-at", help="Optional ISO8601 start timestamp."),
    end_at: str | None = typer.Option(None, "--end-at", help="Optional ISO8601 end timestamp."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.summarize_packet_telemetry(
            limit=limit,
            facet_limit=facet_limit,
            remote_ip=remote_ip,
            session_key=session_key,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            start_at=start_at,
            end_at=end_at,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("summarize-identity-correlations")
def soc_remote_summarize_identity_correlations(
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of identity-correlation alerts to summarize."),
    severity: str | None = typer.Option(None, "--severity", help="Optional severity filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.summarize_identity_correlations(limit=limit, severity=severity),
        json_output=json_output,
    )


@soc_remote_app.command("create-case-from-packet-session")
def soc_remote_create_case_from_packet_session(
    session_key: str,
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP for context."),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.create_case_from_packet_session(
            {"session_key": session_key, "remote_ip": remote_ip},
            SocPacketSessionCaseRequest(session_key=session_key, assignee=assignee),
        ),
        json_output=json_output,
    )


@soc_remote_app.command("create-case-from-network-evidence")
def soc_remote_create_case_from_network_evidence(
    remote_ip: str,
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.create_case_from_network_evidence(
            {"remote_ip": remote_ip},
            SocNetworkEvidenceCaseRequest(remote_ip=remote_ip, assignee=assignee),
        ),
        json_output=json_output,
    )


@soc_remote_app.command("create-case-from-identity-correlation")
def soc_remote_create_case_from_identity_correlation(
    alert_id: str,
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    acted_by: str | None = typer.Option(None, "--acted-by", help="Optional actor identity."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.promote_alert_to_case(
            alert_id,
            SocAlertPromoteCaseRequest(assignee=assignee, acted_by=acted_by),
        ),
        json_output=json_output,
    )


@soc_remote_app.command("open-identity-correlation-case")
def soc_remote_open_identity_correlation_case(
    alert_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    alert_payload = client.get_alert(alert_id)
    linked_case_id = str(alert_payload.get("linked_case_id") or "").strip()
    if not linked_case_id:
        raise typer.Exit(code=1)
    _emit_remote_output(client.get_case(linked_case_id), json_output=json_output)


@soc_remote_app.command("list-packet-captures")
def soc_remote_list_packet_captures(
    limit: int = typer.Option(20, "--limit", min=1, help="Maximum number of retained packet captures to return."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    session_key: str | None = typer.Option(None, "--session-key", help="Optional session-key filter."),
    protocol: str | None = typer.Option(None, "--protocol", help="Optional protocol filter."),
    local_port: int | None = typer.Option(None, "--local-port", min=1, max=65535, help="Optional local port filter."),
    remote_port: int | None = typer.Option(None, "--remote-port", min=1, max=65535, help="Optional remote port filter."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_packet_capture_artifacts(
            limit=limit,
            remote_ip=remote_ip,
            session_key=session_key,
            protocol=protocol,
            local_port=local_port,
            remote_port=remote_port,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("get-packet-capture")
def soc_remote_get_packet_capture(
    capture_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.get_packet_capture_artifact(capture_id), json_output=json_output)


@soc_remote_app.command("get-packet-capture-text")
def soc_remote_get_packet_capture_text(
    capture_id: str,
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.get_packet_capture_text(capture_id), json_output=json_output)


@soc_remote_app.command("create-case-from-packet-capture")
def soc_remote_create_case_from_packet_capture(
    capture_id: str,
    session_key: str | None = typer.Option(None, "--session-key", help="Optional session within the retained capture."),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.create_case_from_packet_capture(
            capture_id,
            SocPacketCaptureCaseRequest(session_key=session_key, assignee=assignee),
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-hunt-clusters")
def soc_remote_list_hunt_clusters(
    cluster_by: str = typer.Option("remote_ip", "--cluster-by", help="remote_ip|device_id|process_guid"),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    filename: str | None = typer.Option(None, "--filename", help="Optional filename filter."),
    artifact_path: str | None = typer.Option(None, "--artifact-path", help="Optional artifact-path filter."),
    session_key: str | None = typer.Option(None, "--session-key", help="Optional session-key filter."),
    start_at: str | None = typer.Option(None, "--start-at", help="Optional ISO8601 start timestamp."),
    end_at: str | None = typer.Option(None, "--end-at", help="Optional ISO8601 end timestamp."),
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of clusters to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_hunt_telemetry_clusters(
            cluster_by=cluster_by,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            start_at=start_at,
            end_at=end_at,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("get-hunt-cluster")
def soc_remote_get_hunt_cluster(
    cluster_key: str,
    cluster_by: str = typer.Option("remote_ip", "--cluster-by", help="remote_ip|device_id|process_guid"),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    filename: str | None = typer.Option(None, "--filename", help="Optional filename filter."),
    artifact_path: str | None = typer.Option(None, "--artifact-path", help="Optional artifact-path filter."),
    session_key: str | None = typer.Option(None, "--session-key", help="Optional session-key filter."),
    start_at: str | None = typer.Option(None, "--start-at", help="Optional ISO8601 start timestamp."),
    end_at: str | None = typer.Option(None, "--end-at", help="Optional ISO8601 end timestamp."),
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of cluster events to resolve."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.get_hunt_telemetry_cluster(
            cluster_key,
            cluster_by=cluster_by,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            start_at=start_at,
            end_at=end_at,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-timeline-clusters")
def soc_remote_list_timeline_clusters(
    cluster_by: str = typer.Option("process", "--cluster-by", help="process|remote_ip"),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of clusters to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_endpoint_timeline_clusters(
            cluster_by=cluster_by,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("get-timeline-cluster")
def soc_remote_get_timeline_cluster(
    cluster_key: str,
    cluster_by: str = typer.Option("process", "--cluster-by", help="process|remote_ip"),
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of cluster events to resolve."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.get_endpoint_timeline_cluster(
            cluster_key=cluster_key,
            cluster_by=cluster_by,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-lineage-clusters")
def soc_remote_list_lineage_clusters(
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of clusters to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.list_endpoint_lineage_clusters(
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("get-lineage-cluster")
def soc_remote_get_lineage_cluster(
    cluster_key: str,
    device_id: str | None = typer.Option(None, "--device-id", help="Optional device filter."),
    process_name: str | None = typer.Option(None, "--process-name", help="Optional process-name filter."),
    process_guid: str | None = typer.Option(None, "--process-guid", help="Optional process-guid filter."),
    remote_ip: str | None = typer.Option(None, "--remote-ip", help="Optional remote IP filter."),
    signer_name: str | None = typer.Option(None, "--signer-name", help="Optional signer filter."),
    sha256: str | None = typer.Option(None, "--sha256", help="Optional SHA-256 filter."),
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of cluster events to resolve."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.get_endpoint_lineage_cluster(
            cluster_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
            limit=limit,
        ),
        json_output=json_output,
    )


@soc_remote_app.command("ack-alert")
def soc_remote_ack_alert(
    alert_id: str,
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.update_alert(alert_id, SocAlertUpdate(status=SocAlertStatus.acknowledged, assignee=assignee)),
        json_output=json_output,
    )


@soc_remote_app.command("set-case-status")
def soc_remote_set_case_status(
    case_id: str,
    status: SocCaseStatus = typer.Argument(..., case_sensitive=False),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.update_case(case_id, SocCaseUpdate(status=status, assignee=assignee)), json_output=json_output)


@soc_remote_app.command("create-case-from-rule-group")
def soc_remote_create_case_from_rule_group(
    rule_id: str,
    group_key: str,
    kind: str = typer.Option("alerts", "--kind", help="alerts|evidence"),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    normalized_kind = str(kind).strip().casefold()
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    payload = SocCaseRuleGroupCaseRequest(group_key=group_key, assignee=assignee)
    if normalized_kind == "alerts":
        _emit_remote_output(client.create_case_from_detection_rule_alert_group(rule_id, payload), json_output=json_output)
        return
    if normalized_kind == "evidence":
        _emit_remote_output(client.create_case_from_detection_rule_evidence_group(rule_id, payload), json_output=json_output)
        return
    typer.echo("Rule group kind must be 'alerts' or 'evidence'.", err=True)
    raise typer.Exit(code=1)


@soc_remote_app.command("create-case-from-hunt-cluster")
def soc_remote_create_case_from_hunt_cluster(
    cluster_key: str,
    cluster_by: str = typer.Option("remote_ip", "--cluster-by", help="remote_ip|device_id|process_guid"),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.promote_hunt_telemetry_cluster(cluster_key, cluster_by=cluster_by, assignee=assignee),
        json_output=json_output,
    )


@soc_remote_app.command("create-case-from-timeline-cluster")
def soc_remote_create_case_from_timeline_cluster(
    cluster_key: str,
    cluster_by: str = typer.Option("process", "--cluster-by", help="process|remote_ip"),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.promote_endpoint_timeline_cluster(cluster_key, cluster_by=cluster_by, assignee=assignee),
        json_output=json_output,
    )


@soc_remote_app.command("create-case-from-lineage-cluster")
def soc_remote_create_case_from_lineage_cluster(
    cluster_key: str,
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.promote_endpoint_lineage_cluster(cluster_key, assignee=assignee), json_output=json_output)


@soc_remote_app.command("list-case-hunt-clusters")
def soc_remote_list_case_hunt_clusters(
    case_id: str,
    cluster_by: str = typer.Option("remote_ip", "--cluster-by", help="remote_ip|device_id|process_guid"),
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of clusters to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.list_case_hunt_telemetry_clusters(case_id, cluster_by=cluster_by, limit=limit), json_output=json_output)


@soc_remote_app.command("get-case-hunt-cluster")
def soc_remote_get_case_hunt_cluster(
    case_id: str,
    cluster_key: str,
    cluster_by: str = typer.Option("remote_ip", "--cluster-by", help="remote_ip|device_id|process_guid"),
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of cluster events to resolve."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.get_case_hunt_telemetry_cluster(case_id, cluster_by=cluster_by, cluster_key=cluster_key, limit=limit),
        json_output=json_output,
    )


@soc_remote_app.command("create-case-from-case-hunt-cluster")
def soc_remote_create_case_from_case_hunt_cluster(
    case_id: str,
    cluster_key: str,
    cluster_by: str = typer.Option("remote_ip", "--cluster-by", help="remote_ip|device_id|process_guid"),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.create_case_from_case_hunt_telemetry_cluster(
            case_id,
            SocCaseTelemetryClusterCaseRequest(cluster_by=cluster_by, cluster_key=cluster_key, assignee=assignee),
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-case-timeline-clusters")
def soc_remote_list_case_timeline_clusters(
    case_id: str,
    cluster_by: str = typer.Option("process", "--cluster-by", help="process|remote_ip"),
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of clusters to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.list_case_endpoint_timeline_clusters(case_id, cluster_by=cluster_by, limit=limit), json_output=json_output)


@soc_remote_app.command("get-case-timeline-cluster")
def soc_remote_get_case_timeline_cluster(
    case_id: str,
    cluster_key: str,
    cluster_by: str = typer.Option("process", "--cluster-by", help="process|remote_ip"),
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of cluster events to resolve."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.get_case_endpoint_timeline_cluster(case_id, cluster_by=cluster_by, cluster_key=cluster_key, limit=limit),
        json_output=json_output,
    )


@soc_remote_app.command("create-case-from-case-timeline-cluster")
def soc_remote_create_case_from_case_timeline_cluster(
    case_id: str,
    cluster_key: str,
    cluster_by: str = typer.Option("process", "--cluster-by", help="process|remote_ip"),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.create_case_from_case_endpoint_timeline_cluster(
            case_id,
            SocCaseEndpointTimelineClusterCaseRequest(cluster_by=cluster_by, cluster_key=cluster_key, assignee=assignee),
        ),
        json_output=json_output,
    )


@soc_remote_app.command("list-case-lineage-clusters")
def soc_remote_list_case_lineage_clusters(
    case_id: str,
    limit: int = typer.Option(50, "--limit", min=1, help="Maximum number of clusters to return."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.list_case_endpoint_lineage_clusters(case_id, limit=limit), json_output=json_output)


@soc_remote_app.command("list-case-rule-groups")
def soc_remote_list_case_rule_groups(
    case_id: str,
    kind: str = typer.Option("alerts", "--kind", help="alerts|evidence"),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    normalized_kind = str(kind).strip().casefold()
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    if normalized_kind == "alerts":
        _emit_remote_output(client.list_case_rule_alert_groups(case_id), json_output=json_output)
        return
    if normalized_kind == "evidence":
        _emit_remote_output(client.list_case_rule_evidence_groups(case_id), json_output=json_output)
        return
    typer.echo("Case rule group kind must be 'alerts' or 'evidence'.", err=True)
    raise typer.Exit(code=1)


@soc_remote_app.command("get-case-rule-group")
def soc_remote_get_case_rule_group(
    case_id: str,
    group_key: str,
    kind: str = typer.Option("alerts", "--kind", help="alerts|evidence"),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    normalized_kind = str(kind).strip().casefold()
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    if normalized_kind == "alerts":
        _emit_remote_output(client.get_case_rule_alert_group(case_id, group_key), json_output=json_output)
        return
    if normalized_kind == "evidence":
        _emit_remote_output(client.get_case_rule_evidence_group(case_id, group_key), json_output=json_output)
        return
    typer.echo("Case rule group kind must be 'alerts' or 'evidence'.", err=True)
    raise typer.Exit(code=1)


@soc_remote_app.command("create-case-from-case-rule-group")
def soc_remote_create_case_from_case_rule_group(
    case_id: str,
    group_key: str,
    kind: str = typer.Option("alerts", "--kind", help="alerts|evidence"),
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    normalized_kind = str(kind).strip().casefold()
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    payload = SocCaseRuleGroupCaseRequest(group_key=group_key, assignee=assignee)
    if normalized_kind == "alerts":
        _emit_remote_output(client.create_case_from_case_rule_alert_group(case_id, payload), json_output=json_output)
        return
    if normalized_kind == "evidence":
        _emit_remote_output(client.create_case_from_case_rule_evidence_group(case_id, payload), json_output=json_output)
        return
    typer.echo("Case rule group kind must be 'alerts' or 'evidence'.", err=True)
    raise typer.Exit(code=1)


@soc_remote_app.command("get-case-lineage-cluster")
def soc_remote_get_case_lineage_cluster(
    case_id: str,
    cluster_key: str,
    limit: int = typer.Option(200, "--limit", min=1, help="Maximum number of cluster events to resolve."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(client.get_case_endpoint_lineage_cluster(case_id, cluster_key=cluster_key, limit=limit), json_output=json_output)


@soc_remote_app.command("create-case-from-case-lineage-cluster")
def soc_remote_create_case_from_case_lineage_cluster(
    case_id: str,
    cluster_key: str,
    assignee: str | None = typer.Option(None, "--assignee", help="Optional analyst assignee."),
    manager_url: str | None = typer.Option(None, "--manager-url", help="Remote manager base URL."),
    bearer_token: str | None = typer.Option(None, "--bearer-token", help="Remote operator token."),
    timeout_seconds: float | None = typer.Option(None, "--timeout-seconds", min=0.1, help="Remote HTTP timeout in seconds."),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    client = _remote_investigation_client(
        manager_url=manager_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
    )
    _emit_remote_output(
        client.create_case_from_case_endpoint_lineage_cluster(
            case_id,
            SocCaseEndpointLineageClusterCaseRequest(cluster_key=cluster_key, assignee=assignee),
        ),
        json_output=json_output,
    )


app.add_typer(soc_remote_app, name="soc-remote")


@linear_forms_app.command("list")
def linear_forms_list(include_disabled: bool = typer.Option(False, "--include-disabled", help="Include disabled forms.")) -> None:
    print(
        {
            "forms": [form.model_dump(mode="json") for form in linear_forms.list_forms(include_disabled=include_disabled)],
            "portal_path": "/linear/asks",
        }
    )


@linear_forms_app.command("upsert")
def linear_forms_upsert(
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


@linear_forms_app.command("remove")
def linear_forms_remove(form_key: str) -> None:
    deleted = linear_forms.delete_form(form_key)
    if not deleted:
        typer.echo("Linear form not found.", err=True)
        raise typer.Exit(code=1)
    print({"status": "deleted", "form_key": form_key})


app.add_typer(linear_forms_app, name="linear-forms")


@docker_resources_app.command("list")
def docker_resources_list() -> None:
    print({"resources": [resource.model_dump(mode="json") for resource in list_docker_resources()]})


@docker_resources_app.command("get")
def docker_resources_get(resource_key: str) -> None:
    resource = get_docker_resource(resource_key)
    if resource is None:
        typer.echo("Docker resource not found.", err=True)
        raise typer.Exit(code=1)
    print({"resource": resource.model_dump(mode="json")})


app.add_typer(docker_resources_app, name="docker-resources")


@app.command("tracker-feed-status")
def tracker_feed_status() -> None:
    print(tracker_intel.feed_status())


@app.command("tracker-feed-refresh")
def tracker_feed_refresh(
    url: list[str] | None = typer.Option(None, "--url", help="Override tracker feed URLs for this refresh run"),
) -> None:
    try:
        result = tracker_intel.refresh_feed_cache(url)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    print({"status": "refreshed", **result})


@app.command("tracker-feed-import")
def tracker_feed_import(path: Path) -> None:
    try:
        result = tracker_intel.import_feed_cache(path)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    print({"status": "imported", **result})


@app.command("health-status")
def health_status() -> None:
    tracker_health = tracker_intel.health_status()
    malware_health = scanner.health_status()
    warnings = [*tracker_health["warnings"], *malware_health["warnings"]]
    platform = build_platform_profile(
        tracker_health=tracker_health,
        malware_health=malware_health,
    )
    print(
        {
            "healthy": not warnings,
            "warnings": warnings,
            "platform": platform,
            "tracker_intel": tracker_health,
            "malware_scanner": malware_health,
        }
    )


def _resolve_uninstaller_path() -> Path | None:
    candidates: list[Path] = []
    executable = Path(getattr(sys, "executable", ""))
    if executable:
        candidates.append(executable.with_name("SecurityGateway-Uninstall.exe"))
        candidates.append(executable.parent / "uninstall" / "SecurityGateway-Uninstall.exe")
        candidates.append(executable.with_name("Uninstall-SecurityGateway.ps1"))
    candidates.append(Path.cwd() / "SecurityGateway-Uninstall.exe")
    candidates.append(Path.cwd() / "uninstall" / "SecurityGateway-Uninstall.exe")
    candidates.append(Path.cwd() / "Uninstall-SecurityGateway.ps1")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _launch_uninstaller(target: Path) -> None:
    if target.suffix.lower() == ".ps1":
        subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(target)])
        return
    os.startfile(str(target))  # type: ignore[attr-defined]


def _center_window(root: Any, width: int, height: int) -> None:
    screen_width = int(root.winfo_screenwidth())
    screen_height = int(root.winfo_screenheight())
    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)
    root.geometry(f"{width}x{height}+{x}+{y}")


def _select_frozen_action() -> str:
    import tkinter as tk

    root = tk.Tk()
    root.title("Security Gateway")
    root.resizable(False, False)
    root.configure(bg="#eef4ff")
    _center_window(root, 440, 250)

    selection = {"value": "report-browser"}

    def choose(action: str) -> None:
        selection["value"] = action
        root.destroy()

    menu_bar = tk.Menu(root)
    tools_menu = tk.Menu(menu_bar, tearoff=False)
    tools_menu.add_command(label="Open SOC Dashboard", command=lambda: choose("soc-dashboard"))
    tools_menu.add_command(label="Open Reports", command=lambda: choose("report-browser"))
    tools_menu.add_command(label="Run Uninstaller", command=lambda: choose("uninstall"))
    tools_menu.add_separator()
    tools_menu.add_command(label="Exit", command=lambda: choose("exit"))
    menu_bar.add_cascade(label="Tools", menu=tools_menu)
    root.config(menu=menu_bar)

    frame = tk.Frame(root, padx=20, pady=20, bg="#eef4ff")
    frame.pack(fill="both", expand=True)

    tk.Label(
        frame,
        text="Security Gateway Tools",
        font=("Segoe UI", 14, "bold"),
        bg="#eef4ff",
        fg="#13315c",
    ).pack(fill="x", pady=(0, 8))
    tk.Label(
        frame,
        text="Use the Tools menu or the buttons below.",
        font=("Segoe UI", 10, "bold"),
        justify="left",
        anchor="w",
        bg="#eef4ff",
        fg="#2f3e52",
    ).pack(fill="x", pady=(0, 16))
    tk.Button(
        frame,
        text="Open SOC Dashboard",
        width=30,
        font=("Segoe UI", 10, "bold"),
        bg="#135a9c",
        fg="white",
        activebackground="#0f477b",
        activeforeground="white",
        relief="flat",
        padx=8,
        pady=8,
        command=lambda: choose("soc-dashboard"),
    ).pack(pady=5)
    tk.Button(
        frame,
        text="Open Reports",
        width=30,
        font=("Segoe UI", 10, "bold"),
        bg="#1f6feb",
        fg="white",
        activebackground="#1558b0",
        activeforeground="white",
        relief="flat",
        padx=8,
        pady=8,
        command=lambda: choose("report-browser"),
    ).pack(pady=5)
    tk.Button(
        frame,
        text="Run Uninstaller",
        width=30,
        font=("Segoe UI", 10, "bold"),
        bg="#b44c2f",
        fg="white",
        activebackground="#8f391f",
        activeforeground="white",
        relief="flat",
        padx=8,
        pady=8,
        command=lambda: choose("uninstall"),
    ).pack(pady=5)
    tk.Button(
        frame,
        text="Exit",
        width=30,
        font=("Segoe UI", 10, "bold"),
        bg="#d8e0ef",
        fg="#1f2a37",
        activebackground="#bcc9df",
        relief="flat",
        padx=8,
        pady=8,
        command=lambda: choose("exit"),
    ).pack(pady=5)

    root.protocol("WM_DELETE_WINDOW", lambda: choose("exit"))
    root.mainloop()
    return selection["value"]


def _launch_frozen_desktop_entry() -> None:
    action = _select_frozen_action()
    if action == "soc-dashboard":
        _open_configured_soc_dashboard()
        return
    if action == "report-browser":
        run_report_browser(report_builder)
        return
    if action == "uninstall":
        target = _resolve_uninstaller_path()
        if target is None:
            typer.echo("Security Gateway uninstaller was not found.", err=True)
            raise typer.Exit(code=1)
        _launch_uninstaller(target)
        return


def launch() -> None:
    if getattr(sys, "frozen", False) and len(sys.argv) == 1:
        _launch_frozen_desktop_entry()
    else:
        app()


if __name__ == "__main__":
    launch()
