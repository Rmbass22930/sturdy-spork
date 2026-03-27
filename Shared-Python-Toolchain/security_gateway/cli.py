"""Typer CLI for the security gateway."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

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
from security_gateway.ip_controls import IPBlocklistManager
from security_gateway.models import AccessRequest
from security_gateway.pam import VaultClient
from security_gateway.policy import PolicyEngine
from security_gateway.report_browser import run_report_browser
from security_gateway.reports import SecurityReportBuilder
from security_gateway.state import dns_security_cache
from security_gateway.tracker_intel import TrackerIntel
from security_gateway.tor import OutboundProxy
from security_gateway.threat_response import ThreatResponseCoordinator

app = typer.Typer(help="Interact with the security gateway modules locally.")

audit_logger = AuditLogger(settings.audit_log_path)
vault = VaultClient(audit_logger=audit_logger)
threat_responder = ThreatResponseCoordinator(vault, audit_logger, alert_manager)
ip_blocklist = IPBlocklistManager(audit_logger=audit_logger)
policy_engine = PolicyEngine(threat_responder=threat_responder, ip_blocklist=ip_blocklist)
resolver = SecureDNSResolver()
proxy = OutboundProxy()
scanner = MalwareScanner()
report_builder = SecurityReportBuilder()
tracker_intel = TrackerIntel(
    extra_domains_path=settings.tracker_domain_list_path,
    feed_cache_path=settings.tracker_feed_cache_path,
    feed_urls=settings.tracker_feed_urls,
    stale_after_hours=settings.tracker_feed_stale_hours,
)


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
    response = proxy.request("GET", url, via=via)
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


@app.command()
def automation_run() -> None:
    """Run automation supervisor in the foreground."""
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit_logger,
        alert_manager=alert_manager,
        interval_seconds=settings.automation_interval_seconds,
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


def launch() -> None:
    if getattr(sys, "frozen", False) and len(sys.argv) == 1:
        run_report_browser(report_builder)
    else:
        app()


if __name__ == "__main__":
    launch()
