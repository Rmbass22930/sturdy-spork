"""FastAPI service exposing the security gateway."""
from __future__ import annotations

import importlib.util
import json
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi.responses import FileResponse, Response

from fastapi import FastAPI, File, HTTPException, UploadFile, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from .audit import AuditLogger
from .alerts import alert_manager, AlertEvent, AlertLevel
from .automation import AutomationSupervisor
from .config import settings
from .dns import SecureDNSResolver
from .endpoint import EndpointTelemetryService, MalwareScanner
from .ip_controls import IPBlocklistManager
from .models import AccessDecision, AccessRequest, CredentialLease, DeviceContext
from .pam import VaultClient
from .policy import PolicyEngine
from .reports import SecurityReportBuilder
from .state import dns_security_cache
from .tracker_intel import TrackerIntel
from .tor import OutboundProxy
from .threat_response import ThreatResponseCoordinator

multipart_installed = importlib.util.find_spec("multipart") is not None

audit_logger = AuditLogger(settings.audit_log_path)
vault = VaultClient(audit_logger=audit_logger)
threat_responder = ThreatResponseCoordinator(vault, audit_logger, alert_manager)
ip_blocklist = IPBlocklistManager(audit_logger=audit_logger)
policy_engine = PolicyEngine(threat_responder=threat_responder, ip_blocklist=ip_blocklist)
resolver = SecureDNSResolver()
proxy = OutboundProxy()
telemetry = EndpointTelemetryService()
scanner = MalwareScanner()
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
)
automation = AutomationSupervisor(
    vault=vault,
    proxy=proxy,
    audit_logger=audit_logger,
    alert_manager=alert_manager,
    interval_seconds=settings.automation_interval_seconds,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    automation.start()
    try:
        yield
    finally:
        automation.stop()
        resolver.close()


app = FastAPI(title="Security Gateway", version="0.1.0", lifespan=lifespan)


@app.post("/access/evaluate", response_model=AccessDecision)
async def evaluate_access(access_request: AccessRequest, http_request: Request) -> AccessDecision:
    if not access_request.source_ip and http_request.client:
        access_request.source_ip = http_request.client.host
    decision = policy_engine.evaluate(access_request)
    audit_logger.log(
        "access.evaluate",
        {
            "user_id": access_request.user.user_id,
            "resource": access_request.resource,
            "privilege_level": access_request.privilege_level,
            "source_ip": access_request.source_ip,
            "dns_secure": access_request.dns_secure,
            "threat_signals": access_request.threat_signals,
            "decision": decision.decision.value,
            "risk_score": decision.risk_score,
            "reasons": decision.reasons,
        },
    )
    return decision


class SecretPayload(BaseModel):
    name: str
    secret: str


@app.put("/pam/secret")
async def store_secret(payload: SecretPayload) -> dict:
    vault.store_secret(payload.name, payload.secret)
    return {"status": "stored", "name": payload.name, "metrics": vault.get_metrics()}


class CheckoutPayload(BaseModel):
    name: str
    ttl_minutes: int = 15


@app.post("/pam/checkout", response_model=CredentialLease)
async def checkout_secret(payload: CheckoutPayload) -> CredentialLease:
    try:
        return vault.checkout(payload.name, payload.ttl_minutes)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/pam/metrics")
async def pam_metrics() -> dict:
    return vault.get_metrics()


@app.get("/dns/resolve")
async def resolve_dns(hostname: str, record_type: str = "A") -> dict:
    tracker_match = tracker_intel.is_tracker_hostname(hostname) if settings.tracker_block_enabled else None
    if tracker_match:
        audit_logger.log(
            "privacy.tracker_block",
            {
                "target_type": "dns",
                "hostname": tracker_match.hostname,
                "matched_domain": tracker_match.matched_domain,
                "source": tracker_match.source,
                "confidence": tracker_match.confidence,
                "reason": tracker_match.reason,
                "record_type": record_type,
            },
        )
        raise HTTPException(status_code=403, detail=f"Tracker domain blocked: {tracker_match.hostname}")
    result = resolver.resolve(hostname, record_type)
    dns_security_cache.record(hostname, result.secure)
    return {
        "secure": result.secure,
        "records": [record.__dict__ for record in result.records],
    }


@app.post("/endpoint/telemetry")
async def publish_telemetry(device: DeviceContext) -> dict:
    signature = telemetry.publish(device)
    return {"signature": signature}


@app.get("/endpoint/telemetry/{device_id}")
async def fetch_telemetry(device_id: str) -> dict:
    payload = telemetry.get_payload(device_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Device not found or signature invalid")
    return payload


if multipart_installed:
    @app.post("/endpoint/scan")
    async def scan_file(file: UploadFile = File(...)) -> dict:
        data = await file.read()
        malicious, verdict = scanner.scan_bytes(data)
        return {"malicious": malicious, "verdict": verdict}
else:
    @app.post("/endpoint/scan")
    async def scan_file_unavailable() -> dict:
        raise HTTPException(
            status_code=503,
            detail="File upload scanning is unavailable; install python-multipart",
        )


class ProxyPayload(BaseModel):
    url: str
    method: str = "GET"
    via: str = "tor"


class BlockIPPayload(BaseModel):
    ip: str
    reason: str = "manual operator block"
    duration_minutes: int | None = None


class UnblockIPPayload(BaseModel):
    reason: str = "operator review cleared"


class PromoteIPPayload(BaseModel):
    reason: str = "confirmed attacker - permanent block"


class RefreshTrackerFeedsPayload(BaseModel):
    urls: list[str] | None = None


@app.post("/tor/request")
async def proxy_request(payload: ProxyPayload) -> dict:
    tracker_match = tracker_intel.is_tracker_url(payload.url) if settings.tracker_block_enabled else None
    if tracker_match:
        audit_logger.log(
            "privacy.tracker_block",
            {
                "target_type": "proxy",
                "url": payload.url,
                "hostname": tracker_match.hostname,
                "matched_domain": tracker_match.matched_domain,
                "source": tracker_match.source,
                "confidence": tracker_match.confidence,
                "reason": tracker_match.reason,
                "via": payload.via,
            },
        )
        raise HTTPException(status_code=403, detail=f"Tracker destination blocked: {tracker_match.hostname}")
    try:
        result = proxy.request(payload.method.upper(), payload.url, via=payload.via)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {
        "status_code": result.status_code,
        "headers": result.headers,
        "body": result.body,
    }


@app.get("/proxy/health")
async def proxy_health() -> dict:
    return proxy.health()


@app.get("/privacy/tracker-events")
async def tracker_events(max_events: int = 50) -> dict:
    events: list[dict] = []
    audit_path = Path(settings.audit_log_path)
    if audit_path.exists():
        lines = audit_path.read_text(encoding="utf-8").splitlines()
        for raw in lines[-max_events:]:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "privacy.tracker_block":
                events.append(event)
    return {"events": events}


@app.get("/privacy/tracker-feeds/status")
async def tracker_feed_status() -> dict:
    return tracker_intel.feed_status()


@app.post("/privacy/tracker-feeds/refresh")
async def tracker_feed_refresh(payload: RefreshTrackerFeedsPayload | None = None) -> dict:
    try:
        return tracker_intel.refresh_feed_cache(payload.urls if payload else None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Tracker feed refresh failed: {exc}") from exc


@app.get("/network/blocked-ips")
async def list_blocked_ips() -> dict:
    return {"blocked_ips": [entry.__dict__ for entry in ip_blocklist.list_entries()]}


@app.post("/network/blocked-ips")
async def block_ip(payload: BlockIPPayload) -> dict:
    entry = ip_blocklist.block(
        payload.ip,
        reason=payload.reason,
        blocked_by="api",
        duration_minutes=payload.duration_minutes,
    )
    return {"status": "blocked", "entry": entry.__dict__}


@app.delete("/network/blocked-ips/{ip}")
async def unblock_ip(ip: str, payload: UnblockIPPayload | None = None) -> dict:
    removed = ip_blocklist.unblock(ip, reason=payload.reason if payload else None, unblocked_by="api")
    if not removed:
        raise HTTPException(status_code=404, detail="IP address not blocked")
    return {"status": "unblocked", "ip": ip}


@app.post("/network/blocked-ips/{ip}/promote")
async def promote_ip_block(ip: str, payload: PromoteIPPayload | None = None) -> dict:
    entry = ip_blocklist.promote_to_permanent(
        ip,
        reason=payload.reason if payload else None,
        promoted_by="api",
    )
    if not entry:
        raise HTTPException(status_code=404, detail="IP address not blocked")
    return {"status": "promoted", "entry": entry.__dict__}


@app.get("/automation/status")
async def automation_status() -> dict:
    return automation.status()


@app.get("/reports/security-summary.pdf")
async def security_summary_report(
    max_events: int = 25,
    time_window_hours: float | None = None,
    min_risk_score: float = 0.0,
    include_blocked_ips: bool = True,
    include_potential_blocked_ips: bool = True,
    include_recent_events: bool = True,
) -> Response:
    pdf_bytes = report_builder.build_summary_pdf(
        max_events=max_events,
        time_window_hours=time_window_hours,
        min_risk_score=min_risk_score,
        include_blocked_ips=include_blocked_ips,
        include_potential_blocked_ips=include_potential_blocked_ips,
        include_recent_events=include_recent_events,
    )
    headers = {"Content-Disposition": 'attachment; filename="security-summary.pdf"'}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


@app.get("/reports")
async def list_reports() -> dict:
    return {"reports": report_builder.list_saved_reports(), "report_output_dir": str(report_builder.get_output_dir())}


@app.get("/reports/{report_name}")
async def fetch_report(report_name: str) -> FileResponse:
    try:
        target = report_builder.resolve_saved_report(report_name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(path=target, media_type="application/pdf", filename=target.name)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    await websocket.send_json({"type": "ready", "message": "connected"})
    try:
        while True:
            payload = await websocket.receive_text()
            message = payload.strip()
            if message.lower() in {"ping", "health"}:
                await websocket.send_text("pong")
            elif message.lower() in {"close", "exit", "quit"}:
                await websocket.close(code=1000)
                break
            else:
                await websocket.send_text(f"echo:{payload}")
    except WebSocketDisconnect:
        return
