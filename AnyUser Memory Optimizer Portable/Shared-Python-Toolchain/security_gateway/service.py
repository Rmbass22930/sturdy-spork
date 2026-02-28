"""FastAPI service exposing the security gateway."""
from __future__ import annotations

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

from .audit import AuditLogger
from .alerts import alert_manager, AlertEvent, AlertLevel
from .automation import AutomationSupervisor
from .config import settings
from .dns import SecureDNSResolver
from .endpoint import EndpointTelemetryService, MalwareScanner
from .models import AccessDecision, AccessRequest, CredentialLease, DeviceContext
from .pam import VaultClient
from .policy import PolicyEngine
from .state import dns_security_cache
from .tor import OutboundProxy
from .threat_response import ThreatResponseCoordinator

app = FastAPI(title="Security Gateway", version="0.1.0")

audit_logger = AuditLogger(settings.audit_log_path)
vault = VaultClient(audit_logger=audit_logger)
threat_responder = ThreatResponseCoordinator(vault, audit_logger, alert_manager)
policy_engine = PolicyEngine(threat_responder=threat_responder)
resolver = SecureDNSResolver()
proxy = OutboundProxy()
telemetry = EndpointTelemetryService()
scanner = MalwareScanner()
automation = AutomationSupervisor(
    vault=vault,
    proxy=proxy,
    audit_logger=audit_logger,
    alert_manager=alert_manager,
    interval_seconds=settings.automation_interval_seconds,
)


@app.post("/access/evaluate", response_model=AccessDecision)
async def evaluate_access(request: AccessRequest) -> AccessDecision:
    return policy_engine.evaluate(request)


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


@app.post("/endpoint/scan")
async def scan_file(file: UploadFile = File(...)) -> dict:
    data = await file.read()
    malicious, verdict = scanner.scan_bytes(data)
    return {"malicious": malicious, "verdict": verdict}


class ProxyPayload(BaseModel):
    url: str
    method: str = "GET"
    via: str = "tor"


@app.post("/tor/request")
async def proxy_request(payload: ProxyPayload) -> dict:
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


@app.get("/automation/status")
async def automation_status() -> dict:
    return automation.status()


@app.on_event("shutdown")
async def shutdown_event() -> None:
    automation.stop()
    resolver.close()


@app.on_event("startup")
async def startup_event() -> None:
    automation.start()
