"""FastAPI service exposing the security gateway."""
from __future__ import annotations

import importlib.util
import json
import secrets
from contextlib import asynccontextmanager
from ipaddress import ip_address
from pathlib import Path
from time import monotonic
from typing import cast
from urllib.parse import urlparse
from fastapi.responses import FileResponse, Response

from fastapi import (
    Depends,
    FastAPI,
    File,
    Header,
    HTTPException,
    Query,
    UploadFile,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
 )
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .audit import AuditLogger
from .alerts import alert_manager
from .automation import AutomationSupervisor
from .config import settings
from .dns import SecureDNSResolver
from .endpoint import EndpointTelemetryService, MalwareScanner
from .ip_controls import IPBlocklistManager
from .models import (
    AccessDecision,
    AccessRequest,
    CredentialLease,
    DeviceContext,
    SocAlertRecord,
    SocAlertPromoteCaseRequest,
    SocAlertStatus,
    SocAlertUpdate,
    SocCaseCreate,
    SocCaseStatus,
    SocCaseUpdate,
    SocEventIngest,
    SocEventRecord,
    SocSeverity,
)
from .pam import (
    MAX_LEASE_TTL_MINUTES,
    MAX_SECRET_NAME_LENGTH,
    MAX_SECRET_VALUE_LENGTH,
    MIN_LEASE_TTL_MINUTES,
    VaultClient,
)
from .policy import PolicyEngine
from .reports import SecurityReportBuilder
from .reports import (
    MAX_REPORT_MAX_EVENTS,
    MAX_REPORT_MIN_RISK_SCORE,
    MAX_REPORT_TIME_WINDOW_HOURS,
    MIN_REPORT_MAX_EVENTS,
    MIN_REPORT_MIN_RISK_SCORE,
)
from .state import dns_security_cache
from .soc import SecurityOperationsManager
from .tracker_intel import TrackerIntel
from .tor import ALLOWED_PROXY_METHODS, OutboundProxy, ProxyRequestTimeoutError, ProxyResponseTooLargeError
from .threat_response import ThreatResponseCoordinator

multipart_installed = importlib.util.find_spec("multipart") is not None

audit_logger = AuditLogger(settings.audit_log_path)
vault = VaultClient(audit_logger=audit_logger)
threat_responder = ThreatResponseCoordinator(vault, audit_logger, alert_manager)
ip_blocklist = IPBlocklistManager(audit_logger=audit_logger)
policy_engine = PolicyEngine(threat_responder=threat_responder, ip_blocklist=ip_blocklist)
resolver = SecureDNSResolver()
proxy = OutboundProxy()
telemetry = EndpointTelemetryService(
    signing_key=settings.endpoint_telemetry_signing_key or settings.pam_master_key,
    max_records=settings.endpoint_telemetry_max_records,
    retention_hours=settings.endpoint_telemetry_retention_hours,
)
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
soc_manager = SecurityOperationsManager(
    event_log_path=settings.soc_event_log_path,
    alert_store_path=settings.soc_alert_store_path,
    case_store_path=settings.soc_case_store_path,
    audit_logger=audit_logger,
    alert_manager=alert_manager,
)
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
automation = AutomationSupervisor(
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
)


def _seed_offline_feeds() -> None:
    if settings.tracker_offline_seed_path and not Path(settings.tracker_feed_cache_path).exists():
        tracker_intel.import_feed_cache(settings.tracker_offline_seed_path)
    if settings.malware_offline_hash_seed_path and not Path(settings.malware_feed_cache_path).exists():
        scanner.import_feed_cache(settings.malware_offline_hash_seed_path)
    if settings.malware_offline_rule_seed_path and not Path(settings.malware_rule_feed_cache_path).exists():
        scanner.import_rule_feed_cache(settings.malware_offline_rule_seed_path)


def _validate_startup_security_dependencies() -> None:
    configured_secret_checks = (
        ("Operator", settings.operator_bearer_secret_name),
        ("Endpoint", settings.endpoint_bearer_secret_name),
    )
    for label, secret_name in configured_secret_checks:
        if not secret_name:
            continue
        try:
            vault.retrieve_secret(secret_name)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"{label} bearer token backend is unavailable during startup.") from exc


def _auth_backend_status(
    label: str,
    secret_name: str | None,
    static_token: str | None,
    loopback_allowed: bool,
) -> tuple[dict[str, object], list[str]]:
    status: dict[str, object] = {
        "name": label,
        "healthy": True,
        "configured": False,
        "source": "unconfigured",
        "loopback_bypass_enabled": loopback_allowed,
    }
    warnings: list[str] = []

    if secret_name:
        status["configured"] = True
        status["source"] = "pam_secret"
        status["secret_configured"] = True
        try:
            token_value, source = _resolve_bearer_token(secret_name, static_token)
        except BearerTokenResolutionError as exc:
            status["healthy"] = False
            status["status"] = "backend_unavailable"
            status["error"] = str(exc)
            warnings.append(f"{label} bearer token backend is unavailable.")
            return status, warnings
        status["source"] = source or "pam_secret"
        status["status"] = "ready" if token_value else "missing_secret"
        if not token_value:
            status["healthy"] = False
            warnings.append(f"{label} bearer token secret is missing or empty.")
        return status, warnings

    if static_token:
        status["configured"] = True
        status["source"] = "static_config"
        status["status"] = "ready"
        return status, warnings

    status["healthy"] = loopback_allowed
    status["status"] = "loopback_only" if loopback_allowed else "unconfigured"
    if not loopback_allowed:
        warnings.append(f"{label} bearer token is not configured.")
    return status, warnings


def _security_auth_health() -> dict[str, object]:
    operator_status, operator_warnings = _auth_backend_status(
        "Operator",
        settings.operator_bearer_secret_name,
        settings.operator_bearer_token,
        settings.operator_allow_loopback_without_token,
    )
    endpoint_status, endpoint_warnings = _auth_backend_status(
        "Endpoint",
        settings.endpoint_bearer_secret_name,
        settings.endpoint_bearer_token,
        settings.endpoint_allow_loopback_without_token,
    )
    warnings = [*operator_warnings, *endpoint_warnings]
    return {
        "healthy": not warnings,
        "warnings": warnings,
        "operator": operator_status,
        "endpoint": endpoint_status,
    }


def _record_soc_event(
    *,
    event_type: str,
    severity: SocSeverity,
    title: str,
    summary: str,
    details: dict[str, object],
    artifacts: list[str] | None = None,
    tags: list[str] | None = None,
) -> tuple[SocEventRecord, SocAlertRecord | None]:
    result = soc_manager.ingest_event(
        SocEventIngest(
            event_type=event_type,
            source="security_gateway",
            severity=severity,
            title=title,
            summary=summary,
            details=details,
            artifacts=artifacts or [],
            tags=tags or [],
        )
    )
    return result.event, result.alert


@asynccontextmanager
async def lifespan(_: FastAPI):
    _validate_startup_security_dependencies()
    _seed_offline_feeds()
    automation.start()
    try:
        yield
    finally:
        automation.stop()
        resolver.close()


app = FastAPI(
    title="Security Gateway",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.service_enable_api_docs else None,
    redoc_url="/redoc" if settings.service_enable_api_docs else None,
    openapi_url="/openapi.json" if settings.service_enable_api_docs else None,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.service_allowed_hosts))


@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    if (
        request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
        and not (request.headers.get("content-type") or "").lower().startswith("multipart/")
    ):
        body = await request.body()
        if len(body) > settings.service_max_request_body_bytes:
            client_host = request.client.host if request.client else "unknown"
            audit_logger.log(
                "http.request_too_large",
                {
                    "path": request.url.path,
                    "source_ip": client_host,
                    "size_bytes": len(body),
                    "limit_bytes": settings.service_max_request_body_bytes,
                },
            )
            response = Response(status_code=413, content="Request body too large.")
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Pragma", "no-cache")
    return response


class PublicRouteRateLimiter:
    def __init__(self) -> None:
        self._windows: dict[tuple[str, str], tuple[float, int]] = {}

    def clear(self) -> None:
        self._windows.clear()

    def check(self, scope: str, client_id: str, max_requests: int, window_seconds: float) -> float | None:
        now = monotonic()
        key = (scope, client_id)
        started_at, count = self._windows.get(key, (now, 0))
        if now - started_at >= window_seconds:
            started_at = now
            count = 0
        count += 1
        self._windows[key] = (started_at, count)
        if count <= max_requests:
            return None
        retry_after = max(1, int(window_seconds - (now - started_at)) + 1)
        return float(retry_after)


public_rate_limiter = PublicRouteRateLimiter()
auth_failure_rate_limiter = PublicRouteRateLimiter()


def _is_loopback_client(host: str | None) -> bool:
    if not host:
        return False
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return host.lower() in {"localhost", "testclient"}


def _normalized_ip_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _normalize_origin(origin: str | None) -> str | None:
    if not origin:
        return None
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def _allowed_websocket_origins() -> set[str]:
    allowed: set[str] = set()
    for origin in settings.websocket_allowed_origins:
        normalized = _normalize_origin(origin)
        if normalized is not None:
            allowed.add(normalized)
    return allowed


async def _read_upload_with_limit(file: UploadFile, max_bytes: int) -> bytes:
    payload = bytearray()
    while True:
        chunk = await file.read(min(65_536, max_bytes + 1))
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Uploaded file exceeds the configured limit of {max_bytes} bytes.",
            )
    return bytes(payload)


def _enforce_public_rate_limit(request: Request, scope: str, max_requests: int) -> None:
    client_host = request.client.host if request.client else "unknown"
    retry_after = public_rate_limiter.check(
        scope=scope,
        client_id=client_host,
        max_requests=max_requests,
        window_seconds=settings.public_rate_limit_window_seconds,
    )
    if retry_after is None:
        return
    audit_logger.log(
        "public.rate_limit.exceeded",
        {"path": request.url.path, "source_ip": client_host, "scope": scope, "retry_after_seconds": retry_after},
    )
    raise HTTPException(
        status_code=429,
        detail="Too many requests; retry later.",
        headers={"Retry-After": str(int(retry_after))},
    )


def _auth_failure_retry_after(scope: str, client_id: str | None, max_failures: int) -> float | None:
    if max_failures < 1:
        return None
    return auth_failure_rate_limiter.check(
        scope=scope,
        client_id=client_id or "unknown",
        max_requests=max_failures,
        window_seconds=settings.auth_failure_rate_limit_window_seconds,
    )


def _audit_backend_failure(event_type: str, request_path: str, source_ip: str | None, error: Exception) -> None:
    audit_logger.log(
        event_type,
        {
            "path": request_path,
            "source_ip": source_ip,
            "error_type": error.__class__.__name__,
            "error": str(error),
        },
    )


def _strip_internal_fields(value):
    if isinstance(value, dict):
        return {
            key: _strip_internal_fields(item)
            for key, item in value.items()
            if key not in {"cache_path", "path", "report_output_dir"}
        }
    if isinstance(value, list):
        return [_strip_internal_fields(item) for item in value]
    return value


class BearerTokenResolutionError(RuntimeError):
    """Raised when a configured PAM-backed bearer token cannot be resolved."""


def _resolve_bearer_token(secret_name: str | None, static_token: str | None) -> tuple[str | None, str | None]:
    if secret_name:
        try:
            secret_token = vault.retrieve_secret(secret_name)
        except Exception as exc:  # noqa: BLE001
            raise BearerTokenResolutionError(f"Failed to resolve bearer token secret: {secret_name}") from exc
        if secret_token:
            return secret_token, "pam_secret"
        return None, None
    if static_token:
        return static_token, "static_config"
    return None, None


def _expected_operator_token() -> tuple[str | None, str | None]:
    return _resolve_bearer_token(settings.operator_bearer_secret_name, settings.operator_bearer_token)


def _expected_endpoint_token() -> tuple[str | None, str | None]:
    return _resolve_bearer_token(settings.endpoint_bearer_secret_name, settings.endpoint_bearer_token)


def require_operator_access(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    client_host = request.client.host if request.client else None
    try:
        expected_token, _ = _expected_operator_token()
    except BearerTokenResolutionError as exc:
        audit_logger.log(
            "operator.auth.failure",
            {"path": request.url.path, "source_ip": client_host, "reason": "operator_token_resolution_failed"},
        )
        raise HTTPException(status_code=503, detail="Operator bearer token backend is unavailable.") from exc
    if expected_token:
        scheme, _, supplied_token = (authorization or "").partition(" ")
        if scheme.lower() == "bearer" and supplied_token and secrets.compare_digest(supplied_token, expected_token):
            return
        retry_after = _auth_failure_retry_after(
            "operator.http",
            client_host,
            settings.operator_auth_max_failures_per_window,
        )
        if retry_after is not None:
            audit_logger.log(
                "operator.auth.rate_limit.exceeded",
                {"path": request.url.path, "source_ip": client_host, "retry_after_seconds": retry_after},
            )
            raise HTTPException(
                status_code=429,
                detail="Too many authentication failures; retry later.",
                headers={"Retry-After": str(int(retry_after))},
            )
        audit_logger.log(
            "operator.auth.failure",
            {"path": request.url.path, "source_ip": client_host, "reason": "missing_or_invalid_bearer_token"},
        )
        raise HTTPException(
            status_code=401,
            detail="Operator authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if settings.operator_allow_loopback_without_token and _is_loopback_client(client_host):
        return
    audit_logger.log(
        "operator.auth.failure",
        {"path": request.url.path, "source_ip": client_host, "reason": "operator_token_not_configured"},
    )
    raise HTTPException(
        status_code=503,
        detail="Operator bearer token is not configured for remote management.",
    )


def require_endpoint_access(
    request: Request,
    authorization: str | None = Header(default=None),
) -> None:
    client_host = request.client.host if request.client else None
    try:
        expected_token, _ = _expected_endpoint_token()
    except BearerTokenResolutionError as exc:
        audit_logger.log(
            "endpoint.auth.failure",
            {"path": request.url.path, "source_ip": client_host, "reason": "endpoint_token_resolution_failed"},
        )
        raise HTTPException(status_code=503, detail="Endpoint bearer token backend is unavailable.") from exc
    if expected_token:
        scheme, _, supplied_token = (authorization or "").partition(" ")
        if scheme.lower() == "bearer" and supplied_token and secrets.compare_digest(supplied_token, expected_token):
            return
        retry_after = _auth_failure_retry_after(
            "endpoint.http",
            client_host,
            settings.endpoint_auth_max_failures_per_window,
        )
        if retry_after is not None:
            audit_logger.log(
                "endpoint.auth.rate_limit.exceeded",
                {"path": request.url.path, "source_ip": client_host, "retry_after_seconds": retry_after},
            )
            raise HTTPException(
                status_code=429,
                detail="Too many authentication failures; retry later.",
                headers={"Retry-After": str(int(retry_after))},
            )
        audit_logger.log(
            "endpoint.auth.failure",
            {"path": request.url.path, "source_ip": client_host, "reason": "missing_or_invalid_bearer_token"},
        )
        raise HTTPException(
            status_code=401,
            detail="Endpoint authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if settings.endpoint_allow_loopback_without_token and _is_loopback_client(client_host):
        return
    audit_logger.log(
        "endpoint.auth.failure",
        {"path": request.url.path, "source_ip": client_host, "reason": "endpoint_token_not_configured"},
    )
    raise HTTPException(
        status_code=503,
        detail="Endpoint bearer token is not configured for remote ingestion.",
    )


async def require_operator_websocket_access(websocket: WebSocket) -> bool:
    client_host = websocket.client.host if websocket.client else None
    authorization = websocket.headers.get("authorization")
    origin = _normalize_origin(websocket.headers.get("origin"))
    allowed_origins = _allowed_websocket_origins()
    if origin and origin not in allowed_origins:
        audit_logger.log(
            "operator.auth.failure",
            {"path": websocket.url.path, "source_ip": client_host, "reason": "disallowed_origin", "origin": origin},
        )
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": "WebSocket origin is not allowed."})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return False
    try:
        expected_token, _ = _expected_operator_token()
    except BearerTokenResolutionError:
        audit_logger.log(
            "operator.auth.failure",
            {"path": websocket.url.path, "source_ip": client_host, "reason": "operator_token_resolution_failed"},
        )
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": "Operator bearer token backend is unavailable."})
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        return False
    if expected_token:
        scheme, _, supplied_token = (authorization or "").partition(" ")
        if scheme.lower() == "bearer" and supplied_token and secrets.compare_digest(supplied_token, expected_token):
            return True
        retry_after = _auth_failure_retry_after(
            "operator.websocket",
            client_host,
            settings.operator_auth_max_failures_per_window,
        )
        if retry_after is not None:
            audit_logger.log(
                "operator.auth.rate_limit.exceeded",
                {"path": websocket.url.path, "source_ip": client_host, "retry_after_seconds": retry_after},
            )
            await websocket.accept()
            await websocket.send_json({"type": "error", "message": "Too many authentication failures; retry later."})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return False
        audit_logger.log(
            "operator.auth.failure",
            {"path": websocket.url.path, "source_ip": client_host, "reason": "missing_or_invalid_bearer_token"},
        )
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": "Operator authentication required."})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return False
    if settings.operator_allow_loopback_without_token and _is_loopback_client(client_host):
        return True
    audit_logger.log(
        "operator.auth.failure",
        {"path": websocket.url.path, "source_ip": client_host, "reason": "operator_token_not_configured"},
    )
    await websocket.accept()
    await websocket.send_json(
        {"type": "error", "message": "Operator bearer token is not configured for remote management."}
    )
    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
    return False


@app.post("/access/evaluate", response_model=AccessDecision)
async def evaluate_access(access_request: AccessRequest, http_request: Request) -> AccessDecision:
    _enforce_public_rate_limit(
        http_request,
        scope="access.evaluate",
        max_requests=settings.access_evaluate_max_requests_per_window,
    )
    if not access_request.source_ip and http_request.client:
        access_request.source_ip = _normalized_ip_or_none(http_request.client.host)
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
    if decision.decision.value != "allow":
        severity = SocSeverity.critical if decision.decision.value == "deny" else SocSeverity.high
        _record_soc_event(
            event_type="policy.access_decision",
            severity=severity,
            title=f"Access {decision.decision.value} for {access_request.resource}",
            summary=f"User {access_request.user.user_id} received a {decision.decision.value} decision.",
            details={
                "user_id": access_request.user.user_id,
                "device_id": access_request.device.device_id,
                "resource": access_request.resource,
                "privilege_level": access_request.privilege_level,
                "source_ip": access_request.source_ip,
                "decision": decision.decision.value,
                "risk_score": decision.risk_score,
                "reasons": decision.reasons,
            },
            tags=["access", decision.decision.value],
        )
    return decision


class SecretPayload(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=MAX_SECRET_NAME_LENGTH,
        pattern=r"^[A-Za-z0-9._:/-]+$",
    )
    secret: str = Field(min_length=1, max_length=MAX_SECRET_VALUE_LENGTH)

    @field_validator("name")
    @classmethod
    def validate_name_boundaries(cls, value: str) -> str:
        if value[0] in "./" or value[-1] in "./":
            raise ValueError("Secret name must not start or end with '.' or '/'.")
        return value


@app.put("/pam/secret")
async def store_secret(
    payload: SecretPayload,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        vault.store_secret(payload.name, payload.secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "stored", "name": payload.name, "metrics": vault.get_metrics()}


class CheckoutPayload(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=MAX_SECRET_NAME_LENGTH,
        pattern=r"^[A-Za-z0-9._:/-]+$",
    )
    ttl_minutes: int = Field(default=15, ge=MIN_LEASE_TTL_MINUTES, le=MAX_LEASE_TTL_MINUTES)

    @field_validator("name")
    @classmethod
    def validate_name_boundaries(cls, value: str) -> str:
        if value[0] in "./" or value[-1] in "./":
            raise ValueError("Secret name must not start or end with '.' or '/'.")
        return value


@app.post("/pam/checkout", response_model=CredentialLease)
async def checkout_secret(
    payload: CheckoutPayload,
    _: None = Depends(require_operator_access),
) -> CredentialLease:
    try:
        return vault.checkout(payload.name, payload.ttl_minutes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/pam/metrics")
async def pam_metrics(_: None = Depends(require_operator_access)) -> dict:
    return vault.get_metrics()


@app.get("/dns/resolve")
async def resolve_dns(request: Request, hostname: str, record_type: str = "A") -> dict:
    _enforce_public_rate_limit(
        request,
        scope="dns.resolve",
        max_requests=settings.dns_resolve_max_requests_per_window,
    )
    try:
        normalized_hostname, normalized_record_type = resolver.normalize_query(hostname, record_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    tracker_match = (
        tracker_intel.is_tracker_hostname(normalized_hostname)
        if settings.tracker_block_enabled
        else None
    )
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
        _record_soc_event(
            event_type="privacy.tracker_block",
            severity=SocSeverity.medium,
            title=f"Tracker domain blocked: {tracker_match.hostname}",
            summary="DNS resolution was denied because the hostname matched tracker intelligence.",
            details={
                "target_type": "dns",
                "hostname": tracker_match.hostname,
                "matched_domain": tracker_match.matched_domain,
                "source": tracker_match.source,
                "confidence": tracker_match.confidence,
                "reason": tracker_match.reason,
                "record_type": record_type,
            },
            tags=["privacy", "tracker"],
        )
        raise HTTPException(status_code=403, detail=f"Tracker domain blocked: {tracker_match.hostname}")
    result = resolver.resolve(normalized_hostname, normalized_record_type)
    dns_security_cache.record(normalized_hostname, result.secure)
    return {
        "secure": result.secure,
        "records": [record.__dict__ for record in result.records],
    }


@app.post("/endpoint/telemetry")
async def publish_telemetry(
    device: DeviceContext,
    _: None = Depends(require_endpoint_access),
) -> dict:
    signature = telemetry.publish(device)
    if device.compliance.value in {"drifted", "compromised"}:
        _record_soc_event(
            event_type="endpoint.telemetry_posture",
            severity=SocSeverity.high if device.compliance.value == "compromised" else SocSeverity.medium,
            title=f"Endpoint posture {device.compliance.value}: {device.device_id}",
            summary=f"Endpoint {device.device_id} reported {device.compliance.value} posture.",
            details=device.model_dump(mode="json"),
            tags=["endpoint", device.compliance.value],
        )
    return {"signature": signature}


@app.get("/endpoint/telemetry/{device_id}")
async def fetch_telemetry(
    device_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    payload = telemetry.get_payload(device_id)
    if not payload:
        raise HTTPException(status_code=404, detail="Device not found or signature invalid")
    return payload


if multipart_installed:
    @app.post("/endpoint/scan")
    async def scan_file(
        _: None = Depends(require_endpoint_access),
        file: UploadFile = File(...),
    ) -> dict:
        data = await _read_upload_with_limit(file, settings.endpoint_scan_max_upload_bytes)
        malicious, verdict = scanner.scan_bytes(data)
        if malicious:
            _record_soc_event(
                event_type="endpoint.malware_detected",
                severity=SocSeverity.critical,
                title=f"Malware detected in upload: {file.filename or 'unknown'}",
                summary="The endpoint scanner marked an uploaded file as malicious.",
                details={"filename": file.filename, "verdict": verdict},
                tags=["endpoint", "malware"],
            )
        return {"malicious": malicious, "verdict": verdict}
else:
    @app.post("/endpoint/scan")
    async def scan_file_unavailable(
        _: None = Depends(require_endpoint_access),
    ) -> dict:
        raise HTTPException(
            status_code=503,
            detail="File upload scanning is unavailable; install python-multipart",
        )


class ProxyPayload(BaseModel):
    url: str
    method: str = "GET"
    via: str = "tor"

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        candidate = value.strip().upper()
        if candidate not in ALLOWED_PROXY_METHODS:
            raise ValueError(f"method must be one of: {', '.join(sorted(ALLOWED_PROXY_METHODS))}")
        return candidate


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


class RefreshMalwareFeedsPayload(BaseModel):
    urls: list[str] | None = None


class RefreshMalwareRuleFeedsPayload(BaseModel):
    urls: list[str] | None = None


class ImportFeedPayload(BaseModel):
    source_path: str


@app.get("/endpoint/malware-feeds/status")
async def malware_feed_status() -> dict:
    return _strip_internal_fields(scanner.feed_status())


@app.post("/endpoint/malware-feeds/refresh")
async def malware_feed_refresh(
    payload: RefreshMalwareFeedsPayload | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return _strip_internal_fields(scanner.refresh_feed_cache(payload.urls if payload else None))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _audit_backend_failure("malware.feed_refresh.failure", "/endpoint/malware-feeds/refresh", None, exc)
        raise HTTPException(status_code=502, detail="Malware feed refresh failed.") from exc


@app.post("/endpoint/malware-feeds/import")
async def malware_feed_import(
    payload: ImportFeedPayload,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return _strip_internal_fields(scanner.import_feed_cache(payload.source_path))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/endpoint/malware-rule-feeds/status")
async def malware_rule_feed_status() -> dict:
    return _strip_internal_fields(scanner.rule_feed_status())


@app.post("/endpoint/malware-rule-feeds/refresh")
async def malware_rule_feed_refresh(
    payload: RefreshMalwareRuleFeedsPayload | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return _strip_internal_fields(scanner.refresh_rule_feed_cache(payload.urls if payload else None))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _audit_backend_failure("malware.rule_feed_refresh.failure", "/endpoint/malware-rule-feeds/refresh", None, exc)
        raise HTTPException(status_code=502, detail="Malware rule feed refresh failed.") from exc


@app.post("/endpoint/malware-rule-feeds/import")
async def malware_rule_feed_import(
    payload: ImportFeedPayload,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return _strip_internal_fields(scanner.import_rule_feed_cache(payload.source_path))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/tor/request")
async def proxy_request(payload: ProxyPayload, request: Request, _: None = Depends(require_operator_access)) -> dict:
    _enforce_public_rate_limit(
        request,
        scope="proxy.request",
        max_requests=settings.proxy_request_max_requests_per_window,
    )
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
        _record_soc_event(
            event_type="privacy.tracker_block",
            severity=SocSeverity.medium,
            title=f"Tracker request blocked: {tracker_match.hostname}",
            summary="Proxy egress was denied because the destination matched tracker intelligence.",
            details={
                "target_type": "proxy",
                "url": payload.url,
                "hostname": tracker_match.hostname,
                "matched_domain": tracker_match.matched_domain,
                "source": tracker_match.source,
                "confidence": tracker_match.confidence,
                "reason": tracker_match.reason,
                "via": payload.via,
            },
            tags=["privacy", "tracker", "proxy"],
        )
        raise HTTPException(status_code=403, detail=f"Tracker destination blocked: {tracker_match.hostname}")
    try:
        result = proxy.request(payload.method, payload.url, via=payload.via)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ProxyResponseTooLargeError as exc:
        _audit_backend_failure("proxy.request.failure", request.url.path, request.client.host if request.client else None, exc)
        raise HTTPException(status_code=413, detail="Proxy response exceeded the configured size limit.") from exc
    except ProxyRequestTimeoutError as exc:
        _audit_backend_failure("proxy.request.failure", request.url.path, request.client.host if request.client else None, exc)
        raise HTTPException(status_code=504, detail="Proxy request timed out.") from exc
    except Exception as exc:  # noqa: BLE001
        _audit_backend_failure("proxy.request.failure", request.url.path, request.client.host if request.client else None, exc)
        raise HTTPException(status_code=502, detail="Proxy request failed.") from exc
    return {
        "status_code": result.status_code,
        "headers": result.headers,
        "body": result.body,
    }


@app.get("/proxy/health")
async def proxy_health(_: None = Depends(require_operator_access)) -> dict:
    return proxy.health()


@app.get("/privacy/tracker-events")
async def tracker_events(
    max_events: int = Query(default=50, ge=1, le=MAX_REPORT_MAX_EVENTS),
    _: None = Depends(require_operator_access),
) -> dict:
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
    return _strip_internal_fields(tracker_intel.feed_status())


@app.post("/privacy/tracker-feeds/refresh")
async def tracker_feed_refresh(
    payload: RefreshTrackerFeedsPayload | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return _strip_internal_fields(tracker_intel.refresh_feed_cache(payload.urls if payload else None))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _audit_backend_failure("tracker.feed_refresh.failure", "/privacy/tracker-feeds/refresh", None, exc)
        raise HTTPException(status_code=502, detail="Tracker feed refresh failed.") from exc


@app.post("/privacy/tracker-feeds/import")
async def tracker_feed_import(
    payload: ImportFeedPayload,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return _strip_internal_fields(tracker_intel.import_feed_cache(payload.source_path))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/network/blocked-ips")
async def list_blocked_ips(_: None = Depends(require_operator_access)) -> dict:
    return {"blocked_ips": [entry.__dict__ for entry in ip_blocklist.list_entries()]}


@app.post("/network/blocked-ips")
async def block_ip(
    payload: BlockIPPayload,
    _: None = Depends(require_operator_access),
) -> dict:
    entry = ip_blocklist.block(
        payload.ip,
        reason=payload.reason,
        blocked_by="api",
        duration_minutes=payload.duration_minutes,
    )
    return {"status": "blocked", "entry": entry.__dict__}


@app.delete("/network/blocked-ips/{ip}")
async def unblock_ip(
    ip: str,
    payload: UnblockIPPayload | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    removed = ip_blocklist.unblock(ip, reason=payload.reason if payload else None, unblocked_by="api")
    if not removed:
        raise HTTPException(status_code=404, detail="IP address not blocked")
    return {"status": "unblocked", "ip": ip}


@app.post("/network/blocked-ips/{ip}/promote")
async def promote_ip_block(
    ip: str,
    payload: PromoteIPPayload | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    entry = ip_blocklist.promote_to_permanent(
        ip,
        reason=payload.reason if payload else None,
        promoted_by="api",
    )
    if not entry:
        raise HTTPException(status_code=404, detail="IP address not blocked")
    return {"status": "promoted", "entry": entry.__dict__}


@app.get("/automation/status")
async def automation_status(_: None = Depends(require_operator_access)) -> dict:
    return automation.status()


@app.get("/soc/overview")
async def soc_overview(_: None = Depends(require_operator_access)) -> dict:
    return soc_manager.overview()


@app.get("/soc/dashboard")
async def soc_dashboard(_: None = Depends(require_operator_access)) -> dict:
    return soc_manager.dashboard()


@app.post("/soc/events")
async def soc_ingest_event(
    payload: SocEventIngest,
    _: None = Depends(require_operator_access),
) -> dict:
    result = _record_soc_event(
        event_type=payload.event_type,
        severity=payload.severity,
        title=payload.title,
        summary=payload.summary,
        details=payload.details,
        artifacts=payload.artifacts,
        tags=payload.tags,
    )
    event_record, alert_record = result
    return {
        "event": event_record.model_dump(mode="json"),
        "alert": alert_record.model_dump(mode="json") if alert_record is not None else None,
    }


@app.get("/soc/events")
async def soc_list_events(
    limit: int = Query(default=50, ge=1, le=250),
    severity: SocSeverity | None = None,
    event_type: str | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.list_events(limit=limit, severity=severity, event_type=event_type)
    return {"events": [event.model_dump(mode="json") for event in events]}


@app.get("/soc/alerts")
async def soc_list_alerts(
    status: SocAlertStatus | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    alerts = soc_manager.list_alerts(status=status)
    return {"alerts": [alert.model_dump(mode="json") for alert in alerts]}


@app.get("/soc/alerts/{alert_id}")
async def soc_get_alert(
    alert_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        alert = soc_manager.get_alert(alert_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return alert.model_dump(mode="json")


@app.patch("/soc/alerts/{alert_id}")
async def soc_update_alert(
    alert_id: str,
    payload: SocAlertUpdate,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        alert = soc_manager.update_alert(alert_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return alert.model_dump(mode="json")


@app.post("/soc/alerts/{alert_id}/case")
async def soc_promote_alert_to_case(
    alert_id: str,
    payload: SocAlertPromoteCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        alert, case = soc_manager.promote_alert_to_case(alert_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "alert": alert.model_dump(mode="json"),
        "case": case.model_dump(mode="json"),
    }


@app.post("/soc/cases")
async def soc_create_case(
    payload: SocCaseCreate,
    _: None = Depends(require_operator_access),
) -> dict:
    case = soc_manager.create_case(payload)
    return case.model_dump(mode="json")


@app.get("/soc/cases")
async def soc_list_cases(
    status: SocCaseStatus | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    cases = soc_manager.list_cases(status=status)
    return {"cases": [case.model_dump(mode="json") for case in cases]}


@app.get("/soc/cases/{case_id}")
async def soc_get_case(
    case_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.get_case(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.patch("/soc/cases/{case_id}")
async def soc_update_case(
    case_id: str,
    payload: SocCaseUpdate,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.update_case(case_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.get("/health/security")
async def security_health() -> dict:
    tracker_health = tracker_intel.health_status()
    malware_health = scanner.health_status()
    auth_health = _security_auth_health()
    auth_warnings = cast(list[str], auth_health["warnings"])
    warnings = [*tracker_health["warnings"], *malware_health["warnings"], *auth_warnings]
    return _strip_internal_fields({
        "healthy": not warnings,
        "warnings": warnings,
        "auth_backends": auth_health,
        "tracker_intel": tracker_health,
        "malware_scanner": malware_health,
        "automation": automation.status(),
        "soc": {
            key: value
            for key, value in soc_manager.overview().items()
            if key != "recent_events"
        },
    })


@app.get("/reports/security-summary.pdf")
async def security_summary_report(
    max_events: int = Query(default=25, ge=MIN_REPORT_MAX_EVENTS, le=MAX_REPORT_MAX_EVENTS),
    time_window_hours: float | None = Query(default=None, gt=0, le=MAX_REPORT_TIME_WINDOW_HOURS),
    min_risk_score: float = Query(
        default=0.0,
        ge=MIN_REPORT_MIN_RISK_SCORE,
        le=MAX_REPORT_MIN_RISK_SCORE,
    ),
    include_blocked_ips: bool = True,
    include_potential_blocked_ips: bool = True,
    include_recent_events: bool = True,
    _: None = Depends(require_operator_access),
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
async def list_reports(_: None = Depends(require_operator_access)) -> dict:
    return _strip_internal_fields({"reports": report_builder.list_saved_reports()})


@app.get("/reports/{report_name}")
async def fetch_report(
    report_name: str,
    _: None = Depends(require_operator_access),
) -> FileResponse:
    try:
        target = report_builder.resolve_saved_report(report_name)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(path=target, media_type="application/pdf", filename=target.name)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    if not await require_operator_websocket_access(websocket):
        return
    await websocket.accept()
    await websocket.send_json({"type": "ready", "message": "connected", "mode": "health_only"})
    window_started_at = monotonic()
    message_count = 0
    try:
        while True:
            payload = await websocket.receive_text()
            now = monotonic()
            if now - window_started_at > settings.websocket_rate_window_seconds:
                window_started_at = now
                message_count = 0
            message_count += 1
            if message_count > settings.websocket_max_messages_per_window:
                await websocket.send_json(
                    {
                        "type": "error",
                        "message": "WebSocket message rate limit exceeded.",
                    }
                )
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                break
            message = payload.strip()
            if message.lower() in {"ping", "health"}:
                await websocket.send_text("pong")
            elif message.lower() in {"close", "exit", "quit"}:
                await websocket.close(code=1000)
                break
            else:
                await websocket.send_json(
                    {
                        "type": "unsupported",
                        "message": "health-only websocket; supported commands: ping, health, close",
                    }
                )
    except WebSocketDisconnect:
        return
