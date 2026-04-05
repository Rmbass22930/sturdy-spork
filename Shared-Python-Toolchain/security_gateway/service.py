"""FastAPI service exposing the security gateway."""
from __future__ import annotations

import html
import importlib.util
import json
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from time import monotonic
from typing import Any, Mapping, cast
from urllib.parse import urlparse
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response

from fastapi import (
    Body,
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
from .host_monitor import HostMonitor
from .network_monitor import NetworkMonitor
from .packet_monitor import PacketMonitor
from .ip_controls import IPBlocklistManager
from .models import (
    AccessDecision,
    AccessRequest,
    CredentialLease,
    DeviceContext,
    EndpointFileTelemetry,
    EndpointProcessTelemetry,
    LinearAsksFormUpsert,
    PlatformNodeAcknowledgeRequest,
    PlatformNodeActionUpdateRequest,
    PlatformNodeDrainRequest,
    PlatformNodeRefreshRequest,
    PlatformNodeMaintenanceRequest,
    PlatformNodeSuppressRequest,
    SocAlertRecord,
    SocAlertPromoteCaseRequest,
    SocAlertStatus,
    SocDashboardViewStateUpdate,
    SocDetectionRuleUpdate,
    SocAlertUpdate,
    SocCaseTelemetryClusterCaseRequest,
    SocCaseEndpointLineageClusterCaseRequest,
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocCaseCreate,
    SocCaseRecord,
    SocEndpointLineageClusterCaseRequest,
    SocEndpointQueryCaseRequest,
    SocEndpointTimelineCaseRequest,
    SocCaseStatus,
    SocCaseUpdate,
    SocEventIngest,
    SocEventRecord,
    SocNetworkEvidenceCaseRequest,
    SocNetworkSensorTelemetryIngest,
    SocPacketCaptureCaseRequest,
    SocPacketSessionCaseRequest,
    SocProtocolEvidence,
    SocRemoteNodeCaseRequest,
    SocTelemetryClusterCaseRequest,
    SocSeverity,
)
from .pam import (
    MAX_LEASE_TTL_MINUTES,
    MAX_SECRET_NAME_LENGTH,
    MAX_SECRET_VALUE_LENGTH,
    MIN_LEASE_TTL_MINUTES,
    VaultClient,
)
from .platform import (
    acknowledge_platform_node_action,
    apply_local_platform_action,
    build_platform_node_actions,
    build_node_heartbeat_payload,
    cancel_platform_node_action,
    build_platform_profile,
    clear_platform_node_drain,
    complete_platform_node_action,
    clear_platform_node_suppression,
    clear_platform_node_maintenance,
    normalize_platform_node_role,
    request_platform_node_refresh,
    retry_platform_node_action,
    role_managed_service_enabled,
    send_platform_node_heartbeat,
    sync_local_platform_action_state,
    synchronize_platform_node_actions,
    start_platform_node_drain,
    start_platform_node_maintenance,
    suppress_platform_node,
    update_platform_node_metadata,
    upsert_platform_node,
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
from .stream_monitor import StreamArtifactMonitor
from .tracker_intel import TrackerIntel
from .tor import ALLOWED_PROXY_METHODS, OutboundProxy, ProxyRequestTimeoutError, ProxyResponseTooLargeError
from .threat_response import ThreatResponseCoordinator
from toolchain_resources.docker_resources import get_docker_resource, list_docker_resources
from toolchain_resources.doctor import ToolchainDoctor
from toolchain_resources.linear_forms import LinearAsksFormRegistry
from toolchain_resources.runtime import get_toolchain_runtime, load_toolchain_runtime

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
linear_asks_forms = LinearAsksFormRegistry(settings.linear_asks_forms_path)
toolchain_runtime = get_toolchain_runtime()
toolchain_doctor = ToolchainDoctor()


def _current_platform_profile() -> dict[str, object]:
    automation_runtime = cast(AutomationSupervisor | None, globals().get("automation"))
    tracker_runtime = cast(TrackerIntel | None, globals().get("tracker_intel"))
    malware_runtime = cast(MalwareScanner | None, globals().get("scanner"))
    return build_platform_profile(
        automation_status=automation_runtime.status() if automation_runtime is not None else None,
        tracker_health=tracker_runtime.health_status() if tracker_runtime is not None else None,
        malware_health=malware_runtime.health_status() if malware_runtime is not None else None,
    )


def _platform_node_heartbeat_enabled() -> bool:
    return (
        settings.platform_manager_heartbeat_enabled
        and bool(settings.platform_manager_url)
        and settings.platform_deployment_mode != "single-node"
        and normalize_platform_node_role() != "manager"
    )


def _emit_platform_node_heartbeat() -> dict[str, object]:
    if not _platform_node_heartbeat_enabled():
        return {"result": "disabled"}
    managed_services = [
        "tracker_feed_refresh",
        "malware_feed_refresh",
        "malware_rule_feed_refresh",
        "host_monitor",
        "network_monitor",
        "packet_monitor",
        "stream_monitor",
    ]
    payload = build_node_heartbeat_payload(_current_platform_profile())
    response = send_platform_node_heartbeat(
        manager_url=str(settings.platform_manager_url),
        bearer_token=settings.platform_manager_bearer_token,
        payload=payload,
        timeout_seconds=settings.platform_manager_timeout_seconds,
    )
    def _execute_action(action_payload: Mapping[str, Any]) -> dict[str, object]:
        return apply_local_platform_action(
            action_payload,
            path=settings.platform_local_action_state_path,
            available_services=managed_services,
        )
    action_sync = synchronize_platform_node_actions(
        manager_url=str(settings.platform_manager_url),
        node_name=str(payload["node_name"]),
        acted_by=str(payload["node_name"]),
        actions=cast(list[dict[str, object]], response.get("actions") or []),
        executor=_execute_action,
        bearer_token=settings.platform_manager_bearer_token,
        timeout_seconds=settings.platform_manager_timeout_seconds,
    )
    local_state = sync_local_platform_action_state(
        node_payload=cast(dict[str, object], response.get("node") or {}),
        path=settings.platform_local_action_state_path,
        available_services=managed_services,
    )
    if automation is not None:
        automation.apply_drained_services(set(cast(list[str], local_state.get("drained_services") or [])))
    return {
        "result": "success",
        "manager_url": str(settings.platform_manager_url),
        "node_name": payload["node_name"],
        "topology": response.get("topology"),
        "actions": action_sync,
        "local_action_state": local_state,
    }


soc_manager = SecurityOperationsManager(
    event_log_path=settings.soc_event_log_path,
    alert_store_path=settings.soc_alert_store_path,
    case_store_path=settings.soc_case_store_path,
    audit_logger=audit_logger,
    alert_manager=alert_manager,
    platform_profile_builder=_current_platform_profile,
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
host_monitor = HostMonitor(
    state_path=settings.host_monitor_state_path,
    system_drive=settings.host_monitor_system_drive,
    disk_free_percent_threshold=settings.host_monitor_disk_free_percent_threshold,
)
network_monitor = NetworkMonitor(
    state_path=settings.network_monitor_state_path,
    suspicious_repeat_threshold=settings.network_monitor_repeat_threshold,
    dos_hit_threshold=settings.network_monitor_dos_hit_threshold,
    dos_syn_threshold=settings.network_monitor_dos_syn_threshold,
    dos_port_span_threshold=settings.network_monitor_dos_port_span_threshold,
    sensitive_ports=settings.network_monitor_sensitive_ports,
)
packet_monitor = PacketMonitor(
    state_path=settings.packet_monitor_state_path,
    sample_seconds=settings.packet_monitor_sample_seconds,
    min_packet_count=settings.packet_monitor_min_packet_count,
    anomaly_multiplier=settings.packet_monitor_anomaly_multiplier,
    learning_samples=settings.packet_monitor_learning_samples,
    pkt_size=settings.packet_monitor_capture_bytes,
    capture_retention_enabled=settings.packet_monitor_capture_retention_enabled,
    capture_retention_path=settings.packet_monitor_capture_retention_path,
    capture_retention_limit=settings.packet_monitor_capture_retention_limit,
    sensitive_ports=settings.packet_monitor_sensitive_ports,
)
stream_monitor = StreamArtifactMonitor(
    state_path=settings.stream_monitor_state_path,
    artifact_roots=settings.stream_monitor_artifact_roots,
    suspicious_extensions=settings.stream_monitor_suspicious_extensions,
    max_age_minutes=settings.stream_monitor_max_age_minutes,
    max_files_per_tick=settings.stream_monitor_max_files_per_tick,
    scan_timeout_seconds=settings.stream_monitor_scan_timeout_seconds,
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
    manager_health = _platform_manager_security_health()
    if not cast(bool, manager_health["healthy"]) and cast(bool, manager_health["required"]):
        raise RuntimeError(str(manager_health["error"]))


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


def _url_host_is_local(hostname: str | None) -> bool:
    if not hostname:
        return False
    normalized = hostname.strip().strip("[]").casefold()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_local_service_url(url: str | None) -> bool:
    candidate = str(url or "").strip()
    if not candidate:
        return False
    parsed = urlparse(candidate)
    if parsed.hostname:
        return _url_host_is_local(parsed.hostname)
    if "://" not in candidate:
        return _url_host_is_local(candidate.split("/", 1)[0].split(":", 1)[0])
    return False


def _platform_manager_required() -> bool:
    return (
        settings.platform_manager_heartbeat_enabled
        and settings.platform_deployment_mode != "single-node"
        and normalize_platform_node_role() != "manager"
    )


def _platform_manager_security_health() -> dict[str, object]:
    url = str(settings.platform_manager_url or "").strip()
    token = str(settings.platform_manager_bearer_token or "").strip()
    required = _platform_manager_required()
    local_url = _is_local_service_url(url)
    warnings: list[str] = []
    status: dict[str, object] = {
        "configured": bool(url),
        "required": required,
        "healthy": True,
        "url": url or None,
        "local_url": local_url,
        "token_configured": bool(token),
        "status": "ready",
        "source": "static_config" if token else "none",
        "warnings": warnings,
    }
    if not url:
        status["healthy"] = not required
        status["status"] = "unconfigured"
        if required:
            status["error"] = "Platform manager URL is required for the current deployment mode and node role."
            warnings.append("Platform manager URL is required but not configured.")
        return status
    if not local_url and not token:
        status["healthy"] = False
        status["status"] = "missing_token"
        status["error"] = "Platform manager bearer token is required for non-local remote manager access."
        warnings.append("Platform manager bearer token is required for non-local remote manager access.")
        return status
    if local_url and not token:
        status["status"] = "loopback_no_token"
        warnings.append("Platform manager URL is local and no bearer token is configured.")
        return status
    return status


def _alert_webhook_security_health() -> dict[str, object]:
    url = str(settings.alert_webhook_url or "").strip()
    warnings: list[str] = []
    status: dict[str, object] = {
        "configured": bool(url),
        "healthy": True,
        "url": url or None,
        "verify_tls": bool(settings.alert_webhook_verify_tls),
        "status": "ready",
        "warnings": warnings,
    }
    if not url:
        status["status"] = "unconfigured"
        return status
    parsed = urlparse(url)
    scheme = parsed.scheme.casefold()
    host = parsed.hostname
    status["scheme"] = scheme or None
    status["host"] = host
    if scheme not in {"http", "https"} or not host:
        status["healthy"] = False
        status["status"] = "invalid_url"
        warnings.append("Alert webhook URL is invalid.")
        return status
    if scheme != "https":
        status["healthy"] = False
        status["status"] = "insecure_transport"
        warnings.append("Alert webhook URL should use HTTPS.")
        return status
    if not settings.alert_webhook_verify_tls:
        status["healthy"] = False
        status["status"] = "tls_verification_disabled"
        warnings.append("Alert webhook TLS verification is disabled.")
        return status
    return status


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
    platform_manager = _platform_manager_security_health()
    alert_webhook = _alert_webhook_security_health()
    if not cast(bool, platform_manager["healthy"]):
        warnings.extend(cast(list[str], platform_manager.get("warnings") or []))
    if not cast(bool, alert_webhook["healthy"]):
        warnings.extend(cast(list[str], alert_webhook.get("warnings") or []))
    return {
        "healthy": not warnings,
        "warnings": warnings,
        "operator": operator_status,
        "endpoint": endpoint_status,
        "platform_manager": platform_manager,
        "alert_webhook": alert_webhook,
    }


def _record_soc_event(
    *,
    event_type: str,
    source: str = "security_gateway",
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
            source=source,
            severity=severity,
            title=title,
            summary=summary,
            details=details,
            artifacts=artifacts or [],
            tags=tags or [],
        )
    )
    return result.event, result.alert


def _normalized_monitor_details(
    *,
    monitor: str,
    finding: dict[str, object],
    observables: dict[str, object] | None = None,
) -> dict[str, object]:
    raw_details = finding.get("details", {})
    normalized: dict[str, object] = {
        "schema": f"{monitor}_finding_v1",
        "document_type": f"{monitor}_finding",
        "monitor": monitor,
        "finding_key": finding.get("key"),
        "resolved": bool(finding.get("resolved")),
        "details": raw_details,
    }
    if observables:
        normalized.update({key: value for key, value in observables.items() if value not in (None, "", [], {})})
    return normalized


def _normalized_endpoint_posture_details(device: DeviceContext) -> dict[str, object]:
    payload = device.model_dump(mode="json")
    return {
        "schema": "endpoint_posture_v1",
        "document_type": "endpoint_posture",
        "device_id": device.device_id,
        "compliance": device.compliance.value,
        "os": device.os,
        "os_version": device.os_version,
        "is_encrypted": device.is_encrypted,
        "edr_active": device.edr_active,
        "details": payload,
    }


def _normalized_endpoint_malware_details(*, filename: str | None, verdict: str, artifact_path: str | None = None) -> dict[str, object]:
    normalized_filename = (filename or "").strip() or None
    normalized_artifact_path = (artifact_path or "").strip() or None
    return {
        "schema": "endpoint_malware_v1",
        "document_type": "endpoint_malware",
        "filename": normalized_filename,
        "artifact_path": normalized_artifact_path,
        "verdict": verdict,
        "details": {
            "filename": normalized_filename,
            "artifact_path": normalized_artifact_path,
            "verdict": verdict,
        },
    }


def _normalized_endpoint_process_details(payload: EndpointProcessTelemetry) -> dict[str, object]:
    process_name = payload.process_name.strip()
    process_path = payload.process_path.strip() if payload.process_path else None
    process_sha256 = payload.process_sha256.strip() if payload.process_sha256 else None
    network_connections = [
        item for item in payload.network_connections
        if isinstance(item, dict)
    ]
    return {
        "schema": "endpoint_process_v1",
        "document_type": "endpoint_process",
        "device_id": payload.device_id,
        "process_name": process_name,
        "process_guid": payload.process_guid.strip() if payload.process_guid else None,
        "process_path": process_path,
        "sha256": process_sha256,
        "process_sha256": process_sha256,
        "parent_process_name": payload.parent_process_name.strip() if payload.parent_process_name else None,
        "parent_process_guid": payload.parent_process_guid.strip() if payload.parent_process_guid else None,
        "parent_process_path": payload.parent_process_path.strip() if payload.parent_process_path else None,
        "parent_process_sha256": payload.parent_process_sha256.strip() if payload.parent_process_sha256 else None,
        "parent_chain": list(payload.parent_chain),
        "command_line": payload.command_line,
        "user_name": payload.user_name,
        "integrity_level": payload.integrity_level,
        "signer_name": payload.signer_name.strip() if payload.signer_name else None,
        "signer_status": payload.signer_status.strip() if payload.signer_status else None,
        "reputation": payload.reputation.strip() if payload.reputation else None,
        "risk_flags": list(payload.risk_flags),
        "remote_ips": list(payload.remote_ips),
        "network_connections": network_connections,
        "details": payload.model_dump(mode="json"),
    }


def _normalized_endpoint_file_details(payload: EndpointFileTelemetry) -> dict[str, object]:
    filename = payload.filename.strip()
    artifact_path = payload.artifact_path.strip() if payload.artifact_path else None
    sha256 = payload.sha256.strip() if payload.sha256 else None
    file_extension = payload.file_extension.strip() if payload.file_extension else None
    return {
        "schema": "endpoint_file_v1",
        "document_type": "endpoint_file",
        "device_id": payload.device_id,
        "filename": filename,
        "artifact_path": artifact_path,
        "sha256": sha256,
        "operation": payload.operation.strip(),
        "size_bytes": payload.size_bytes,
        "verdict": payload.verdict,
        "actor_process_name": payload.actor_process_name.strip() if payload.actor_process_name else None,
        "actor_process_sha256": payload.actor_process_sha256.strip() if payload.actor_process_sha256 else None,
        "signer_name": payload.signer_name.strip() if payload.signer_name else None,
        "signer_status": payload.signer_status.strip() if payload.signer_status else None,
        "reputation": payload.reputation.strip() if payload.reputation else None,
        "file_extension": file_extension,
        "risk_flags": list(payload.risk_flags),
        "details": payload.model_dump(mode="json"),
    }


def _normalized_endpoint_connection_details(
    *,
    process_details: Mapping[str, object],
    connection: Mapping[str, object],
) -> dict[str, object] | None:
    remote_ip = str(connection.get("remote_ip") or "").strip()
    if not remote_ip:
        return None
    observed_at = str(connection.get("observed_at") or datetime.now(UTC).isoformat())
    first_seen_at = str(connection.get("first_seen_at") or observed_at)
    last_seen_at = str(connection.get("last_seen_at") or observed_at)
    state = connection.get("state")
    state_history = connection.get("state_history")
    if not isinstance(state_history, list):
        state_history = [state] if state else []
    return {
        "schema": "endpoint_connection_v1",
        "document_type": "endpoint_connection",
        "device_id": process_details.get("device_id"),
        "process_name": process_details.get("process_name"),
        "process_guid": process_details.get("process_guid"),
        "process_path": process_details.get("process_path"),
        "sha256": process_details.get("sha256"),
        "signer_name": process_details.get("signer_name"),
        "signer_status": process_details.get("signer_status"),
        "reputation": process_details.get("reputation"),
        "risk_flags": process_details.get("risk_flags") or [],
        "remote_ip": remote_ip,
        "remote_port": connection.get("remote_port"),
        "local_ip": connection.get("local_ip"),
        "local_port": connection.get("local_port"),
        "protocol": connection.get("protocol"),
        "state": state,
        "state_history": state_history,
        "connection_count": connection.get("connection_count") or 1,
        "observed_at": observed_at,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "details": {
            "process": dict(process_details),
            "connection": dict(connection),
        },
    }


def _endpoint_timeline_entry(event: SocEventRecord) -> dict[str, object]:
    details = event.details if isinstance(event.details, dict) else {}
    recorded_at = (
        details.get("observed_at")
        or details.get("last_seen_at")
        or details.get("snapshot_at")
        or event.created_at.isoformat()
    )
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "document_type": details.get("document_type"),
        "device_id": details.get("device_id"),
        "process_name": details.get("process_name") or details.get("actor_process_name"),
        "process_guid": details.get("process_guid"),
        "filename": details.get("filename"),
        "artifact_path": details.get("artifact_path"),
        "remote_ip": details.get("remote_ip"),
        "recorded_at": recorded_at,
        "created_at": event.created_at.isoformat(),
        "severity": event.severity.value,
        "title": event.title,
        "summary": event.summary,
        "details": details,
    }


def _record_network_monitor_snapshot(snapshot: dict[str, object]) -> None:
    checked_at = str(snapshot.get("checked_at") or "")
    observations = snapshot.get("suspicious_observations")
    if not isinstance(observations, list):
        return
    for item in observations:
        if not isinstance(item, dict):
            continue
        remote_ip = str(item.get("remote_ip") or "").strip()
        if not remote_ip:
            continue
        _record_soc_event(
            event_type="network.telemetry.connection",
            severity=SocSeverity.low,
            title=f"Network telemetry for {remote_ip}",
            summary="Network monitor captured a normalized remote-IP observation.",
            details={
                "schema": "network_connection_v1",
                "document_type": "network_connection",
                "remote_ip": remote_ip,
                "local_ports": item.get("local_ports") or [],
                "remote_ports": item.get("remote_ports") or [],
                "states": item.get("states") or [],
                "transport_families": sorted(
                    {
                        str(flow.get("transport_family") or "").strip().lower()
                        for flow in cast(list[dict[str, object]], item.get("sample_connections") or [])
                        if isinstance(flow, dict) and str(flow.get("transport_family") or "").strip()
                    }
                ),
                "service_names": sorted(
                    {
                        str(flow.get("service_name") or "").strip().lower()
                        for flow in cast(list[dict[str, object]], item.get("sample_connections") or [])
                        if isinstance(flow, dict) and str(flow.get("service_name") or "").strip()
                    }
                ),
                "application_protocols": sorted(
                    {
                        str(flow.get("application_protocol") or "").strip().lower()
                        for flow in cast(list[dict[str, object]], item.get("sample_connections") or [])
                        if isinstance(flow, dict) and str(flow.get("application_protocol") or "").strip()
                    }
                ),
                "flow_ids": [
                    str(flow.get("flow_id"))
                    for flow in cast(list[dict[str, object]], item.get("sample_connections") or [])
                    if isinstance(flow, dict) and str(flow.get("flow_id") or "").strip()
                ],
                "state_counts": item.get("state_counts") or {},
                "hit_count": item.get("hit_count") or 0,
                "sensitive_ports": item.get("sensitive_ports") or [],
                "process_ids": item.get("process_ids") or [],
                "process_names": item.get("process_names") or [],
                "sample_connections": item.get("sample_connections") or [],
                "snapshot_at": checked_at,
                "details": item,
            },
            tags=["network", "telemetry", "connection"],
        )
        sample_connections = item.get("sample_connections")
        if not isinstance(sample_connections, list):
            continue
        for flow in sample_connections:
            if not isinstance(flow, dict):
                continue
            local_ip = str(flow.get("local_ip") or "").strip()
            remote_flow_ip = str(flow.get("remote_ip") or "").strip()
            local_port = flow.get("local_port")
            remote_port = flow.get("remote_port")
            state = str(flow.get("state") or "").strip()
            if (
                not local_ip
                or not remote_flow_ip
                or not isinstance(local_port, int)
                or not isinstance(remote_port, int)
                or not state
            ):
                continue
            protocol = str(flow.get("protocol") or "tcp").strip().lower()
            flow_key = f"{remote_flow_ip}:{remote_port}->{local_ip}:{local_port}/{protocol}"
            flow_id = str(flow.get("flow_id") or "").strip() or flow_key
            service_name = str(flow.get("service_name") or "").strip().lower() or None
            application_protocol = str(flow.get("application_protocol") or "").strip().lower() or None
            process_name = str(flow.get("process_name") or "").strip() or None
            _record_soc_event(
                event_type="network.telemetry.flow",
                severity=SocSeverity.low,
                title=f"Network flow telemetry for {remote_flow_ip}",
                summary="Network monitor captured a normalized inbound flow document.",
                details={
                    "schema": "network_flow_v1",
                    "document_type": "network_flow",
                    "flow_key": flow_key,
                    "flow_id": flow_id,
                    "direction": "inbound",
                    "remote_ip": remote_flow_ip,
                    "remote_port": remote_port,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "protocol": protocol,
                    "transport_family": str(flow.get("transport_family") or protocol).strip().lower(),
                    "service_name": service_name,
                    "application_protocol": application_protocol,
                    "state": state,
                    "process_id": flow.get("process_id"),
                    "process_name": process_name,
                    "state_history": [state],
                    "hit_count": item.get("hit_count") or 1,
                    "sensitive_port": local_port in cast(list[int], item.get("sensitive_ports") or []),
                    "snapshot_at": checked_at,
                    "first_seen_at": checked_at,
                    "last_seen_at": checked_at,
                    "details": {
                        "connection": dict(flow),
                        "observation": dict(item),
                    },
                },
                tags=[
                    "network",
                    "telemetry",
                    "flow",
                    protocol,
                    *(["process-bound"] if process_name else []),
                    *(["service:" + service_name] if service_name else []),
                    *(["app:" + application_protocol] if application_protocol else []),
                ],
            )


def _record_packet_monitor_snapshot(snapshot: dict[str, object]) -> None:
    checked_at = str(snapshot.get("checked_at") or "")
    capture_status = str(snapshot.get("capture_status") or "")
    evidence_mode = str(snapshot.get("evidence_mode") or "")
    retained_capture = snapshot.get("retained_capture")
    sessions = snapshot.get("session_observations")
    if not isinstance(sessions, list):
        return
    for item in sessions:
        if not isinstance(item, dict):
            continue
        session_key = str(item.get("session_key") or "").strip()
        remote_ip = str(item.get("remote_ip") or "").strip()
        if not session_key or not remote_ip:
            continue
        sample_packet_endpoints = item.get("sample_packet_endpoints")
        primary_endpoint = (
            sample_packet_endpoints[0]
            if isinstance(sample_packet_endpoints, list) and sample_packet_endpoints and isinstance(sample_packet_endpoints[0], dict)
            else {}
        )
        local_ip = str(primary_endpoint.get("local_ip") or "").strip() or None
        if local_ip is None:
            local_ips = item.get("local_ips")
            if isinstance(local_ips, list) and local_ips and isinstance(local_ips[0], str):
                local_ip = str(local_ips[0]).strip() or None
        local_port = primary_endpoint.get("local_port") if isinstance(primary_endpoint.get("local_port"), int) else None
        if local_port is None:
            local_ports = item.get("local_ports")
            if isinstance(local_ports, list) and local_ports and isinstance(local_ports[0], int):
                local_port = local_ports[0]
        remote_port = primary_endpoint.get("remote_port") if isinstance(primary_endpoint.get("remote_port"), int) else None
        if remote_port is None:
            remote_ports = item.get("remote_ports")
            if isinstance(remote_ports, list) and remote_ports and isinstance(remote_ports[0], int):
                remote_port = remote_ports[0]
        protocol = str(primary_endpoint.get("protocol") or "").strip().lower() or None
        if protocol is None:
            protocols = item.get("protocols")
            if isinstance(protocols, list) and protocols and isinstance(protocols[0], str):
                protocol = str(protocols[0]).strip().lower() or None
        tags = ["packet", "telemetry", "session"]
        if evidence_mode:
            tags.append(evidence_mode)
        protocol_evidence = item.get("protocol_evidence") if isinstance(item.get("protocol_evidence"), dict) else {}
        _record_soc_event(
            event_type="packet.telemetry.session",
            severity=SocSeverity.low,
            title=f"Packet session telemetry for {remote_ip}",
            summary="Packet monitor captured a normalized session document.",
            details={
                "schema": "packet_session_v1",
                "document_type": "packet_session",
                "session_key": session_key,
                "remote_ip": remote_ip,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
                "protocols": item.get("protocols") or [],
                "local_ips": item.get("local_ips") or [],
                "local_ports": item.get("local_ports") or [],
                "remote_ports": item.get("remote_ports") or [],
                "packet_count": item.get("packet_count") or 0,
                "sensitive_ports": item.get("sensitive_ports") or [],
                "transport_families": item.get("transport_families") or [],
                "service_names": item.get("service_names") or [],
                "application_protocols": item.get("application_protocols") or [],
                "flow_ids": item.get("flow_ids") or [],
                "protocol_evidence": protocol_evidence,
                "sample_packet_endpoints": sample_packet_endpoints or [],
                "sample_count": len(sample_packet_endpoints) if isinstance(sample_packet_endpoints, list) else 0,
                "capture_status": capture_status,
                "evidence_mode": evidence_mode,
                "retained_capture": retained_capture if isinstance(retained_capture, dict) else None,
                "snapshot_at": checked_at,
                "first_seen_at": checked_at,
                "last_seen_at": checked_at,
                "details": item,
            },
            tags=tags,
        )


def _record_host_monitor_finding(finding: dict[str, object]) -> None:
    raw_tags = finding.get("tags")
    tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
    _record_soc_event(
        event_type="host.monitor.recovered" if bool(finding.get("resolved")) else "host.monitor.finding",
        severity=SocSeverity.low if bool(finding.get("resolved")) else SocSeverity(str(finding.get("severity", "medium"))),
        title=str(finding.get("title", "Host monitor finding")),
        summary=str(finding.get("summary", "")),
        details=_normalized_monitor_details(monitor="host", finding=finding),
        tags=tags,
    )


def _record_network_monitor_finding(finding: dict[str, object]) -> None:
    raw_tags = finding.get("tags")
    tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
    severity_name = "low" if bool(finding.get("resolved")) else str(finding.get("severity", "medium"))
    details = finding.get("details", {})
    observables = details if isinstance(details, dict) else {}
    soc_manager.ingest_event(
        SocEventIngest(
            event_type="network.monitor.recovered" if bool(finding.get("resolved")) else "network.monitor.finding",
            source="security_gateway",
            severity=SocSeverity(severity_name),
            title=str(finding.get("title", "Suspicious remote IP activity")),
            summary=str(finding.get("summary", "")),
            details=_normalized_monitor_details(
                monitor="network",
                finding=finding,
                observables={
                    "remote_ip": observables.get("remote_ip"),
                    "local_ports": observables.get("local_ports"),
                    "remote_ports": observables.get("remote_ports"),
                    "finding_type": observables.get("finding_type"),
                    "hit_count": observables.get("hit_count"),
                },
            ),
            tags=tags,
        )
    )


def _record_packet_monitor_finding(finding: dict[str, object]) -> None:
    raw_tags = finding.get("tags")
    tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
    severity_name = "low" if bool(finding.get("resolved")) else str(finding.get("severity", "medium"))
    details = finding.get("details", {})
    observables = details if isinstance(details, dict) else {}
    soc_manager.ingest_event(
        SocEventIngest(
            event_type="packet.monitor.recovered" if bool(finding.get("resolved")) else "packet.monitor.finding",
            source="security_gateway",
            severity=SocSeverity(severity_name),
            title=str(finding.get("title", "Packet monitor finding")),
            summary=str(finding.get("summary", "")),
            details=_normalized_monitor_details(
                monitor="packet",
                finding=finding,
                observables={
                    "remote_ip": observables.get("remote_ip"),
                    "session_key": observables.get("session_key"),
                    "protocols": observables.get("protocols"),
                    "local_ports": observables.get("local_ports"),
                    "remote_ports": observables.get("remote_ports"),
                    "packet_count": observables.get("packet_count"),
                },
            ),
            tags=tags,
        )
    )


def _record_stream_monitor_finding(finding: dict[str, object]) -> None:
    raw_tags = finding.get("tags")
    tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
    severity_name = "low" if bool(finding.get("resolved")) else str(finding.get("severity", "medium"))
    details = finding.get("details", {})
    artifacts = [str(details.get("artifact_path"))] if isinstance(details, dict) and details.get("artifact_path") else []
    normalized_filename = None
    if isinstance(details, dict) and details.get("artifact_path"):
        normalized_filename = Path(str(details["artifact_path"])).name
    soc_manager.ingest_event(
        SocEventIngest(
            event_type="stream.monitor.recovered" if bool(finding.get("resolved")) else "stream.monitor.finding",
            source="security_gateway",
            severity=SocSeverity(severity_name),
            title=str(finding.get("title", "Stream monitor finding")),
            summary=str(finding.get("summary", "")),
            details=_normalized_monitor_details(
                monitor="stream",
                finding=finding,
                observables={
                    "artifact_path": details.get("artifact_path") if isinstance(details, dict) else None,
                    "filename": normalized_filename,
                },
            ),
            artifacts=artifacts,
            tags=tags,
        )
    )


automation = AutomationSupervisor(
    vault=vault,
    proxy=proxy,
    audit_logger=audit_logger,
    alert_manager=alert_manager,
    ip_blocklist=ip_blocklist,
    tracker_intel=tracker_intel,
    malware_scanner=scanner,
    interval_seconds=settings.automation_interval_seconds,
    tracker_feed_refresh_enabled=role_managed_service_enabled(
        "tracker_feed_refresh",
        configured=settings.automation_tracker_feed_refresh_enabled,
    ),
    tracker_feed_refresh_every_ticks=settings.automation_tracker_feed_refresh_every_ticks,
    malware_feed_refresh_enabled=role_managed_service_enabled(
        "malware_feed_refresh",
        configured=settings.automation_malware_feed_refresh_enabled,
    ),
    malware_feed_refresh_every_ticks=settings.automation_malware_feed_refresh_every_ticks,
    malware_rule_feed_refresh_enabled=role_managed_service_enabled(
        "malware_rule_feed_refresh",
        configured=settings.automation_malware_rule_feed_refresh_enabled,
    ),
    malware_rule_feed_refresh_every_ticks=settings.automation_malware_rule_feed_refresh_every_ticks,
    host_monitor=host_monitor,
    host_monitor_enabled=role_managed_service_enabled(
        "host_monitor",
        configured=settings.host_monitor_enabled,
    ),
    host_monitor_every_ticks=settings.host_monitor_every_ticks,
    host_monitor_callback=_record_host_monitor_finding,
    network_monitor=network_monitor,
    network_monitor_enabled=role_managed_service_enabled(
        "network_monitor",
        configured=settings.network_monitor_enabled,
    ),
    network_monitor_every_ticks=settings.network_monitor_every_ticks,
    network_monitor_callback=_record_network_monitor_finding,
    network_snapshot_callback=_record_network_monitor_snapshot,
    packet_monitor=packet_monitor,
    packet_monitor_enabled=role_managed_service_enabled(
        "packet_monitor",
        configured=settings.packet_monitor_enabled,
    ),
    packet_monitor_every_ticks=settings.packet_monitor_every_ticks,
    packet_monitor_callback=_record_packet_monitor_finding,
    packet_snapshot_callback=_record_packet_monitor_snapshot,
    stream_monitor=stream_monitor,
    stream_monitor_enabled=role_managed_service_enabled(
        "stream_monitor",
        configured=settings.stream_monitor_enabled,
    ),
    stream_monitor_every_ticks=settings.stream_monitor_every_ticks,
    stream_monitor_callback=_record_stream_monitor_finding,
    node_heartbeat_enabled=_platform_node_heartbeat_enabled(),
    node_heartbeat_every_ticks=settings.platform_manager_heartbeat_every_ticks,
    node_heartbeat_callback=_emit_platform_node_heartbeat,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    _validate_startup_security_dependencies()
    _seed_offline_feeds()
    load_toolchain_runtime(sync_updates=True, apply_safe_only=True)
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
            details=_normalized_endpoint_posture_details(device),
            tags=["endpoint", device.compliance.value],
        )
    return {"signature": signature}


@app.post("/endpoint/telemetry/process")
async def publish_process_telemetry(
    payload: EndpointProcessTelemetry,
    _: None = Depends(require_endpoint_access),
) -> dict:
    details = _normalized_endpoint_process_details(payload)
    severity = SocSeverity.high if payload.risk_flags else SocSeverity.low
    artifacts: list[str] = []
    process_path = details.get("process_path")
    if isinstance(process_path, str):
        artifacts.append(process_path)
    result = _record_soc_event(
        event_type="endpoint.telemetry.process",
        severity=severity,
        title=f"Endpoint process telemetry: {payload.process_name}",
        summary=f"Endpoint {payload.device_id} reported process activity for {payload.process_name}.",
        details=details,
        artifacts=artifacts,
        tags=["endpoint", "telemetry", "process", *payload.risk_flags],
    )
    event_record, alert_record = result
    connection_records: list[dict[str, object]] = []
    for connection in payload.network_connections:
        if not isinstance(connection, dict):
            continue
        connection_details = _normalized_endpoint_connection_details(process_details=details, connection=connection)
        if connection_details is None:
            continue
        connection_result = _record_soc_event(
            event_type="endpoint.telemetry.connection",
            severity=severity,
            title=f"Endpoint connection telemetry: {payload.process_name}",
            summary=f"Endpoint {payload.device_id} reported a live connection for {payload.process_name}.",
            details=connection_details,
            tags=["endpoint", "telemetry", "connection", *payload.risk_flags],
        )
        connection_records.append(connection_result[0].model_dump(mode="json"))
    return {
        "event": event_record.model_dump(mode="json"),
        "alert": alert_record.model_dump(mode="json") if alert_record is not None else None,
        "connections": connection_records,
    }


@app.post("/endpoint/telemetry/file")
async def publish_file_telemetry(
    payload: EndpointFileTelemetry,
    _: None = Depends(require_endpoint_access),
) -> dict:
    details = _normalized_endpoint_file_details(payload)
    verdict = (payload.verdict or "").strip().casefold()
    severity = SocSeverity.high if verdict in {"malicious", "quarantined"} or payload.risk_flags else SocSeverity.low
    artifacts: list[str] = []
    artifact_path = details.get("artifact_path")
    if isinstance(artifact_path, str):
        artifacts.append(artifact_path)
    result = _record_soc_event(
        event_type="endpoint.telemetry.file",
        severity=severity,
        title=f"Endpoint file telemetry: {payload.filename}",
        summary=f"Endpoint {payload.device_id} reported file activity for {payload.filename}.",
        details=details,
        artifacts=artifacts,
        tags=["endpoint", "telemetry", "file", payload.operation.strip(), *payload.risk_flags],
    )
    event_record, alert_record = result
    return {
        "event": event_record.model_dump(mode="json"),
        "alert": alert_record.model_dump(mode="json") if alert_record is not None else None,
    }


@app.get("/endpoint/telemetry/processes")
async def list_endpoint_process_telemetry(
    limit: int = Query(default=100, ge=1, le=250),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="endpoint.telemetry.process",
        device_id=device_id,
        process_name=process_name,
        process_guid=process_guid,
        signer_name=signer_name,
        sha256=sha256,
        limit=limit,
    )
    return {"processes": [event.model_dump(mode="json") for event in events]}


@app.get("/endpoint/telemetry/summary")
async def summarize_endpoint_telemetry(
    limit: int = Query(default=250, ge=1, le=500),
    facet_limit: int = Query(default=5, ge=1, le=20),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    filename: str | None = Query(default=None, min_length=1, max_length=256),
    artifact_path: str | None = Query(default=None, min_length=1, max_length=512),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.summarize_endpoint_telemetry(
        device_id=device_id,
        process_name=process_name,
        process_guid=process_guid,
        remote_ip=remote_ip,
        signer_name=signer_name,
        sha256=sha256,
        filename=filename,
        artifact_path=artifact_path,
        start_at=start_at,
        end_at=end_at,
        facet_limit=facet_limit,
        limit=limit,
    )


@app.get("/endpoint/telemetry/query")
async def query_endpoint_telemetry(
    limit: int = Query(default=200, ge=1, le=500),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    filename: str | None = Query(default=None, min_length=1, max_length=256),
    artifact_path: str | None = Query(default=None, min_length=1, max_length=512),
    local_ip: str | None = Query(default=None, min_length=1, max_length=128),
    local_port: str | None = Query(default=None, min_length=1, max_length=16),
    remote_port: str | None = Query(default=None, min_length=1, max_length=16),
    protocol: str | None = Query(default=None, min_length=1, max_length=32),
    state: str | None = Query(default=None, min_length=1, max_length=64),
    document_type: str | None = Query(default=None, min_length=1, max_length=64),
    parent_process_name: str | None = Query(default=None, min_length=1, max_length=256),
    reputation: str | None = Query(default=None, min_length=1, max_length=64),
    risk_flag: str | None = Query(default=None, min_length=1, max_length=128),
    verdict: str | None = Query(default=None, min_length=1, max_length=64),
    operation: str | None = Query(default=None, min_length=1, max_length=64),
    file_extension: str | None = Query(default=None, min_length=1, max_length=32),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.query_endpoint_telemetry(
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
    )


@app.post("/endpoint/telemetry/query/case")
async def create_case_from_endpoint_query(
    payload: SocEndpointQueryCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_endpoint_query(payload)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.get("/endpoint/telemetry/lineage/summary")
async def summarize_endpoint_lineage(
    limit: int = Query(default=250, ge=1, le=500),
    facet_limit: int = Query(default=5, ge=1, le=20),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.summarize_endpoint_lineage(
        device_id=device_id,
        process_name=process_name,
        process_guid=process_guid,
        remote_ip=remote_ip,
        signer_name=signer_name,
        sha256=sha256,
        start_at=start_at,
        end_at=end_at,
        facet_limit=facet_limit,
        limit=limit,
    )


@app.get("/endpoint/telemetry/files")
async def list_endpoint_file_telemetry(
    limit: int = Query(default=100, ge=1, le=250),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    filename: str | None = Query(default=None, min_length=1, max_length=256),
    artifact_path: str | None = Query(default=None, min_length=1, max_length=512),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="endpoint.telemetry.file",
        device_id=device_id,
        filename=filename,
        artifact_path=artifact_path,
        signer_name=signer_name,
        sha256=sha256,
        limit=limit,
    )
    return {"files": [event.model_dump(mode="json") for event in events]}


@app.get("/endpoint/telemetry/connections")
async def list_endpoint_connection_telemetry(
    limit: int = Query(default=100, ge=1, le=250),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="endpoint.telemetry.connection",
        device_id=device_id,
        process_name=process_name,
        process_guid=process_guid,
        remote_ip=remote_ip,
        signer_name=signer_name,
        sha256=sha256,
        limit=limit,
    )
    return {"connections": [event.model_dump(mode="json") for event in events]}


@app.get("/endpoint/telemetry/timeline")
async def list_endpoint_telemetry_timeline(
    limit: int = Query(default=200, ge=1, le=500),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    _: None = Depends(require_operator_access),
) -> dict:
    ordered = soc_manager.list_endpoint_timeline(
        limit=limit,
        device_id=device_id,
        process_name=process_name,
        process_guid=process_guid,
        remote_ip=remote_ip,
        signer_name=signer_name,
        sha256=sha256,
    )
    return {
        "timeline": [_endpoint_timeline_entry(event) for event in ordered],
        "filters": {
            "device_id": device_id,
            "process_name": process_name,
            "process_guid": process_guid,
            "remote_ip": remote_ip,
            "signer_name": signer_name,
            "sha256": sha256,
            "limit": limit,
        },
    }


@app.get("/endpoint/telemetry/timeline/clusters")
async def list_endpoint_telemetry_timeline_clusters(
    cluster_by: str = Query(default="process", pattern="^(process|remote_ip)$"),
    limit: int = Query(default=200, ge=1, le=500),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    _: None = Depends(require_operator_access),
) -> dict:
    clusters = soc_manager.cluster_endpoint_timeline(
        cluster_by=cluster_by,
        limit=limit,
        device_id=device_id,
        process_name=process_name,
        process_guid=process_guid,
        remote_ip=remote_ip,
        signer_name=signer_name,
        sha256=sha256,
    )
    return {
        "clusters": clusters,
        "filters": {
            "cluster_by": cluster_by,
            "device_id": device_id,
            "process_name": process_name,
            "process_guid": process_guid,
            "remote_ip": remote_ip,
            "signer_name": signer_name,
            "sha256": sha256,
            "limit": limit,
        },
    }


@app.get("/endpoint/telemetry/timeline/clusters/{cluster_key}")
async def get_endpoint_telemetry_timeline_cluster(
    cluster_key: str,
    cluster_by: str = Query(default="process", pattern="^(process|remote_ip)$"),
    limit: int = Query(default=500, ge=1, le=500),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        cluster = soc_manager.resolve_endpoint_timeline_cluster(
            cluster_by=cluster_by,
            cluster_key=cluster_key,
            limit=limit,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"cluster": cluster}


@app.get("/endpoint/telemetry/lineage/clusters")
async def list_endpoint_lineage_clusters(
    limit: int = Query(default=200, ge=1, le=500),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    _: None = Depends(require_operator_access),
) -> dict:
    clusters = soc_manager.list_endpoint_lineage_clusters(
        limit=limit,
        device_id=device_id,
        process_name=process_name,
        process_guid=process_guid,
        remote_ip=remote_ip,
        signer_name=signer_name,
        sha256=sha256,
    )
    return {
        "clusters": clusters,
        "filters": {
            "device_id": device_id,
            "process_name": process_name,
            "process_guid": process_guid,
            "remote_ip": remote_ip,
            "signer_name": signer_name,
            "sha256": sha256,
            "limit": limit,
        },
    }


@app.get("/endpoint/telemetry/lineage/clusters/{cluster_key}")
async def get_endpoint_lineage_cluster(
    cluster_key: str,
    limit: int = Query(default=500, ge=1, le=500),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        cluster = soc_manager.resolve_endpoint_lineage_cluster(
            cluster_key,
            limit=limit,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"cluster": cluster}


@app.post("/endpoint/telemetry/lineage/clusters/case")
async def create_case_from_endpoint_lineage_cluster(
    payload: SocEndpointLineageClusterCaseRequest,
    _: None = Depends(require_operator_access),
) -> SocCaseRecord:
    try:
        case = soc_manager.create_case_from_endpoint_lineage_cluster(payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return case


@app.post("/endpoint/telemetry/timeline/case")
async def create_case_from_endpoint_timeline(
    payload: SocEndpointTimelineCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_endpoint_timeline(payload)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return case.model_dump(mode="json")


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
            normalized_filename = file.filename or "unknown"
            _record_soc_event(
                event_type="endpoint.malware_detected",
                severity=SocSeverity.critical,
                title=f"Malware detected in upload: {normalized_filename}",
                summary="The endpoint scanner marked an uploaded file as malicious.",
                details=_normalized_endpoint_malware_details(filename=normalized_filename, verdict=verdict),
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


class PlatformNodeHeartbeatPayload(BaseModel):
    node_name: str = Field(min_length=1, max_length=128)
    node_role: str = Field(min_length=1, max_length=32)
    deployment_mode: str = Field(default="single-node", min_length=1, max_length=64)
    service_health: dict[str, object] = Field(default_factory=dict)
    metadata: dict[str, object] = Field(default_factory=dict)
    last_seen_at: str | None = Field(default=None, max_length=64)


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


def _merge_string_values(existing: object, incoming: object) -> list[str]:
    values = {
        str(item).strip()
        for item in cast(list[object], existing or [])
        if str(item).strip()
    }
    values.update(
        str(item).strip()
        for item in cast(list[object], incoming or [])
        if str(item).strip()
    )
    return sorted(values)


def _merge_int_values(existing: object, incoming: object) -> list[int]:
    values: set[int] = set()
    for source in (existing, incoming):
        for item in cast(list[object], source or []):
            if isinstance(item, bool):
                continue
            if isinstance(item, int):
                values.add(item)
            elif isinstance(item, str) and item.isdigit():
                values.add(int(item))
    return sorted(values)


def _int_from_value(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _protocol_evidence_payload(payload: SocProtocolEvidence) -> dict[str, object]:
    return payload.model_dump(mode="json")


def _build_sensor_connection_rows(
    payload: SocNetworkSensorTelemetryIngest,
    *,
    checked_at: str,
) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for flow in payload.flows:
        transport_family = (flow.transport_family or flow.protocol).strip().lower()
        service_name = (
            (flow.service_name or NetworkMonitor._service_name_for_port(flow.local_port) or "").strip().lower()
            or None
        )
        application_protocol = (
            (
                flow.application_protocol
                or (flow.protocol_evidence.application_protocols[0] if flow.protocol_evidence.application_protocols else None)
                or NetworkMonitor._application_protocol_for_ports(flow.local_port, flow.remote_port)
                or ""
            )
            .strip()
            .lower()
            or None
        )
        flow_id = (
            str(flow.flow_id or "").strip()
            or NetworkMonitor._build_flow_id(
                remote_ip=flow.remote_ip,
                remote_port=flow.remote_port,
                local_ip=flow.local_ip,
                local_port=flow.local_port,
                protocol=transport_family,
                process_id=flow.process_id,
            )
        )
        entry = grouped.setdefault(
            flow.remote_ip,
            {
                "remote_ip": flow.remote_ip,
                "local_ports": set(),
                "remote_ports": set(),
                "states": set(),
                "transport_families": set(),
                "service_names": set(),
                "application_protocols": set(),
                "flow_ids": set(),
                "process_ids": set(),
                "process_names": set(),
                "sample_connections": [],
                "hit_count": 0,
                "sensitive_ports": set(),
                "last_seen_at": checked_at,
                "sensor_name": payload.sensor_name,
            },
        )
        cast(set[int], entry["local_ports"]).add(flow.local_port)
        cast(set[int], entry["remote_ports"]).add(flow.remote_port)
        cast(set[str], entry["states"]).add(flow.state)
        cast(set[str], entry["transport_families"]).add(transport_family)
        cast(set[str], entry["flow_ids"]).add(flow_id)
        if service_name:
            cast(set[str], entry["service_names"]).add(service_name)
        if application_protocol:
            cast(set[str], entry["application_protocols"]).add(application_protocol)
        if flow.process_id is not None:
            cast(set[int], entry["process_ids"]).add(flow.process_id)
        if flow.process_name:
            cast(set[str], entry["process_names"]).add(flow.process_name)
        if flow.local_port in network_monitor._sensitive_ports:
            cast(set[int], entry["sensitive_ports"]).add(flow.local_port)
        entry["hit_count"] = cast(int, entry["hit_count"]) + flow.hit_count
        last_seen_at = (flow.last_seen_at or flow.first_seen_at)
        if last_seen_at is not None:
            entry["last_seen_at"] = max(str(entry["last_seen_at"] or ""), last_seen_at.isoformat())
        sample_connections = cast(list[dict[str, object]], entry["sample_connections"])
        if len(sample_connections) < network_monitor._evidence_sample_limit:  # type: ignore[attr-defined]
            sample_connections.append(
                {
                    "remote_ip": flow.remote_ip,
                    "remote_port": flow.remote_port,
                    "local_ip": flow.local_ip,
                    "local_port": flow.local_port,
                    "protocol": flow.protocol.strip().lower(),
                    "transport_family": transport_family,
                    "service_name": service_name,
                    "application_protocol": application_protocol,
                    "state": flow.state,
                    "process_id": flow.process_id,
                    "process_name": flow.process_name,
                    "flow_id": flow_id,
                    "protocol_evidence": _protocol_evidence_payload(flow.protocol_evidence),
                }
            )

    rows: list[dict[str, object]] = []
    for remote_ip, item in grouped.items():
        rows.append(
            {
                "remote_ip": remote_ip,
                "local_ports": sorted(cast(set[int], item["local_ports"])),
                "remote_ports": sorted(cast(set[int], item["remote_ports"])),
                "states": sorted(cast(set[str], item["states"])),
                "transport_families": sorted(cast(set[str], item["transport_families"])),
                "service_names": sorted(cast(set[str], item["service_names"])),
                "application_protocols": sorted(cast(set[str], item["application_protocols"])),
                "flow_ids": sorted(cast(set[str], item["flow_ids"])),
                "state_counts": {state: 1 for state in sorted(cast(set[str], item["states"]))},
                "hit_count": item["hit_count"],
                "total_hits": item["hit_count"],
                "sensitive_ports": sorted(cast(set[int], item["sensitive_ports"])),
                "process_ids": sorted(cast(set[int], item["process_ids"])),
                "process_names": sorted(cast(set[str], item["process_names"])),
                "sample_connections": cast(list[dict[str, object]], item["sample_connections"]),
                "last_seen_at": item["last_seen_at"],
                "sensor_name": item["sensor_name"],
            }
        )
    return rows


def _record_sensor_network_telemetry(payload: SocNetworkSensorTelemetryIngest) -> dict[str, object]:
    checked_at = payload.checked_at.isoformat() if payload.checked_at is not None else datetime.now(UTC).isoformat()
    common_tags = ["network", "telemetry", "sensor", f"sensor:{payload.sensor_name}", *payload.tags]
    flow_events: list[str] = []
    connection_events: list[str] = []
    session_events: list[str] = []
    dns_events: list[str] = []
    http_events: list[str] = []
    tls_events: list[str] = []
    certificate_events: list[str] = []
    proxy_events: list[str] = []
    auth_events: list[str] = []
    vpn_events: list[str] = []
    dhcp_events: list[str] = []
    directory_auth_events: list[str] = []
    radius_events: list[str] = []
    nac_events: list[str] = []
    connection_rows = _build_sensor_connection_rows(payload, checked_at=checked_at)

    for row in connection_rows:
        remote_ip = str(row.get("remote_ip") or "").strip()
        if not remote_ip:
            continue
        result = _record_soc_event(
            event_type="network.telemetry.connection",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"Network telemetry for {remote_ip}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized network observation.",
            details={
                "schema": "network_connection_sensor_v1",
                "document_type": "network_connection",
                **row,
                "snapshot_at": checked_at,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(dict.fromkeys([*common_tags, "connection"])),
        )
        connection_events.append(result[0].event_id)

    for flow in payload.flows:
        transport_family = (flow.transport_family or flow.protocol).strip().lower()
        service_name = (
            (flow.service_name or NetworkMonitor._service_name_for_port(flow.local_port) or "").strip().lower()
            or None
        )
        application_protocol = (
            (
                flow.application_protocol
                or (flow.protocol_evidence.application_protocols[0] if flow.protocol_evidence.application_protocols else None)
                or NetworkMonitor._application_protocol_for_ports(flow.local_port, flow.remote_port)
                or ""
            )
            .strip()
            .lower()
            or None
        )
        flow_id = (
            str(flow.flow_id or "").strip()
            or NetworkMonitor._build_flow_id(
                remote_ip=flow.remote_ip,
                remote_port=flow.remote_port,
                local_ip=flow.local_ip,
                local_port=flow.local_port,
                protocol=transport_family,
                process_id=flow.process_id,
            )
        )
        observed_at = (flow.last_seen_at or flow.first_seen_at)
        result = _record_soc_event(
            event_type="network.telemetry.flow",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"Network flow telemetry for {flow.remote_ip}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized flow document.",
            details={
                "schema": "network_flow_sensor_v1",
                "document_type": "network_flow",
                "flow_key": f"{flow.remote_ip}:{flow.remote_port}->{flow.local_ip}:{flow.local_port}/{transport_family}",
                "flow_id": flow_id,
                "direction": flow.direction,
                "remote_ip": flow.remote_ip,
                "remote_port": flow.remote_port,
                "local_ip": flow.local_ip,
                "local_port": flow.local_port,
                "protocol": flow.protocol.strip().lower(),
                "transport_family": transport_family,
                "service_name": service_name,
                "application_protocol": application_protocol,
                "state": flow.state,
                "process_id": flow.process_id,
                "process_name": flow.process_name,
                "state_history": [flow.state],
                "hit_count": flow.hit_count,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "protocol_evidence": _protocol_evidence_payload(flow.protocol_evidence),
                "sensitive_port": flow.local_port in network_monitor._sensitive_ports,
                "snapshot_at": checked_at,
                "first_seen_at": (flow.first_seen_at.isoformat() if flow.first_seen_at is not None else checked_at),
                "last_seen_at": (observed_at.isoformat() if observed_at is not None else checked_at),
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "flow",
                        flow.protocol.strip().lower(),
                        *(["process-bound"] if flow.process_name else []),
                        *(["service:" + service_name] if service_name else []),
                        *(["app:" + application_protocol] if application_protocol else []),
                    ]
                )
            ),
        )
        flow_events.append(result[0].event_id)

    for session in payload.sessions:
        session_key = str(session.session_key or "").strip() or f"packet-session:{session.remote_ip}"
        session_protocols = [protocol.strip().upper() for protocol in session.protocols if protocol.strip()]
        session_transport_families = [item.strip().lower() for item in session.transport_families if item.strip()]
        local_ip = session.local_ips[0].strip() if session.local_ips else None
        local_port = session.local_ports[0] if session.local_ports else None
        remote_port = session.remote_ports[0] if session.remote_ports else None
        protocol = session_protocols[0].lower() if session_protocols else None
        observed_at = (session.last_seen_at or session.first_seen_at)
        result = _record_soc_event(
            event_type="packet.telemetry.session",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"Packet session telemetry for {session.remote_ip}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized packet session.",
            details={
                "schema": "packet_session_sensor_v1",
                "document_type": "packet_session",
                "session_key": session_key,
                "remote_ip": session.remote_ip,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
                "protocols": session_protocols,
                "local_ips": session.local_ips,
                "local_ports": session.local_ports,
                "remote_ports": session.remote_ports,
                "packet_count": session.packet_count,
                "total_packets": session.total_packets if session.total_packets is not None else session.packet_count,
                "sensitive_ports": session.sensitive_ports,
                "transport_families": session_transport_families,
                "service_names": [item.strip().lower() for item in session.service_names if item.strip()],
                "application_protocols": [item.strip().lower() for item in session.application_protocols if item.strip()],
                "flow_ids": [item.strip() for item in session.flow_ids if item.strip()],
                "protocol_evidence": _protocol_evidence_payload(session.protocol_evidence),
                "snapshot_at": checked_at,
                "first_seen_at": (session.first_seen_at.isoformat() if session.first_seen_at is not None else checked_at),
                "last_seen_at": (observed_at.isoformat() if observed_at is not None else checked_at),
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(dict.fromkeys([*common_tags, "packet", "session", *session_transport_families])),
        )
        session_events.append(result[0].event_id)

    for dns_record in payload.dns_records:
        observed_at_value = dns_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.dns",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"DNS telemetry for {dns_record.hostname}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized DNS record.",
            details={
                "schema": "network_dns_sensor_v1",
                "document_type": "network_dns",
                "remote_ip": dns_record.remote_ip,
                "local_ip": dns_record.local_ip,
                "hostname": dns_record.hostname,
                "record_type": dns_record.record_type.strip().upper(),
                "answers": dns_record.answers,
                "response_code": dns_record.response_code,
                "dns_secure": dns_record.dns_secure,
                "flow_id": dns_record.flow_id,
                "session_key": dns_record.session_key,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(dict.fromkeys([*common_tags, "dns", dns_record.record_type.strip().lower(), f"hostname:{dns_record.hostname}"])),
        )
        dns_events.append(result[0].event_id)

    for http_record in payload.http_records:
        observed_at_value = http_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.http",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"HTTP telemetry for {http_record.hostname}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized HTTP record.",
            details={
                "schema": "network_http_sensor_v1",
                "document_type": "network_http",
                "remote_ip": http_record.remote_ip,
                "local_ip": http_record.local_ip,
                "hostname": http_record.hostname,
                "method": http_record.method.strip().upper(),
                "path": http_record.path,
                "status_code": http_record.status_code,
                "user_agent": http_record.user_agent,
                "flow_id": http_record.flow_id,
                "session_key": http_record.session_key,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(dict.fromkeys([*common_tags, "http", http_record.method.strip().lower(), f"hostname:{http_record.hostname}"])),
        )
        http_events.append(result[0].event_id)

    for tls_record in payload.tls_records:
        observed_at_value = tls_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.tls",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"TLS telemetry for {tls_record.server_name}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized TLS record.",
            details={
                "schema": "network_tls_sensor_v1",
                "document_type": "network_tls",
                "remote_ip": tls_record.remote_ip,
                "local_ip": tls_record.local_ip,
                "hostname": tls_record.server_name,
                "server_name": tls_record.server_name,
                "tls_version": tls_record.tls_version,
                "ja3": tls_record.ja3,
                "ja3s": tls_record.ja3s,
                "issuer": tls_record.issuer,
                "subject": tls_record.subject,
                "flow_id": tls_record.flow_id,
                "session_key": tls_record.session_key,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(dict.fromkeys([*common_tags, "tls", f"hostname:{tls_record.server_name}"])),
        )
        tls_events.append(result[0].event_id)

    for certificate_record in payload.certificate_records:
        observed_at_value = certificate_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.certificate",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"Certificate telemetry for {certificate_record.hostname}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized certificate record.",
            details={
                "schema": "network_certificate_sensor_v1",
                "document_type": "network_certificate",
                "remote_ip": certificate_record.remote_ip,
                "local_ip": certificate_record.local_ip,
                "hostname": certificate_record.hostname,
                "serial_number": certificate_record.serial_number,
                "sha1": certificate_record.sha1,
                "sha256": certificate_record.sha256,
                "issuer": certificate_record.issuer,
                "subject": certificate_record.subject,
                "not_before": (
                    certificate_record.not_before.isoformat() if certificate_record.not_before is not None else None
                ),
                "not_after": (
                    certificate_record.not_after.isoformat() if certificate_record.not_after is not None else None
                ),
                "ja3": certificate_record.ja3,
                "ja3s": certificate_record.ja3s,
                "flow_id": certificate_record.flow_id,
                "session_key": certificate_record.session_key,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "certificate",
                        f"hostname:{certificate_record.hostname}",
                        *(["issuer:" + certificate_record.issuer] if certificate_record.issuer else []),
                    ]
                )
            ),
        )
        certificate_events.append(result[0].event_id)

    for proxy_record in payload.proxy_records:
        observed_at_value = proxy_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.proxy",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"Proxy telemetry for {proxy_record.hostname}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized proxy record.",
            details={
                "schema": "network_proxy_sensor_v1",
                "document_type": "network_proxy",
                "remote_ip": proxy_record.remote_ip,
                "local_ip": proxy_record.local_ip,
                "hostname": proxy_record.hostname,
                "proxy_type": proxy_record.proxy_type,
                "action": proxy_record.action,
                "username": proxy_record.username,
                "flow_id": proxy_record.flow_id,
                "session_key": proxy_record.session_key,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "proxy",
                        proxy_record.proxy_type.strip().lower(),
                        proxy_record.action.strip().lower(),
                        f"hostname:{proxy_record.hostname}",
                    ]
                )
            ),
        )
        proxy_events.append(result[0].event_id)

    for auth_record in payload.auth_records:
        observed_at_value = auth_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.auth",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"Auth telemetry for {auth_record.username}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized auth record.",
            details={
                "schema": "network_auth_sensor_v1",
                "document_type": "network_auth",
                "remote_ip": auth_record.remote_ip,
                "local_ip": auth_record.local_ip,
                "hostname": auth_record.hostname,
                "username": auth_record.username,
                "outcome": auth_record.outcome,
                "auth_protocol": auth_record.auth_protocol,
                "realm": auth_record.realm,
                "flow_id": auth_record.flow_id,
                "session_key": auth_record.session_key,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "auth",
                        auth_record.outcome.strip().lower(),
                        auth_record.auth_protocol.strip().lower(),
                        f"user:{auth_record.username}",
                    ]
                )
            ),
        )
        auth_events.append(result[0].event_id)

    for vpn_record in payload.vpn_records:
        observed_at_value = vpn_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.vpn",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"VPN telemetry for {vpn_record.username}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized VPN record.",
            details={
                "schema": "network_vpn_sensor_v1",
                "document_type": "network_vpn",
                "remote_ip": vpn_record.remote_ip,
                "hostname": vpn_record.hostname,
                "username": vpn_record.username,
                "tunnel_type": vpn_record.tunnel_type,
                "assigned_ip": vpn_record.assigned_ip,
                "outcome": vpn_record.outcome,
                "gateway": vpn_record.gateway,
                "session_event": vpn_record.session_event,
                "close_reason": vpn_record.close_reason,
                "duration_seconds": vpn_record.duration_seconds,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "vpn",
                        vpn_record.tunnel_type.strip().lower(),
                        vpn_record.outcome.strip().lower(),
                        *( [vpn_record.session_event.strip().lower()] if vpn_record.session_event else [] ),
                        *( [vpn_record.close_reason.strip().lower()] if vpn_record.close_reason else [] ),
                        f"user:{vpn_record.username}",
                    ]
                )
            ),
        )
        vpn_events.append(result[0].event_id)

    for dhcp_record in payload.dhcp_records:
        observed_at_value = dhcp_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.dhcp",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"DHCP telemetry for {dhcp_record.assigned_ip}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized DHCP record.",
            details={
                "schema": "network_dhcp_sensor_v1",
                "document_type": "network_dhcp",
                "remote_ip": dhcp_record.remote_ip,
                "assigned_ip": dhcp_record.assigned_ip,
                "mac_address": dhcp_record.mac_address,
                "hostname": dhcp_record.hostname,
                "lease_action": dhcp_record.lease_action,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "dhcp",
                        dhcp_record.lease_action.strip().lower(),
                        f"assigned_ip:{dhcp_record.assigned_ip}",
                    ]
                )
            ),
        )
        dhcp_events.append(result[0].event_id)

    for directory_auth_record in payload.directory_auth_records:
        observed_at_value = directory_auth_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.directory_auth",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"Directory auth telemetry for {directory_auth_record.username}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized directory auth record.",
            details={
                "schema": "network_directory_auth_sensor_v1",
                "document_type": "network_directory_auth",
                "remote_ip": directory_auth_record.remote_ip,
                "hostname": directory_auth_record.hostname,
                "username": directory_auth_record.username,
                "directory_service": directory_auth_record.directory_service,
                "outcome": directory_auth_record.outcome,
                "realm": directory_auth_record.realm,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "directory-auth",
                        directory_auth_record.directory_service.strip().lower(),
                        directory_auth_record.outcome.strip().lower(),
                        f"user:{directory_auth_record.username}",
                    ]
                )
            ),
        )
        directory_auth_events.append(result[0].event_id)

    for radius_record in payload.radius_records:
        observed_at_value = radius_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.radius",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"RADIUS telemetry for {radius_record.username}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized RADIUS record.",
            details={
                "schema": "network_radius_sensor_v1",
                "document_type": "network_radius",
                "remote_ip": radius_record.remote_ip,
                "hostname": radius_record.hostname,
                "username": radius_record.username,
                "outcome": radius_record.outcome,
                "reject_reason": radius_record.reject_reason,
                "reject_code": radius_record.reject_code,
                "nas_identifier": radius_record.nas_identifier,
                "realm": radius_record.realm,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "radius",
                        radius_record.outcome.strip().lower(),
                        *( [radius_record.reject_code.strip().lower()] if radius_record.reject_code else [] ),
                        f"user:{radius_record.username}",
                    ]
                )
            ),
        )
        radius_events.append(result[0].event_id)

    for nac_record in payload.nac_records:
        observed_at_value = nac_record.observed_at
        observed_at_text = observed_at_value.isoformat() if observed_at_value is not None else checked_at
        result = _record_soc_event(
            event_type="network.telemetry.nac",
            source=payload.source,
            severity=SocSeverity.low,
            title=f"NAC telemetry for {nac_record.device_id}",
            summary=f"External sensor {payload.sensor_name} submitted a normalized NAC record.",
            details={
                "schema": "network_nac_sensor_v1",
                "document_type": "network_nac",
                "remote_ip": nac_record.remote_ip,
                "device_id": nac_record.device_id,
                "mac_address": nac_record.mac_address,
                "hostname": nac_record.hostname,
                "posture": nac_record.posture,
                "previous_posture": nac_record.previous_posture,
                "transition_reason": nac_record.transition_reason,
                "action": nac_record.action,
                "observed_at": observed_at_text,
                "details": {"sensor_name": payload.sensor_name, "ingest_source": "sensor"},
            },
            tags=list(
                dict.fromkeys(
                    [
                        *common_tags,
                        "nac",
                        nac_record.posture.strip().lower(),
                        nac_record.action.strip().lower(),
                        f"device:{nac_record.device_id}",
                    ]
                )
            ),
        )
        nac_events.append(result[0].event_id)

    return {
        "sensor_name": payload.sensor_name,
        "checked_at": checked_at,
        "connection_count": len(connection_events),
        "flow_count": len(flow_events),
        "session_count": len(session_events),
        "dns_count": len(dns_events),
        "http_count": len(http_events),
        "tls_count": len(tls_events),
        "certificate_count": len(certificate_events),
        "proxy_count": len(proxy_events),
        "auth_count": len(auth_events),
        "vpn_count": len(vpn_events),
        "dhcp_count": len(dhcp_events),
        "directory_auth_count": len(directory_auth_events),
        "radius_count": len(radius_events),
        "nac_count": len(nac_events),
        "event_ids": [
            *connection_events,
            *flow_events,
            *session_events,
            *dns_events,
            *http_events,
            *tls_events,
            *certificate_events,
            *proxy_events,
            *auth_events,
            *vpn_events,
            *dhcp_events,
            *directory_auth_events,
            *radius_events,
            *nac_events,
        ],
    }


def _merged_network_observation_rows(*, remote_ip: str | None, limit: int) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for item in network_monitor.list_recent_observations(limit=limit, remote_ip=remote_ip):
        key = str(item.get("remote_ip") or "").strip()
        if key:
            grouped[key] = dict(item)
    for event in soc_manager.query_events(event_type="network.telemetry.connection", remote_ip=remote_ip, limit=max(limit * 4, 200)):
        details = cast(dict[str, object], event.details or {})
        key = str(details.get("remote_ip") or "").strip()
        if not key:
            continue
        if key not in grouped:
            grouped[key] = {
                "remote_ip": key,
                "local_ports": cast(list[object], details.get("local_ports") or []),
                "remote_ports": cast(list[object], details.get("remote_ports") or []),
                "states": cast(list[object], details.get("states") or []),
                "transport_families": cast(list[object], details.get("transport_families") or []),
                "service_names": cast(list[object], details.get("service_names") or []),
                "application_protocols": cast(list[object], details.get("application_protocols") or []),
                "flow_ids": cast(list[object], details.get("flow_ids") or []),
                "state_counts": cast(dict[str, object], details.get("state_counts") or {}),
                "total_hits": _int_from_value(details.get("hit_count") or details.get("total_hits")),
                "hit_count": _int_from_value(details.get("hit_count") or details.get("total_hits")),
                "sensitive_ports": cast(list[object], details.get("sensitive_ports") or []),
                "process_ids": cast(list[object], details.get("process_ids") or []),
                "process_names": cast(list[object], details.get("process_names") or []),
                "sample_connections": cast(list[object], details.get("sample_connections") or []),
                "last_seen_at": details.get("last_seen_at") or details.get("snapshot_at") or event.created_at.isoformat(),
            }
            continue
        current = grouped[key]
        current["local_ports"] = _merge_int_values(current.get("local_ports"), details.get("local_ports"))
        current["remote_ports"] = _merge_int_values(current.get("remote_ports"), details.get("remote_ports"))
        current["states"] = _merge_string_values(current.get("states"), details.get("states"))
        current["transport_families"] = _merge_string_values(current.get("transport_families"), details.get("transport_families"))
        current["service_names"] = _merge_string_values(current.get("service_names"), details.get("service_names"))
        current["application_protocols"] = _merge_string_values(current.get("application_protocols"), details.get("application_protocols"))
        current["flow_ids"] = _merge_string_values(current.get("flow_ids"), details.get("flow_ids"))
        current["sensitive_ports"] = _merge_int_values(current.get("sensitive_ports"), details.get("sensitive_ports"))
        current["process_ids"] = _merge_int_values(current.get("process_ids"), details.get("process_ids"))
        current["process_names"] = _merge_string_values(current.get("process_names"), details.get("process_names"))
        existing_samples = cast(list[dict[str, object]], current.get("sample_connections") or [])
        for sample in cast(list[object], details.get("sample_connections") or []):
            if (
                isinstance(sample, dict)
                and sample not in existing_samples
                and len(existing_samples) < network_monitor._evidence_sample_limit  # type: ignore[attr-defined]
            ):
                existing_samples.append(sample)
        current["sample_connections"] = existing_samples
        current["total_hits"] = max(_int_from_value(current.get("total_hits")), _int_from_value(details.get("hit_count") or details.get("total_hits")))
        current["hit_count"] = current["total_hits"]
        current["last_seen_at"] = max(
            str(current.get("last_seen_at") or ""),
            str(details.get("last_seen_at") or details.get("snapshot_at") or event.created_at.isoformat()),
        )
    rows = list(grouped.values())
    rows.sort(key=lambda item: str(item.get("last_seen_at") or ""), reverse=True)
    return rows[:limit]


def _merged_packet_session_rows(*, remote_ip: str | None, limit: int) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for item in packet_monitor.list_recent_sessions(limit=limit, remote_ip=remote_ip):
        key = str(item.get("session_key") or "").strip()
        if key:
            grouped[key] = dict(item)
    for event in soc_manager.query_events(event_type="packet.telemetry.session", remote_ip=remote_ip, limit=max(limit * 4, 200)):
        details = cast(dict[str, object], event.details or {})
        key = str(details.get("session_key") or "").strip()
        if not key:
            continue
        if key not in grouped:
            grouped[key] = dict(details)
            continue
        current = grouped[key]
        current["protocols"] = _merge_string_values(current.get("protocols"), details.get("protocols"))
        current["local_ips"] = _merge_string_values(current.get("local_ips"), details.get("local_ips"))
        current["local_ports"] = _merge_int_values(current.get("local_ports"), details.get("local_ports"))
        current["remote_ports"] = _merge_int_values(current.get("remote_ports"), details.get("remote_ports"))
        current["transport_families"] = _merge_string_values(current.get("transport_families"), details.get("transport_families"))
        current["service_names"] = _merge_string_values(current.get("service_names"), details.get("service_names"))
        current["application_protocols"] = _merge_string_values(current.get("application_protocols"), details.get("application_protocols"))
        current["flow_ids"] = _merge_string_values(current.get("flow_ids"), details.get("flow_ids"))
        current["sensitive_ports"] = _merge_int_values(current.get("sensitive_ports"), details.get("sensitive_ports"))
        current["protocol_evidence"] = packet_monitor._merge_protocol_evidence(  # type: ignore[attr-defined]
            current.get("protocol_evidence"),
            details.get("protocol_evidence"),
        )
        current["packet_count"] = max(_int_from_value(current.get("packet_count")), _int_from_value(details.get("packet_count")))
        current["total_packets"] = max(
            _int_from_value(current.get("total_packets")),
            _int_from_value(details.get("total_packets") or details.get("packet_count")),
        )
        current["last_seen_at"] = max(
            str(current.get("last_seen_at") or ""),
            str(details.get("last_seen_at") or details.get("snapshot_at") or event.created_at.isoformat()),
        )
    rows = list(grouped.values())
    rows.sort(key=lambda item: str(item.get("last_seen_at") or ""), reverse=True)
    return rows[:limit]


@app.get("/network/blocked-ips")
async def list_blocked_ips(_: None = Depends(require_operator_access)) -> dict:
    return {"blocked_ips": [entry.__dict__ for entry in ip_blocklist.list_entries()]}


@app.get("/network/packet-sessions")
async def list_packet_sessions(
    remote_ip: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    _: None = Depends(require_operator_access),
) -> dict:
    return {"sessions": _merged_packet_session_rows(remote_ip=remote_ip, limit=limit)}


@app.get("/network/telemetry/connections")
async def list_network_telemetry_connections(
    remote_ip: str | None = None,
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.connection",
        remote_ip=remote_ip,
        limit=limit,
    )
    return {
        "connections": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/flows")
async def list_network_telemetry_flows(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    flow_id: str | None = Query(default=None, min_length=1, max_length=256),
    service_name: str | None = Query(default=None, min_length=1, max_length=128),
    application_protocol: str | None = Query(default=None, min_length=1, max_length=128),
    local_ip: str | None = Query(default=None, min_length=1, max_length=128),
    local_port: str | None = Query(default=None, min_length=1, max_length=16),
    remote_port: str | None = Query(default=None, min_length=1, max_length=16),
    protocol: str | None = Query(default=None, min_length=1, max_length=32),
    state: str | None = Query(default=None, min_length=1, max_length=64),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.flow",
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
    )
    return {
        "flows": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/summary")
async def summarize_network_telemetry(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    flow_id: str | None = Query(default=None, min_length=1, max_length=256),
    service_name: str | None = Query(default=None, min_length=1, max_length=128),
    application_protocol: str | None = Query(default=None, min_length=1, max_length=128),
    local_ip: str | None = Query(default=None, min_length=1, max_length=128),
    local_port: str | None = Query(default=None, min_length=1, max_length=16),
    remote_port: str | None = Query(default=None, min_length=1, max_length=16),
    protocol: str | None = Query(default=None, min_length=1, max_length=32),
    state: str | None = Query(default=None, min_length=1, max_length=64),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    facet_limit: int = Query(default=5, ge=1, le=20),
    limit: int = Query(default=250, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.summarize_network_telemetry(
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
        facet_limit=facet_limit,
        limit=limit,
    )


@app.get("/network/telemetry/dns")
async def list_network_telemetry_dns(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.dns",
        remote_ip=remote_ip,
        hostname=hostname,
        limit=limit,
    )
    return {
        "dns_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/http")
async def list_network_telemetry_http(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.http",
        remote_ip=remote_ip,
        hostname=hostname,
        limit=limit,
    )
    return {
        "http_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/tls")
async def list_network_telemetry_tls(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.tls",
        remote_ip=remote_ip,
        hostname=hostname,
        limit=limit,
    )
    return {
        "tls_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/certificates")
async def list_network_telemetry_certificates(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.certificate",
        remote_ip=remote_ip,
        hostname=hostname,
        limit=limit,
    )
    return {
        "certificate_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/proxy")
async def list_network_telemetry_proxy(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    username: str | None = Query(default=None, min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.proxy",
        remote_ip=remote_ip,
        hostname=hostname,
        text=username,
        limit=limit,
    )
    return {
        "proxy_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/auth")
async def list_network_telemetry_auth(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    username: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.auth",
        remote_ip=remote_ip,
        hostname=hostname,
        text=username,
        limit=limit,
    )
    return {
        "auth_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/vpn")
async def list_network_telemetry_vpn(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    username: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.vpn",
        remote_ip=remote_ip,
        hostname=hostname,
        text=username,
        limit=limit,
    )
    return {
        "vpn_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/dhcp")
async def list_network_telemetry_dhcp(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    assigned_ip: str | None = Query(default=None, min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.dhcp",
        remote_ip=remote_ip,
        hostname=hostname,
        text=assigned_ip,
        limit=limit,
    )
    return {
        "dhcp_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/directory-auth")
async def list_network_telemetry_directory_auth(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    username: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.directory_auth",
        remote_ip=remote_ip,
        hostname=hostname,
        text=username,
        limit=limit,
    )
    return {
        "directory_auth_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/radius")
async def list_network_telemetry_radius(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    username: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.radius",
        remote_ip=remote_ip,
        hostname=hostname,
        text=username,
        limit=limit,
    )
    return {
        "radius_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/network/telemetry/nac")
async def list_network_telemetry_nac(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    device_id: str | None = Query(default=None, min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="network.telemetry.nac",
        remote_ip=remote_ip,
        hostname=hostname,
        text=device_id,
        limit=limit,
    )
    return {
        "nac_records": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_network_telemetry_retention_hours,
    }


@app.get("/packet/telemetry/sessions")
async def list_packet_telemetry_sessions(
    remote_ip: str | None = None,
    session_key: str | None = None,
    local_ip: str | None = Query(default=None, min_length=1, max_length=128),
    local_port: str | None = Query(default=None, min_length=1, max_length=16),
    remote_port: str | None = Query(default=None, min_length=1, max_length=16),
    protocol: str | None = Query(default=None, min_length=1, max_length=32),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="packet.telemetry.session",
        remote_ip=remote_ip,
        session_key=session_key,
        local_ip=local_ip,
        local_port=local_port,
        remote_port=remote_port,
        protocol=protocol,
        limit=limit,
    )
    return {
        "sessions": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_packet_telemetry_retention_hours,
    }


@app.get("/packet/telemetry/captures")
async def list_packet_telemetry_captures(
    limit: int = Query(default=20, ge=1, le=100),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    session_key: str | None = Query(default=None, min_length=1, max_length=256),
    protocol: str | None = Query(default=None, min_length=1, max_length=32),
    local_port: int | None = Query(default=None, ge=1, le=65535),
    remote_port: int | None = Query(default=None, ge=1, le=65535),
    _: None = Depends(require_operator_access),
) -> dict:
    return {
        "captures": packet_monitor.list_retained_captures(
            limit=limit,
            remote_ip=remote_ip,
            session_key=session_key,
            protocol=protocol,
            local_port=local_port,
            remote_port=remote_port,
        ),
        "retention_enabled": settings.packet_monitor_capture_retention_enabled,
    }


@app.get("/packet/telemetry/captures/{capture_id}")
async def get_packet_telemetry_capture(
    capture_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        capture = packet_monitor.get_retained_capture(capture_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"capture": capture}


@app.get("/packet/telemetry/captures/{capture_id}/text")
async def get_packet_telemetry_capture_text(
    capture_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        capture = packet_monitor.get_retained_capture(capture_id)
        text = packet_monitor.get_retained_capture_text(capture_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"capture": capture, "text": text}


@app.post("/packet/telemetry/captures/{capture_id}/case")
async def create_case_from_packet_capture(
    capture_id: str,
    payload: SocPacketCaptureCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        capture = packet_monitor.get_retained_capture(capture_id)
        case = soc_manager.create_case_from_packet_capture(capture, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.get("/packet/telemetry/summary")
async def summarize_packet_telemetry(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    session_key: str | None = Query(default=None, min_length=1, max_length=256),
    local_ip: str | None = Query(default=None, min_length=1, max_length=128),
    local_port: str | None = Query(default=None, min_length=1, max_length=16),
    remote_port: str | None = Query(default=None, min_length=1, max_length=16),
    protocol: str | None = Query(default=None, min_length=1, max_length=32),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    facet_limit: int = Query(default=5, ge=1, le=20),
    limit: int = Query(default=250, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.summarize_packet_telemetry(
        remote_ip=remote_ip,
        session_key=session_key,
        local_ip=local_ip,
        local_port=local_port,
        remote_port=remote_port,
        protocol=protocol,
        start_at=start_at,
        end_at=end_at,
        facet_limit=facet_limit,
        limit=limit,
    )


@app.get("/network/observations")
async def list_network_observations(
    remote_ip: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    _: None = Depends(require_operator_access),
) -> dict:
    return {"observations": _merged_network_observation_rows(remote_ip=remote_ip, limit=limit)}


@app.get("/network/evidence")
async def list_network_evidence(
    remote_ip: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    _: None = Depends(require_operator_access),
) -> dict:
    packet_sessions = _merged_packet_session_rows(remote_ip=remote_ip, limit=200)
    network_observations = _merged_network_observation_rows(remote_ip=remote_ip, limit=200)
    grouped: dict[str, dict[str, object]] = {}

    for item in network_observations:
        key = str(item.get("remote_ip") or "")
        if not key:
            continue
        grouped[key] = {
            "remote_ip": key,
            "network_observation": item,
            "packet_sessions": [],
            "last_seen_at": item.get("last_seen_at"),
        }
    for item in packet_sessions:
        key = str(item.get("remote_ip") or "")
        if not key:
            continue
        entry = grouped.setdefault(
            key,
            {"remote_ip": key, "network_observation": None, "packet_sessions": [], "last_seen_at": item.get("last_seen_at")},
        )
        cast(list[dict[str, object]], entry["packet_sessions"]).append(item)
        last_seen_at = str(item.get("last_seen_at") or "")
        current_last = str(entry.get("last_seen_at") or "")
        if last_seen_at > current_last:
            entry["last_seen_at"] = last_seen_at

    evidence = list(grouped.values())
    for item in evidence:
        packet_session_rows = cast(list[dict[str, object]], item.get("packet_sessions") or [])
        service_names: set[str] = set()
        application_protocols: set[str] = set()
        flow_ids: set[str] = set()
        transport_families: set[str] = set()
        protocol_hosts: set[str] = set()
        protocol_indicators: set[str] = set()
        observation = cast(dict[str, object] | None, item.get("network_observation"))
        if isinstance(observation, dict):
            for sample in cast(list[object], observation.get("sample_connections") or []):
                if not isinstance(sample, dict):
                    continue
                service_name = str(sample.get("service_name") or "").strip()
                if service_name:
                    service_names.add(service_name)
                application_protocol = str(sample.get("application_protocol") or "").strip()
                if application_protocol:
                    application_protocols.add(application_protocol)
                flow_id = str(sample.get("flow_id") or "").strip()
                if flow_id:
                    flow_ids.add(flow_id)
                transport_family = str(sample.get("transport_family") or "").strip()
                if transport_family:
                    transport_families.add(transport_family)
        for session in packet_session_rows:
            for service_name_value in cast(list[object], session.get("service_names") or []):
                value = str(service_name_value).strip()
                if value:
                    service_names.add(value)
            for application_protocol_value in cast(list[object], session.get("application_protocols") or []):
                value = str(application_protocol_value).strip()
                if value:
                    application_protocols.add(value)
            for flow_id_value in cast(list[object], session.get("flow_ids") or []):
                value = str(flow_id_value).strip()
                if value:
                    flow_ids.add(value)
            for transport_family_value in cast(list[object], session.get("transport_families") or []):
                value = str(transport_family_value).strip()
                if value:
                    transport_families.add(value)
            protocol_evidence = session.get("protocol_evidence")
            if isinstance(protocol_evidence, dict):
                for host_value in cast(list[object], protocol_evidence.get("hostnames") or []):
                    value = str(host_value).strip()
                    if value:
                        protocol_hosts.add(value)
                for indicator_value in cast(list[object], protocol_evidence.get("indicators") or []):
                    value = str(indicator_value).strip()
                    if value:
                        protocol_indicators.add(value)
                for app_value in cast(list[object], protocol_evidence.get("application_protocols") or []):
                    value = str(app_value).strip()
                    if value:
                        application_protocols.add(value)
        evidence_payload: dict[str, object] = {
            "remote_ip": str(item.get("remote_ip") or ""),
            "observation": observation,
            "packet_session": packet_session_rows[0] if packet_session_rows else None,
        }
        source_events = soc_manager.resolve_network_evidence_events(evidence_payload)
        related_cases = soc_manager.resolve_network_evidence_cases(source_events)
        item["service_names"] = sorted(service_names)
        item["application_protocols"] = sorted(application_protocols)
        item["flow_ids"] = sorted(flow_ids)
        item["transport_families"] = sorted(transport_families)
        item["protocol_hosts"] = sorted(protocol_hosts)
        item["protocol_indicators"] = sorted(protocol_indicators)
        item["related_alert_ids"] = soc_manager.resolve_network_evidence_alert_ids(source_events)
        item["related_case_ids"] = [case.case_id for case in related_cases]
        item["open_case_ids"] = [case.case_id for case in related_cases if case.status is not SocCaseStatus.closed]
        item["open_case_count"] = len(cast(list[str], item["open_case_ids"]))
    evidence.sort(key=lambda item: str(item.get("last_seen_at") or ""), reverse=True)
    return {"evidence": evidence[:limit]}


@app.post("/network/telemetry/ingest")
async def ingest_network_sensor_telemetry(
    payload: SocNetworkSensorTelemetryIngest,
    _: None = Depends(require_endpoint_access),
) -> dict:
    return _record_sensor_network_telemetry(payload)


@app.post("/network/packet-sessions/case")
async def create_case_from_packet_session(
    payload: SocPacketSessionCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    session = next(
        (
            item
            for item in packet_monitor.list_recent_sessions(limit=200)
            if str(item.get("session_key") or "") == payload.session_key
        ),
        None,
    )
    if session is None:
        raise HTTPException(status_code=404, detail=f"Packet session not found: {payload.session_key}")
    case = soc_manager.create_case_from_packet_session(session, payload)
    return case.model_dump(mode="json")


@app.post("/network/evidence/case")
async def create_case_from_network_evidence(
    payload: SocNetworkEvidenceCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    packet_sessions = packet_monitor.list_recent_sessions(limit=200, remote_ip=payload.remote_ip)
    network_observations = network_monitor.list_recent_observations(limit=200, remote_ip=payload.remote_ip)
    observation = network_observations[0] if network_observations else None
    packet_session = packet_sessions[0] if packet_sessions else None
    if observation is None and packet_session is None:
        raise HTTPException(status_code=404, detail=f"Network evidence not found: {payload.remote_ip}")
    evidence_payload: dict[str, object] = {
        "remote_ip": payload.remote_ip,
        "observation": observation,
        "packet_session": packet_session,
    }
    case = soc_manager.create_case_from_network_evidence(evidence_payload, payload)
    return case.model_dump(mode="json")


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


@app.get("/linear/asks", response_class=HTMLResponse)
async def linear_asks_portal() -> HTMLResponse:
    forms = linear_asks_forms.list_forms()
    if not forms:
        body = """
        <html><body>
        <h1>Linear Asks</h1>
        <p>No Linear forms are configured.</p>
        </body></html>
        """
        return HTMLResponse(body)
    cards = []
    for form in forms:
        title = html.escape(form.title)
        form_key = html.escape(form.form_key)
        description = html.escape(form.description or "Open the configured Linear Asks form.")
        meta = [part for part in [form.category, form.team] if part]
        meta_html = f"<p><small>{html.escape(' · '.join(meta))}</small></p>" if meta else ""
        cards.append(
            f"<li><a href=\"/linear/asks/{form_key}\">{title}</a>{meta_html}<p>{description}</p></li>"
        )
    body = (
        "<html><body><h1>Linear Asks</h1>"
        "<p>Open one of the configured Linear request forms.</p>"
        f"<ul>{''.join(cards)}</ul>"
        "</body></html>"
    )
    return HTMLResponse(body)


@app.get("/linear/asks/{form_key}")
async def open_linear_asks_form(form_key: str) -> RedirectResponse:
    form = linear_asks_forms.get_form(form_key)
    if form is None or not form.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linear form not found")
    return RedirectResponse(url=form.url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.get("/linear/forms")
async def list_linear_forms(
    include_disabled: bool = Query(False),
    _: None = Depends(require_operator_access),
) -> dict:
    forms = [form.model_dump(mode="json") for form in linear_asks_forms.list_forms(include_disabled=include_disabled)]
    return {"forms": forms, "portal_path": "/linear/asks"}


@app.get("/linear/forms/{form_key}")
async def get_linear_form(form_key: str, _: None = Depends(require_operator_access)) -> dict:
    form = linear_asks_forms.get_form(form_key)
    if form is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linear form not found")
    return {"form": form.model_dump(mode="json")}


@app.post("/linear/forms")
async def upsert_linear_form(
    payload: LinearAsksFormUpsert,
    _: None = Depends(require_operator_access),
) -> dict:
    form = linear_asks_forms.upsert_form(payload)
    return {"form": form.model_dump(mode="json")}


@app.delete("/linear/forms/{form_key}")
async def delete_linear_form(form_key: str, _: None = Depends(require_operator_access)) -> dict:
    deleted = linear_asks_forms.delete_form(form_key)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Linear form not found")
    return {"status": "deleted", "form_key": form_key}


@app.get("/docker/resources")
async def list_docker_resource_catalog() -> dict:
    resources = [resource.model_dump(mode="json") for resource in list_docker_resources()]
    return {"resources": resources, "portal_path": "/docker/resources/portal"}


@app.get("/docker/resources/portal", response_class=HTMLResponse)
async def docker_resources_portal() -> HTMLResponse:
    resources = list_docker_resources()
    cards = []
    for resource in resources:
        title = html.escape(resource.title)
        category = html.escape(resource.category)
        announced_at = html.escape(resource.announced_at.date().isoformat())
        summary = html.escape(resource.summary)
        relevance = html.escape(resource.toolchain_relevance)
        url = html.escape(resource.url)
        cards.append(
            "<li>"
            f"<a href=\"{url}\">{title}</a>"
            f"<p><small>{category} · {announced_at}</small></p>"
            f"<p>{summary}</p>"
            f"<p><strong>Toolchain:</strong> {relevance}</p>"
            "</li>"
        )
    body = (
        "<html><body><h1>Docker Resources</h1>"
        "<p>Current Docker announcements and product surfaces relevant to this toolchain.</p>"
        f"<ul>{''.join(cards)}</ul>"
        "</body></html>"
    )
    return HTMLResponse(body)


@app.get("/docker/resources/{resource_key}")
async def get_docker_resource_detail(resource_key: str) -> dict:
    resource = get_docker_resource(resource_key)
    if resource is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Docker resource not found")
    return {"resource": resource.model_dump(mode="json")}


@app.get("/toolchain/updates")
async def list_toolchain_updates(
    provider: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    updates = [
        record.model_dump(mode="json")
        for record in toolchain_runtime.updates.list_updates(provider=provider, status=status_filter)
    ]
    return {"updates": updates}


@app.get("/toolchain/providers")
async def list_toolchain_providers(_: None = Depends(require_operator_access)) -> dict:
    providers = [record.model_dump(mode="json") for record in toolchain_runtime.providers.list_providers()]
    return {"providers": providers}


@app.get("/toolchain/providers/{provider_id}")
async def get_toolchain_provider(provider_id: str, _: None = Depends(require_operator_access)) -> dict:
    provider = toolchain_runtime.providers.get_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain provider not found")
    return {"provider": provider.model_dump(mode="json")}


@app.get("/toolchain/health")
async def list_toolchain_health(
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    checks = toolchain_runtime.health.list_checks()
    if status_filter:
        checks = [record for record in checks if record.status == status_filter]
    return {"checks": [record.model_dump(mode="json") for record in checks]}


@app.get("/toolchain/health/{check_id}")
async def get_toolchain_health(check_id: str, _: None = Depends(require_operator_access)) -> dict:
    check = toolchain_runtime.health.get_check(check_id)
    if check is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain health check not found")
    return {"check": check.model_dump(mode="json")}


@app.get("/toolchain/security")
async def list_toolchain_security_checks(
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    _: None = Depends(require_operator_access),
) -> dict:
    checks = toolchain_runtime.security.list_checks()
    if status_filter:
        checks = [record for record in checks if record.status == status_filter]
    if severity:
        checks = [record for record in checks if record.severity == severity]
    return {"checks": [record.model_dump(mode="json") for record in checks]}


@app.get("/toolchain/security/{check_id}")
async def get_toolchain_security_check(check_id: str, _: None = Depends(require_operator_access)) -> dict:
    check = toolchain_runtime.security.get_check(check_id)
    if check is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain security check not found")
    return {"check": check.model_dump(mode="json")}


@app.get("/toolchain/languages")
async def list_toolchain_languages(
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    languages = toolchain_runtime.languages.list_languages()
    if status_filter:
        languages = [record for record in languages if record.status == status_filter]
    return {"languages": [record.model_dump(mode="json") for record in languages]}


@app.get("/toolchain/languages/health")
async def list_toolchain_language_health(
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    checks = toolchain_runtime.language_health.list_checks()
    if status_filter:
        checks = [record for record in checks if record.status == status_filter]
    return {"checks": [record.model_dump(mode="json") for record in checks]}


@app.get("/toolchain/languages/health/{language_id}")
async def get_toolchain_language_health(language_id: str, _: None = Depends(require_operator_access)) -> dict:
    check = toolchain_runtime.language_health.get_check(language_id)
    if check is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain language health check not found")
    return {"check": check.model_dump(mode="json")}


@app.get("/toolchain/languages/{language_id}")
async def get_toolchain_language(language_id: str, _: None = Depends(require_operator_access)) -> dict:
    language = toolchain_runtime.languages.get_language(language_id)
    if language is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain language not found")
    return {"language": language.model_dump(mode="json")}


@app.get("/toolchain/package-managers")
async def list_toolchain_package_managers(
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    package_managers = toolchain_runtime.package_managers.list_package_managers()
    if status_filter:
        package_managers = [record for record in package_managers if record.status == status_filter]
    return {"package_managers": [record.model_dump(mode="json") for record in package_managers]}


@app.get("/toolchain/package-managers/{manager_id}")
async def get_toolchain_package_manager(manager_id: str, _: None = Depends(require_operator_access)) -> dict:
    package_manager = toolchain_runtime.package_managers.get_package_manager(manager_id)
    if package_manager is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain package manager not found")
    return {"package_manager": package_manager.model_dump(mode="json")}


@app.get("/toolchain/secret-sources")
async def list_toolchain_secret_sources(
    status_filter: str | None = Query(None, alias="status"),
    source: str | None = Query(None),
    _: None = Depends(require_operator_access),
) -> dict:
    secret_sources = toolchain_runtime.secret_sources.list_secret_sources()
    if status_filter:
        secret_sources = [record for record in secret_sources if record.status == status_filter]
    if source:
        secret_sources = [record for record in secret_sources if record.source == source]
    return {"secret_sources": [record.model_dump(mode="json") for record in secret_sources]}


@app.get("/toolchain/secret-sources/{secret_id}")
async def get_toolchain_secret_source(secret_id: str, _: None = Depends(require_operator_access)) -> dict:
    secret_source = toolchain_runtime.secret_sources.get_secret_source(secret_id)
    if secret_source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain secret source not found")
    return {"secret_source": secret_source.model_dump(mode="json")}


@app.get("/toolchain/secret-resolution")
async def list_toolchain_secret_resolution(
    status_filter: str | None = Query(None, alias="status"),
    source: str | None = Query(None),
    _: None = Depends(require_operator_access),
) -> dict:
    resolutions = toolchain_runtime.secret_resolver.list_resolutions()
    if status_filter:
        resolutions = [record for record in resolutions if record.status == status_filter]
    if source:
        resolutions = [record for record in resolutions if record.source == source]
    return {"resolutions": [record.model_dump(mode="json") for record in resolutions]}


@app.get("/toolchain/secret-resolution/{secret_id}")
async def get_toolchain_secret_resolution(secret_id: str, _: None = Depends(require_operator_access)) -> dict:
    resolution = toolchain_runtime.secret_resolver.get_resolution(secret_id)
    if resolution is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain secret resolution not found")
    return {"resolution": resolution.model_dump(mode="json")}


@app.post("/toolchain/secret-resolution/{secret_id}/resolve")
async def resolve_toolchain_secret(secret_id: str, _: None = Depends(require_operator_access)) -> dict:
    if toolchain_runtime.secret_sources.get_secret_source(secret_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain secret resolution not found")
    resolution = toolchain_runtime.secret_resolver.resolve_secret(secret_id)
    return {"resolution": resolution.model_dump(mode="json")}


@app.post("/toolchain/secret-resolution/{secret_id}/set")
async def set_toolchain_secret(
    secret_id: str,
    value: str = Body(..., embed=True, min_length=1),
    persist: str = Query("auto", pattern="^(auto|vault|override)$"),
    _: None = Depends(require_operator_access),
) -> dict:
    result = toolchain_runtime.secret_resolver.set_secret(secret_id, value, persist=persist)
    if result.status == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain secret resolution not found")
    return {"result": result.model_dump(mode="json")}


@app.post("/toolchain/secret-resolution/{secret_id}/clear")
async def clear_toolchain_secret(secret_id: str, _: None = Depends(require_operator_access)) -> dict:
    result = toolchain_runtime.secret_resolver.clear_secret(secret_id)
    if result.status == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain secret resolution not found")
    return {"result": result.model_dump(mode="json")}


@app.get("/toolchain/cache")
async def list_toolchain_cache(
    namespace: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    entries = toolchain_runtime.cache_store.list_entries(namespace=namespace, status=status_filter)
    return {"entries": [record.model_dump(mode="json") for record in entries], "summary": toolchain_runtime.cache_store.summary()}


@app.get("/toolchain/cache/{namespace}/{cache_key}")
async def get_toolchain_cache_entry(namespace: str, cache_key: str, _: None = Depends(require_operator_access)) -> dict:
    entry = toolchain_runtime.cache_store.get_entry(namespace, cache_key)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain cache entry not found")
    return {"entry": entry.model_dump(mode="json")}


@app.get("/toolchain/projects")
async def list_toolchain_projects(
    root_path: str = Query("."),
    _: None = Depends(require_operator_access),
) -> dict:
    projects = toolchain_runtime.projects.detect_projects(root_path)
    return {"projects": [record.model_dump(mode="json") for record in projects]}


@app.get("/toolchain/projects/{project_id:path}")
async def get_toolchain_project(
    project_id: str,
    root_path: str = Query("."),
    _: None = Depends(require_operator_access),
) -> dict:
    project = toolchain_runtime.projects.get_project(project_id, root_path=root_path)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain project not found")
    return {"project": project.model_dump(mode="json")}


@app.get("/toolchain/provisioning")
async def list_toolchain_provisioning(
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    actions = toolchain_runtime.provisioning.list_actions()
    if status_filter:
        actions = [record for record in actions if record.status == status_filter]
    return {"actions": [record.model_dump(mode="json") for record in actions]}


@app.get("/toolchain/provisioning/{target_id}")
async def get_toolchain_provisioning(target_id: str, _: None = Depends(require_operator_access)) -> dict:
    action = toolchain_runtime.provisioning.get_action(target_id)
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain provisioning action not found")
    return {"action": action.model_dump(mode="json")}


@app.post("/toolchain/bootstrap/{target_id}")
async def run_toolchain_bootstrap(
    target_id: str,
    project_path: str = Query("."),
    mode: str = Query("install", pattern="^(install|repair)$"),
    execute: bool = Query(False),
    verify_after: bool = Query(True),
    timeout_seconds: float = Query(300.0),
    _: None = Depends(require_operator_access),
) -> dict:
    result = toolchain_runtime.bootstrap.run(
        target_id,
        mode=mode,
        execute=execute,
        verify_after=verify_after,
        project_path=project_path,
        timeout_seconds=timeout_seconds,
    )
    if result.status == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain bootstrap target not found")
    return {"result": result.model_dump(mode="json")}


@app.get("/toolchain/package-operations")
async def list_toolchain_package_operations(
    manager_id: str | None = Query(None, alias="manager"),
    _: None = Depends(require_operator_access),
) -> dict:
    operations = toolchain_runtime.package_operations.list_operations(manager_id)
    return {"operations": [record.model_dump(mode="json") for record in operations]}


@app.get("/toolchain/package-operations/{manager_id}/{operation}")
async def get_toolchain_package_operation(manager_id: str, operation: str, _: None = Depends(require_operator_access)) -> dict:
    record = toolchain_runtime.package_operations.build_operation(manager_id, operation)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain package operation not found")
    return {"operation": record.model_dump(mode="json")}


@app.post("/toolchain/package-operations/{manager_id}/{operation}/run")
async def run_toolchain_package_operation(
    manager_id: str,
    operation: str,
    project_path: str = Query("."),
    execute: bool = Query(False),
    timeout_seconds: float = Query(60.0),
    _: None = Depends(require_operator_access),
) -> dict:
    result = toolchain_runtime.package_operations.run_operation(
        manager_id,
        operation,
        project_path=project_path,
        execute=execute,
        timeout_seconds=timeout_seconds,
    )
    if result.get("status") == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain package operation not found")
    return result


@app.get("/toolchain/version-policy")
async def list_toolchain_version_policy(
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    results = toolchain_runtime.version_policy.evaluate()
    if status_filter:
        results = [record for record in results if record.status == status_filter]
    return {"results": [record.model_dump(mode="json") for record in results]}


@app.get("/toolchain/version-policy/{target_id}")
async def get_toolchain_version_policy(target_id: str, _: None = Depends(require_operator_access)) -> dict:
    result = toolchain_runtime.version_policy.get_result(target_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain version policy result not found")
    return {"result": result.model_dump(mode="json")}


@app.get("/toolchain/provider-templates")
async def list_toolchain_provider_templates(_: None = Depends(require_operator_access)) -> dict:
    templates = [record.model_dump(mode="json") for record in toolchain_runtime.provider_templates.list_templates()]
    return {"templates": templates}


@app.get("/toolchain/provider-templates/{provider_id}")
async def get_toolchain_provider_template(provider_id: str, _: None = Depends(require_operator_access)) -> dict:
    template = toolchain_runtime.provider_templates.get_template(provider_id)
    if template is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain provider template not found")
    return {"template": template.model_dump(mode="json")}


@app.get("/toolchain/provider-templates/{provider_id}/render")
async def render_toolchain_provider_template(provider_id: str, _: None = Depends(require_operator_access)) -> dict:
    payload = toolchain_runtime.provider_templates.render_template(provider_id)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain provider template not found")
    return payload


@app.post("/toolchain/provider-templates/{provider_id}/scaffold")
async def scaffold_toolchain_provider_template(
    provider_id: str,
    target_dir: str = Query("."),
    write: bool = Query(False),
    _: None = Depends(require_operator_access),
) -> dict:
    payload = toolchain_runtime.provider_scaffolder.scaffold(provider_id, target_dir, write=write)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain provider template not found")
    return payload


@app.get("/toolchain/report")
async def get_toolchain_report(
    format: str = Query("json", pattern="^(json|markdown)$"),
    _: None = Depends(require_operator_access),
) -> dict:
    if format == "markdown":
        return {"format": "markdown", "report": toolchain_runtime.reporting.render_markdown()}
    return {"format": "json", "report": toolchain_runtime.reporting.snapshot()}


@app.get("/toolchain/jobs")
async def list_toolchain_jobs(_: None = Depends(require_operator_access)) -> dict:
    return {"jobs": [record.model_dump(mode="json") for record in toolchain_runtime.jobs.list_jobs()]}


@app.get("/toolchain/jobs/{job_id}")
async def get_toolchain_job(job_id: str, _: None = Depends(require_operator_access)) -> dict:
    job = toolchain_runtime.jobs.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain job not found")
    return {"job": job.model_dump(mode="json")}


@app.post("/toolchain/jobs/{job_id}/run")
async def run_toolchain_job(job_id: str, _: None = Depends(require_operator_access)) -> dict:
    result = toolchain_runtime.jobs.run_job(job_id)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain job not found")
    return result


@app.get("/toolchain/schedules")
async def list_toolchain_schedules(_: None = Depends(require_operator_access)) -> dict:
    return {"schedules": [record.model_dump(mode="json") for record in toolchain_runtime.scheduler.list_schedules()]}


@app.get("/toolchain/schedules/runtime")
async def get_toolchain_schedule_runtime(_: None = Depends(require_operator_access)) -> dict:
    return {"runtime": toolchain_runtime.scheduler.get_runtime_status().model_dump(mode="json")}


@app.get("/toolchain/schedules/{schedule_id}")
async def get_toolchain_schedule(schedule_id: str, _: None = Depends(require_operator_access)) -> dict:
    schedule = toolchain_runtime.scheduler.get_schedule(schedule_id)
    if schedule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain schedule not found")
    return {"schedule": schedule.model_dump(mode="json")}


@app.post("/toolchain/schedules/run-due")
async def run_due_toolchain_schedules(_: None = Depends(require_operator_access)) -> dict:
    return cast(dict[str, Any], toolchain_runtime.scheduler.run_due_jobs())


@app.post("/toolchain/schedules/runtime/start")
async def start_toolchain_schedule_runtime(
    poll_seconds: float = Query(60.0, ge=0.01, le=86_400.0),
    _: None = Depends(require_operator_access),
) -> dict:
    return {"runtime": toolchain_runtime.scheduler.start_background_runner(poll_seconds=poll_seconds).model_dump(mode="json")}


@app.post("/toolchain/schedules/runtime/stop")
async def stop_toolchain_schedule_runtime(_: None = Depends(require_operator_access)) -> dict:
    return {"runtime": toolchain_runtime.scheduler.stop_background_runner().model_dump(mode="json")}


@app.post("/toolchain/schedules/{job_id}")
async def upsert_toolchain_schedule(
    job_id: str,
    every_minutes: int = Query(..., ge=1, le=10_080),
    enabled: bool = Query(True),
    _: None = Depends(require_operator_access),
) -> dict:
    return {
        "schedule": toolchain_runtime.scheduler.upsert_schedule(
            job_id,
            interval_minutes=every_minutes,
            enabled=enabled,
        ).model_dump(mode="json")
    }


@app.delete("/toolchain/schedules/{schedule_id}")
async def delete_toolchain_schedule(schedule_id: str, _: None = Depends(require_operator_access)) -> dict:
    if not toolchain_runtime.scheduler.remove_schedule(schedule_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain schedule not found")
    return {"status": "deleted", "schedule_id": schedule_id}


@app.get("/toolchain/policy-enforcement")
async def list_toolchain_policy_enforcement(
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    results = toolchain_runtime.policy_enforcement.evaluate()
    if status_filter:
        results = [record for record in results if record.status == status_filter]
    return {"results": [record.model_dump(mode="json") for record in results]}


@app.get("/toolchain/policy-enforcement/{policy_id}")
async def get_toolchain_policy_enforcement(policy_id: str, _: None = Depends(require_operator_access)) -> dict:
    result = toolchain_runtime.policy_enforcement.get_result(policy_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain policy enforcement result not found")
    return {"result": result.model_dump(mode="json")}


@app.get("/toolchain/policy-gates")
async def list_toolchain_policy_gates(
    status_filter: str | None = Query(None, alias="status"),
    _: None = Depends(require_operator_access),
) -> dict:
    records = toolchain_runtime.policy_gates.evaluate()
    if status_filter:
        records = [record for record in records if record.status == status_filter]
    return {"gates": [record.model_dump(mode="json") for record in records]}


@app.get("/toolchain/policy-gates/{gate_id}")
async def get_toolchain_policy_gate(gate_id: str, _: None = Depends(require_operator_access)) -> dict:
    gate = toolchain_runtime.policy_gates.get_gate(gate_id)
    if gate is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain policy gate not found")
    return {"gate": gate.model_dump(mode="json")}


@app.post("/toolchain/updates/sync")
async def sync_toolchain_updates(
    apply_safe_only: bool = Query(True),
    _: None = Depends(require_operator_access),
) -> dict:
    return toolchain_runtime.updates.sync(apply_safe_only=apply_safe_only)


@app.get("/toolchain/doctor")
async def get_toolchain_doctor(_: None = Depends(require_operator_access)) -> dict:
    return cast(dict[str, Any], toolchain_doctor.run())


@app.post("/toolchain/doctor/repair")
async def repair_toolchain_doctor(
    force_reinstall: bool = False,
    _: None = Depends(require_operator_access),
) -> dict:
    return cast(dict[str, Any], toolchain_doctor.repair(force_reinstall=force_reinstall))


@app.get("/toolchain/updates/{update_id}")
async def get_toolchain_update(update_id: str, _: None = Depends(require_operator_access)) -> dict:
    update = toolchain_runtime.updates.get_update(update_id)
    if update is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain update not found")
    return {"update": update.model_dump(mode="json")}


@app.post("/toolchain/updates/{update_id}/mark-seen")
async def mark_toolchain_update_seen(update_id: str, _: None = Depends(require_operator_access)) -> dict:
    update = toolchain_runtime.updates.mark_seen(update_id)
    if update is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Toolchain update not found")
    return {"update": update.model_dump(mode="json")}


@app.post("/soc/dashboard/view-state")
async def soc_update_dashboard_view_state(
    payload: SocDashboardViewStateUpdate,
    _: None = Depends(require_operator_access),
) -> dict:
    return {"view_state": soc_manager.update_dashboard_view_state(payload)}


@app.post("/soc/events")
async def soc_ingest_event(
    payload: SocEventIngest,
    _: None = Depends(require_operator_access),
) -> dict:
    result = _record_soc_event(
        event_type=payload.event_type,
        source=payload.source,
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
    source: str | None = Query(default=None, min_length=1, max_length=64),
    tag: str | None = Query(default=None, min_length=1, max_length=256),
    text: str | None = Query(default=None, min_length=1, max_length=512),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    filename: str | None = Query(default=None, min_length=1, max_length=256),
    artifact_path: str | None = Query(default=None, min_length=1, max_length=512),
    session_key: str | None = Query(default=None, min_length=1, max_length=256),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    flow_id: str | None = Query(default=None, min_length=1, max_length=256),
    service_name: str | None = Query(default=None, min_length=1, max_length=128),
    application_protocol: str | None = Query(default=None, min_length=1, max_length=128),
    local_ip: str | None = Query(default=None, min_length=1, max_length=128),
    local_port: str | None = Query(default=None, min_length=1, max_length=16),
    remote_port: str | None = Query(default=None, min_length=1, max_length=16),
    protocol: str | None = Query(default=None, min_length=1, max_length=32),
    state: str | None = Query(default=None, min_length=1, max_length=64),
    close_reason: str | None = Query(default=None, min_length=1, max_length=128),
    reject_code: str | None = Query(default=None, min_length=1, max_length=128),
    start_at: datetime | None = None,
    end_at: datetime | None = None,
    linked_alert_state: str | None = Query(default=None, pattern="^(linked|unlinked)$"),
    sort: str = Query(default="created_desc", pattern="^(created_desc|created_asc|severity_desc|severity_asc)$"),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
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
    )
    return {"events": [event.model_dump(mode="json") for event in events]}


@app.get("/soc/events/index")
async def get_soc_event_index_status(_: None = Depends(require_operator_access)) -> dict:
    return soc_manager.event_index_status()


@app.post("/soc/events/index/rebuild")
async def rebuild_soc_event_index(_: None = Depends(require_operator_access)) -> dict:
    return soc_manager.rebuild_event_index()


@app.get("/soc/events/{event_id}")
async def soc_get_event(
    event_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        event = soc_manager.get_event(event_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return event.model_dump(mode="json")


@app.get("/soc/alerts")
async def soc_list_alerts(
    status: SocAlertStatus | None = None,
    severity: SocSeverity | None = None,
    assignee: str | None = Query(default=None, min_length=1, max_length=128),
    correlation_rule: str | None = Query(default=None, min_length=1, max_length=128),
    linked_case_state: str | None = Query(default=None, pattern="^(linked|unlinked)$"),
    sort: str = Query(default="updated_desc", pattern="^(updated_desc|updated_asc|severity_desc|severity_asc)$"),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    alerts = soc_manager.query_alerts(
        status=status,
        severity=severity,
        assignee=assignee,
        correlation_rule=correlation_rule,
        linked_case_state=linked_case_state,
        sort=sort,
        limit=limit,
    )
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
    severity: SocSeverity | None = None,
    assignee: str | None = Query(default=None, min_length=1, max_length=128),
    sort: str = Query(default="updated_desc", pattern="^(updated_desc|updated_asc|severity_desc|severity_asc)$"),
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    cases = soc_manager.query_cases(
        status=status,
        severity=severity,
        assignee=assignee,
        sort=sort,
        limit=limit,
    )
    return {"cases": [case.model_dump(mode="json") for case in cases]}


@app.get("/soc/search")
async def soc_search(
    q: str = Query(min_length=1, max_length=512),
    severity: SocSeverity | None = None,
    tag: str | None = Query(default=None, min_length=1, max_length=256),
    limit: int = Query(default=25, ge=1, le=100),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.search(query=q, severity=severity, tag=tag, limit=limit)


@app.get("/soc/hunt")
async def soc_hunt(
    q: str | None = Query(default=None, min_length=1, max_length=512),
    severity: SocSeverity | None = None,
    tag: str | None = Query(default=None, min_length=1, max_length=256),
    source: str | None = Query(default=None, min_length=1, max_length=64),
    event_type: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    hostname: str | None = Query(default=None, min_length=1, max_length=256),
    filename: str | None = Query(default=None, min_length=1, max_length=256),
    artifact_path: str | None = Query(default=None, min_length=1, max_length=512),
    session_key: str | None = Query(default=None, min_length=1, max_length=256),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    flow_id: str | None = Query(default=None, min_length=1, max_length=256),
    service_name: str | None = Query(default=None, min_length=1, max_length=128),
    application_protocol: str | None = Query(default=None, min_length=1, max_length=128),
    local_ip: str | None = Query(default=None, min_length=1, max_length=128),
    local_port: str | None = Query(default=None, min_length=1, max_length=16),
    remote_port: str | None = Query(default=None, min_length=1, max_length=16),
    protocol: str | None = Query(default=None, min_length=1, max_length=32),
    state: str | None = Query(default=None, min_length=1, max_length=64),
    close_reason: str | None = Query(default=None, min_length=1, max_length=128),
    reject_code: str | None = Query(default=None, min_length=1, max_length=128),
    start_at: datetime | None = None,
    end_at: datetime | None = None,
    facet_limit: int = Query(default=5, ge=1, le=20),
    limit: int = Query(default=50, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.hunt(
        query=q,
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
    )


@app.get("/soc/hunt/telemetry/clusters")
async def soc_list_hunt_telemetry_clusters(
    cluster_by: str = Query(default="remote_ip", pattern="^(remote_ip|device_id|process_guid)$"),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    filename: str | None = Query(default=None, min_length=1, max_length=256),
    artifact_path: str | None = Query(default=None, min_length=1, max_length=512),
    session_key: str | None = Query(default=None, min_length=1, max_length=256),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    return {
        "clusters": soc_manager.list_hunt_telemetry_clusters(
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
        )
    }


@app.get("/soc/hunt/telemetry/clusters/{cluster_key}")
async def soc_get_hunt_telemetry_cluster(
    cluster_key: str,
    cluster_by: str = Query(default="remote_ip", pattern="^(remote_ip|device_id|process_guid)$"),
    device_id: str | None = Query(default=None, min_length=1, max_length=256),
    process_name: str | None = Query(default=None, min_length=1, max_length=256),
    process_guid: str | None = Query(default=None, min_length=1, max_length=128),
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    signer_name: str | None = Query(default=None, min_length=1, max_length=256),
    sha256: str | None = Query(default=None, min_length=1, max_length=128),
    filename: str | None = Query(default=None, min_length=1, max_length=256),
    artifact_path: str | None = Query(default=None, min_length=1, max_length=512),
    session_key: str | None = Query(default=None, min_length=1, max_length=256),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    limit: int = Query(default=500, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        cluster = soc_manager.resolve_hunt_telemetry_cluster(
            cluster_by=cluster_by,
            cluster_key=cluster_key,
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
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"cluster": cluster}


@app.post("/soc/hunt/telemetry/clusters/case")
async def soc_create_case_from_hunt_telemetry_cluster(
    payload: SocTelemetryClusterCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_telemetry_cluster(payload)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.get("/soc/detections")
async def soc_list_detections(_: None = Depends(require_operator_access)) -> dict:
    return {"rules": [rule.model_dump(mode="json") for rule in soc_manager.list_detection_rules()]}


@app.get("/soc/detections/{rule_id}")
async def soc_get_detection(rule_id: str, _: None = Depends(require_operator_access)) -> dict:
    try:
        rule = soc_manager.get_detection_rule(rule_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return rule.model_dump(mode="json")


@app.patch("/soc/detections/{rule_id}")
async def soc_update_detection(
    rule_id: str,
    payload: SocDetectionRuleUpdate,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        rule = soc_manager.update_detection_rule(rule_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return rule.model_dump(mode="json")


@app.get("/soc/detections/{rule_id}/rule-alert-groups")
async def soc_list_detection_rule_alert_groups(
    rule_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    return {"groups": soc_manager.list_rule_alert_groups(rule_id)}


@app.get("/soc/detections/{rule_id}/rule-alert-groups/{group_key}")
async def soc_get_detection_rule_alert_group(
    rule_id: str,
    group_key: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        group = soc_manager.resolve_rule_alert_group(rule_id, group_key=group_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"group": group}


@app.post("/soc/detections/{rule_id}/rule-alert-groups/case")
async def soc_create_case_from_detection_rule_alert_group(
    rule_id: str,
    payload: SocCaseRuleGroupCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_rule_alert_group(rule_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.get("/soc/detections/{rule_id}/rule-evidence-groups")
async def soc_list_detection_rule_evidence_groups(
    rule_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    return {"groups": soc_manager.list_rule_evidence_groups(rule_id)}


@app.get("/soc/detections/{rule_id}/rule-evidence-groups/{group_key}")
async def soc_get_detection_rule_evidence_group(
    rule_id: str,
    group_key: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        group = soc_manager.resolve_rule_evidence_group(rule_id, group_key=group_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"group": group}


@app.post("/soc/detections/{rule_id}/rule-evidence-groups/case")
async def soc_create_case_from_detection_rule_evidence_group(
    rule_id: str,
    payload: SocCaseRuleGroupCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_rule_evidence_group(rule_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return case.model_dump(mode="json")


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


@app.get("/soc/cases/{case_id}/alerts")
async def soc_get_case_alerts(
    case_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        alerts = soc_manager.resolve_case_linked_alerts(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"alerts": [item.model_dump(mode="json") for item in alerts]}


@app.get("/soc/cases/{case_id}/events")
async def soc_get_case_events(
    case_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        events = soc_manager.resolve_case_source_events(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"events": [item.model_dump(mode="json") for item in events]}


@app.get("/soc/cases/{case_id}/rule-alert-groups")
async def soc_get_case_rule_alert_groups(
    case_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        groups = soc_manager.list_case_rule_alert_groups(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"groups": groups}


@app.get("/soc/cases/{case_id}/rule-alert-groups/{group_key}")
async def soc_get_case_rule_alert_group(
    case_id: str,
    group_key: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        group = soc_manager.resolve_case_rule_alert_group(case_id, group_key=group_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"group": group}


@app.post("/soc/cases/{case_id}/rule-alert-groups/case")
async def soc_create_case_from_case_rule_alert_group(
    case_id: str,
    payload: SocCaseRuleGroupCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_case_rule_alert_group(case_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.get("/soc/cases/{case_id}/rule-evidence-groups")
async def soc_get_case_rule_evidence_groups(
    case_id: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        groups = soc_manager.list_case_rule_evidence_groups(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"groups": groups}


@app.get("/soc/cases/{case_id}/rule-evidence-groups/{group_key}")
async def soc_get_case_rule_evidence_group(
    case_id: str,
    group_key: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        group = soc_manager.resolve_case_rule_evidence_group(case_id, group_key=group_key)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"group": group}


@app.post("/soc/cases/{case_id}/rule-evidence-groups/case")
async def soc_create_case_from_case_rule_evidence_group(
    case_id: str,
    payload: SocCaseRuleGroupCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_case_rule_evidence_group(case_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.get("/soc/cases/{case_id}/endpoint-timeline/clusters")
async def soc_get_case_endpoint_timeline_clusters(
    case_id: str,
    cluster_by: str = Query(default="process", pattern="^(process|remote_ip)$"),
    limit: int = Query(default=200, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return soc_manager.list_case_endpoint_timeline_clusters(case_id, cluster_by=cluster_by, limit=limit)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/soc/cases/{case_id}/endpoint-timeline/clusters/{cluster_key}")
async def soc_get_case_endpoint_timeline_cluster(
    case_id: str,
    cluster_key: str,
    cluster_by: str = Query(default="process", pattern="^(process|remote_ip)$"),
    limit: int = Query(default=500, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        cluster = soc_manager.resolve_case_endpoint_timeline_cluster(
            case_id,
            cluster_by=cluster_by,
            cluster_key=cluster_key,
            limit=limit,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"cluster": cluster}


@app.get("/soc/cases/{case_id}/endpoint-timeline")
async def soc_get_case_endpoint_timeline(
    case_id: str,
    limit: int = Query(default=200, ge=1, le=500),
    device_id: str | None = None,
    process_name: str | None = None,
    process_guid: str | None = None,
    remote_ip: str | None = None,
    signer_name: str | None = None,
    sha256: str | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return soc_manager.list_case_endpoint_timeline(
            case_id,
            limit=limit,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            remote_ip=remote_ip,
            signer_name=signer_name,
            sha256=sha256,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/soc/cases/{case_id}/endpoint-lineage/clusters")
async def soc_get_case_endpoint_lineage_clusters(
    case_id: str,
    limit: int = Query(default=200, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return soc_manager.list_case_endpoint_lineage_clusters(case_id, limit=limit)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/soc/cases/{case_id}/endpoint-lineage/clusters/{cluster_key}")
async def soc_get_case_endpoint_lineage_cluster(
    case_id: str,
    cluster_key: str,
    limit: int = Query(default=500, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        cluster = soc_manager.resolve_case_endpoint_lineage_cluster(case_id, cluster_key=cluster_key, limit=limit)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"cluster": cluster}


@app.get("/soc/cases/{case_id}/hunt-telemetry/clusters")
async def soc_get_case_hunt_telemetry_clusters(
    case_id: str,
    cluster_by: str = Query(default="remote_ip", pattern="^(remote_ip|device_id|process_guid)$"),
    limit: int = Query(default=200, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        return soc_manager.list_case_hunt_telemetry_clusters(case_id, cluster_by=cluster_by, limit=limit)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/soc/cases/{case_id}/hunt-telemetry/clusters/{cluster_key}")
async def soc_get_case_hunt_telemetry_cluster(
    case_id: str,
    cluster_key: str,
    cluster_by: str = Query(default="remote_ip", pattern="^(remote_ip|device_id|process_guid)$"),
    limit: int = Query(default=500, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        cluster = soc_manager.resolve_case_hunt_telemetry_cluster(
            case_id,
            cluster_by=cluster_by,
            cluster_key=cluster_key,
            limit=limit,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"cluster": cluster}


@app.post("/soc/cases/{case_id}/hunt-telemetry/clusters/case")
async def soc_create_case_from_case_hunt_telemetry_cluster(
    case_id: str,
    payload: SocCaseTelemetryClusterCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_case_hunt_telemetry_cluster(case_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.post("/soc/cases/{case_id}/endpoint-lineage/clusters/case")
async def soc_create_case_from_case_endpoint_lineage_cluster(
    case_id: str,
    payload: SocCaseEndpointLineageClusterCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_case_endpoint_lineage_cluster(case_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return case.model_dump(mode="json")


@app.post("/soc/cases/{case_id}/endpoint-timeline/clusters/case")
async def soc_create_case_from_case_endpoint_timeline_cluster(
    case_id: str,
    payload: SocCaseEndpointTimelineClusterCaseRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        case = soc_manager.create_case_from_case_endpoint_timeline_cluster(case_id, payload)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
    overview = soc_manager.overview()
    return _strip_internal_fields({
        "healthy": not warnings,
        "warnings": warnings,
        "platform": overview["platform"],
        "auth_backends": auth_health,
        "tracker_intel": tracker_health,
        "malware_scanner": malware_health,
        "automation": automation.status(),
        "soc": {
            key: value
            for key, value in overview.items()
            if key != "recent_events"
        },
    })


@app.get("/platform/nodes")
async def list_platform_nodes(
    action: str | None = Query(default=None),
    transition: str | None = Query(default=None),
    failed_only: bool = Query(default=False),
    limit: int = Query(default=100, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    profile = _current_platform_profile()
    topology = cast(dict[str, object], profile.get("topology") or {})
    all_nodes = [topology.get("local_node"), *cast(list[dict[str, object]], topology.get("remote_nodes") or [])]
    normalized_action = action.strip().casefold() if action else None
    normalized_transition = transition.strip().casefold() if transition else None
    filtered_nodes: list[dict[str, object]] = []
    for item in all_nodes:
        if not isinstance(item, dict):
            continue
        metadata = cast(dict[str, object], item.get("metadata") or {})
        history = [
            dict(entry)
            for entry in cast(list[object], metadata.get("action_history") or [])
            if isinstance(entry, dict)
        ]
        action_failures = [str(entry) for entry in cast(list[object], item.get("action_failures") or []) if str(entry)]
        if failed_only and not action_failures:
            continue
        if normalized_action or normalized_transition:
            matching = False
            for entry in history:
                entry_action = str(entry.get("action") or "").casefold()
                entry_transition = str(entry.get("transition") or "").casefold()
                if normalized_action and entry_action != normalized_action:
                    continue
                if normalized_transition and entry_transition != normalized_transition:
                    continue
                matching = True
                break
            if not matching:
                continue
        filtered_nodes.append(item)
        if len(filtered_nodes) >= limit:
            break
    return {
        "platform": profile,
        "topology": topology,
        "nodes": filtered_nodes,
    }


def _resolve_remote_platform_node(node_name: str) -> dict[str, Any]:
    profile = _current_platform_profile()
    topology = cast(dict[str, Any], profile.get("topology") or {})
    remote_nodes = cast(list[dict[str, Any]], topology.get("remote_nodes") or [])
    for item in remote_nodes:
        if str(item.get("node_name") or "") != node_name:
            continue
        related_cases = soc_manager.resolve_remote_node_cases(item)
        enriched = dict(item)
        enriched["related_case_ids"] = [case.case_id for case in related_cases]
        enriched["open_case_ids"] = [case.case_id for case in related_cases if case.status is not SocCaseStatus.closed]
        enriched["open_case_count"] = len(cast(list[str], enriched["open_case_ids"]))
        return enriched
    raise KeyError(f"Platform node not found: {node_name}")


@app.get("/platform/nodes/{node_name}")
async def get_platform_node_detail(node_name: str, _: None = Depends(require_operator_access)) -> dict:
    try:
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.get("/platform/nodes/{node_name}/cases")
async def get_platform_node_cases(node_name: str, _: None = Depends(require_operator_access)) -> dict:
    try:
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    cases = soc_manager.resolve_remote_node_cases(node)
    return {"node_name": node_name, "cases": [case.model_dump(mode="json") for case in cases]}


@app.get("/platform/nodes/{node_name}/actions")
async def get_platform_node_actions(node_name: str, _: None = Depends(require_operator_access)) -> dict:
    try:
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {
        "node_name": node_name,
        "actions": build_platform_node_actions(cast(dict[str, Any], node.get("metadata") or {})),
    }


@app.post("/platform/nodes/heartbeat")
async def register_platform_node_heartbeat(
    payload: PlatformNodeHeartbeatPayload,
    _: None = Depends(require_operator_access),
) -> dict:
    entry = upsert_platform_node(
        payload.model_dump(exclude_none=True),
        path=settings.platform_node_registry_path,
    )
    profile = _current_platform_profile()
    topology = cast(dict[str, object], profile.get("topology") or {})
    node_name = str(entry.get("node_name") or "")
    node = _resolve_remote_platform_node(node_name)
    return {
        "node": node,
        "topology": topology,
        "actions": build_platform_node_actions(cast(dict[str, Any], node.get("metadata") or {})),
    }


@app.post("/platform/nodes/{node_name}/acknowledge")
async def acknowledge_platform_node(
    node_name: str,
    payload: PlatformNodeAcknowledgeRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    updates: dict[str, Any] = {
        "acknowledged_at": datetime.now(UTC).isoformat(),
        "acknowledged_by": payload.acknowledged_by if payload and payload.acknowledged_by else "operator",
    }
    if payload and payload.note:
        updates["acknowledgement_note"] = payload.note
    try:
        update_platform_node_metadata(
            node_name,
            updates,
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/suppress")
async def suppress_platform_node_pressure(
    node_name: str,
    payload: PlatformNodeSuppressRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        suppress_platform_node(
            node_name,
            minutes=payload.minutes,
            suppressed_by=payload.suppressed_by or "operator",
            reason=payload.reason,
            scopes=payload.scopes,
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/clear-suppression")
async def clear_platform_node_pressure_suppression(
    node_name: str,
    payload: PlatformNodeSuppressRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        clear_platform_node_suppression(
            node_name,
            cleared_by="operator",
            scopes=payload.scopes if payload else None,
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/maintenance")
async def start_platform_node_maintenance_mode(
    node_name: str,
    payload: PlatformNodeMaintenanceRequest,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        start_platform_node_maintenance(
            node_name,
            minutes=payload.minutes,
            maintenance_by=payload.started_by or "operator",
            reason=payload.reason,
            services=payload.services,
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/refresh")
async def request_platform_node_refresh_endpoint(
    node_name: str,
    payload: PlatformNodeRefreshRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        request_platform_node_refresh(
            node_name,
            requested_by=payload.requested_by if payload and payload.requested_by else "operator",
            reason=payload.reason if payload else None,
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/drain")
async def start_platform_node_drain_endpoint(
    node_name: str,
    payload: PlatformNodeDrainRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        start_platform_node_drain(
            node_name,
            drained_by=payload.drained_by if payload and payload.drained_by else "operator",
            reason=payload.reason if payload else None,
            services=payload.services if payload else None,
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/actions/{action}/acknowledge")
async def acknowledge_platform_node_action_endpoint(
    node_name: str,
    action: str,
    payload: PlatformNodeActionUpdateRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        acknowledge_platform_node_action(
            node_name,
            action=action,
            acted_by=payload.acted_by if payload and payload.acted_by else "operator",
            note=payload.note if payload else None,
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/actions/{action}/complete")
async def complete_platform_node_action_endpoint(
    node_name: str,
    action: str,
    payload: PlatformNodeActionUpdateRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        complete_platform_node_action(
            node_name,
            action=action,
            acted_by=payload.acted_by if payload and payload.acted_by else "operator",
            result=payload.result if payload else None,
            note=payload.note if payload else None,
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/actions/{action}/retry")
async def retry_platform_node_action_endpoint(
    node_name: str,
    action: str,
    payload: PlatformNodeActionUpdateRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        retry_platform_node_action(
            node_name,
            action=action,
            requested_by=payload.acted_by if payload and payload.acted_by else "operator",
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/actions/{action}/cancel")
async def cancel_platform_node_action_endpoint(
    node_name: str,
    action: str,
    payload: PlatformNodeActionUpdateRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        cancel_platform_node_action(
            node_name,
            action=action,
            cancelled_by=payload.acted_by if payload and payload.acted_by else "operator",
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/ready")
async def clear_platform_node_drain_endpoint(
    node_name: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        clear_platform_node_drain(
            node_name,
            cleared_by="operator",
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/clear-maintenance")
async def clear_platform_node_maintenance_mode(
    node_name: str,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        clear_platform_node_maintenance(
            node_name,
            cleared_by="operator",
            path=settings.platform_node_registry_path,
        )
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"node": node}


@app.post("/platform/nodes/{node_name}/case")
async def create_case_from_platform_node(
    node_name: str,
    payload: SocRemoteNodeCaseRequest | None = None,
    _: None = Depends(require_operator_access),
) -> dict:
    try:
        node = _resolve_remote_platform_node(node_name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    case = soc_manager.create_case_from_remote_node(node, payload)
    return case.model_dump(mode="json")


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
