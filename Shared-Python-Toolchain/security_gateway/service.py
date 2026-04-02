"""FastAPI service exposing the security gateway."""
from __future__ import annotations

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
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocCaseCreate,
    SocEndpointTimelineCaseRequest,
    SocCaseStatus,
    SocCaseUpdate,
    SocEventIngest,
    SocEventRecord,
    SocNetworkEvidenceCaseRequest,
    SocPacketSessionCaseRequest,
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
                "state_counts": item.get("state_counts") or {},
                "hit_count": item.get("hit_count") or 0,
                "sensitive_ports": item.get("sensitive_ports") or [],
                "sample_connections": item.get("sample_connections") or [],
                "snapshot_at": checked_at,
                "details": item,
            },
            tags=["network", "telemetry", "connection"],
        )


def _record_packet_monitor_snapshot(snapshot: dict[str, object]) -> None:
    checked_at = str(snapshot.get("checked_at") or "")
    capture_status = str(snapshot.get("capture_status") or "")
    evidence_mode = str(snapshot.get("evidence_mode") or "")
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
        tags = ["packet", "telemetry", "session"]
        if evidence_mode:
            tags.append(evidence_mode)
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
                "protocols": item.get("protocols") or [],
                "local_ips": item.get("local_ips") or [],
                "local_ports": item.get("local_ports") or [],
                "remote_ports": item.get("remote_ports") or [],
                "packet_count": item.get("packet_count") or 0,
                "sensitive_ports": item.get("sensitive_ports") or [],
                "sample_packet_endpoints": item.get("sample_packet_endpoints") or [],
                "capture_status": capture_status,
                "evidence_mode": evidence_mode,
                "snapshot_at": checked_at,
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


@app.get("/network/blocked-ips")
async def list_blocked_ips(_: None = Depends(require_operator_access)) -> dict:
    return {"blocked_ips": [entry.__dict__ for entry in ip_blocklist.list_entries()]}


@app.get("/network/packet-sessions")
async def list_packet_sessions(
    remote_ip: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    _: None = Depends(require_operator_access),
) -> dict:
    return {"sessions": packet_monitor.list_recent_sessions(limit=limit, remote_ip=remote_ip)}


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


@app.get("/network/telemetry/summary")
async def summarize_network_telemetry(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    facet_limit: int = Query(default=5, ge=1, le=20),
    limit: int = Query(default=250, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.summarize_network_telemetry(
        remote_ip=remote_ip,
        start_at=start_at,
        end_at=end_at,
        facet_limit=facet_limit,
        limit=limit,
    )


@app.get("/packet/telemetry/sessions")
async def list_packet_telemetry_sessions(
    remote_ip: str | None = None,
    session_key: str | None = None,
    limit: int = Query(default=100, ge=1, le=250),
    _: None = Depends(require_operator_access),
) -> dict:
    events = soc_manager.query_events(
        event_type="packet.telemetry.session",
        remote_ip=remote_ip,
        session_key=session_key,
        limit=limit,
    )
    return {
        "sessions": [event.model_dump(mode="json") for event in events],
        "retention_hours": settings.soc_packet_telemetry_retention_hours,
    }


@app.get("/packet/telemetry/summary")
async def summarize_packet_telemetry(
    remote_ip: str | None = Query(default=None, min_length=1, max_length=128),
    session_key: str | None = Query(default=None, min_length=1, max_length=256),
    start_at: datetime | None = Query(default=None),
    end_at: datetime | None = Query(default=None),
    facet_limit: int = Query(default=5, ge=1, le=20),
    limit: int = Query(default=250, ge=1, le=500),
    _: None = Depends(require_operator_access),
) -> dict:
    return soc_manager.summarize_packet_telemetry(
        remote_ip=remote_ip,
        session_key=session_key,
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
    return {"observations": network_monitor.list_recent_observations(limit=limit, remote_ip=remote_ip)}


@app.get("/network/evidence")
async def list_network_evidence(
    remote_ip: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    _: None = Depends(require_operator_access),
) -> dict:
    packet_sessions = packet_monitor.list_recent_sessions(limit=200, remote_ip=remote_ip)
    network_observations = network_monitor.list_recent_observations(limit=200, remote_ip=remote_ip)
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
        evidence_payload: dict[str, object] = {
            "remote_ip": str(item.get("remote_ip") or ""),
            "observation": cast(dict[str, object] | None, item.get("network_observation")),
            "packet_session": packet_session_rows[0] if packet_session_rows else None,
        }
        source_events = soc_manager.resolve_network_evidence_events(evidence_payload)
        related_cases = soc_manager.resolve_network_evidence_cases(source_events)
        item["related_alert_ids"] = soc_manager.resolve_network_evidence_alert_ids(source_events)
        item["related_case_ids"] = [case.case_id for case in related_cases]
        item["open_case_ids"] = [case.case_id for case in related_cases if case.status is not SocCaseStatus.closed]
        item["open_case_count"] = len(cast(list[str], item["open_case_ids"]))
    evidence.sort(key=lambda item: str(item.get("last_seen_at") or ""), reverse=True)
    return {"evidence": evidence[:limit]}


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
        start_at=start_at,
        end_at=end_at,
        linked_alert_state=linked_alert_state,
        sort=sort,
    )
    return {"events": [event.model_dump(mode="json") for event in events]}


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
