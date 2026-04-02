"""Runtime entrypoint for the installed Security Gateway background monitor."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, cast

from .alerts import alert_manager
from .audit import AuditLogger
from .automation import AutomationSupervisor, run_forever
from .config import settings
from .endpoint import MalwareScanner
from .host_monitor import HostMonitor
from .ip_controls import IPBlocklistManager
from .network_monitor import NetworkMonitor
from .packet_monitor import PacketMonitor
from .pam import VaultClient
from .platform import (
    apply_local_platform_action,
    build_node_heartbeat_payload,
    build_platform_profile,
    normalize_platform_node_role,
    role_managed_service_enabled,
    send_platform_node_heartbeat,
    sync_local_platform_action_state,
    synchronize_platform_node_actions,
)
from .soc import SecurityOperationsManager
from .stream_monitor import StreamArtifactMonitor
from .tor import OutboundProxy
from .tracker_intel import TrackerIntel
from .models import SocEventIngest, SocSeverity


def _seed_offline_feeds(tracker_intel: TrackerIntel, scanner: MalwareScanner) -> None:
    if settings.tracker_offline_seed_path and not Path(settings.tracker_feed_cache_path).exists():
        tracker_intel.import_feed_cache(settings.tracker_offline_seed_path)
    if settings.malware_offline_hash_seed_path and not Path(settings.malware_feed_cache_path).exists():
        scanner.import_feed_cache(settings.malware_offline_hash_seed_path)
    if settings.malware_offline_rule_seed_path and not Path(settings.malware_rule_feed_cache_path).exists():
        scanner.import_rule_feed_cache(settings.malware_offline_rule_seed_path)


def build_runtime_supervisor() -> AutomationSupervisor:
    audit_logger = AuditLogger(settings.audit_log_path)
    vault = VaultClient(audit_logger=audit_logger)
    ip_blocklist = IPBlocklistManager(path=settings.ip_blocklist_path, audit_logger=audit_logger)
    proxy = OutboundProxy()
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
    soc_manager = SecurityOperationsManager(
        event_log_path=settings.soc_event_log_path,
        alert_store_path=settings.soc_alert_store_path,
        case_store_path=settings.soc_case_store_path,
        audit_logger=audit_logger,
        alert_manager=alert_manager,
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

    def _platform_node_heartbeat_enabled() -> bool:
        return (
            settings.platform_manager_heartbeat_enabled
            and bool(settings.platform_manager_url)
            and settings.platform_deployment_mode != "single-node"
            and normalize_platform_node_role() != "manager"
        )

    def _emit_platform_node_heartbeat() -> dict[str, object]:
        managed_services = [
            "tracker_feed_refresh",
            "malware_feed_refresh",
            "malware_rule_feed_refresh",
            "host_monitor",
            "network_monitor",
            "packet_monitor",
            "stream_monitor",
        ]
        payload = build_node_heartbeat_payload(
            build_platform_profile(
                automation_status=supervisor.status(),
                tracker_health=tracker_intel.health_status(),
                malware_health=scanner.health_status(),
            )
        )
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
        supervisor.apply_drained_services(set(cast(list[str], local_state.get("drained_services") or [])))
        return {
            "result": "success",
            "manager_url": str(settings.platform_manager_url),
            "node_name": payload["node_name"],
            "topology": response.get("topology"),
            "actions": action_sync,
            "local_action_state": local_state,
        }

    def _record_host_finding(finding: dict[str, object]) -> None:
        raw_tags = finding.get("tags")
        tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
        severity_name = "low" if bool(finding.get("resolved")) else str(finding.get("severity", "medium"))
        soc_manager.ingest_event(
            SocEventIngest(
                event_type="host.monitor.recovered" if bool(finding.get("resolved")) else "host.monitor.finding",
                source="security_gateway",
                severity=SocSeverity(severity_name),
                title=str(finding.get("title", "Host monitor finding")),
                summary=str(finding.get("summary", "")),
                details={
                    "key": finding.get("key"),
                    "resolved": bool(finding.get("resolved")),
                    "details": finding.get("details", {}),
                },
                tags=tags,
            )
        )

    def _record_network_finding(finding: dict[str, object]) -> None:
        raw_tags = finding.get("tags")
        tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
        severity_name = "low" if bool(finding.get("resolved")) else str(finding.get("severity", "medium"))
        soc_manager.ingest_event(
            SocEventIngest(
                event_type="network.monitor.recovered" if bool(finding.get("resolved")) else "network.monitor.finding",
                source="security_gateway",
                severity=SocSeverity(severity_name),
                title=str(finding.get("title", "Suspicious remote IP activity")),
                summary=str(finding.get("summary", "")),
                details={
                    "key": finding.get("key"),
                    "resolved": bool(finding.get("resolved")),
                    "details": finding.get("details", {}),
                },
                tags=tags,
            )
        )

    def _record_packet_finding(finding: dict[str, object]) -> None:
        raw_tags = finding.get("tags")
        tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
        severity_name = "low" if bool(finding.get("resolved")) else str(finding.get("severity", "medium"))
        soc_manager.ingest_event(
            SocEventIngest(
                event_type="packet.monitor.recovered" if bool(finding.get("resolved")) else "packet.monitor.finding",
                source="security_gateway",
                severity=SocSeverity(severity_name),
                title=str(finding.get("title", "Packet monitor finding")),
                summary=str(finding.get("summary", "")),
                details={
                    "key": finding.get("key"),
                    "resolved": bool(finding.get("resolved")),
                    "details": finding.get("details", {}),
                },
                tags=tags,
            )
        )

    def _record_stream_finding(finding: dict[str, object]) -> None:
        raw_tags = finding.get("tags")
        tags = [str(item) for item in raw_tags] if isinstance(raw_tags, list) else []
        severity_name = "low" if bool(finding.get("resolved")) else str(finding.get("severity", "medium"))
        raw_details = finding.get("details")
        details = raw_details if isinstance(raw_details, dict) else {}
        artifact_path = details.get("artifact_path")
        soc_manager.ingest_event(
            SocEventIngest(
                event_type="stream.monitor.recovered" if bool(finding.get("resolved")) else "stream.monitor.finding",
                source="security_gateway",
                severity=SocSeverity(severity_name),
                title=str(finding.get("title", "Stream monitor finding")),
                summary=str(finding.get("summary", "")),
                details={
                    "key": finding.get("key"),
                    "resolved": bool(finding.get("resolved")),
                    "details": details,
                },
                artifacts=[str(artifact_path)] if artifact_path else [],
                tags=tags,
            )
        )

    _seed_offline_feeds(tracker_intel, scanner)
    supervisor = AutomationSupervisor(
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
        host_monitor_callback=_record_host_finding,
        network_monitor=network_monitor,
        network_monitor_enabled=role_managed_service_enabled(
            "network_monitor",
            configured=settings.network_monitor_enabled,
        ),
        network_monitor_every_ticks=settings.network_monitor_every_ticks,
        network_monitor_callback=_record_network_finding,
        packet_monitor=packet_monitor,
        packet_monitor_enabled=role_managed_service_enabled(
            "packet_monitor",
            configured=settings.packet_monitor_enabled,
        ),
        packet_monitor_every_ticks=settings.packet_monitor_every_ticks,
        packet_monitor_callback=_record_packet_finding,
        stream_monitor=stream_monitor,
        stream_monitor_enabled=role_managed_service_enabled(
            "stream_monitor",
            configured=settings.stream_monitor_enabled,
        ),
        stream_monitor_every_ticks=settings.stream_monitor_every_ticks,
        stream_monitor_callback=_record_stream_finding,
        node_heartbeat_enabled=_platform_node_heartbeat_enabled(),
        node_heartbeat_every_ticks=settings.platform_manager_heartbeat_every_ticks,
        node_heartbeat_callback=_emit_platform_node_heartbeat,
        operational_callback=lambda: soc_manager.emit_operational_notifications(
            state_path=settings.soc_notification_state_path
        ),
    )
    return supervisor


def run_background_monitor() -> None:
    run_forever(build_runtime_supervisor())
