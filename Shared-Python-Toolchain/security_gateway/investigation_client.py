from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlparse

import httpx

from .config import settings
from .models import (
    SocEndpointLineageClusterCaseRequest,
    SocEndpointQueryCaseRequest,
    SocEndpointTimelineCaseRequest,
    SocSeverity,
    SocTelemetryClusterCaseRequest,
)
from .soc_dashboard import RemoteSocDashboardConnector


def _is_local_manager_url(url: str) -> bool:
    parsed = urlparse(url)
    hostname = parsed.hostname or (url.split("/", 1)[0].split(":", 1)[0] if "://" not in url else "")
    normalized = str(hostname or "").strip().strip("[]").casefold()
    return normalized in {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True)
class RemoteSocInvestigationClient:
    connector: RemoteSocDashboardConnector

    @classmethod
    def connect(
        cls,
        *,
        base_url: str,
        bearer_token: str | None = None,
        timeout_seconds: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> "RemoteSocInvestigationClient":
        return cls(
            connector=RemoteSocDashboardConnector(
                base_url=base_url,
                bearer_token=bearer_token,
                timeout_seconds=timeout_seconds,
                transport=transport,
            )
        )

    @classmethod
    def from_settings(
        cls,
        *,
        manager_url: str | None = None,
        bearer_token: str | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> "RemoteSocInvestigationClient":
        resolved_url = str(manager_url or settings.platform_manager_url or "").strip()
        if not resolved_url:
            raise ValueError("No platform manager URL is configured.")
        resolved_token = bearer_token if bearer_token is not None else settings.platform_manager_bearer_token
        if not _is_local_manager_url(resolved_url) and not resolved_token:
            raise ValueError("Platform manager bearer token is required for non-local remote manager access.")
        resolved_timeout = (
            float(timeout_seconds)
            if timeout_seconds is not None
            else float(settings.platform_manager_timeout_seconds or 10.0)
        )
        return cls.connect(
            base_url=resolved_url,
            bearer_token=resolved_token,
            timeout_seconds=resolved_timeout,
            transport=transport,
        )

    def dashboard(self) -> dict[str, object]:
        return self.connector.read_dashboard()

    def dashboard_state(self) -> dict[str, object]:
        return self.connector.read_dashboard_state()

    def toolchain_updates_status(self) -> dict[str, object]:
        return self.connector.read_toolchain_updates_status()

    def toolchain_runtime_status(self) -> dict[str, object]:
        return self.connector.read_toolchain_runtime_status()

    def toolchain_doctor(self) -> dict[str, object]:
        return self.connector.get_toolchain_doctor()

    def repair_toolchain_doctor(self, *, force_reinstall: bool = False) -> dict[str, object]:
        return self.connector.repair_toolchain_doctor(force_reinstall=force_reinstall)

    def list_toolchain_providers(self) -> list[dict[str, object]]:
        return self.connector.list_toolchain_providers()

    def get_toolchain_provider(self, provider_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_provider(provider_id)

    def list_toolchain_health(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_health(**filters)

    def get_toolchain_health(self, check_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_health(check_id)

    def list_toolchain_security(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_security(**filters)

    def get_toolchain_security(self, check_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_security(check_id)

    def list_toolchain_languages(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_languages(**filters)

    def get_toolchain_language(self, language_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_language(language_id)

    def list_toolchain_language_health(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_language_health(**filters)

    def get_toolchain_language_health(self, language_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_language_health(language_id)

    def list_toolchain_package_managers(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_package_managers(**filters)

    def get_toolchain_package_manager(self, manager_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_package_manager(manager_id)

    def list_toolchain_secret_sources(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_secret_sources(**filters)

    def get_toolchain_secret_source(self, secret_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_secret_source(secret_id)

    def list_toolchain_secret_resolutions(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_secret_resolutions(**filters)

    def get_toolchain_secret_resolution(self, secret_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_secret_resolution(secret_id)

    def resolve_toolchain_secret(self, secret_id: str) -> dict[str, object]:
        return self.connector.resolve_toolchain_secret(secret_id)

    def set_toolchain_secret(self, secret_id: str, value: str, *, persist: str = "auto") -> dict[str, object]:
        return self.connector.set_toolchain_secret(secret_id, value, persist=persist)

    def clear_toolchain_secret(self, secret_id: str) -> dict[str, object]:
        return self.connector.clear_toolchain_secret(secret_id)

    def list_toolchain_cache_entries(self, **filters: Any) -> dict[str, object]:
        return self.connector.list_toolchain_cache_entries(**filters)

    def get_toolchain_cache_entry(self, namespace: str, cache_key: str) -> dict[str, object]:
        return self.connector.get_toolchain_cache_entry(namespace, cache_key)

    def list_toolchain_projects(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_projects(**filters)

    def get_toolchain_project(self, project_id: str, **filters: Any) -> dict[str, object]:
        return self.connector.get_toolchain_project(project_id, **filters)

    def list_toolchain_provisioning(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_provisioning(**filters)

    def get_toolchain_provisioning(self, target_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_provisioning(target_id)

    def run_toolchain_bootstrap(self, target_id: str, **filters: Any) -> dict[str, object]:
        return self.connector.run_toolchain_bootstrap(target_id, **filters)

    def list_toolchain_package_operations(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_package_operations(**filters)

    def get_toolchain_package_operation(self, manager_id: str, operation: str) -> dict[str, object]:
        return self.connector.get_toolchain_package_operation(manager_id, operation)

    def run_toolchain_package_operation(self, manager_id: str, operation: str, **filters: Any) -> dict[str, object]:
        return self.connector.run_toolchain_package_operation(manager_id, operation, **filters)

    def list_toolchain_version_policy(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_version_policy(**filters)

    def get_toolchain_version_policy(self, target_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_version_policy(target_id)

    def list_toolchain_provider_templates(self) -> list[dict[str, object]]:
        return self.connector.list_toolchain_provider_templates()

    def get_toolchain_provider_template(self, provider_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_provider_template(provider_id)

    def render_toolchain_provider_template(self, provider_id: str) -> dict[str, object]:
        return self.connector.render_toolchain_provider_template(provider_id)

    def scaffold_toolchain_provider_template(self, provider_id: str, **filters: Any) -> dict[str, object]:
        return self.connector.scaffold_toolchain_provider_template(provider_id, **filters)

    def get_toolchain_report(self, *, format: str = "json") -> dict[str, object]:
        return self.connector.get_toolchain_report(format=format)

    def list_toolchain_jobs(self) -> list[dict[str, object]]:
        return self.connector.list_toolchain_jobs()

    def get_toolchain_job(self, job_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_job(job_id)

    def run_toolchain_job(self, job_id: str) -> dict[str, object]:
        return self.connector.run_toolchain_job(job_id)

    def list_toolchain_schedules(self) -> list[dict[str, object]]:
        return self.connector.list_toolchain_schedules()

    def get_toolchain_schedule(self, schedule_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_schedule(schedule_id)

    def upsert_toolchain_schedule(self, job_id: str, **filters: Any) -> dict[str, object]:
        return self.connector.upsert_toolchain_schedule(job_id, **filters)

    def delete_toolchain_schedule(self, schedule_id: str) -> dict[str, object]:
        return self.connector.delete_toolchain_schedule(schedule_id)

    def run_due_toolchain_schedules(self) -> dict[str, object]:
        return self.connector.run_due_toolchain_schedules()

    def get_toolchain_schedule_runtime(self) -> dict[str, object]:
        return self.connector.get_toolchain_schedule_runtime()

    def start_toolchain_schedule_runtime(self, *, poll_seconds: float = 60.0) -> dict[str, object]:
        return self.connector.start_toolchain_schedule_runtime(poll_seconds=poll_seconds)

    def stop_toolchain_schedule_runtime(self) -> dict[str, object]:
        return self.connector.stop_toolchain_schedule_runtime()

    def list_toolchain_policy_enforcement(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_policy_enforcement(**filters)

    def get_toolchain_policy_enforcement(self, policy_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_policy_enforcement(policy_id)

    def list_toolchain_policy_gates(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_toolchain_policy_gates(**filters)

    def get_toolchain_policy_gate(self, gate_id: str) -> dict[str, object]:
        return self.connector.get_toolchain_policy_gate(gate_id)

    def query_events(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.query_events(**filters)

    def hunt(self, **filters: Any) -> dict[str, object]:
        return self.connector.hunt(**filters)

    def list_alerts(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_alerts(**filters)

    def get_alert(self, alert_id: str) -> dict[str, object]:
        return self.connector.get_alert(alert_id)

    def update_alert(self, alert_id: str, payload: Any) -> dict[str, object]:
        return self.connector.update_alert(alert_id, payload)

    def list_cases(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_cases(**filters)

    def get_event(self, event_id: str) -> dict[str, object]:
        return self.connector.get_event(event_id)

    def list_cases_for_event(self, event_id: str) -> list[dict[str, object]]:
        return self.connector.list_cases_for_event(event_id)

    def open_event_case(self, event_id: str) -> dict[str, object]:
        return self.connector.open_event_case(event_id)

    def create_case_from_event(
        self,
        event_id: str,
        *,
        assignee: str | None = None,
        title: str | None = None,
        summary: str | None = None,
        severity: str | None = None,
    ) -> dict[str, object]:
        return self.connector.create_case_from_event(
            event_id,
            assignee=assignee,
            title=title,
            summary=summary,
            severity=severity,
        )

    def get_case(self, case_id: str) -> dict[str, object]:
        return self.connector.get_case(case_id)

    def list_case_linked_alerts(self, case_id: str) -> list[dict[str, object]]:
        return self.connector.list_alerts_for_case(case_id)

    def list_case_source_events(self, case_id: str) -> list[dict[str, object]]:
        return self.connector.list_events_for_case(case_id)

    def update_case(self, case_id: str, payload: Any) -> dict[str, object]:
        return self.connector.update_case(case_id, payload)

    def list_detection_rules(self) -> list[dict[str, object]]:
        return self.connector.list_detection_rules()

    def get_detection_rule(self, rule_id: str) -> dict[str, object]:
        return self.connector.get_detection_rule(rule_id)

    def update_detection_rule(self, rule_id: str, payload: Any) -> dict[str, object]:
        return self.connector.update_detection_rule(rule_id, payload)

    def list_detection_rule_alert_groups(self, rule_id: str) -> list[dict[str, object]]:
        return self.connector.list_detection_rule_alert_groups(rule_id)

    def get_detection_rule_alert_group(self, rule_id: str, group_key: str) -> dict[str, object]:
        return self.connector.get_detection_rule_alert_group(rule_id, group_key)

    def create_case_from_detection_rule_alert_group(self, rule_id: str, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_detection_rule_alert_group(rule_id, payload)

    def list_detection_rule_evidence_groups(self, rule_id: str) -> list[dict[str, object]]:
        return self.connector.list_detection_rule_evidence_groups(rule_id)

    def get_detection_rule_evidence_group(self, rule_id: str, group_key: str) -> dict[str, object]:
        return self.connector.get_detection_rule_evidence_group(rule_id, group_key)

    def create_case_from_detection_rule_evidence_group(self, rule_id: str, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_detection_rule_evidence_group(rule_id, payload)

    def list_case_rule_alert_groups(self, case_id: str) -> list[dict[str, object]]:
        return self.connector.list_case_rule_alert_groups(case_id)

    def get_case_rule_alert_group(self, case_id: str, group_key: str) -> dict[str, object]:
        return self.connector.get_case_rule_alert_group(case_id, group_key)

    def list_case_rule_alerts(self, case_id: str, group_key: str) -> list[dict[str, object]]:
        group = self.get_case_rule_alert_group(case_id, group_key)
        if isinstance(group.get("group"), dict):
            group = cast(dict[str, object], group["group"])
        return cast(list[dict[str, object]], group.get("alerts") or [])

    def create_case_from_case_rule_alert_group(self, case_id: str, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_case_rule_alert_group(case_id, payload)

    def list_case_rule_evidence_groups(self, case_id: str) -> list[dict[str, object]]:
        return self.connector.list_case_rule_evidence_groups(case_id)

    def get_case_rule_evidence_group(self, case_id: str, group_key: str) -> dict[str, object]:
        return self.connector.get_case_rule_evidence_group(case_id, group_key)

    def list_case_rule_evidence_events(self, case_id: str, group_key: str) -> list[dict[str, object]]:
        group = self.get_case_rule_evidence_group(case_id, group_key)
        if isinstance(group.get("group"), dict):
            group = cast(dict[str, object], group["group"])
        return cast(list[dict[str, object]], group.get("events") or [])

    def create_case_from_case_rule_evidence_group(self, case_id: str, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_case_rule_evidence_group(case_id, payload)

    def list_case_endpoint_timeline_clusters(self, case_id: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.list_case_endpoint_timeline_clusters(case_id, **filters))

    def get_case_endpoint_timeline_cluster(self, case_id: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.get_case_endpoint_timeline_cluster(case_id, **filters))

    def list_case_endpoint_timeline(self, case_id: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.list_case_endpoint_timeline(case_id, **filters))

    def create_case_from_case_endpoint_timeline_cluster(self, case_id: str, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_case_endpoint_timeline_cluster(case_id, payload)

    def list_case_endpoint_lineage_clusters(self, case_id: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.list_case_endpoint_lineage_clusters(case_id, **filters))

    def get_case_endpoint_lineage_cluster(self, case_id: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.get_case_endpoint_lineage_cluster(case_id, **filters))

    def list_case_endpoint_lineage_events(self, case_id: str, **filters: Any) -> list[dict[str, object]]:
        cluster = self.get_case_endpoint_lineage_cluster(case_id, **filters)
        if isinstance(cluster.get("cluster"), dict):
            cluster = cast(dict[str, object], cluster["cluster"])
        return cast(list[dict[str, object]], cluster.get("events") or [])

    def create_case_from_case_endpoint_lineage_cluster(self, case_id: str, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_case_endpoint_lineage_cluster(case_id, payload)

    def list_case_hunt_telemetry_clusters(self, case_id: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.list_case_hunt_telemetry_clusters(case_id, **filters))

    def get_case_hunt_telemetry_cluster(self, case_id: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.get_case_hunt_telemetry_cluster(case_id, **filters))

    def create_case_from_case_hunt_telemetry_cluster(self, case_id: str, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_case_hunt_telemetry_cluster(case_id, payload)

    def get_event_index_status(self) -> dict[str, object]:
        return self.connector.get_event_index_status()

    def rebuild_event_index(self) -> dict[str, object]:
        return self.connector.rebuild_event_index()

    def query_endpoint_telemetry(self, **filters: Any) -> dict[str, object]:
        return self.connector.query_endpoint_telemetry(**filters)

    def create_case_from_endpoint_query(self, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_endpoint_query(payload)

    def list_network_telemetry_flows(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_flows(**filters)

    def summarize_network_telemetry(self, **filters: Any) -> dict[str, object]:
        return self.connector.summarize_network_telemetry(**filters)

    def list_network_telemetry_dns(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_dns(**filters)

    def list_network_telemetry_http(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_http(**filters)

    def list_network_telemetry_tls(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_tls(**filters)

    def list_network_telemetry_certificates(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_certificates(**filters)

    def list_network_telemetry_proxy(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_proxy(**filters)

    def list_network_telemetry_auth(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_auth(**filters)

    def list_network_telemetry_vpn(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_vpn(**filters)

    def list_network_telemetry_dhcp(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_dhcp(**filters)

    def list_network_telemetry_directory_auth(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_directory_auth(**filters)

    def list_network_telemetry_radius(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_radius(**filters)

    def list_network_telemetry_nac(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_telemetry_nac(**filters)

    def list_packet_sessions(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_packet_sessions(**filters)

    def summarize_packet_telemetry(self, **filters: Any) -> dict[str, object]:
        return self.connector.summarize_packet_telemetry(**filters)

    def list_network_evidence(self, **filters: Any) -> list[dict[str, object]]:
        return self.connector.list_network_evidence(**filters)

    def list_identity_correlations(self, *, limit: int = 50, severity: str | None = None) -> list[dict[str, object]]:
        return self.connector.list_identity_correlations(limit=limit, severity=severity)

    def summarize_identity_correlations(self, *, limit: int = 50, severity: str | None = None) -> dict[str, object]:
        return self.connector.summarize_identity_correlations(limit=limit, severity=severity)

    def list_packet_capture_artifacts(self, **filters: Any) -> dict[str, object]:
        return self.connector.list_packet_capture_artifacts(**filters)

    def get_packet_capture_artifact(self, capture_id: str) -> dict[str, object]:
        return self.connector.get_packet_capture_artifact(capture_id)

    def get_packet_capture_text(self, capture_id: str) -> dict[str, object]:
        return self.connector.get_packet_capture_text(capture_id)

    def create_case_from_packet_capture(self, capture_id: str, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_packet_capture(capture_id, payload)

    def create_case_from_packet_session(self, session_payload: Any, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_packet_session(session_payload, payload)

    def create_case_from_network_evidence(self, evidence_payload: Any, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_network_evidence(evidence_payload, payload)

    def promote_alert_to_case(self, alert_id: str, payload: Any) -> dict[str, object]:
        return self.connector.promote_alert_to_case(alert_id, payload)

    def list_hunt_telemetry_clusters(self, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.list_hunt_telemetry_clusters(**filters))

    def get_hunt_telemetry_cluster(self, cluster_key: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.get_hunt_telemetry_cluster(cluster_key, **filters))

    def create_case_from_hunt_telemetry_cluster(self, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_hunt_telemetry_cluster(payload)

    def promote_hunt_telemetry_cluster(
        self,
        cluster_key: str,
        *,
        cluster_by: str = "remote_ip",
        assignee: str | None = None,
        **filters: Any,
    ) -> dict[str, object]:
        cluster = self.get_hunt_telemetry_cluster(cluster_key, cluster_by=cluster_by, **filters)
        request_payload = SocTelemetryClusterCaseRequest(
            cluster_by=str(cluster.get("cluster_by") or cluster_by),
            cluster_key=str(cluster.get("cluster_key") or cluster_key),
            device_id=next(iter(cast(list[str], cluster.get("device_ids") or [])), None),
            process_name=next(iter(cast(list[str], cluster.get("process_names") or [])), None),
            process_guid=next(iter(cast(list[str], cluster.get("process_guids") or [])), None),
            remote_ip=next(iter(cast(list[str], cluster.get("remote_ips") or [])), None),
            filename=next(iter(cast(list[str], cluster.get("filenames") or [])), None),
            session_key=next(iter(cast(list[str], cluster.get("session_keys") or [])), None),
            signer_name=next(iter(cast(list[str], cluster.get("signers") or [])), None),
            title=(
                f"Investigate {cluster.get('cluster_by', cluster_by)} cluster "
                f"{cluster.get('label', cluster.get('cluster_key', cluster_key))}"
            ),
            summary=(
                f"Investigate hunt telemetry cluster "
                f"{cluster.get('label', cluster.get('cluster_key', cluster_key))}. "
                f"Event count: {cluster.get('event_count', 0)}."
            ),
            severity=SocSeverity(str(cluster.get("severity") or SocSeverity.high.value)),
            assignee=assignee,
        )
        return self.create_case_from_hunt_telemetry_cluster(request_payload)

    def list_endpoint_timeline_clusters(self, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.list_endpoint_timeline_clusters(**filters))

    def get_endpoint_timeline_cluster(self, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.get_endpoint_timeline_cluster(**filters))

    def create_case_from_endpoint_timeline(self, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_endpoint_timeline(payload)

    def promote_endpoint_query_results(
        self,
        *,
        assignee: str | None = None,
        **filters: Any,
    ) -> dict[str, object]:
        request_payload = SocEndpointQueryCaseRequest(assignee=assignee, **filters)
        return self.create_case_from_endpoint_query(request_payload)

    def promote_endpoint_timeline_cluster(
        self,
        cluster_key: str,
        *,
        cluster_by: str = "process",
        assignee: str | None = None,
        **filters: Any,
    ) -> dict[str, object]:
        cluster = self.get_endpoint_timeline_cluster(cluster_key=cluster_key, cluster_by=cluster_by, **filters)
        event_count = int(cast(int | str, cluster.get("event_count") or 0))
        request_payload = SocEndpointTimelineCaseRequest(
            device_id=next(iter(cast(list[str], cluster.get("device_ids") or [])), None),
            process_name=next(iter(cast(list[str], cluster.get("process_names") or [])), None),
            process_guid=next(iter(cast(list[str], cluster.get("process_guids") or [])), None),
            remote_ip=next(iter(cast(list[str], cluster.get("remote_ips") or [])), None),
            title=(
                f"Investigate endpoint timeline "
                f"{cluster.get('label', cluster.get('cluster_key', cluster_key))}"
            ),
            summary=(
                f"Investigate endpoint timeline cluster "
                f"{cluster.get('label', cluster.get('cluster_key', cluster_key))}. "
                f"Event count: {cluster.get('event_count', 0)}."
            ),
            severity=SocSeverity.high,
            limit=max(event_count, 1),
            assignee=assignee,
        )
        return self.create_case_from_endpoint_timeline(request_payload)

    def list_endpoint_lineage_clusters(self, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.list_endpoint_lineage_clusters(**filters))

    def get_endpoint_lineage_cluster(self, cluster_key: str, **filters: Any) -> dict[str, object]:
        return cast(dict[str, object], self.connector.get_endpoint_lineage_cluster(cluster_key, **filters))

    def create_case_from_endpoint_lineage_cluster(self, payload: Any) -> dict[str, object]:
        return self.connector.create_case_from_endpoint_lineage_cluster(payload)

    def promote_endpoint_lineage_cluster(
        self,
        cluster_key: str,
        *,
        assignee: str | None = None,
        **filters: Any,
    ) -> dict[str, object]:
        cluster = self.get_endpoint_lineage_cluster(cluster_key, **filters)
        request_payload = SocEndpointLineageClusterCaseRequest(
            cluster_key=str(cluster.get("cluster_key") or cluster_key),
            device_id=next(iter(cast(list[str], cluster.get("device_ids") or [])), None),
            process_name=next(iter(cast(list[str], cluster.get("process_names") or [])), None),
            process_guid=next(iter(cast(list[str], cluster.get("process_guids") or [])), None),
            remote_ip=next(iter(cast(list[str], cluster.get("remote_ips") or [])), None),
            title=(
                f"Investigate endpoint lineage "
                f"{cluster.get('label', cluster.get('cluster_key', cluster_key))}"
            ),
            summary=(
                f"Investigate endpoint lineage cluster "
                f"{cluster.get('label', cluster.get('cluster_key', cluster_key))}. "
                f"Event count: {cluster.get('event_count', 0)}."
            ),
            severity=SocSeverity(str(cluster.get("severity") or SocSeverity.high.value)),
            assignee=assignee,
        )
        return self.create_case_from_endpoint_lineage_cluster(request_payload)
