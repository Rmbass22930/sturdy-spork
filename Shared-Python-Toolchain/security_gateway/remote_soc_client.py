"""HTTP-backed SOC and monitor clients for remote dashboard use."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, cast

import httpx

from .models import (
    PlatformNodeAcknowledgeRequest,
    PlatformNodeActionUpdateRequest,
    PlatformNodeDrainRequest,
    SocCaseTelemetryClusterCaseRequest,
    SocCaseEndpointLineageClusterCaseRequest,
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocEndpointLineageClusterCaseRequest,
    SocEndpointQueryCaseRequest,
    SocEndpointTimelineCaseRequest,
    PlatformNodeMaintenanceRequest,
    PlatformNodeRefreshRequest,
    PlatformNodeSuppressRequest,
    SocAlertPromoteCaseRequest,
    SocAlertRecord,
    SocAlertStatus,
    SocAlertUpdate,
    SocCaseCreate,
    SocCaseRecord,
    SocCaseStatus,
    SocCaseUpdate,
    SocDetectionRuleRecord,
    SocDetectionRuleUpdate,
    SocEventRecord,
    SocNetworkEvidenceCaseRequest,
    SocNetworkSensorTelemetryIngest,
    SocPacketCaptureCaseRequest,
    SocPacketSessionCaseRequest,
    SocRemoteNodeCaseRequest,
    SocTelemetryClusterCaseRequest,
    SocSeverity,
)


class _RemoteApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str | None = None,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._bearer_token = bearer_token
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        if not self._bearer_token:
            return {}
        return {"Authorization": f"Bearer {self._bearer_token}"}

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_body: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
            response = client.request(
                method,
                f"{self._base_url}{path}",
                headers=self._headers(),
                params=params,
                json=json_body,
            )
            response.raise_for_status()
            return cast(dict[str, Any], response.json())

    @staticmethod
    def _query_datetime(value: datetime | str | None) -> str | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.isoformat()
        return value


class RemoteSecurityOperationsClient(_RemoteApiClient):
    def dashboard(self) -> dict[str, Any]:
        payload = self._request("GET", "/soc/dashboard")
        payload["view_state"] = cast(dict[str, Any], payload.get("view_state") or {})
        payload["summary_labels"] = cast(dict[str, Any], payload.get("summary_labels") or {})
        return payload

    def get_toolchain_doctor(self) -> dict[str, Any]:
        return self._request("GET", "/toolchain/doctor")

    def repair_toolchain_doctor(self, *, force_reinstall: bool = False) -> dict[str, Any]:
        return self._request(
            "POST",
            "/toolchain/doctor/repair",
            params={"force_reinstall": str(force_reinstall).lower()},
        )

    def list_toolchain_providers(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/providers")
        return cast(list[dict[str, Any]], payload.get("providers") or [])

    def get_toolchain_provider(self, provider_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/providers/{provider_id}")
        return cast(dict[str, Any], payload.get("provider") or {})

    def list_toolchain_health(self, *, status: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/health", params={"status": status})
        return cast(list[dict[str, Any]], payload.get("checks") or [])

    def get_toolchain_health(self, check_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/health/{check_id}")
        return cast(dict[str, Any], payload.get("check") or {})

    def list_toolchain_security(self, *, status: str | None = None, severity: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/security", params={"status": status, "severity": severity})
        return cast(list[dict[str, Any]], payload.get("checks") or [])

    def get_toolchain_security(self, check_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/security/{check_id}")
        return cast(dict[str, Any], payload.get("check") or {})

    def list_toolchain_languages(self, *, status: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/languages", params={"status": status})
        return cast(list[dict[str, Any]], payload.get("languages") or [])

    def get_toolchain_language(self, language_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/languages/{language_id}")
        return cast(dict[str, Any], payload.get("language") or {})

    def list_toolchain_language_health(self, *, status: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/languages/health", params={"status": status})
        return cast(list[dict[str, Any]], payload.get("checks") or [])

    def get_toolchain_language_health(self, language_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/languages/health/{language_id}")
        return cast(dict[str, Any], payload.get("check") or {})

    def list_toolchain_package_managers(self, *, status: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/package-managers", params={"status": status})
        return cast(list[dict[str, Any]], payload.get("package_managers") or [])

    def get_toolchain_package_manager(self, manager_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/package-managers/{manager_id}")
        return cast(dict[str, Any], payload.get("package_manager") or {})

    def list_toolchain_secret_sources(self, *, status: str | None = None, source: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/secret-sources", params={"status": status, "source": source})
        return cast(list[dict[str, Any]], payload.get("secret_sources") or [])

    def get_toolchain_secret_source(self, secret_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/secret-sources/{secret_id}")
        return cast(dict[str, Any], payload.get("secret_source") or {})

    def list_toolchain_secret_resolutions(self, *, status: str | None = None, source: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/secret-resolution", params={"status": status, "source": source})
        return cast(list[dict[str, Any]], payload.get("resolutions") or [])

    def get_toolchain_secret_resolution(self, secret_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/secret-resolution/{secret_id}")
        return cast(dict[str, Any], payload.get("resolution") or {})

    def resolve_toolchain_secret(self, secret_id: str) -> dict[str, Any]:
        payload = self._request("POST", f"/toolchain/secret-resolution/{secret_id}/resolve")
        return cast(dict[str, Any], payload.get("resolution") or {})

    def set_toolchain_secret(self, secret_id: str, value: str, *, persist: str = "auto") -> dict[str, Any]:
        payload = self._request(
            "POST",
            f"/toolchain/secret-resolution/{secret_id}/set",
            params={"persist": persist},
            json_body={"value": value},
        )
        return cast(dict[str, Any], payload.get("result") or {})

    def clear_toolchain_secret(self, secret_id: str) -> dict[str, Any]:
        payload = self._request("POST", f"/toolchain/secret-resolution/{secret_id}/clear")
        return cast(dict[str, Any], payload.get("result") or {})

    def list_toolchain_cache_entries(self, *, namespace: str | None = None, status: str | None = None) -> dict[str, Any]:
        return self._request("GET", "/toolchain/cache", params={"namespace": namespace, "status": status})

    def get_toolchain_cache_entry(self, namespace: str, cache_key: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/cache/{namespace}/{cache_key}")
        return cast(dict[str, Any], payload.get("entry") or {})

    def list_toolchain_projects(self, *, root_path: str = ".") -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/projects", params={"root_path": root_path})
        return cast(list[dict[str, Any]], payload.get("projects") or [])

    def get_toolchain_project(self, project_id: str, *, root_path: str = ".") -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/projects/{project_id}", params={"root_path": root_path})
        return cast(dict[str, Any], payload.get("project") or {})

    def list_toolchain_provisioning(self, *, status: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/provisioning", params={"status": status})
        return cast(list[dict[str, Any]], payload.get("actions") or [])

    def get_toolchain_provisioning(self, target_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/provisioning/{target_id}")
        return cast(dict[str, Any], payload.get("action") or {})

    def run_toolchain_bootstrap(
        self,
        target_id: str,
        *,
        mode: str = "install",
        project_path: str = ".",
        execute: bool = False,
        verify_after: bool = True,
        timeout_seconds: float = 300.0,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/toolchain/bootstrap/{target_id}",
            params={
                "project_path": project_path,
                "mode": mode,
                "execute": execute,
                "verify_after": verify_after,
                "timeout_seconds": timeout_seconds,
            },
        )

    def list_toolchain_package_operations(self, *, manager: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/package-operations", params={"manager": manager})
        return cast(list[dict[str, Any]], payload.get("operations") or [])

    def get_toolchain_package_operation(self, manager_id: str, operation: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/package-operations/{manager_id}/{operation}")
        return cast(dict[str, Any], payload.get("operation") or {})

    def run_toolchain_package_operation(
        self,
        manager_id: str,
        operation: str,
        *,
        project_path: str = ".",
        execute: bool = False,
        timeout_seconds: float = 60.0,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/toolchain/package-operations/{manager_id}/{operation}/run",
            params={"project_path": project_path, "execute": execute, "timeout_seconds": timeout_seconds},
        )

    def list_toolchain_version_policy(self, *, status: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/version-policy", params={"status": status})
        return cast(list[dict[str, Any]], payload.get("results") or [])

    def get_toolchain_version_policy(self, target_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/version-policy/{target_id}")
        return cast(dict[str, Any], payload.get("result") or {})

    def list_toolchain_provider_templates(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/provider-templates")
        return cast(list[dict[str, Any]], payload.get("templates") or [])

    def get_toolchain_provider_template(self, provider_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/provider-templates/{provider_id}")
        return cast(dict[str, Any], payload.get("template") or {})

    def render_toolchain_provider_template(self, provider_id: str) -> dict[str, Any]:
        return self._request("GET", f"/toolchain/provider-templates/{provider_id}/render")

    def scaffold_toolchain_provider_template(
        self,
        provider_id: str,
        *,
        target_dir: str = ".",
        write: bool = False,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/toolchain/provider-templates/{provider_id}/scaffold",
            params={"target_dir": target_dir, "write": write},
        )

    def get_toolchain_report(self, *, format: str = "json") -> dict[str, Any]:
        return self._request("GET", "/toolchain/report", params={"format": format})

    def list_toolchain_jobs(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/jobs")
        return cast(list[dict[str, Any]], payload.get("jobs") or [])

    def get_toolchain_job(self, job_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/jobs/{job_id}")
        return cast(dict[str, Any], payload.get("job") or {})

    def run_toolchain_job(self, job_id: str) -> dict[str, Any]:
        return self._request("POST", f"/toolchain/jobs/{job_id}/run")

    def list_toolchain_schedules(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/schedules")
        return cast(list[dict[str, Any]], payload.get("schedules") or [])

    def get_toolchain_schedule(self, schedule_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/schedules/{schedule_id}")
        return cast(dict[str, Any], payload.get("schedule") or {})

    def upsert_toolchain_schedule(
        self,
        job_id: str,
        *,
        every_minutes: int,
        enabled: bool = True,
    ) -> dict[str, Any]:
        payload = self._request(
            "POST",
            f"/toolchain/schedules/{job_id}",
            params={"every_minutes": every_minutes, "enabled": enabled},
        )
        return cast(dict[str, Any], payload.get("schedule") or {})

    def delete_toolchain_schedule(self, schedule_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/toolchain/schedules/{schedule_id}")

    def run_due_toolchain_schedules(self) -> dict[str, Any]:
        return self._request("POST", "/toolchain/schedules/run-due")

    def get_toolchain_schedule_runtime(self) -> dict[str, Any]:
        payload = self._request("GET", "/toolchain/schedules/runtime")
        return cast(dict[str, Any], payload.get("runtime") or {})

    def start_toolchain_schedule_runtime(self, *, poll_seconds: float = 60.0) -> dict[str, Any]:
        payload = self._request("POST", "/toolchain/schedules/runtime/start", params={"poll_seconds": poll_seconds})
        return cast(dict[str, Any], payload.get("runtime") or {})

    def stop_toolchain_schedule_runtime(self) -> dict[str, Any]:
        payload = self._request("POST", "/toolchain/schedules/runtime/stop")
        return cast(dict[str, Any], payload.get("runtime") or {})

    def list_toolchain_policy_enforcement(self, *, status: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/policy-enforcement", params={"status": status})
        return cast(list[dict[str, Any]], payload.get("results") or [])

    def get_toolchain_policy_enforcement(self, policy_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/policy-enforcement/{policy_id}")
        return cast(dict[str, Any], payload.get("result") or {})

    def list_toolchain_policy_gates(self, *, status: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/toolchain/policy-gates", params={"status": status})
        return cast(list[dict[str, Any]], payload.get("gates") or [])

    def get_toolchain_policy_gate(self, gate_id: str) -> dict[str, Any]:
        payload = self._request("GET", f"/toolchain/policy-gates/{gate_id}")
        return cast(dict[str, Any], payload.get("gate") or {})

    def list_events(
        self,
        *,
        limit: int = 50,
        severity: SocSeverity | None = None,
        event_type: str | None = None,
    ) -> list[SocEventRecord]:
        return self.query_events(limit=limit, severity=severity, event_type=event_type)

    def query_events(
        self,
        *,
        severity: SocSeverity | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
        linked_alert_state: str | None = None,
        sort: str = "created_desc",
        limit: int = 100,
    ) -> list[SocEventRecord]:
        payload = self._request(
            "GET",
            "/soc/events",
            params={
                "limit": limit,
                "severity": severity.value if severity is not None else None,
                "event_type": event_type,
                "source": source,
                "tag": tag,
                "text": text,
                "remote_ip": remote_ip,
                "hostname": hostname,
                "filename": filename,
                "artifact_path": artifact_path,
                "session_key": session_key,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "signer_name": signer_name,
                "sha256": sha256,
                "flow_id": flow_id,
                "service_name": service_name,
                "application_protocol": application_protocol,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
                "state": state,
                "close_reason": close_reason,
                "reject_code": reject_code,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
                "linked_alert_state": linked_alert_state,
                "sort": sort,
            },
        )
        return [SocEventRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("events") or [])]

    def get_event_index_status(self) -> dict[str, Any]:
        return self._request("GET", "/soc/events/index")

    def rebuild_event_index(self) -> dict[str, Any]:
        return self._request("POST", "/soc/events/index/rebuild")

    def get_event(self, event_id: str) -> SocEventRecord:
        return SocEventRecord.model_validate(self._request("GET", f"/soc/events/{event_id}"))

    def hunt(
        self,
        *,
        query: str | None = None,
        severity: SocSeverity | None = None,
        tag: str | None = None,
        source: str | None = None,
        event_type: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
        facet_limit: int = 5,
        limit: int = 50,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/soc/hunt",
            params={
                "q": query,
                "severity": severity.value if severity is not None else None,
                "tag": tag,
                "source": source,
                "event_type": event_type,
                "remote_ip": remote_ip,
                "hostname": hostname,
                "filename": filename,
                "artifact_path": artifact_path,
                "session_key": session_key,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "signer_name": signer_name,
                "sha256": sha256,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
                "state": state,
                "close_reason": close_reason,
                "reject_code": reject_code,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
                "facet_limit": facet_limit,
                "limit": limit,
            },
        )

    def list_hunt_telemetry_clusters(
        self,
        *,
        cluster_by: str = "remote_ip",
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/soc/hunt/telemetry/clusters",
            params={
                "cluster_by": cluster_by,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
                "filename": filename,
                "artifact_path": artifact_path,
                "session_key": session_key,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
                "limit": limit,
            },
        )
        return cast(list[dict[str, Any]], payload.get("clusters") or [])

    def get_hunt_telemetry_cluster(
        self,
        cluster_key: str,
        *,
        cluster_by: str = "remote_ip",
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
        limit: int = 500,
    ) -> dict[str, Any]:
        payload = self._request(
            "GET",
            f"/soc/hunt/telemetry/clusters/{cluster_key}",
            params={
                "cluster_by": cluster_by,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
                "filename": filename,
                "artifact_path": artifact_path,
                "session_key": session_key,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
                "limit": limit,
            },
        )
        return cast(dict[str, Any], payload.get("cluster") or {})

    def create_case_from_hunt_telemetry_cluster(
        self,
        payload: SocTelemetryClusterCaseRequest,
    ) -> SocCaseRecord:
        result = self._request(
            "POST",
            "/soc/hunt/telemetry/clusters/case",
            json_body=payload.model_dump(mode="json"),
        )
        return SocCaseRecord.model_validate(result)

    def list_endpoint_process_telemetry(
        self,
        *,
        limit: int = 100,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> list[SocEventRecord]:
        payload = self._request(
            "GET",
            "/endpoint/telemetry/processes",
            params={
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )
        return [SocEventRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("processes") or [])]

    def query_endpoint_telemetry(
        self,
        *,
        limit: int = 200,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        document_type: str | None = None,
        parent_process_name: str | None = None,
        reputation: str | None = None,
        risk_flag: str | None = None,
        verdict: str | None = None,
        operation: str | None = None,
        file_extension: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/endpoint/telemetry/query",
            params={
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
                "filename": filename,
                "artifact_path": artifact_path,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
                "state": state,
                "document_type": document_type,
                "parent_process_name": parent_process_name,
                "reputation": reputation,
                "risk_flag": risk_flag,
                "verdict": verdict,
                "operation": operation,
                "file_extension": file_extension,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
            },
        )

    def summarize_endpoint_telemetry(
        self,
        *,
        limit: int = 250,
        facet_limit: int = 5,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/endpoint/telemetry/summary",
            params={
                "limit": limit,
                "facet_limit": facet_limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
                "filename": filename,
                "artifact_path": artifact_path,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
            },
        )

    def summarize_endpoint_lineage(
        self,
        *,
        limit: int = 250,
        facet_limit: int = 5,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/endpoint/telemetry/lineage/summary",
            params={
                "limit": limit,
                "facet_limit": facet_limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
            },
        )

    def list_endpoint_file_telemetry(
        self,
        *,
        limit: int = 100,
        device_id: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> list[SocEventRecord]:
        payload = self._request(
            "GET",
            "/endpoint/telemetry/files",
            params={
                "limit": limit,
                "device_id": device_id,
                "filename": filename,
                "artifact_path": artifact_path,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )
        return [SocEventRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("files") or [])]

    def list_endpoint_connection_telemetry(
        self,
        *,
        limit: int = 100,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> list[SocEventRecord]:
        payload = self._request(
            "GET",
            "/endpoint/telemetry/connections",
            params={
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )
        return [SocEventRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("connections") or [])]

    def list_endpoint_timeline(
        self,
        *,
        limit: int = 200,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/endpoint/telemetry/timeline",
            params={
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )

    def list_endpoint_timeline_clusters(
        self,
        *,
        cluster_by: str = "process",
        limit: int = 200,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/endpoint/telemetry/timeline/clusters",
            params={
                "cluster_by": cluster_by,
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )

    def get_endpoint_timeline_cluster(
        self,
        *,
        cluster_by: str = "process",
        cluster_key: str,
        limit: int = 500,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        payload = self._request(
            "GET",
            f"/endpoint/telemetry/timeline/clusters/{cluster_key}",
            params={
                "cluster_by": cluster_by,
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )
        return cast(dict[str, Any], payload.get("cluster") or {})

    def list_endpoint_lineage_clusters(
        self,
        *,
        limit: int = 200,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/endpoint/telemetry/lineage/clusters",
            params={
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )

    def get_endpoint_lineage_cluster(
        self,
        cluster_key: str,
        *,
        limit: int = 500,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        payload = self._request(
            "GET",
            f"/endpoint/telemetry/lineage/clusters/{cluster_key}",
            params={
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )
        return cast(dict[str, Any], payload.get("cluster") or {})

    def create_case_from_endpoint_lineage_cluster(
        self,
        payload: SocEndpointLineageClusterCaseRequest | None = None,
        **filters: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocEndpointLineageClusterCaseRequest(**filters)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                "/endpoint/telemetry/lineage/clusters/case",
                json_body=request_payload.model_dump(mode="json"),
            )
        )

    def create_case_from_endpoint_timeline(
        self,
        payload: SocEndpointTimelineCaseRequest | None = None,
        **filters: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocEndpointTimelineCaseRequest(**filters)
        return SocCaseRecord.model_validate(
            self._request("POST", "/endpoint/telemetry/timeline/case", json_body=request_payload.model_dump(mode="json"))
        )

    def create_case_from_endpoint_query(
        self,
        payload: SocEndpointQueryCaseRequest | None = None,
        **filters: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocEndpointQueryCaseRequest(**filters)
        return SocCaseRecord.model_validate(
            self._request("POST", "/endpoint/telemetry/query/case", json_body=request_payload.model_dump(mode="json"))
        )

    def list_case_rule_alert_groups(self, case_id: str) -> list[dict[str, Any]]:
        payload = self._request("GET", f"/soc/cases/{case_id}/rule-alert-groups")
        return cast(list[dict[str, Any]], payload.get("groups") or [])

    def get_case_rule_alert_group(self, case_id: str, group_key: str) -> dict[str, Any]:
        payload = self._request("GET", f"/soc/cases/{case_id}/rule-alert-groups/{group_key}")
        return cast(dict[str, Any], payload.get("group") or {})

    def create_case_from_case_rule_alert_group(
        self,
        case_id: str,
        payload: SocCaseRuleGroupCaseRequest | None = None,
        **request_kwargs: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocCaseRuleGroupCaseRequest(**request_kwargs)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                f"/soc/cases/{case_id}/rule-alert-groups/case",
                json_body=request_payload.model_dump(mode="json"),
            )
        )

    def list_case_rule_evidence_groups(self, case_id: str) -> list[dict[str, Any]]:
        payload = self._request("GET", f"/soc/cases/{case_id}/rule-evidence-groups")
        return cast(list[dict[str, Any]], payload.get("groups") or [])

    def get_case_rule_evidence_group(self, case_id: str, group_key: str) -> dict[str, Any]:
        payload = self._request("GET", f"/soc/cases/{case_id}/rule-evidence-groups/{group_key}")
        return cast(dict[str, Any], payload.get("group") or {})

    def create_case_from_case_rule_evidence_group(
        self,
        case_id: str,
        payload: SocCaseRuleGroupCaseRequest | None = None,
        **request_kwargs: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocCaseRuleGroupCaseRequest(**request_kwargs)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                f"/soc/cases/{case_id}/rule-evidence-groups/case",
                json_body=request_payload.model_dump(mode="json"),
            )
        )

    def list_case_endpoint_timeline_clusters(
        self,
        case_id: str,
        *,
        cluster_by: str = "process",
        limit: int = 200,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/soc/cases/{case_id}/endpoint-timeline/clusters",
            params={"cluster_by": cluster_by, "limit": limit},
        )

    def get_case_endpoint_timeline_cluster(
        self,
        case_id: str,
        *,
        cluster_by: str = "process",
        cluster_key: str,
        limit: int = 500,
    ) -> dict[str, Any]:
        payload = self._request(
            "GET",
            f"/soc/cases/{case_id}/endpoint-timeline/clusters/{cluster_key}",
            params={"cluster_by": cluster_by, "limit": limit},
        )
        return cast(dict[str, Any], payload.get("cluster") or {})

    def list_case_endpoint_timeline(
        self,
        case_id: str,
        *,
        limit: int = 200,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        remote_ip: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/soc/cases/{case_id}/endpoint-timeline",
            params={
                "limit": limit,
                "device_id": device_id,
                "process_name": process_name,
                "process_guid": process_guid,
                "remote_ip": remote_ip,
                "signer_name": signer_name,
                "sha256": sha256,
            },
        )

    def list_case_endpoint_lineage_clusters(
        self,
        case_id: str,
        *,
        limit: int = 200,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/soc/cases/{case_id}/endpoint-lineage/clusters",
            params={"limit": limit},
        )

    def get_case_endpoint_lineage_cluster(
        self,
        case_id: str,
        *,
        cluster_key: str,
        limit: int = 500,
    ) -> dict[str, Any]:
        payload = self._request(
            "GET",
            f"/soc/cases/{case_id}/endpoint-lineage/clusters/{cluster_key}",
            params={"limit": limit},
        )
        return cast(dict[str, Any], payload.get("cluster") or {})

    def list_case_hunt_telemetry_clusters(
        self,
        case_id: str,
        *,
        cluster_by: str = "remote_ip",
        limit: int = 200,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/soc/cases/{case_id}/hunt-telemetry/clusters",
            params={"cluster_by": cluster_by, "limit": limit},
        )

    def get_case_hunt_telemetry_cluster(
        self,
        case_id: str,
        *,
        cluster_by: str = "remote_ip",
        cluster_key: str,
        limit: int = 500,
    ) -> dict[str, Any]:
        payload = self._request(
            "GET",
            f"/soc/cases/{case_id}/hunt-telemetry/clusters/{cluster_key}",
            params={"cluster_by": cluster_by, "limit": limit},
        )
        return cast(dict[str, Any], payload.get("cluster") or {})

    def create_case_from_case_hunt_telemetry_cluster(
        self,
        case_id: str,
        payload: SocCaseTelemetryClusterCaseRequest | None = None,
        **request_kwargs: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocCaseTelemetryClusterCaseRequest(**request_kwargs)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                f"/soc/cases/{case_id}/hunt-telemetry/clusters/case",
                json_body=request_payload.model_dump(mode="json"),
            )
        )

    def create_case_from_case_endpoint_lineage_cluster(
        self,
        case_id: str,
        payload: SocCaseEndpointLineageClusterCaseRequest | None = None,
        **request_kwargs: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocCaseEndpointLineageClusterCaseRequest(**request_kwargs)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                f"/soc/cases/{case_id}/endpoint-lineage/clusters/case",
                json_body=request_payload.model_dump(mode="json"),
            )
        )

    def create_case_from_case_endpoint_timeline_cluster(
        self,
        case_id: str,
        payload: SocCaseEndpointTimelineClusterCaseRequest | None = None,
        **request_kwargs: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocCaseEndpointTimelineClusterCaseRequest(**request_kwargs)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                f"/soc/cases/{case_id}/endpoint-timeline/clusters/case",
                json_body=request_payload.model_dump(mode="json"),
            )
        )

    def list_alerts(self, *, status: SocAlertStatus | None = None) -> list[SocAlertRecord]:
        return self.query_alerts(status=status, limit=250)

    def query_alerts(
        self,
        *,
        status: SocAlertStatus | None = None,
        severity: SocSeverity | None = None,
        assignee: str | None = None,
        correlation_rule: str | None = None,
        linked_case_state: str | None = None,
        sort: str = "updated_desc",
        limit: int = 100,
    ) -> list[SocAlertRecord]:
        payload = self._request(
            "GET",
            "/soc/alerts",
            params={
                "status": status.value if status is not None else None,
                "severity": severity.value if severity is not None else None,
                "assignee": assignee,
                "correlation_rule": correlation_rule,
                "linked_case_state": linked_case_state,
                "sort": sort,
                "limit": limit,
            },
        )
        return [SocAlertRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("alerts") or [])]

    def get_alert(self, alert_id: str) -> SocAlertRecord:
        return SocAlertRecord.model_validate(self._request("GET", f"/soc/alerts/{alert_id}"))

    def update_alert(self, alert_id: str, payload: SocAlertUpdate) -> SocAlertRecord:
        return SocAlertRecord.model_validate(
            self._request("PATCH", f"/soc/alerts/{alert_id}", json_body=payload.model_dump(mode="json"))
        )

    def promote_alert_to_case(
        self,
        alert_id: str,
        payload: SocAlertPromoteCaseRequest,
    ) -> tuple[SocAlertRecord, SocCaseRecord]:
        result = self._request("POST", f"/soc/alerts/{alert_id}/case", json_body=payload.model_dump(mode="json"))
        return SocAlertRecord.model_validate(result["alert"]), SocCaseRecord.model_validate(result["case"])

    def create_case(self, payload: SocCaseCreate) -> SocCaseRecord:
        return SocCaseRecord.model_validate(self._request("POST", "/soc/cases", json_body=payload.model_dump(mode="json")))

    def list_cases(self, *, status: SocCaseStatus | None = None) -> list[SocCaseRecord]:
        return self.query_cases(status=status, limit=250)

    def query_cases(
        self,
        *,
        status: SocCaseStatus | None = None,
        severity: SocSeverity | None = None,
        assignee: str | None = None,
        sort: str = "updated_desc",
        limit: int = 100,
    ) -> list[SocCaseRecord]:
        payload = self._request(
            "GET",
            "/soc/cases",
            params={
                "status": status.value if status is not None else None,
                "severity": severity.value if severity is not None else None,
                "assignee": assignee,
                "sort": sort,
                "limit": limit,
            },
        )
        return [SocCaseRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("cases") or [])]

    def get_case(self, case_id: str) -> SocCaseRecord:
        return SocCaseRecord.model_validate(self._request("GET", f"/soc/cases/{case_id}"))

    def list_case_linked_alerts(self, case_id: str) -> list[SocAlertRecord]:
        payload = self._request("GET", f"/soc/cases/{case_id}/alerts")
        return [SocAlertRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("alerts") or [])]

    def list_case_source_events(self, case_id: str) -> list[SocEventRecord]:
        payload = self._request("GET", f"/soc/cases/{case_id}/events")
        return [SocEventRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("events") or [])]

    def update_case(self, case_id: str, payload: SocCaseUpdate) -> SocCaseRecord:
        return SocCaseRecord.model_validate(
            self._request("PATCH", f"/soc/cases/{case_id}", json_body=payload.model_dump(mode="json"))
        )

    def list_detection_rules(self) -> list[SocDetectionRuleRecord]:
        payload = self._request("GET", "/soc/detections")
        return [SocDetectionRuleRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("rules") or [])]

    def get_detection_rule(self, rule_id: str) -> SocDetectionRuleRecord:
        return SocDetectionRuleRecord.model_validate(self._request("GET", f"/soc/detections/{rule_id}"))

    def update_detection_rule(self, rule_id: str, payload: SocDetectionRuleUpdate) -> SocDetectionRuleRecord:
        return SocDetectionRuleRecord.model_validate(
            self._request("PATCH", f"/soc/detections/{rule_id}", json_body=payload.model_dump(mode="json"))
        )

    def list_detection_rule_alert_groups(self, rule_id: str) -> list[dict[str, Any]]:
        payload = self._request("GET", f"/soc/detections/{rule_id}/rule-alert-groups")
        return cast(list[dict[str, Any]], payload.get("groups") or [])

    def get_detection_rule_alert_group(self, rule_id: str, group_key: str) -> dict[str, Any]:
        payload = self._request("GET", f"/soc/detections/{rule_id}/rule-alert-groups/{group_key}")
        return cast(dict[str, Any], payload.get("group") or {})

    def create_case_from_detection_rule_alert_group(
        self,
        rule_id: str,
        payload: SocCaseRuleGroupCaseRequest | None = None,
        **request_kwargs: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocCaseRuleGroupCaseRequest(**request_kwargs)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                f"/soc/detections/{rule_id}/rule-alert-groups/case",
                json_body=request_payload.model_dump(mode="json"),
            )
        )

    def list_detection_rule_evidence_groups(self, rule_id: str) -> list[dict[str, Any]]:
        payload = self._request("GET", f"/soc/detections/{rule_id}/rule-evidence-groups")
        return cast(list[dict[str, Any]], payload.get("groups") or [])

    def get_detection_rule_evidence_group(self, rule_id: str, group_key: str) -> dict[str, Any]:
        payload = self._request("GET", f"/soc/detections/{rule_id}/rule-evidence-groups/{group_key}")
        return cast(dict[str, Any], payload.get("group") or {})

    def create_case_from_detection_rule_evidence_group(
        self,
        rule_id: str,
        payload: SocCaseRuleGroupCaseRequest | None = None,
        **request_kwargs: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocCaseRuleGroupCaseRequest(**request_kwargs)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                f"/soc/detections/{rule_id}/rule-evidence-groups/case",
                json_body=request_payload.model_dump(mode="json"),
            )
        )

    def create_case_from_packet_session(
        self,
        session_payload: Mapping[str, Any],
        payload: SocPacketSessionCaseRequest | None = None,
    ) -> SocCaseRecord:
        request_payload = payload or SocPacketSessionCaseRequest(session_key=str(session_payload.get("session_key") or ""))
        return SocCaseRecord.model_validate(
            self._request("POST", "/network/packet-sessions/case", json_body=request_payload.model_dump(mode="json"))
        )

    def create_case_from_network_evidence(
        self,
        evidence_payload: Mapping[str, Any],
        payload: SocNetworkEvidenceCaseRequest | None = None,
    ) -> SocCaseRecord:
        request_payload = payload or SocNetworkEvidenceCaseRequest(remote_ip=str(evidence_payload.get("remote_ip") or ""))
        return SocCaseRecord.model_validate(
            self._request("POST", "/network/evidence/case", json_body=request_payload.model_dump(mode="json"))
        )

    def create_case_from_packet_capture(
        self,
        capture_id: str,
        payload: SocPacketCaptureCaseRequest | None = None,
        **request_kwargs: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocPacketCaptureCaseRequest(**request_kwargs)
        return SocCaseRecord.model_validate(
            self._request(
                "POST",
                f"/packet/telemetry/captures/{capture_id}/case",
                json_body=request_payload.model_dump(mode="json", exclude_none=True),
            )
        )

    def create_case_from_remote_node(
        self,
        node_payload: Mapping[str, Any],
        payload: SocRemoteNodeCaseRequest | None = None,
    ) -> SocCaseRecord:
        node_name = str(node_payload.get("node_name") or "")
        request_payload = payload or SocRemoteNodeCaseRequest()
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/case",
            json_body=request_payload.model_dump(mode="json"),
        )
        return SocCaseRecord.model_validate(result["case"])

    def resolve_remote_node_cases(self, node_payload: Mapping[str, Any]) -> list[SocCaseRecord]:
        node_name = str(node_payload.get("node_name") or "")
        related_case_ids = cast(list[str], node_payload.get("related_case_ids") or [])
        if not related_case_ids and node_name:
            detail = self._request("GET", f"/platform/nodes/{node_name}")
            related_case_ids = cast(list[str], cast(dict[str, Any], detail.get("node") or {}).get("related_case_ids") or [])
        cases: list[SocCaseRecord] = []
        for case_id in related_case_ids:
            cases.append(self.get_case(case_id))
        return cases

    def get_platform_node_detail(self, node_name: str) -> dict[str, Any]:
        result = self._request("GET", f"/platform/nodes/{node_name}")
        return cast(dict[str, Any], result["node"])

    def acknowledge_platform_node(
        self,
        node_name: str,
        *,
        acknowledged_by: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeAcknowledgeRequest(acknowledged_by=acknowledged_by, note=note)
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/acknowledge",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])

    def suppress_platform_node(
        self,
        node_name: str,
        *,
        minutes: int,
        suppressed_by: str | None = None,
        reason: str | None = None,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeSuppressRequest(
            suppressed_by=suppressed_by,
            reason=reason,
            minutes=minutes,
            scopes=scopes or ["remote_node_health"],
        )
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/suppress",
            json_body=payload.model_dump(mode="json"),
        )
        return cast(dict[str, Any], result["node"])

    def clear_platform_node_suppression(
        self,
        node_name: str,
        *,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeSuppressRequest(scopes=scopes or ["remote_node_health"])
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/clear-suppression",
            json_body=payload.model_dump(mode="json"),
        )
        return cast(dict[str, Any], result["node"])

    def start_platform_node_maintenance(
        self,
        node_name: str,
        *,
        minutes: int,
        maintenance_by: str | None = None,
        reason: str | None = None,
        services: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeMaintenanceRequest(
            started_by=maintenance_by,
            reason=reason,
            minutes=minutes,
            services=services or [],
        )
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/maintenance",
            json_body=payload.model_dump(mode="json"),
        )
        return cast(dict[str, Any], result["node"])

    def clear_platform_node_maintenance(
        self,
        node_name: str,
    ) -> dict[str, Any]:
        result = self._request("POST", f"/platform/nodes/{node_name}/clear-maintenance")
        return cast(dict[str, Any], result["node"])

    def request_platform_node_refresh(
        self,
        node_name: str,
        *,
        requested_by: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeRefreshRequest(requested_by=requested_by, reason=reason)
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/refresh",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])

    def start_platform_node_drain(
        self,
        node_name: str,
        *,
        drained_by: str | None = None,
        reason: str | None = None,
        services: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeDrainRequest(drained_by=drained_by, reason=reason, services=services or [])
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/drain",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])

    def clear_platform_node_drain(self, node_name: str) -> dict[str, Any]:
        result = self._request("POST", f"/platform/nodes/{node_name}/ready")
        return cast(dict[str, Any], result["node"])

    def retry_platform_node_action(
        self,
        node_name: str,
        *,
        action: str,
        requested_by: str | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeActionUpdateRequest(acted_by=requested_by)
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/actions/{action}/retry",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])

    def cancel_platform_node_action(
        self,
        node_name: str,
        *,
        action: str,
        cancelled_by: str | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeActionUpdateRequest(acted_by=cancelled_by)
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/actions/{action}/cancel",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])


class RemoteTrackerIntelClient(_RemoteApiClient):
    def feed_status(self) -> dict[str, Any]:
        return self._request("GET", "/privacy/tracker-feeds/status")

    def refresh_feed_cache(self) -> dict[str, Any]:
        return self._request("POST", "/privacy/tracker-feeds/refresh")


class RemotePacketMonitorClient(_RemoteApiClient):
    def list_recent_sessions(self, *, limit: int = 50, remote_ip: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/network/packet-sessions", params={"limit": limit, "remote_ip": remote_ip})
        return cast(list[dict[str, Any]], payload.get("sessions") or [])

    def list_telemetry_sessions(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        session_key: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/packet/telemetry/sessions",
            params={
                "limit": limit,
                "remote_ip": remote_ip,
                "session_key": session_key,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
            },
        )
        return cast(list[dict[str, Any]], payload.get("sessions") or [])

    def list_packet_capture_artifacts(
        self,
        *,
        limit: int = 20,
        remote_ip: str | None = None,
        session_key: str | None = None,
        protocol: str | None = None,
        local_port: int | None = None,
        remote_port: int | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/packet/telemetry/captures",
            params={
                "limit": limit,
                "remote_ip": remote_ip,
                "session_key": session_key,
                "protocol": protocol,
                "local_port": local_port,
                "remote_port": remote_port,
            },
        )

    def get_packet_capture_artifact(self, capture_id: str) -> dict[str, Any]:
        return self._request("GET", f"/packet/telemetry/captures/{capture_id}")

    def get_packet_capture_text(self, capture_id: str) -> dict[str, Any]:
        return self._request("GET", f"/packet/telemetry/captures/{capture_id}/text")

    def summarize_telemetry_sessions(
        self,
        *,
        limit: int = 250,
        facet_limit: int = 5,
        remote_ip: str | None = None,
        session_key: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/packet/telemetry/summary",
            params={
                "limit": limit,
                "facet_limit": facet_limit,
                "remote_ip": remote_ip,
                "session_key": session_key,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
            },
        )


class RemoteNetworkMonitorClient(_RemoteApiClient):
    def ingest_sensor_telemetry(self, payload: SocNetworkSensorTelemetryIngest) -> dict[str, Any]:
        return self._request("POST", "/network/telemetry/ingest", json_body=payload.model_dump(mode="json"))

    def list_recent_observations(self, *, limit: int = 50, remote_ip: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/network/observations", params={"limit": limit, "remote_ip": remote_ip})
        return cast(list[dict[str, Any]], payload.get("observations") or [])

    def list_telemetry_connections(self, *, limit: int = 100, remote_ip: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/network/telemetry/connections", params={"limit": limit, "remote_ip": remote_ip})
        return cast(list[dict[str, Any]], payload.get("connections") or [])

    def list_telemetry_flows(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        process_name: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/flows",
            params={
                "limit": limit,
                "remote_ip": remote_ip,
                "process_name": process_name,
                "flow_id": flow_id,
                "service_name": service_name,
                "application_protocol": application_protocol,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
                "state": state,
            },
        )
        return cast(list[dict[str, Any]], payload.get("flows") or [])

    def list_telemetry_dns(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        hostname: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/dns",
            params={"limit": limit, "remote_ip": remote_ip, "hostname": hostname},
        )
        return cast(list[dict[str, Any]], payload.get("dns_records") or [])

    def list_telemetry_http(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        hostname: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/http",
            params={"limit": limit, "remote_ip": remote_ip, "hostname": hostname},
        )
        return cast(list[dict[str, Any]], payload.get("http_records") or [])

    def list_telemetry_tls(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        hostname: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/tls",
            params={"limit": limit, "remote_ip": remote_ip, "hostname": hostname},
        )
        return cast(list[dict[str, Any]], payload.get("tls_records") or [])

    def list_telemetry_certificates(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        hostname: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/certificates",
            params={"limit": limit, "remote_ip": remote_ip, "hostname": hostname},
        )
        return cast(list[dict[str, Any]], payload.get("certificate_records") or [])

    def list_telemetry_proxy(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/proxy",
            params={"limit": limit, "remote_ip": remote_ip, "hostname": hostname, "username": username},
        )
        return cast(list[dict[str, Any]], payload.get("proxy_records") or [])

    def list_telemetry_auth(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        username: str | None = None,
        hostname: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/auth",
            params={"limit": limit, "remote_ip": remote_ip, "username": username, "hostname": hostname},
        )
        return cast(list[dict[str, Any]], payload.get("auth_records") or [])

    def list_telemetry_vpn(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        username: str | None = None,
        hostname: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/vpn",
            params={"limit": limit, "remote_ip": remote_ip, "username": username, "hostname": hostname},
        )
        return cast(list[dict[str, Any]], payload.get("vpn_records") or [])

    def list_telemetry_dhcp(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        hostname: str | None = None,
        assigned_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/dhcp",
            params={"limit": limit, "remote_ip": remote_ip, "hostname": hostname, "assigned_ip": assigned_ip},
        )
        return cast(list[dict[str, Any]], payload.get("dhcp_records") or [])

    def list_telemetry_directory_auth(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        username: str | None = None,
        hostname: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/directory-auth",
            params={"limit": limit, "remote_ip": remote_ip, "username": username, "hostname": hostname},
        )
        return cast(list[dict[str, Any]], payload.get("directory_auth_records") or [])

    def list_telemetry_radius(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        username: str | None = None,
        hostname: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/radius",
            params={"limit": limit, "remote_ip": remote_ip, "username": username, "hostname": hostname},
        )
        return cast(list[dict[str, Any]], payload.get("radius_records") or [])

    def list_telemetry_nac(
        self,
        *,
        limit: int = 100,
        remote_ip: str | None = None,
        hostname: str | None = None,
        device_id: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/network/telemetry/nac",
            params={"limit": limit, "remote_ip": remote_ip, "hostname": hostname, "device_id": device_id},
        )
        return cast(list[dict[str, Any]], payload.get("nac_records") or [])

    def summarize_telemetry_connections(
        self,
        *,
        limit: int = 250,
        facet_limit: int = 5,
        remote_ip: str | None = None,
        process_name: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        start_at: datetime | str | None = None,
        end_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            "/network/telemetry/summary",
            params={
                "limit": limit,
                "facet_limit": facet_limit,
                "remote_ip": remote_ip,
                "process_name": process_name,
                "flow_id": flow_id,
                "service_name": service_name,
                "application_protocol": application_protocol,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": protocol,
                "state": state,
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
            },
        )

    def list_combined_evidence(self, *, limit: int = 50, remote_ip: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/network/evidence", params={"limit": limit, "remote_ip": remote_ip})
        rows = cast(list[dict[str, Any]], payload.get("evidence") or [])
        normalized: list[dict[str, Any]] = []
        for item in rows:
            packet_sessions = cast(list[dict[str, Any]], item.get("packet_sessions") or [])
            normalized.append(
                {
                    "remote_ip": item.get("remote_ip"),
                    "title": item.get("title") or f"Network evidence for {item.get('remote_ip', '-')}",
                    "severity": item.get("severity") or "medium",
                    "last_seen_at": item.get("last_seen_at"),
                    "observation": item.get("network_observation"),
                    "packet_session": packet_sessions[0] if packet_sessions else None,
                    "related_alert_ids": item.get("related_alert_ids") or [],
                    "related_case_ids": item.get("related_case_ids") or [],
                    "open_case_ids": item.get("open_case_ids") or [],
                    "open_case_count": item.get("open_case_count") or 0,
                }
            )
        return normalized


class RemotePlatformClient(_RemoteApiClient):
    def list_remote_nodes(self, *, limit: int = 100) -> list[dict[str, Any]]:
        payload = self._request("GET", "/platform/nodes", params={"limit": limit})
        topology = cast(dict[str, Any], payload.get("topology") or {})
        return [dict(item) for item in cast(list[dict[str, Any]], topology.get("remote_nodes") or [])]

    def get_platform_node_detail(self, node_name: str) -> dict[str, Any]:
        payload = self._request("GET", f"/platform/nodes/{node_name}")
        return cast(dict[str, Any], payload.get("node") or {})

    def create_case_from_remote_node(
        self,
        node_payload: Mapping[str, Any],
        payload: SocRemoteNodeCaseRequest | None = None,
    ) -> SocCaseRecord:
        node_name = str(node_payload.get("node_name") or "")
        request_payload = payload or SocRemoteNodeCaseRequest()
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/case",
            json_body=request_payload.model_dump(mode="json"),
        )
        return SocCaseRecord.model_validate(result)

    def resolve_remote_node_cases(self, node_payload: Mapping[str, Any]) -> list[SocCaseRecord]:
        node_name = str(node_payload.get("node_name") or "")
        if not node_name:
            return []
        payload = self._request("GET", f"/platform/nodes/{node_name}/cases")
        return [
            SocCaseRecord.model_validate(item)
            for item in cast(list[dict[str, Any]], payload.get("cases") or [])
        ]

    def acknowledge_platform_node(
        self,
        node_name: str,
        *,
        acknowledged_by: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeAcknowledgeRequest(acknowledged_by=acknowledged_by, note=note)
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/acknowledge",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])

    def suppress_platform_node(
        self,
        node_name: str,
        *,
        minutes: int,
        suppressed_by: str | None = None,
        reason: str | None = None,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeSuppressRequest(
            suppressed_by=suppressed_by,
            reason=reason,
            minutes=minutes,
            scopes=scopes or ["remote_node_health"],
        )
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/suppress",
            json_body=payload.model_dump(mode="json"),
        )
        return cast(dict[str, Any], result["node"])

    def clear_platform_node_suppression(
        self,
        node_name: str,
        *,
        scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeSuppressRequest(scopes=scopes or ["remote_node_health"])
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/clear-suppression",
            json_body=payload.model_dump(mode="json"),
        )
        return cast(dict[str, Any], result["node"])

    def start_platform_node_maintenance(
        self,
        node_name: str,
        *,
        minutes: int,
        maintenance_by: str | None = None,
        reason: str | None = None,
        services: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeMaintenanceRequest(
            started_by=maintenance_by,
            reason=reason,
            minutes=minutes,
            services=services or [],
        )
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/maintenance",
            json_body=payload.model_dump(mode="json"),
        )
        return cast(dict[str, Any], result["node"])

    def clear_platform_node_maintenance(self, node_name: str) -> dict[str, Any]:
        result = self._request("POST", f"/platform/nodes/{node_name}/clear-maintenance")
        return cast(dict[str, Any], result["node"])

    def request_platform_node_refresh(
        self,
        node_name: str,
        *,
        requested_by: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeRefreshRequest(requested_by=requested_by, reason=reason)
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/refresh",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])

    def start_platform_node_drain(
        self,
        node_name: str,
        *,
        drained_by: str | None = None,
        reason: str | None = None,
        services: list[str] | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeDrainRequest(drained_by=drained_by, reason=reason, services=services or [])
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/drain",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])

    def clear_platform_node_drain(self, node_name: str) -> dict[str, Any]:
        result = self._request("POST", f"/platform/nodes/{node_name}/ready")
        return cast(dict[str, Any], result["node"])

    def retry_platform_node_action(
        self,
        node_name: str,
        *,
        action: str,
        requested_by: str | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeActionUpdateRequest(acted_by=requested_by)
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/actions/{action}/retry",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])

    def cancel_platform_node_action(
        self,
        node_name: str,
        *,
        action: str,
        cancelled_by: str | None = None,
    ) -> dict[str, Any]:
        payload = PlatformNodeActionUpdateRequest(acted_by=cancelled_by)
        result = self._request(
            "POST",
            f"/platform/nodes/{node_name}/actions/{action}/cancel",
            json_body=payload.model_dump(mode="json", exclude_none=True),
        )
        return cast(dict[str, Any], result["node"])
