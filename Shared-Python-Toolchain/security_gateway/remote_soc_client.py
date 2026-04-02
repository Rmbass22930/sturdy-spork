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
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
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
        return self._request("GET", "/soc/dashboard")

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
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
                "linked_alert_state": linked_alert_state,
                "sort": sort,
            },
        )
        return [SocEventRecord.model_validate(item) for item in cast(list[dict[str, Any]], payload.get("events") or [])]

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

    def create_case_from_endpoint_timeline(
        self,
        payload: SocEndpointTimelineCaseRequest | None = None,
        **filters: Any,
    ) -> SocCaseRecord:
        request_payload = payload or SocEndpointTimelineCaseRequest(**filters)
        return SocCaseRecord.model_validate(
            self._request("POST", "/endpoint/telemetry/timeline/case", json_body=request_payload.model_dump(mode="json"))
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

    def list_detection_rule_evidence_groups(self, rule_id: str) -> list[dict[str, Any]]:
        payload = self._request("GET", f"/soc/detections/{rule_id}/rule-evidence-groups")
        return cast(list[dict[str, Any]], payload.get("groups") or [])

    def get_detection_rule_evidence_group(self, rule_id: str, group_key: str) -> dict[str, Any]:
        payload = self._request("GET", f"/soc/detections/{rule_id}/rule-evidence-groups/{group_key}")
        return cast(dict[str, Any], payload.get("group") or {})

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
    ) -> list[dict[str, Any]]:
        payload = self._request(
            "GET",
            "/packet/telemetry/sessions",
            params={"limit": limit, "remote_ip": remote_ip, "session_key": session_key},
        )
        return cast(list[dict[str, Any]], payload.get("sessions") or [])

    def summarize_telemetry_sessions(
        self,
        *,
        limit: int = 250,
        facet_limit: int = 5,
        remote_ip: str | None = None,
        session_key: str | None = None,
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
                "start_at": self._query_datetime(start_at),
                "end_at": self._query_datetime(end_at),
            },
        )


class RemoteNetworkMonitorClient(_RemoteApiClient):
    def list_recent_observations(self, *, limit: int = 50, remote_ip: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/network/observations", params={"limit": limit, "remote_ip": remote_ip})
        return cast(list[dict[str, Any]], payload.get("observations") or [])

    def list_telemetry_connections(self, *, limit: int = 100, remote_ip: str | None = None) -> list[dict[str, Any]]:
        payload = self._request("GET", "/network/telemetry/connections", params={"limit": limit, "remote_ip": remote_ip})
        return cast(list[dict[str, Any]], payload.get("connections") or [])

    def summarize_telemetry_connections(
        self,
        *,
        limit: int = 250,
        facet_limit: int = 5,
        remote_ip: str | None = None,
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
