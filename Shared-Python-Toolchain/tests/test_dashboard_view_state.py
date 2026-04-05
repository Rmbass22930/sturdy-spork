from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import httpx

import security_gateway.soc_dashboard as soc_dashboard_module
from security_gateway.dashboard_view_state import (
    FileDashboardViewStateClient,
    HttpDashboardViewStateClient,
    ManagerDashboardViewStateClient,
    build_dashboard_view_state_client,
)
from security_gateway.models import (
    SocAlertPromoteCaseRequest,
    SocAlertUpdate,
    SocAlertStatus,
    SocCaseUpdate,
    SocCaseStatus,
    SocCaseEndpointLineageClusterCaseRequest,
    SocCaseTelemetryClusterCaseRequest,
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocDashboardViewStateUpdate,
    SocDetectionRuleUpdate,
    SocEndpointLineageClusterCaseRequest,
    SocNetworkEvidenceCaseRequest,
    SocPacketSessionCaseRequest,
    SocEndpointTimelineCaseRequest,
    SocTelemetryClusterCaseRequest,
)
from security_gateway.remote_soc_client import (
    RemoteNetworkMonitorClient,
    RemotePacketMonitorClient,
    RemotePlatformClient,
    RemoteSecurityOperationsClient,
    RemoteTrackerIntelClient,
)
from security_gateway.soc_dashboard import RemoteSocDashboardConnector, run_remote_soc_dashboard


def test_file_dashboard_view_state_client_reads_and_writes(tmp_path: Path) -> None:
    client = FileDashboardViewStateClient(tmp_path / "view_state.json")

    written = client.write(
        SocDashboardViewStateUpdate(
            operational_reason_filter="stuck action",
            hunt_cluster_mode="device_id",
            hunt_cluster_value="device-11",
            hunt_cluster_key="cluster-11",
            hunt_cluster_action="case",
            endpoint_timeline_cluster_mode="remote_ip",
            endpoint_timeline_cluster_key="timeline-11",
            endpoint_timeline_cluster_action="details",
            endpoint_lineage_cluster_mode="device_id",
            endpoint_lineage_cluster_value="device-11",
            endpoint_lineage_cluster_key="lineage-11",
            endpoint_lineage_cluster_action="existing_case",
        )
    )

    assert written["operational_reason_filter"] == "stuck action"
    assert written["hunt_cluster_mode"] == "device_id"
    assert written["hunt_cluster_value"] == "device-11"
    assert written["hunt_cluster_key"] == "cluster-11"
    assert written["hunt_cluster_action"] == "case"
    assert written["endpoint_timeline_cluster_mode"] == "remote_ip"
    assert written["endpoint_timeline_cluster_key"] == "timeline-11"
    assert written["endpoint_timeline_cluster_action"] == "details"
    assert written["endpoint_lineage_cluster_mode"] == "device_id"
    assert written["endpoint_lineage_cluster_value"] == "device-11"
    assert written["endpoint_lineage_cluster_key"] == "lineage-11"
    assert written["endpoint_lineage_cluster_action"] == "existing_case"
    assert client.read()["operational_reason_filter"] == "stuck action"
    assert client.read()["hunt_cluster_mode"] == "device_id"
    assert client.read()["hunt_cluster_value"] == "device-11"
    assert client.read()["hunt_cluster_key"] == "cluster-11"
    assert client.read()["hunt_cluster_action"] == "case"
    assert client.read()["endpoint_timeline_cluster_mode"] == "remote_ip"
    assert client.read()["endpoint_timeline_cluster_key"] == "timeline-11"
    assert client.read()["endpoint_timeline_cluster_action"] == "details"
    assert client.read()["endpoint_lineage_cluster_mode"] == "device_id"
    assert client.read()["endpoint_lineage_cluster_value"] == "device-11"
    assert client.read()["endpoint_lineage_cluster_key"] == "lineage-11"
    assert client.read()["endpoint_lineage_cluster_action"] == "existing_case"
    dashboard_state = client.read_dashboard_state()
    assert cast(dict[str, object], dashboard_state["view_state"])["hunt_cluster_mode"] == "device_id"
    assert cast(dict[str, object], dashboard_state["summary_labels"])["hunt_clusters"] is None
    assert json.loads((tmp_path / "view_state.json").read_text(encoding="utf-8")) == {
        "operational_reason_filter": "stuck action",
        "hunt_cluster_mode": "device_id",
        "hunt_cluster_value": "device-11",
        "hunt_cluster_key": "cluster-11",
        "hunt_cluster_action": "case",
        "endpoint_timeline_cluster_mode": "remote_ip",
        "endpoint_timeline_cluster_key": "timeline-11",
        "endpoint_timeline_cluster_action": "details",
        "endpoint_lineage_cluster_mode": "device_id",
        "endpoint_lineage_cluster_value": "device-11",
        "endpoint_lineage_cluster_key": "lineage-11",
        "endpoint_lineage_cluster_action": "existing_case",
    }


def test_manager_dashboard_view_state_client_uses_manager_contract() -> None:
    calls: list[Any] = []
    def _update_dashboard_view_state(_self: Any, payload: Any) -> dict[str, Any]:
        calls.append(payload)
        return {
            "operational_reason_filter": payload.operational_reason_filter,
            "hunt_cluster_mode": payload.hunt_cluster_mode,
            "hunt_cluster_value": payload.hunt_cluster_value,
            "hunt_cluster_key": payload.hunt_cluster_key,
            "hunt_cluster_action": payload.hunt_cluster_action,
            "endpoint_timeline_cluster_mode": payload.endpoint_timeline_cluster_mode,
            "endpoint_timeline_cluster_key": payload.endpoint_timeline_cluster_key,
            "endpoint_timeline_cluster_action": payload.endpoint_timeline_cluster_action,
            "endpoint_lineage_cluster_mode": payload.endpoint_lineage_cluster_mode,
            "endpoint_lineage_cluster_value": payload.endpoint_lineage_cluster_value,
            "endpoint_lineage_cluster_key": payload.endpoint_lineage_cluster_key,
            "endpoint_lineage_cluster_action": payload.endpoint_lineage_cluster_action,
        }

    manager = type(
        "Manager",
        (),
        {
            "dashboard": lambda self: {
                "view_state": {
                    "operational_reason_filter": "retry pressure",
                    "hunt_cluster_mode": "process_guid",
                    "hunt_cluster_value": "proc-guid-1",
                    "hunt_cluster_key": "cluster-22",
                    "hunt_cluster_action": "details",
                    "endpoint_timeline_cluster_mode": "process",
                    "endpoint_timeline_cluster_key": "timeline-22",
                    "endpoint_timeline_cluster_action": "existing_case",
                    "endpoint_lineage_cluster_mode": "device_id",
                    "endpoint_lineage_cluster_value": "device-22",
                    "endpoint_lineage_cluster_key": "lineage-22",
                    "endpoint_lineage_cluster_action": "details",
                }
            },
            "update_dashboard_view_state": _update_dashboard_view_state,
        },
    )()
    client = ManagerDashboardViewStateClient(manager)

    assert client.read()["operational_reason_filter"] == "retry pressure"
    assert client.read()["hunt_cluster_mode"] == "process_guid"
    assert client.read()["hunt_cluster_value"] == "proc-guid-1"
    assert client.read()["hunt_cluster_key"] == "cluster-22"
    assert client.read()["hunt_cluster_action"] == "details"
    assert client.read()["endpoint_timeline_cluster_mode"] == "process"
    assert client.read()["endpoint_timeline_cluster_key"] == "timeline-22"
    assert client.read()["endpoint_timeline_cluster_action"] == "existing_case"
    assert client.read()["endpoint_lineage_cluster_mode"] == "device_id"
    assert client.read()["endpoint_lineage_cluster_value"] == "device-22"
    assert client.read()["endpoint_lineage_cluster_key"] == "lineage-22"
    assert client.read()["endpoint_lineage_cluster_action"] == "details"
    dashboard_state = client.read_dashboard_state()
    assert cast(dict[str, object], dashboard_state["view_state"])["hunt_cluster_mode"] == "process_guid"
    assert cast(dict[str, object], dashboard_state["summary_labels"])["hunt_clusters"] is None
    updated = client.write(
        SocDashboardViewStateUpdate(
            operational_reason_filter="action failed",
            hunt_cluster_mode="device_id",
            hunt_cluster_value="device-22",
            hunt_cluster_key="cluster-33",
            hunt_cluster_action="case",
            endpoint_timeline_cluster_mode="remote_ip",
            endpoint_timeline_cluster_key="timeline-33",
            endpoint_timeline_cluster_action="details",
            endpoint_lineage_cluster_mode="process_guid",
            endpoint_lineage_cluster_value="proc-guid-33",
            endpoint_lineage_cluster_key="lineage-33",
            endpoint_lineage_cluster_action="case",
        )
    )

    assert updated["operational_reason_filter"] == "action failed"
    assert updated["hunt_cluster_mode"] == "device_id"
    assert updated["hunt_cluster_value"] == "device-22"
    assert updated["hunt_cluster_key"] == "cluster-33"
    assert updated["hunt_cluster_action"] == "case"
    assert updated["endpoint_timeline_cluster_mode"] == "remote_ip"
    assert updated["endpoint_timeline_cluster_key"] == "timeline-33"
    assert updated["endpoint_timeline_cluster_action"] == "details"
    assert updated["endpoint_lineage_cluster_mode"] == "process_guid"
    assert updated["endpoint_lineage_cluster_value"] == "proc-guid-33"
    assert updated["endpoint_lineage_cluster_key"] == "lineage-33"
    assert updated["endpoint_lineage_cluster_action"] == "case"
    assert len(calls) == 1
    assert calls[0].operational_reason_filter == "action failed"
    assert calls[0].hunt_cluster_mode == "device_id"
    assert calls[0].hunt_cluster_value == "device-22"
    assert calls[0].hunt_cluster_key == "cluster-33"
    assert calls[0].hunt_cluster_action == "case"
    assert calls[0].endpoint_timeline_cluster_mode == "remote_ip"
    assert calls[0].endpoint_timeline_cluster_key == "timeline-33"
    assert calls[0].endpoint_timeline_cluster_action == "details"
    assert calls[0].endpoint_lineage_cluster_mode == "process_guid"
    assert calls[0].endpoint_lineage_cluster_value == "proc-guid-33"
    assert calls[0].endpoint_lineage_cluster_key == "lineage-33"
    assert calls[0].endpoint_lineage_cluster_action == "case"


def test_http_dashboard_view_state_client_reads_and_writes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            assert request.headers["Authorization"] == "Bearer operator-token"
            return httpx.Response(
                200,
                json={
                    "view_state": {
                        "operational_reason_filter": "stuck action",
                        "hunt_cluster_mode": "device_id",
                    "hunt_cluster_value": "device-11",
                    "hunt_cluster_key": "cluster-11",
                        "hunt_cluster_action": "existing_case",
                        "endpoint_timeline_cluster_mode": "remote_ip",
                        "endpoint_timeline_cluster_key": "timeline-11",
                        "endpoint_timeline_cluster_action": "case",
                        "endpoint_lineage_cluster_mode": "filename",
                        "endpoint_lineage_cluster_value": "payload.dll",
                        "endpoint_lineage_cluster_key": "lineage-11",
                        "endpoint_lineage_cluster_action": "details",
                    },
                    "summary_labels": {
                        "hunt_clusters": "Hunt Clusters [device_id]",
                        "endpoint_timeline_clusters": "Timeline Clusters [remote_ip]",
                        "endpoint_lineage_clusters": "Endpoint Lineage [filename=payload.dll]",
                        "operational_alerts": "Operational Alerts [stuck action]",
                        "operational_cases": "Operational Cases [stuck action]",
                    },
                },
            )
        if request.method == "POST" and request.url.path == "/soc/dashboard/view-state":
            assert request.headers["Authorization"] == "Bearer operator-token"
            return httpx.Response(200, json={"view_state": cast(dict[str, Any], json.loads(request.content))})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = HttpDashboardViewStateClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    assert client.read()["operational_reason_filter"] == "stuck action"
    assert client.read()["hunt_cluster_mode"] == "device_id"
    assert client.read()["hunt_cluster_value"] == "device-11"
    assert client.read()["hunt_cluster_key"] == "cluster-11"
    assert client.read()["hunt_cluster_action"] == "existing_case"
    assert client.read()["endpoint_timeline_cluster_mode"] == "remote_ip"
    assert client.read()["endpoint_timeline_cluster_key"] == "timeline-11"
    assert client.read()["endpoint_timeline_cluster_action"] == "case"
    assert client.read()["endpoint_lineage_cluster_mode"] == "filename"
    assert client.read()["endpoint_lineage_cluster_value"] == "payload.dll"
    assert client.read()["endpoint_lineage_cluster_key"] == "lineage-11"
    assert client.read()["endpoint_lineage_cluster_action"] == "details"
    dashboard_state = client.read_dashboard_state()
    assert cast(dict[str, object], dashboard_state["view_state"])["hunt_cluster_mode"] == "device_id"
    assert cast(dict[str, object], dashboard_state["summary_labels"])["hunt_clusters"] == "Hunt Clusters [device_id]"
    assert (
        cast(dict[str, object], dashboard_state["summary_labels"])["endpoint_timeline_clusters"]
        == "Timeline Clusters [remote_ip]"
    )
    assert (
        cast(dict[str, object], dashboard_state["summary_labels"])["endpoint_lineage_clusters"]
        == "Endpoint Lineage [filename=payload.dll]"
    )
    updated = client.write(
        SocDashboardViewStateUpdate(
            operational_reason_filter="retry pressure",
            hunt_cluster_mode="process_guid",
            hunt_cluster_value="proc-guid-1",
            hunt_cluster_key="cluster-44",
            hunt_cluster_action="details",
            endpoint_timeline_cluster_mode="process",
            endpoint_timeline_cluster_key="timeline-44",
            endpoint_timeline_cluster_action="existing_case",
            endpoint_lineage_cluster_mode="remote_ip",
            endpoint_lineage_cluster_value="8.8.8.8",
            endpoint_lineage_cluster_key="lineage-44",
            endpoint_lineage_cluster_action="case",
        )
    )

    assert updated["operational_reason_filter"] == "retry pressure"
    assert updated["hunt_cluster_mode"] == "process_guid"
    assert updated["hunt_cluster_value"] == "proc-guid-1"
    assert updated["hunt_cluster_key"] == "cluster-44"
    assert updated["hunt_cluster_action"] == "details"
    assert updated["endpoint_timeline_cluster_mode"] == "process"
    assert updated["endpoint_timeline_cluster_key"] == "timeline-44"
    assert updated["endpoint_timeline_cluster_action"] == "existing_case"
    assert updated["endpoint_lineage_cluster_mode"] == "remote_ip"
    assert updated["endpoint_lineage_cluster_value"] == "8.8.8.8"
    assert updated["endpoint_lineage_cluster_key"] == "lineage-44"
    assert updated["endpoint_lineage_cluster_action"] == "case"


def test_build_dashboard_view_state_client_prefers_manager_contract(tmp_path: Path) -> None:
    manager = type(
        "Manager",
        (),
        {
            "dashboard": lambda self: {"view_state": {}},
            "update_dashboard_view_state": lambda self, payload: {
                "operational_reason_filter": payload.operational_reason_filter,
                "hunt_cluster_mode": payload.hunt_cluster_mode,
                "hunt_cluster_value": payload.hunt_cluster_value,
                "hunt_cluster_key": payload.hunt_cluster_key,
                "hunt_cluster_action": payload.hunt_cluster_action,
                "endpoint_timeline_cluster_mode": payload.endpoint_timeline_cluster_mode,
                "endpoint_timeline_cluster_key": payload.endpoint_timeline_cluster_key,
                "endpoint_timeline_cluster_action": payload.endpoint_timeline_cluster_action,
            },
        },
    )()

    client = build_dashboard_view_state_client(manager=manager, path=tmp_path / "view_state.json")

    assert isinstance(client, ManagerDashboardViewStateClient)


def test_remote_soc_dashboard_connector_builds_dashboard_with_http_view_state_client() -> None:
    captured: dict[str, Any] = {}
    original_dashboard = soc_dashboard_module.SocDashboard

    class DummyDashboard:
        def __init__(
            self,
            manager: Any = None,
            dashboard_view_state_client: Any = None,
            tracker_intel: Any = None,
            packet_monitor: Any = None,
            network_monitor: Any = None,
            platform_client: Any = None,
        ) -> None:
            captured["manager"] = manager
            captured["client"] = dashboard_view_state_client
            captured["tracker"] = tracker_intel
            captured["packet"] = packet_monitor
            captured["network"] = network_monitor
            captured["platform"] = platform_client

    try:
        cast(Any, soc_dashboard_module).SocDashboard = DummyDashboard
        connector = RemoteSocDashboardConnector(
            base_url="https://manager.local",
            bearer_token="operator-token",
        )
        connector.create_dashboard(manager=cast(Any, "manager-object"))
    finally:
        cast(Any, soc_dashboard_module).SocDashboard = original_dashboard

    assert captured["manager"] == "manager-object"
    assert isinstance(captured["client"], HttpDashboardViewStateClient)


def test_run_remote_soc_dashboard_uses_remote_connector() -> None:
    called: dict[str, Any] = {}
    original_dashboard = soc_dashboard_module.SocDashboard

    class DummyDashboard:
        def __init__(
            self,
            manager: Any = None,
            dashboard_view_state_client: Any = None,
            tracker_intel: Any = None,
            packet_monitor: Any = None,
            network_monitor: Any = None,
            platform_client: Any = None,
        ) -> None:
            called["manager"] = manager
            called["client"] = dashboard_view_state_client
            called["tracker"] = tracker_intel
            called["packet"] = packet_monitor
            called["network"] = network_monitor
            called["platform"] = platform_client

        def run(self) -> None:
            called["ran"] = True

    try:
        cast(Any, soc_dashboard_module).SocDashboard = DummyDashboard
        run_remote_soc_dashboard(
            base_url="https://manager.local",
            bearer_token="operator-token",
            manager=cast(Any, "manager-object"),
        )
    finally:
        cast(Any, soc_dashboard_module).SocDashboard = original_dashboard

    assert called["manager"] == "manager-object"
    assert isinstance(called["client"], HttpDashboardViewStateClient)
    assert called["ran"] is True


def test_remote_soc_dashboard_connector_injects_remote_data_plane_clients() -> None:
    captured: dict[str, Any] = {}
    original_dashboard = soc_dashboard_module.SocDashboard

    class DummyDashboard:
        def __init__(
            self,
            manager: Any = None,
            dashboard_view_state_client: Any = None,
            tracker_intel: Any = None,
            packet_monitor: Any = None,
            network_monitor: Any = None,
            platform_client: Any = None,
        ) -> None:
            captured["manager"] = manager
            captured["client"] = dashboard_view_state_client
            captured["tracker"] = tracker_intel
            captured["packet"] = packet_monitor
            captured["network"] = network_monitor
            captured["platform"] = platform_client

    try:
        cast(Any, soc_dashboard_module).SocDashboard = DummyDashboard
        connector = RemoteSocDashboardConnector(
            base_url="https://manager.local",
            bearer_token="operator-token",
        )
        connector.create_dashboard()
    finally:
        cast(Any, soc_dashboard_module).SocDashboard = original_dashboard

    assert isinstance(captured["manager"], RemoteSecurityOperationsClient)
    assert isinstance(captured["client"], HttpDashboardViewStateClient)
    assert isinstance(captured["tracker"], RemoteTrackerIntelClient)
    assert isinstance(captured["packet"], RemotePacketMonitorClient)
    assert isinstance(captured["network"], RemoteNetworkMonitorClient)
    assert isinstance(captured["platform"], RemotePlatformClient)


def test_remote_soc_dashboard_connector_exposes_dashboard_state_helper() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            return httpx.Response(
                200,
                json={
                    "view_state": {
                        "hunt_cluster_mode": "device_id",
                        "hunt_cluster_value": "device-11",
                    },
                    "summary_labels": {
                        "hunt_clusters": "Hunt Clusters [device_id]",
                        "endpoint_timeline_clusters": "Timeline Clusters [remote_ip]",
                    },
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    dashboard_state = connector.read_dashboard_state()
    assert cast(dict[str, object], dashboard_state["view_state"])["hunt_cluster_mode"] == "device_id"
    assert cast(dict[str, object], dashboard_state["view_state"])["hunt_cluster_value"] == "device-11"
    assert cast(dict[str, object], dashboard_state["summary_labels"])["hunt_clusters"] == "Hunt Clusters [device_id]"
    assert (
        cast(dict[str, object], dashboard_state["summary_labels"])["endpoint_timeline_clusters"]
        == "Timeline Clusters [remote_ip]"
    )


def test_remote_soc_dashboard_connector_exposes_full_dashboard_helper() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            return httpx.Response(
                200,
                json={
                    "summary": {"open_alerts": 2, "open_cases": 1},
                    "view_state": {
                        "hunt_cluster_mode": "device_id",
                    },
                    "summary_labels": {
                        "hunt_clusters": "Hunt Clusters [device_id]",
                    },
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    dashboard = connector.read_dashboard()
    assert cast(dict[str, object], dashboard["summary"])["open_alerts"] == 2
    assert cast(dict[str, object], dashboard["summary"])["open_cases"] == 1
    assert cast(dict[str, object], dashboard["view_state"])["hunt_cluster_mode"] == "device_id"
    assert cast(dict[str, object], dashboard["summary_labels"])["hunt_clusters"] == "Hunt Clusters [device_id]"


def test_remote_soc_dashboard_connector_exposes_toolchain_update_status() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            return httpx.Response(
                200,
                json={
                    "summary": {"open_alerts": 1},
                    "toolchain_updates_status": {"count": 3, "new_count": 1, "applied_count": 2},
                    "view_state": {},
                    "summary_labels": {},
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    status = connector.read_toolchain_updates_status()

    assert status["count"] == 3
    assert status["new_count"] == 1


def test_remote_soc_dashboard_connector_exposes_telemetry_summary_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/summary":
            assert request.url.params["device_id"] == "device-11"
            return httpx.Response(200, json={"telemetry": "endpoint", "match_count": 2})
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/lineage/summary":
            assert request.url.params["device_id"] == "device-11"
            return httpx.Response(200, json={"telemetry": "endpoint_lineage", "match_count": 1})
        if request.method == "GET" and request.url.path == "/network/telemetry/summary":
            assert request.url.params["remote_ip"] == "203.0.113.77"
            return httpx.Response(200, json={"telemetry": "network", "match_count": 1})
        if request.method == "GET" and request.url.path == "/packet/telemetry/summary":
            assert request.url.params["session_key"] == "packet-session:summary"
            return httpx.Response(200, json={"telemetry": "packet", "match_count": 1})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    endpoint_summary = connector.summarize_endpoint_telemetry(device_id="device-11")
    endpoint_lineage_summary = connector.summarize_endpoint_lineage(device_id="device-11")
    network_summary = connector.summarize_network_telemetry(remote_ip="203.0.113.77")
    packet_summary = connector.summarize_packet_telemetry(session_key="packet-session:summary")

    assert endpoint_summary["telemetry"] == "endpoint"
    assert endpoint_summary["match_count"] == 2
    assert endpoint_lineage_summary["telemetry"] == "endpoint_lineage"
    assert endpoint_lineage_summary["match_count"] == 1
    assert network_summary["telemetry"] == "network"
    assert network_summary["match_count"] == 1
    assert packet_summary["telemetry"] == "packet"
    assert packet_summary["match_count"] == 1


def test_remote_soc_dashboard_connector_exposes_cluster_workflow_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/hunt/telemetry/clusters":
            assert request.url.params["cluster_by"] == "remote_ip"
            return httpx.Response(
                200,
                json={
                    "clusters": [
                        {
                            "cluster_by": "remote_ip",
                            "cluster_key": "203.0.113.88",
                            "label": "203.0.113.88",
                            "event_count": 2,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/hunt/telemetry/clusters/203.0.113.88":
            assert request.url.params["cluster_by"] == "remote_ip"
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_by": "remote_ip",
                        "cluster_key": "203.0.113.88",
                        "label": "203.0.113.88",
                        "event_count": 2,
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/soc/hunt/telemetry/clusters/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["cluster_by"] == "remote_ip"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-hunt-1",
                    "title": "Hunt cluster case",
                    "summary": "Cluster summary",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "artifacts": [],
                    "observables": [],
                    "assignee": None,
                    "notes": [],
                    "created_at": "2026-04-02T00:00:00+00:00",
                    "updated_at": "2026-04-02T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/timeline/clusters":
            assert request.url.params["cluster_by"] == "process"
            return httpx.Response(
                200,
                json={
                    "clusters": [
                        {
                            "cluster_by": "process",
                            "cluster_key": "device-11:proc-guid-1",
                            "label": "powershell.exe on device-11",
                            "event_count": 3,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/timeline/clusters/device-11:proc-guid-1":
            assert request.url.params["cluster_by"] == "process"
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_by": "process",
                        "cluster_key": "device-11:proc-guid-1",
                        "label": "powershell.exe on device-11",
                        "event_count": 3,
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/endpoint/telemetry/timeline/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["device_id"] == "device-11"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-timeline-1",
                    "title": "Timeline case",
                    "summary": "Timeline summary",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "artifacts": [],
                    "observables": [],
                    "assignee": None,
                    "notes": [],
                    "created_at": "2026-04-02T00:00:00+00:00",
                    "updated_at": "2026-04-02T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/lineage/clusters":
            assert request.url.params["device_id"] == "device-11"
            return httpx.Response(
                200,
                json={
                    "clusters": [
                        {
                            "cluster_key": "device-11:proc-guid-1",
                            "label": "device-11 / winword.exe > powershell.exe",
                            "event_count": 3,
                            "severity": "high",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/lineage/clusters/device-11:proc-guid-1":
            assert request.url.params["process_guid"] == "proc-guid-1"
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_key": "device-11:proc-guid-1",
                        "label": "device-11 / winword.exe > powershell.exe",
                        "event_count": 3,
                        "severity": "high",
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/endpoint/telemetry/lineage/clusters/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["cluster_key"] == "device-11:proc-guid-1"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-lineage-1",
                    "title": "Lineage case",
                    "summary": "Lineage summary",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "artifacts": [],
                    "observables": [],
                    "assignee": None,
                    "notes": [],
                    "created_at": "2026-04-02T00:00:00+00:00",
                    "updated_at": "2026-04-02T00:00:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    hunt_clusters = connector.list_hunt_telemetry_clusters(cluster_by="remote_ip", remote_ip="203.0.113.88")
    hunt_cluster = connector.get_hunt_telemetry_cluster("203.0.113.88", cluster_by="remote_ip")
    hunt_case = connector.create_case_from_hunt_telemetry_cluster(
        SocTelemetryClusterCaseRequest(cluster_by="remote_ip", cluster_key="203.0.113.88")
    )
    timeline_clusters = connector.list_endpoint_timeline_clusters(cluster_by="process", device_id="device-11")
    timeline_cluster = connector.get_endpoint_timeline_cluster(
        cluster_by="process",
        cluster_key="device-11:proc-guid-1",
        process_guid="proc-guid-1",
    )
    timeline_case = connector.create_case_from_endpoint_timeline(
        SocEndpointTimelineCaseRequest(device_id="device-11", process_guid="proc-guid-1")
    )
    lineage_clusters = connector.list_endpoint_lineage_clusters(device_id="device-11")
    lineage_cluster = connector.get_endpoint_lineage_cluster(
        "device-11:proc-guid-1",
        process_guid="proc-guid-1",
    )
    lineage_case = connector.create_case_from_endpoint_lineage_cluster(
        SocEndpointLineageClusterCaseRequest(
            cluster_key="device-11:proc-guid-1",
            device_id="device-11",
            process_guid="proc-guid-1",
        )
    )

    assert hunt_clusters[0]["cluster_key"] == "203.0.113.88"
    assert hunt_cluster["event_count"] == 2
    assert hunt_case["case_id"] == "case-hunt-1"
    assert cast(list[dict[str, object]], timeline_clusters["clusters"])[0]["cluster_key"] == "device-11:proc-guid-1"
    assert timeline_cluster["event_count"] == 3
    assert timeline_case["case_id"] == "case-timeline-1"
    assert cast(list[dict[str, object]], lineage_clusters["clusters"])[0]["cluster_key"] == "device-11:proc-guid-1"
    assert lineage_cluster["event_count"] == 3
    assert lineage_case["case_id"] == "case-lineage-1"


def test_remote_soc_dashboard_connector_exposes_case_investigation_pivot_helpers() -> None:
    def _case_payload(case_id: str) -> dict[str, Any]:
        return {
            "case_id": case_id,
            "title": f"Case {case_id}",
            "summary": "Case summary",
            "severity": "high",
            "status": "open",
            "linked_alert_ids": [],
            "source_event_ids": [],
            "artifacts": [],
            "observables": [],
            "assignee": None,
            "notes": [],
            "created_at": "2026-04-02T00:00:00+00:00",
            "updated_at": "2026-04-02T00:00:00+00:00",
        }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/rule-alert-groups":
            return httpx.Response(
                200,
                json={"groups": [{"group_key": "device-11:proc-guid-1", "alert_count": 1}]},
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/rule-alert-groups/device-11:proc-guid-1":
            return httpx.Response(
                200,
                json={"group": {"group_key": "device-11:proc-guid-1", "alerts": [{"alert_id": "alert-11"}]}},
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/rule-alert-groups/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["group_key"] == "device-11:proc-guid-1"
            return httpx.Response(200, json=_case_payload("case-alert-group-1"))
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/rule-evidence-groups":
            return httpx.Response(
                200,
                json={"groups": [{"group_key": "device-11", "event_count": 3}]},
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/rule-evidence-groups/device-11":
            return httpx.Response(
                200,
                json={"group": {"group_key": "device-11", "events": [{"event_id": "evt-file-1"}]}},
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/rule-evidence-groups/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["group_key"] == "device-11"
            return httpx.Response(200, json=_case_payload("case-evidence-group-1"))
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/endpoint-timeline/clusters":
            assert request.url.params["cluster_by"] == "process"
            return httpx.Response(
                200,
                json={"clusters": [{"cluster_key": "device-11:proc-guid-1", "event_count": 3}]},
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/endpoint-timeline/clusters/device-11:proc-guid-1":
            assert request.url.params["cluster_by"] == "process"
            return httpx.Response(
                200,
                json={"cluster": {"cluster_key": "device-11:proc-guid-1", "event_count": 3}},
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/endpoint-timeline/clusters/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["cluster_key"] == "device-11:proc-guid-1"
            return httpx.Response(200, json=_case_payload("case-timeline-cluster-1"))
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/endpoint-lineage/clusters":
            return httpx.Response(
                200,
                json={"clusters": [{"cluster_key": "device-11:proc-guid-1", "event_count": 4}]},
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/endpoint-lineage/clusters/device-11:proc-guid-1":
            return httpx.Response(
                200,
                json={"cluster": {"cluster_key": "device-11:proc-guid-1", "event_count": 4}},
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/endpoint-lineage/clusters/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["cluster_key"] == "device-11:proc-guid-1"
            return httpx.Response(200, json=_case_payload("case-lineage-cluster-1"))
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/hunt-telemetry/clusters":
            assert request.url.params["cluster_by"] == "remote_ip"
            return httpx.Response(
                200,
                json={"clusters": [{"cluster_key": "203.0.113.118", "event_count": 2}]},
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/hunt-telemetry/clusters/203.0.113.118":
            assert request.url.params["cluster_by"] == "remote_ip"
            return httpx.Response(
                200,
                json={"cluster": {"cluster_key": "203.0.113.118", "event_count": 2}},
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/hunt-telemetry/clusters/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["cluster_key"] == "203.0.113.118"
            return httpx.Response(200, json=_case_payload("case-hunt-cluster-1"))
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    alert_groups = connector.list_case_rule_alert_groups("case-1")
    alert_group = connector.get_case_rule_alert_group("case-1", "device-11:proc-guid-1")
    alert_group_case = connector.create_case_from_case_rule_alert_group(
        "case-1",
        SocCaseRuleGroupCaseRequest(group_key="device-11:proc-guid-1"),
    )
    evidence_groups = connector.list_case_rule_evidence_groups("case-1")
    evidence_group = connector.get_case_rule_evidence_group("case-1", "device-11")
    evidence_group_case = connector.create_case_from_case_rule_evidence_group(
        "case-1",
        SocCaseRuleGroupCaseRequest(group_key="device-11"),
    )
    timeline_clusters = connector.list_case_endpoint_timeline_clusters("case-1", cluster_by="process", limit=10)
    timeline_cluster = connector.get_case_endpoint_timeline_cluster(
        "case-1",
        cluster_by="process",
        cluster_key="device-11:proc-guid-1",
    )
    timeline_cluster_case = connector.create_case_from_case_endpoint_timeline_cluster(
        "case-1",
        SocCaseEndpointTimelineClusterCaseRequest(cluster_key="device-11:proc-guid-1"),
    )
    lineage_clusters = connector.list_case_endpoint_lineage_clusters("case-1", limit=10)
    lineage_cluster = connector.get_case_endpoint_lineage_cluster(
        "case-1",
        cluster_key="device-11:proc-guid-1",
    )
    lineage_cluster_case = connector.create_case_from_case_endpoint_lineage_cluster(
        "case-1",
        SocCaseEndpointLineageClusterCaseRequest(cluster_key="device-11:proc-guid-1"),
    )
    hunt_clusters = connector.list_case_hunt_telemetry_clusters("case-1", cluster_by="remote_ip", limit=10)
    hunt_cluster = connector.get_case_hunt_telemetry_cluster(
        "case-1",
        cluster_by="remote_ip",
        cluster_key="203.0.113.118",
    )
    hunt_cluster_case = connector.create_case_from_case_hunt_telemetry_cluster(
        "case-1",
        SocCaseTelemetryClusterCaseRequest(cluster_by="remote_ip", cluster_key="203.0.113.118"),
    )

    assert alert_groups[0]["group_key"] == "device-11:proc-guid-1"
    assert cast(list[dict[str, object]], alert_group["alerts"])[0]["alert_id"] == "alert-11"
    assert alert_group_case["case_id"] == "case-alert-group-1"
    assert evidence_groups[0]["group_key"] == "device-11"
    assert cast(list[dict[str, object]], evidence_group["events"])[0]["event_id"] == "evt-file-1"
    assert evidence_group_case["case_id"] == "case-evidence-group-1"
    assert cast(list[dict[str, object]], timeline_clusters["clusters"])[0]["cluster_key"] == "device-11:proc-guid-1"
    assert timeline_cluster["event_count"] == 3
    assert timeline_cluster_case["case_id"] == "case-timeline-cluster-1"
    assert cast(list[dict[str, object]], lineage_clusters["clusters"])[0]["cluster_key"] == "device-11:proc-guid-1"
    assert lineage_cluster["event_count"] == 4
    assert lineage_cluster_case["case_id"] == "case-lineage-cluster-1"
    assert cast(list[dict[str, object]], hunt_clusters["clusters"])[0]["cluster_key"] == "203.0.113.118"
    assert hunt_cluster["event_count"] == 2
    assert hunt_cluster_case["case_id"] == "case-hunt-cluster-1"


def test_remote_soc_dashboard_connector_exposes_detection_rule_group_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-alert-groups":
            return httpx.Response(
                200,
                json={"groups": [{"group_key": "device-11:proc-guid-1", "alert_count": 1}]},
            )
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-alert-groups/device-11:proc-guid-1":
            return httpx.Response(
                200,
                json={"group": {"group_key": "device-11:proc-guid-1", "alerts": [{"alert_id": "alert-11"}]}},
            )
        if request.method == "POST" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-alert-groups/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["group_key"] == "device-11:proc-guid-1"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-detection-alert-group-1",
                    "title": "Investigate endpoint timeline device-11:proc-guid-1",
                    "summary": "Endpoint timeline investigation",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "observables": [],
                    "assignee": None,
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-evidence-groups":
            return httpx.Response(
                200,
                json={"groups": [{"group_key": "device-11", "event_count": 3}]},
            )
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-evidence-groups/device-11":
            return httpx.Response(
                200,
                json={"group": {"group_key": "device-11", "events": [{"event_id": "evt-file-1"}]}},
            )
        if request.method == "POST" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-evidence-groups/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["group_key"] == "device-11"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-detection-evidence-group-1",
                    "title": "Investigate endpoint timeline device-11",
                    "summary": "Endpoint timeline investigation",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "observables": [],
                    "assignee": None,
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    alert_groups = connector.list_detection_rule_alert_groups("endpoint_timeline_execution_chain")
    alert_group = connector.get_detection_rule_alert_group(
        "endpoint_timeline_execution_chain",
        "device-11:proc-guid-1",
    )
    alert_group_case = connector.create_case_from_detection_rule_alert_group(
        "endpoint_timeline_execution_chain",
        SocCaseRuleGroupCaseRequest(group_key="device-11:proc-guid-1"),
    )
    evidence_groups = connector.list_detection_rule_evidence_groups("endpoint_timeline_execution_chain")
    evidence_group = connector.get_detection_rule_evidence_group(
        "endpoint_timeline_execution_chain",
        "device-11",
    )
    evidence_group_case = connector.create_case_from_detection_rule_evidence_group(
        "endpoint_timeline_execution_chain",
        SocCaseRuleGroupCaseRequest(group_key="device-11"),
    )

    assert alert_groups[0]["group_key"] == "device-11:proc-guid-1"
    assert cast(list[dict[str, object]], alert_group["alerts"])[0]["alert_id"] == "alert-11"
    assert alert_group_case["case_id"] == "case-detection-alert-group-1"
    assert evidence_groups[0]["group_key"] == "device-11"
    assert cast(list[dict[str, object]], evidence_group["events"])[0]["event_id"] == "evt-file-1"
    assert evidence_group_case["case_id"] == "case-detection-evidence-group-1"


def test_remote_soc_dashboard_connector_exposes_detection_rule_action_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/detections":
            return httpx.Response(
                200,
                json={
                    "rules": [
                        {
                            "rule_id": "endpoint_timeline_execution_chain",
                            "title": "Endpoint timeline execution chain",
                            "description": "Timeline rule",
                            "category": "correlation",
                            "enabled": True,
                            "parameters": {"window_minutes": 30},
                            "hit_count": 2,
                            "open_alert_count": 1,
                            "last_match_at": None,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain":
            return httpx.Response(
                200,
                json={
                    "rule_id": "endpoint_timeline_execution_chain",
                    "title": "Endpoint timeline execution chain",
                    "description": "Timeline rule",
                    "category": "correlation",
                    "enabled": True,
                    "parameters": {"window_minutes": 30},
                    "hit_count": 2,
                    "open_alert_count": 1,
                    "last_match_at": None,
                },
            )
        if request.method == "PATCH" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["enabled"] is False
            assert body["parameters"]["window_minutes"] == 45
            return httpx.Response(
                200,
                json={
                    "rule_id": "endpoint_timeline_execution_chain",
                    "title": "Endpoint timeline execution chain",
                    "description": "Timeline rule",
                    "category": "correlation",
                    "enabled": False,
                    "parameters": {"window_minutes": 45},
                    "hit_count": 2,
                    "open_alert_count": 1,
                    "last_match_at": None,
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    rules = connector.list_detection_rules()
    rule = connector.get_detection_rule("endpoint_timeline_execution_chain")
    updated = connector.update_detection_rule(
        "endpoint_timeline_execution_chain",
        SocDetectionRuleUpdate(enabled=False, parameters={"window_minutes": 45}),
    )

    assert rules[0]["rule_id"] == "endpoint_timeline_execution_chain"
    assert rule["enabled"] is True
    assert updated["enabled"] is False
    assert cast(dict[str, object], updated["parameters"])["window_minutes"] == 45


def test_remote_soc_dashboard_connector_exposes_case_read_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/cases":
            return httpx.Response(
                200,
                json={
                    "cases": [
                        {
                            "case_id": "case-11",
                            "title": "Existing investigation",
                            "summary": "Investigate endpoint activity.",
                            "severity": "high",
                            "status": "open",
                            "linked_alert_ids": ["alert-11"],
                            "source_event_ids": ["evt-11"],
                            "observables": ["device:device-11"],
                            "assignee": "tier2",
                            "notes": [],
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:00:00+00:00",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-11":
            return httpx.Response(
                200,
                json={
                    "case_id": "case-11",
                    "title": "Existing investigation",
                    "summary": "Investigate endpoint activity.",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": ["alert-11"],
                    "source_event_ids": ["evt-11"],
                    "observables": ["device:device-11"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    cases = connector.list_cases()
    case_payload = connector.get_case("case-11")

    assert cases[0]["case_id"] == "case-11"
    assert case_payload["title"] == "Existing investigation"


def test_remote_soc_dashboard_connector_exposes_alert_read_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/alerts":
            return httpx.Response(
                200,
                json={
                    "alerts": [
                        {
                            "alert_id": "alert-11",
                            "title": "Endpoint timeline execution chain",
                            "summary": "Suspicious endpoint timeline activity.",
                            "severity": "high",
                            "status": "open",
                            "source_event_ids": ["evt-11"],
                            "linked_case_id": "case-11",
                            "assignee": "tier2",
                            "correlation_rule": "endpoint_timeline_execution_chain",
                            "correlation_key": "device-11:proc-guid-11",
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:00:00+00:00",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/alerts/alert-11":
            return httpx.Response(
                200,
                json={
                    "alert_id": "alert-11",
                    "title": "Endpoint timeline execution chain",
                    "summary": "Suspicious endpoint timeline activity.",
                    "severity": "high",
                    "status": "open",
                    "source_event_ids": ["evt-11"],
                    "linked_case_id": "case-11",
                    "assignee": "tier2",
                    "correlation_rule": "endpoint_timeline_execution_chain",
                    "correlation_key": "device-11:proc-guid-11",
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    alerts = connector.list_alerts()
    alert_payload = connector.get_alert("alert-11")

    assert alerts[0]["alert_id"] == "alert-11"
    assert alert_payload["linked_case_id"] == "case-11"


def test_remote_soc_dashboard_connector_exposes_alert_and_case_update_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH" and request.url.path == "/soc/alerts/alert-11":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["status"] == "acknowledged"
            assert body["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "alert_id": "alert-11",
                    "title": "Endpoint timeline execution chain",
                    "summary": "Suspicious endpoint timeline activity.",
                    "severity": "high",
                    "status": "acknowledged",
                    "source_event_ids": ["evt-11"],
                    "linked_case_id": "case-11",
                    "assignee": "tier2",
                    "correlation_rule": "endpoint_timeline_execution_chain",
                    "correlation_key": "device-11:proc-guid-11",
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:05:00+00:00",
                },
            )
        if request.method == "PATCH" and request.url.path == "/soc/cases/case-11":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["status"] == "investigating"
            assert body["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-11",
                    "title": "Existing investigation",
                    "summary": "Investigate endpoint activity.",
                    "severity": "high",
                    "status": "investigating",
                    "linked_alert_ids": ["alert-11"],
                    "source_event_ids": ["evt-11"],
                    "observables": ["device:device-11"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:05:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    updated_alert = connector.update_alert("alert-11", SocAlertUpdate(status=SocAlertStatus.acknowledged, assignee="tier2"))
    updated_case = connector.update_case("case-11", SocCaseUpdate(status=SocCaseStatus.investigating, assignee="tier2"))

    assert updated_alert["status"] == "acknowledged"
    assert updated_case["status"] == "investigating"


def test_remote_soc_dashboard_connector_exposes_event_index_endpoint_query_and_capture_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/events":
            assert request.url.params["close_reason"] == "idle-timeout"
            assert request.url.params["reject_code"] == "access-reject"
            return httpx.Response(
                200,
                json={
                    "events": [
                        {
                            "event_id": "evt-ops-11",
                            "event_type": "network.telemetry.vpn",
                            "source": "sensor-auth",
                            "severity": "high",
                            "title": "VPN session closed",
                            "summary": "VPN session closed because of idle timeout.",
                            "details": {"close_reason": "idle-timeout"},
                            "tags": ["network", "telemetry", "vpn"],
                            "artifacts": [],
                            "created_at": "2026-04-01T04:00:00+00:00",
                            "linked_alert_id": None,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/hunt":
            assert request.url.params["close_reason"] == "idle-timeout"
            assert request.url.params["reject_code"] == "access-reject"
            return httpx.Response(200, json={"events": [{"event_id": "evt-hunt-11"}], "match_count": 1, "facets": {}, "summaries": {}, "timeline": {"bucket_unit": "hour", "buckets": []}})
        if request.method == "GET" and request.url.path == "/soc/events/index":
            return httpx.Response(200, json={"event_count": 7, "document_count": 7, "status": "ready"})
        if request.method == "POST" and request.url.path == "/soc/events/index/rebuild":
            return httpx.Response(200, json={"event_count": 7, "document_count": 7, "status": "rebuilt"})
        if request.method == "GET" and request.url.path == "/soc/cases":
            return httpx.Response(
                200,
                json={
                    "cases": [
                        {
                            "case_id": "case-11",
                            "title": "Identity case",
                            "summary": "Identity case",
                            "severity": "high",
                            "status": "investigating",
                            "linked_alert_ids": ["alert-11"],
                            "source_event_ids": ["evt-ops-11"],
                            "observables": [],
                            "assignee": "tier2",
                            "notes": [],
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:00:00+00:00",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/alerts":
            assert request.url.params["limit"] == "10"
            return httpx.Response(
                200,
                json={
                    "alerts": [
                        {
                            "alert_id": "alert-11",
                            "title": "Auth failure burst",
                            "summary": "Repeated auth failures",
                            "severity": "high",
                            "status": "open",
                            "source_event_ids": ["evt-ops-11"],
                            "linked_case_id": "case-11",
                            "assignee": None,
                            "correlation_rule": "network_auth_failure_burst",
                            "correlation_key": "tier1@example.test",
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:05:00+00:00",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/query":
            assert request.url.params["document_type"] == "endpoint.telemetry.file"
            assert request.url.params["parent_process_name"] == "cmd.exe"
            return httpx.Response(200, json={"match_count": 1, "events": [{"event_id": "evt-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/flows":
            assert request.url.params["process_name"] == "svchost.exe"
            return httpx.Response(200, json={"flows": [{"event_id": "flow-11"}], "retention_hours": 24.0})
        if request.method == "GET" and request.url.path == "/network/telemetry/dns":
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(200, json={"dns_records": [{"event_id": "dns-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/http":
            assert request.url.params["hostname"] == "example.test"
            return httpx.Response(200, json={"http_records": [{"event_id": "http-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/tls":
            assert request.url.params["limit"] == "5"
            return httpx.Response(200, json={"tls_records": [{"event_id": "tls-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/certificates":
            assert request.url.params["hostname"] == "example.test"
            return httpx.Response(200, json={"certificate_records": [{"event_id": "cert-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/proxy":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"proxy_records": [{"event_id": "proxy-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/auth":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"auth_records": [{"event_id": "auth-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/vpn":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"vpn_records": [{"event_id": "vpn-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/dhcp":
            assert request.url.params["assigned_ip"] == "10.0.0.25"
            return httpx.Response(200, json={"dhcp_records": [{"event_id": "dhcp-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/directory-auth":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"directory_auth_records": [{"event_id": "dirauth-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/radius":
            assert request.url.params["username"] == "tier1"
            return httpx.Response(200, json={"radius_records": [{"event_id": "radius-11"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/nac":
            assert request.url.params["device_id"] == "device-11"
            return httpx.Response(200, json={"nac_records": [{"event_id": "nac-11"}]})
        if request.method == "GET" and request.url.path == "/network/packet-sessions":
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(200, json={"sessions": [{"session_key": "packet-session:8.8.8.8"}]})
        if request.method == "GET" and request.url.path == "/network/evidence":
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(200, json={"evidence": [{"remote_ip": "8.8.8.8", "title": "Network evidence for 8.8.8.8"}]})
        if request.method == "GET" and request.url.path == "/packet/telemetry/captures":
            assert request.url.params["limit"] == "15"
            return httpx.Response(200, json={"captures": [{"capture_id": "cap-11"}]})
        if request.method == "GET" and request.url.path == "/packet/telemetry/captures/cap-11":
            return httpx.Response(200, json={"capture": {"capture_id": "cap-11", "has_text": True}})
        if request.method == "GET" and request.url.path == "/packet/telemetry/captures/cap-11/text":
            return httpx.Response(200, json={"capture_id": "cap-11", "text": "packet text"})
        if request.method == "POST" and request.url.path == "/network/packet-sessions/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["session_key"] == "packet-session:8.8.8.8"
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"case_id": "case-session-11", "title": "session", "summary": "session", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        if request.method == "POST" and request.url.path == "/network/evidence/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["remote_ip"] == "8.8.8.8"
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"case_id": "case-evidence-11", "title": "evidence", "summary": "evidence", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": [], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        if request.method == "POST" and request.url.path == "/soc/alerts/alert-11/case":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"alert": {"alert_id": "alert-11", "title": "Auth failure burst", "summary": "Repeated auth failures", "severity": "high", "status": "acknowledged", "source_event_ids": ["evt-ops-11"], "linked_case_id": "case-identity-11", "assignee": "tier2", "correlation_rule": "network_auth_failure_burst", "correlation_key": "tier1@example.test", "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:05:00+00:00"}, "case": {"case_id": "case-identity-11", "title": "identity", "summary": "identity", "severity": "high", "status": "investigating", "linked_alert_ids": ["alert-11"], "source_event_ids": ["evt-ops-11"], "observables": [], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"}})
        if request.method == "GET" and request.url.path == "/soc/events/evt-ops-11":
            return httpx.Response(200, json={"event_id": "evt-ops-11", "event_type": "network.telemetry.auth", "source": "sensor", "severity": "high", "title": "Auth failures", "summary": "Repeated auth failures", "details": {}, "artifacts": ["username:tier1"], "tags": ["identity"], "created_at": "2026-03-31T00:00:00+00:00", "linked_alert_id": "alert-11"})
        if request.method == "POST" and request.url.path == "/soc/cases":
            body = cast(dict[str, Any], json.loads(request.content))
            assert body["source_event_ids"] == ["evt-ops-11"]
            assert body["assignee"] == "tier2"
            return httpx.Response(200, json={"case_id": "case-event-11", "title": "Auth failures", "summary": "Repeated auth failures", "severity": "high", "status": "open", "linked_alert_ids": [], "source_event_ids": ["evt-ops-11"], "observables": ["username:tier1"], "assignee": "tier2", "notes": [], "created_at": "2026-03-31T00:00:00+00:00", "updated_at": "2026-03-31T00:00:00+00:00"})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    events = connector.query_events(close_reason="idle-timeout", reject_code="access-reject")
    hunt_payload = connector.hunt(close_reason="idle-timeout", reject_code="access-reject")
    status = connector.get_event_index_status()
    rebuilt = connector.rebuild_event_index()
    endpoint_query = connector.query_endpoint_telemetry(
        document_type="endpoint.telemetry.file",
        parent_process_name="cmd.exe",
    )
    flows = connector.list_network_telemetry_flows(process_name="svchost.exe")
    dns_records = connector.list_network_telemetry_dns(remote_ip="8.8.8.8")
    http_records = connector.list_network_telemetry_http(hostname="example.test")
    tls_records = connector.list_network_telemetry_tls(limit=5)
    certificate_records = connector.list_network_telemetry_certificates(hostname="example.test")
    proxy_records = connector.list_network_telemetry_proxy(username="tier1")
    auth_records = connector.list_network_telemetry_auth(username="tier1")
    vpn_records = connector.list_network_telemetry_vpn(username="tier1")
    dhcp_records = connector.list_network_telemetry_dhcp(assigned_ip="10.0.0.25")
    directory_auth_records = connector.list_network_telemetry_directory_auth(username="tier1")
    radius_records = connector.list_network_telemetry_radius(username="tier1")
    nac_records = connector.list_network_telemetry_nac(device_id="device-11")
    packet_sessions = connector.list_packet_sessions(remote_ip="8.8.8.8")
    network_evidence = connector.list_network_evidence(remote_ip="8.8.8.8")
    identity_correlations = connector.list_identity_correlations(limit=10, severity="high")
    event_payload = connector.get_event("evt-ops-11")
    event_cases = connector.list_cases_for_event("evt-ops-11")
    opened_event_case = connector.open_event_case("evt-ops-11")
    session_case = connector.create_case_from_packet_session(
        {"session_key": "packet-session:8.8.8.8", "remote_ip": "8.8.8.8"},
        SocPacketSessionCaseRequest(session_key="packet-session:8.8.8.8", assignee="tier2"),
    )
    evidence_case = connector.create_case_from_network_evidence(
        {"remote_ip": "8.8.8.8"},
        SocNetworkEvidenceCaseRequest(remote_ip="8.8.8.8", assignee="tier2"),
    )
    event_case = connector.create_case_from_event("evt-ops-11", assignee="tier2")
    promoted = connector.promote_alert_to_case("alert-11", SocAlertPromoteCaseRequest(assignee="tier2"))
    captures = connector.list_packet_capture_artifacts(limit=15)
    capture = connector.get_packet_capture_artifact("cap-11")
    capture_text = connector.get_packet_capture_text("cap-11")

    assert events[0]["event_id"] == "evt-ops-11"
    assert hunt_payload["match_count"] == 1
    assert status["status"] == "ready"
    assert rebuilt["status"] == "rebuilt"
    assert endpoint_query["match_count"] == 1
    assert flows[0]["event_id"] == "flow-11"
    assert dns_records[0]["event_id"] == "dns-11"
    assert http_records[0]["event_id"] == "http-11"
    assert tls_records[0]["event_id"] == "tls-11"
    assert certificate_records[0]["event_id"] == "cert-11"
    assert proxy_records[0]["event_id"] == "proxy-11"
    assert auth_records[0]["event_id"] == "auth-11"
    assert vpn_records[0]["event_id"] == "vpn-11"
    assert dhcp_records[0]["event_id"] == "dhcp-11"
    assert directory_auth_records[0]["event_id"] == "dirauth-11"
    assert radius_records[0]["event_id"] == "radius-11"
    assert nac_records[0]["event_id"] == "nac-11"
    assert packet_sessions[0]["session_key"] == "packet-session:8.8.8.8"
    assert network_evidence[0]["remote_ip"] == "8.8.8.8"
    assert identity_correlations[0]["alert_id"] == "alert-11"
    assert event_payload["event_id"] == "evt-ops-11"
    assert event_cases[0]["case_id"] == "case-11"
    assert opened_event_case["case_id"] == "case-11"
    assert session_case["case_id"] == "case-session-11"
    assert evidence_case["case_id"] == "case-evidence-11"
    assert event_case["case_id"] == "case-event-11"
    assert cast(dict[str, Any], promoted["case"])["case_id"] == "case-identity-11"
    assert cast(list[dict[str, Any]], captures["captures"])[0]["capture_id"] == "cap-11"
    assert cast(dict[str, Any], capture["capture"])["capture_id"] == "cap-11"
    assert capture_text["text"] == "packet text"


def test_remote_soc_dashboard_connector_exposes_toolchain_runtime_project_and_job_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            return httpx.Response(
                200,
                json={
                    "summary": {"open_alerts": 0, "open_cases": 0},
                    "toolchain_runtime_status": {
                        "languages": {"count": 2},
                        "package_managers": {"count": 3},
                        "provisioning": {"pending_count": 1},
                    },
                    "view_state": {},
                    "summary_labels": {},
                },
            )
        if request.method == "GET" and request.url.path == "/toolchain/projects":
            assert request.url.params["root_path"] == "J:/workspace"
            return httpx.Response(
                200,
                json={
                    "projects": [
                        {
                            "project_id": "J:/workspace/python_app",
                            "title": "python_app",
                            "root_path": "J:/workspace/python_app",
                            "ecosystems": ["python"],
                            "manifest_files": ["pyproject.toml"],
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/toolchain/projects/J:/workspace/python_app":
            assert request.url.params["root_path"] == "J:/workspace"
            return httpx.Response(
                200,
                json={
                    "project": {
                        "project_id": "J:/workspace/python_app",
                        "title": "python_app",
                        "root_path": "J:/workspace/python_app",
                        "ecosystems": ["python"],
                        "manifest_files": ["pyproject.toml"],
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/toolchain/bootstrap/python":
            assert request.url.params["project_path"] == "J:/workspace"
            assert request.url.params["execute"] == "false"
            return httpx.Response(200, json={"target": {"target_id": "python", "status": "planned"}})
        if request.method == "POST" and request.url.path == "/toolchain/provider-templates/docker/scaffold":
            assert request.url.params["target_dir"] == "J:/workspace/scaffold"
            return httpx.Response(
                200,
                json={"provider_id": "docker", "files": {"manifest.json": "{\"provider_id\": \"docker\"}"}, "write": False},
            )
        if request.method == "GET" and request.url.path == "/toolchain/jobs":
            return httpx.Response(200, json={"jobs": [{"job_id": "snapshot_report", "status": "idle"}]})
        if request.method == "GET" and request.url.path == "/toolchain/jobs/snapshot_report":
            return httpx.Response(200, json={"job": {"job_id": "snapshot_report", "status": "idle"}})
        if request.method == "POST" and request.url.path == "/toolchain/jobs/snapshot_report/run":
            return httpx.Response(200, json={"job": {"job_id": "snapshot_report", "status": "completed"}})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    runtime_status = connector.read_toolchain_runtime_status()
    projects = connector.list_toolchain_projects(root_path="J:/workspace")
    project = connector.get_toolchain_project("J:/workspace/python_app", root_path="J:/workspace")
    bootstrap = connector.run_toolchain_bootstrap("python", project_path="J:/workspace")
    scaffold = connector.scaffold_toolchain_provider_template("docker", target_dir="J:/workspace/scaffold")
    jobs = connector.list_toolchain_jobs()
    job = connector.get_toolchain_job("snapshot_report")
    job_run = connector.run_toolchain_job("snapshot_report")

    assert cast(dict[str, Any], runtime_status["languages"])["count"] == 2
    assert projects[0]["project_id"] == "J:/workspace/python_app"
    assert project["title"] == "python_app"
    assert cast(dict[str, Any], bootstrap["target"])["status"] == "planned"
    assert cast(dict[str, Any], scaffold["files"])["manifest.json"] == "{\"provider_id\": \"docker\"}"
    assert jobs[0]["job_id"] == "snapshot_report"
    assert job["status"] == "idle"
    assert cast(dict[str, Any], job_run["job"])["status"] == "completed"


def test_remote_soc_dashboard_connector_exposes_toolchain_doctor_helpers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/toolchain/doctor":
            return httpx.Response(
                200,
                json={"status": "ok", "summary": "healthy", "checks": [{"check_id": "manifest", "status": "ok"}]},
            )
        if request.method == "POST" and request.url.path == "/toolchain/doctor/repair":
            assert request.url.params["force_reinstall"] == "true"
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "summary": "repaired",
                    "force_reinstall": True,
                    "actions": [{"action_id": "environment_write", "status": "ok"}],
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    connector = RemoteSocDashboardConnector(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    doctor_status = connector.get_toolchain_doctor()
    repair_status = connector.repair_toolchain_doctor(force_reinstall=True)

    assert doctor_status["status"] == "ok"
    assert cast(list[dict[str, Any]], doctor_status["checks"])[0]["check_id"] == "manifest"
    assert repair_status["status"] == "ok"
    assert cast(list[dict[str, Any]], repair_status["actions"])[0]["action_id"] == "environment_write"
