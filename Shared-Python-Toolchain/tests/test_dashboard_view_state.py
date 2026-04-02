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
from security_gateway.models import SocDashboardViewStateUpdate
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
        )
    )

    assert written["operational_reason_filter"] == "stuck action"
    assert written["hunt_cluster_mode"] == "device_id"
    assert written["hunt_cluster_value"] == "device-11"
    assert written["hunt_cluster_key"] == "cluster-11"
    assert written["hunt_cluster_action"] == "case"
    assert client.read()["operational_reason_filter"] == "stuck action"
    assert client.read()["hunt_cluster_mode"] == "device_id"
    assert client.read()["hunt_cluster_value"] == "device-11"
    assert client.read()["hunt_cluster_key"] == "cluster-11"
    assert client.read()["hunt_cluster_action"] == "case"
    assert json.loads((tmp_path / "view_state.json").read_text(encoding="utf-8")) == {
        "operational_reason_filter": "stuck action",
        "hunt_cluster_mode": "device_id",
        "hunt_cluster_value": "device-11",
        "hunt_cluster_key": "cluster-11",
        "hunt_cluster_action": "case",
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
    updated = client.write(
        SocDashboardViewStateUpdate(
            operational_reason_filter="action failed",
            hunt_cluster_mode="device_id",
            hunt_cluster_value="device-22",
            hunt_cluster_key="cluster-33",
            hunt_cluster_action="case",
        )
    )

    assert updated["operational_reason_filter"] == "action failed"
    assert updated["hunt_cluster_mode"] == "device_id"
    assert updated["hunt_cluster_value"] == "device-22"
    assert updated["hunt_cluster_key"] == "cluster-33"
    assert updated["hunt_cluster_action"] == "case"
    assert len(calls) == 1
    assert calls[0].operational_reason_filter == "action failed"
    assert calls[0].hunt_cluster_mode == "device_id"
    assert calls[0].hunt_cluster_value == "device-22"
    assert calls[0].hunt_cluster_key == "cluster-33"
    assert calls[0].hunt_cluster_action == "case"


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
                    }
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
    updated = client.write(
        SocDashboardViewStateUpdate(
            operational_reason_filter="retry pressure",
            hunt_cluster_mode="process_guid",
            hunt_cluster_value="proc-guid-1",
            hunt_cluster_key="cluster-44",
            hunt_cluster_action="details",
        )
    )

    assert updated["operational_reason_filter"] == "retry pressure"
    assert updated["hunt_cluster_mode"] == "process_guid"
    assert updated["hunt_cluster_value"] == "proc-guid-1"
    assert updated["hunt_cluster_key"] == "cluster-44"
    assert updated["hunt_cluster_action"] == "details"


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
