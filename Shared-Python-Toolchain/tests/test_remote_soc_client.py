from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast

import httpx

from security_gateway.models import (
    SocAlertStatus,
    SocAlertUpdate,
    SocCaseTelemetryClusterCaseRequest,
    SocTelemetryClusterCaseRequest,
)
from security_gateway.remote_soc_client import (
    RemoteNetworkMonitorClient,
    RemotePacketMonitorClient,
    RemotePlatformClient,
    RemoteSecurityOperationsClient,
    RemoteTrackerIntelClient,
)


def test_remote_security_operations_client_reads_dashboard_and_alerts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/dashboard":
            return httpx.Response(200, json={"summary": {"open_alerts": 1, "open_cases": 0}, "view_state": {}})
        if request.method == "GET" and request.url.path == "/soc/hunt":
            assert request.url.params["q"] == "185.146.173.20"
            assert request.url.params["source"] == "sensor-a"
            return httpx.Response(
                200,
                json={
                    "query": "185.146.173.20",
                    "filters": {"source": "sensor-a", "limit": 10},
                    "index": {"backend": "json-event-index", "indexed_event_count": 2, "token_count": 10},
                    "events": [],
                },
            )
        if request.method == "GET" and request.url.path == "/soc/alerts":
            assert request.url.params["status"] == "open"
            return httpx.Response(
                200,
                json={
                    "alerts": [
                        {
                            "alert_id": "alert-1",
                            "title": "Remote alert",
                            "summary": "Remote alert summary",
                            "severity": "high",
                            "category": "event",
                            "status": "open",
                            "source_event_ids": [],
                            "correlation_rule": None,
                            "correlation_key": None,
                            "linked_case_id": None,
                            "acknowledged_by": None,
                            "escalated_by": None,
                            "assignee": None,
                            "notes": [],
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:00:00+00:00",
                        }
                    ]
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSecurityOperationsClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    dashboard = client.dashboard()
    hunt = client.hunt(query="185.146.173.20", source="sensor-a", limit=10)
    alerts = client.list_alerts(status=SocAlertStatus.open)

    assert dashboard["summary"]["open_alerts"] == 1
    assert hunt["index"]["backend"] == "json-event-index"
    assert alerts[0].alert_id == "alert-1"


def test_remote_security_operations_client_passes_observable_filters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/hunt":
            assert request.url.params["hostname"] == "db-admin-01"
            assert request.url.params["filename"] == "bad.exe"
            assert request.url.params["artifact_path"] == "C:/temp/bad.exe"
            assert request.url.params["process_name"] == "powershell.exe"
            assert request.url.params["process_guid"] == "proc-guid-1"
            assert request.url.params["signer_name"] == "Unknown"
            assert request.url.params["sha256"] == "abc123"
            return httpx.Response(200, json={"query": "", "filters": {}, "index": {"backend": "json-event-index"}, "events": []})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSecurityOperationsClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    payload = client.hunt(
        hostname="db-admin-01",
        filename="bad.exe",
        artifact_path="C:/temp/bad.exe",
        process_name="powershell.exe",
        process_guid="proc-guid-1",
        signer_name="Unknown",
        sha256="abc123",
    )

    assert payload["index"]["backend"] == "json-event-index"


def test_remote_security_operations_client_passes_time_filters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/events":
            assert request.url.params["start_at"] == "2026-03-31T12:00:00+00:00"
            assert request.url.params["end_at"] == "2026-04-01T12:00:00+00:00"
            return httpx.Response(200, json={"events": []})
        if request.method == "GET" and request.url.path == "/soc/hunt":
            assert request.url.params["start_at"] == "2026-03-31T12:00:00+00:00"
            assert request.url.params["end_at"] == "2026-04-01T12:00:00+00:00"
            assert request.url.params["facet_limit"] == "3"
            return httpx.Response(
                200,
                json={
                    "query": "",
                    "filters": {"start_at": "2026-03-31T12:00:00+00:00", "end_at": "2026-04-01T12:00:00+00:00"},
                    "index": {"backend": "json-event-index"},
                    "match_count": 0,
                    "facets": {"source": [], "document_type": []},
                    "timeline": {"bucket_unit": "hour", "buckets": []},
                    "summaries": {"document_types": [], "severities": []},
                    "events": [],
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSecurityOperationsClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    client.query_events(
        start_at=datetime(2026, 3, 31, 12, 0, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 12, 0, tzinfo=UTC),
    )
    payload = client.hunt(
        start_at=datetime(2026, 3, 31, 12, 0, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 12, 0, tzinfo=UTC),
        facet_limit=3,
    )

    assert payload["index"]["backend"] == "json-event-index"
    assert payload["timeline"]["bucket_unit"] == "hour"
    assert payload["summaries"]["document_types"] == []


def test_remote_telemetry_summary_clients_use_http_endpoints() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/summary":
            assert request.url.params["device_id"] == "device-summary"
            assert request.url.params["start_at"] == "2026-04-01T00:00:00+00:00"
            assert request.url.params["end_at"] == "2026-04-01T02:00:00+00:00"
            assert request.url.params["facet_limit"] == "3"
            return httpx.Response(
                200,
                json={
                    "telemetry": "endpoint",
                    "match_count": 2,
                    "facets": {"document_type": [{"value": "endpoint_process", "count": 1}]},
                    "timeline": {"bucket_unit": "hour", "buckets": []},
                    "summaries": {"device_ids": [{"value": "device-summary", "count": 2}]},
                },
            )
        if request.method == "GET" and request.url.path == "/network/telemetry/summary":
            assert request.url.params["remote_ip"] == "203.0.113.77"
            assert request.url.params["facet_limit"] == "2"
            return httpx.Response(
                200,
                json={
                    "telemetry": "network",
                    "match_count": 1,
                    "retention_hours": 24,
                    "facets": {"remote_ip": [{"value": "203.0.113.77", "count": 1}]},
                    "timeline": {"bucket_unit": "hour", "buckets": []},
                    "summaries": {"remote_ips": [{"value": "203.0.113.77", "count": 1}]},
                },
            )
        if request.method == "GET" and request.url.path == "/packet/telemetry/summary":
            assert request.url.params["session_key"] == "packet-session:summary"
            assert request.url.params["facet_limit"] == "2"
            return httpx.Response(
                200,
                json={
                    "telemetry": "packet",
                    "match_count": 1,
                    "retention_hours": 24,
                    "facets": {"remote_ip": [{"value": "203.0.113.77", "count": 1}]},
                    "timeline": {"bucket_unit": "hour", "buckets": []},
                    "summaries": {"remote_ips": [{"value": "203.0.113.77", "count": 1}]},
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    transport = httpx.MockTransport(handler)
    soc_client = RemoteSecurityOperationsClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=transport,
    )
    network_client = RemoteNetworkMonitorClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=transport,
    )
    packet_client = RemotePacketMonitorClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=transport,
    )

    endpoint_summary = soc_client.summarize_endpoint_telemetry(
        device_id="device-summary",
        start_at=datetime(2026, 4, 1, 0, 0, tzinfo=UTC),
        end_at=datetime(2026, 4, 1, 2, 0, tzinfo=UTC),
        facet_limit=3,
    )
    network_summary = network_client.summarize_telemetry_connections(
        remote_ip="203.0.113.77",
        facet_limit=2,
    )
    packet_summary = packet_client.summarize_telemetry_sessions(
        session_key="packet-session:summary",
        facet_limit=2,
    )

    assert endpoint_summary["telemetry"] == "endpoint"
    assert endpoint_summary["match_count"] == 2
    assert network_summary["telemetry"] == "network"
    assert network_summary["retention_hours"] == 24
    assert packet_summary["telemetry"] == "packet"
    assert packet_summary["retention_hours"] == 24


def test_remote_security_operations_client_supports_hunt_telemetry_clusters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/hunt/telemetry/clusters":
            assert request.url.params["cluster_by"] == "remote_ip"
            assert request.url.params["remote_ip"] == "203.0.113.88"
            return httpx.Response(
                200,
                json={
                    "clusters": [
                        {
                            "cluster_by": "remote_ip",
                            "cluster_key": "203.0.113.88",
                            "event_count": 3,
                            "telemetry_kinds": {"endpoint": 1, "network": 1, "packet": 1},
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
                        "event_count": 3,
                        "events": [
                            {"event_id": "evt-endpoint-conn"},
                            {"event_id": "evt-network-conn"},
                            {"event_id": "evt-packet-session"},
                        ],
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/soc/hunt/telemetry/clusters/case":
            payload = cast(dict[str, Any], json.loads(request.content))
            assert payload["cluster_by"] == "remote_ip"
            assert payload["cluster_key"] == "203.0.113.88"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-telemetry-cluster",
                    "title": "Investigate remote_ip cluster 203.0.113.88",
                    "summary": "Investigate normalized telemetry records.",
                    "severity": "high",
                    "status": "open",
                    "source_event_ids": ["evt-endpoint-conn", "evt-network-conn", "evt-packet-session"],
                    "linked_alert_ids": [],
                    "observables": ["remote_ip:203.0.113.88"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-04-01T00:00:00+00:00",
                    "updated_at": "2026-04-01T00:00:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSecurityOperationsClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    clusters = client.list_hunt_telemetry_clusters(cluster_by="remote_ip", remote_ip="203.0.113.88")
    detail = client.get_hunt_telemetry_cluster("203.0.113.88", cluster_by="remote_ip")
    created = client.create_case_from_hunt_telemetry_cluster(
        SocTelemetryClusterCaseRequest(cluster_by="remote_ip", cluster_key="203.0.113.88", assignee="tier2")
    )

    assert clusters[0]["event_count"] == 3
    assert detail["cluster_key"] == "203.0.113.88"
    assert created.case_id == "case-telemetry-cluster"
    assert created.assignee == "tier2"


def test_remote_security_operations_client_supports_case_hunt_telemetry_clusters() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/hunt-telemetry/clusters":
            assert request.url.params["cluster_by"] == "remote_ip"
            return httpx.Response(
                200,
                json={
                    "clusters": [
                        {
                            "cluster_by": "remote_ip",
                            "cluster_key": "203.0.113.118",
                            "event_count": 3,
                        }
                    ],
                    "filters": {"case_id": "case-1", "cluster_by": "remote_ip"},
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/hunt-telemetry/clusters/203.0.113.118":
            assert request.url.params["cluster_by"] == "remote_ip"
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_by": "remote_ip",
                        "cluster_key": "203.0.113.118",
                        "event_count": 3,
                        "events": [{"event_id": "evt-1"}, {"event_id": "evt-2"}, {"event_id": "evt-3"}],
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/hunt-telemetry/clusters/case":
            payload = cast(dict[str, Any], json.loads(request.content))
            assert payload["cluster_by"] == "remote_ip"
            assert payload["cluster_key"] == "203.0.113.118"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-hunt-cluster-1",
                    "title": "Investigate remote_ip cluster 203.0.113.118",
                    "summary": "Investigate case-linked hunt telemetry cluster 203.0.113.118.",
                    "severity": "high",
                    "status": "open",
                    "source_event_ids": ["evt-1", "evt-2", "evt-3"],
                    "linked_alert_ids": [],
                    "observables": ["remote_ip:203.0.113.118"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-04-01T00:00:00+00:00",
                    "updated_at": "2026-04-01T00:00:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSecurityOperationsClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    listed = client.list_case_hunt_telemetry_clusters("case-1", cluster_by="remote_ip", limit=10)
    detail = client.get_case_hunt_telemetry_cluster("case-1", cluster_by="remote_ip", cluster_key="203.0.113.118")
    created = client.create_case_from_case_hunt_telemetry_cluster(
        "case-1",
        SocCaseTelemetryClusterCaseRequest(cluster_by="remote_ip", cluster_key="203.0.113.118", assignee="tier2"),
    )

    assert listed["clusters"][0]["cluster_key"] == "203.0.113.118"
    assert detail["cluster_key"] == "203.0.113.118"
    assert created.case_id == "case-hunt-cluster-1"
    assert created.assignee == "tier2"


def test_remote_security_operations_client_updates_alert() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH" and request.url.path == "/soc/alerts/alert-1":
            payload = cast(dict[str, Any], json.loads(request.content))
            assert payload["status"] == "acknowledged"
            assert payload["acted_by"] == "tier1"
            return httpx.Response(
                200,
                json={
                    "alert_id": "alert-1",
                    "title": "Remote alert",
                    "summary": "Remote alert summary",
                    "severity": "high",
                    "category": "event",
                    "status": "acknowledged",
                    "source_event_ids": [],
                    "correlation_rule": None,
                    "correlation_key": None,
                    "linked_case_id": None,
                    "acknowledged_by": "tier1",
                    "escalated_by": None,
                    "assignee": None,
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:05:00+00:00",
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSecurityOperationsClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    updated = client.update_alert("alert-1", SocAlertUpdate(status=SocAlertStatus.acknowledged, acted_by="tier1"))

    assert updated.status is SocAlertStatus.acknowledged
    assert updated.acknowledged_by == "tier1"


def test_remote_tracker_packet_and_network_clients_use_http_endpoints() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/privacy/tracker-feeds/status":
            return httpx.Response(200, json={"domain_count": 12, "is_stale": False})
        if request.method == "POST" and request.url.path == "/privacy/tracker-feeds/refresh":
            return httpx.Response(200, json={"domain_count": 15, "status": "refreshed"})
        if request.method == "GET" and request.url.path == "/network/packet-sessions":
            return httpx.Response(200, json={"sessions": [{"session_key": "packet-session:1", "remote_ip": "8.8.8.8"}]})
        if request.method == "GET" and request.url.path == "/packet/telemetry/sessions":
            return httpx.Response(200, json={"sessions": [{"details": {"session_key": "packet-session:1", "remote_ip": "8.8.8.8"}}]})
        if request.method == "GET" and request.url.path == "/network/observations":
            return httpx.Response(200, json={"observations": [{"remote_ip": "8.8.8.8", "last_seen_at": "2026-03-31T00:00:00+00:00"}]})
        if request.method == "GET" and request.url.path == "/network/telemetry/connections":
            return httpx.Response(200, json={"connections": [{"details": {"remote_ip": "8.8.8.8"}}]})
        if request.method == "GET" and request.url.path == "/network/evidence":
            return httpx.Response(
                200,
                json={
                    "evidence": [
                        {
                            "remote_ip": "8.8.8.8",
                            "network_observation": {"remote_ip": "8.8.8.8"},
                            "packet_sessions": [{"session_key": "packet-session:1", "remote_ip": "8.8.8.8"}],
                            "last_seen_at": "2026-03-31T00:00:00+00:00",
                            "related_alert_ids": ["alert-1"],
                            "related_case_ids": ["case-1"],
                            "open_case_ids": ["case-1"],
                            "open_case_count": 1,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/processes":
            assert request.url.params["process_guid"] == "proc-guid-1"
            assert request.url.params["signer_name"] == "Unknown"
            return httpx.Response(
                200,
                json={
                    "processes": [
                        {
                            "event_id": "evt-proc-1",
                            "event_type": "endpoint.telemetry.process",
                            "source": "security_gateway",
                            "severity": "high",
                            "title": "Endpoint process telemetry: powershell.exe",
                            "summary": "Endpoint device-11 reported process activity for powershell.exe.",
                            "details": {"process_name": "powershell.exe", "process_guid": "proc-guid-1", "signer_name": "Unknown", "sha256": "abc123"},
                            "artifacts": [],
                            "tags": ["endpoint", "telemetry", "process"],
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "linked_alert_id": None,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/files":
            assert request.url.params["signer_name"] == "Unknown"
            return httpx.Response(
                200,
                json={
                    "files": [
                        {
                            "event_id": "evt-file-1",
                            "event_type": "endpoint.telemetry.file",
                            "source": "security_gateway",
                            "severity": "high",
                            "title": "Endpoint file telemetry: payload.dll",
                            "summary": "Endpoint device-11 reported file activity for payload.dll.",
                            "details": {"filename": "payload.dll", "signer_name": "Unknown", "sha256": "feedface"},
                            "artifacts": [],
                            "tags": ["endpoint", "telemetry", "file"],
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "linked_alert_id": None,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/connections":
            assert request.url.params["process_guid"] == "proc-guid-1"
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(
                200,
                json={
                    "connections": [
                        {
                            "event_id": "evt-conn-1",
                            "event_type": "endpoint.telemetry.connection",
                            "source": "security_gateway",
                            "severity": "high",
                            "title": "Endpoint connection telemetry: powershell.exe",
                            "summary": "Endpoint device-11 reported a live connection for powershell.exe.",
                            "details": {"process_name": "powershell.exe", "process_guid": "proc-guid-1", "remote_ip": "8.8.8.8"},
                            "artifacts": [],
                            "tags": ["endpoint", "telemetry", "connection"],
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "linked_alert_id": None,
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/timeline":
            assert request.url.params["process_guid"] == "proc-guid-1"
            assert request.url.params["remote_ip"] == "8.8.8.8"
            return httpx.Response(
                200,
                json={
                    "timeline": [
                        {
                            "event_id": "evt-proc-1",
                            "event_type": "endpoint.telemetry.process",
                            "recorded_at": "2026-03-31T00:00:00+00:00",
                        },
                        {
                            "event_id": "evt-conn-1",
                            "event_type": "endpoint.telemetry.connection",
                            "recorded_at": "2026-03-31T00:01:00+00:00",
                        },
                    ],
                    "filters": {"process_guid": "proc-guid-1", "remote_ip": "8.8.8.8"},
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/timeline/clusters":
            assert request.url.params["cluster_by"] == "process"
            assert request.url.params["device_id"] == "device-11"
            return httpx.Response(
                200,
                json={
                    "clusters": [
                        {
                            "cluster_by": "process",
                            "cluster_key": "device-11:proc-guid-1",
                            "label": "device-11 / powershell.exe",
                            "event_count": 3,
                            "event_ids": ["evt-proc-1", "evt-conn-1", "evt-file-1"],
                        }
                    ],
                    "filters": {"cluster_by": "process", "device_id": "device-11"},
                },
            )
        if request.method == "GET" and request.url.path == "/endpoint/telemetry/timeline/clusters/device-11:proc-guid-1":
            assert request.url.params["cluster_by"] == "process"
            assert request.url.params["process_guid"] == "proc-guid-1"
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_by": "process",
                        "cluster_key": "device-11:proc-guid-1",
                        "label": "device-11 / powershell.exe",
                        "event_count": 3,
                        "event_ids": ["evt-proc-1", "evt-conn-1", "evt-file-1"],
                        "device_ids": ["device-11"],
                        "process_guids": ["proc-guid-1"],
                        "process_names": ["powershell.exe"],
                        "remote_ips": ["8.8.8.8"],
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/endpoint/telemetry/timeline/case":
            payload = cast(dict[str, Any], json.loads(request.content))
            assert payload["device_id"] == "device-11"
            assert payload["process_guid"] == "proc-guid-1"
            assert payload["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-timeline-1",
                    "title": "Investigate endpoint timeline device-11 / proc-guid-1",
                    "summary": "Endpoint timeline investigation",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": ["evt-proc-1", "evt-conn-1"],
                    "observables": ["device:device-11", "process_guid:proc-guid-1"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-alert-groups":
            return httpx.Response(
                200,
                json={
                    "groups": [
                        {
                            "group_key": "device-11:proc-guid-1",
                            "alert_count": 1,
                            "severity": "critical",
                            "title": "device-11:proc-guid-1",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-alert-groups/device-11:proc-guid-1":
            return httpx.Response(
                200,
                json={
                    "group": {
                        "group_key": "device-11:proc-guid-1",
                        "title": "device-11:proc-guid-1",
                        "alerts": [{"alert_id": "alert-11", "source_event_ids": ["evt-proc-1", "evt-conn-1", "evt-file-1"]}],
                        "open_case_ids": [],
                        "open_case_count": 0,
                    }
                },
            )
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-evidence-groups":
            return httpx.Response(
                200,
                json={
                    "groups": [
                        {
                            "group_key": "device-11",
                            "event_count": 3,
                            "severity": "high",
                            "title": "device-11",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/detections/endpoint_timeline_execution_chain/rule-evidence-groups/device-11":
            return httpx.Response(
                200,
                json={
                    "group": {
                        "group_key": "device-11",
                        "title": "device-11",
                        "events": [{"event_id": "evt-proc-1"}, {"event_id": "evt-conn-1"}, {"event_id": "evt-file-1"}],
                        "open_case_ids": [],
                        "open_case_count": 0,
                    }
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/rule-alert-groups":
            return httpx.Response(
                200,
                json={
                    "groups": [
                        {
                            "group_key": "device-11:proc-guid-1",
                            "alert_count": 1,
                            "severity": "critical",
                            "title": "device-11:proc-guid-1",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/rule-evidence-groups":
            return httpx.Response(
                200,
                json={
                    "groups": [
                        {
                            "group_key": "device-11",
                            "event_count": 2,
                            "severity": "high",
                            "title": "device-11",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/endpoint-timeline/clusters":
            assert request.url.params["cluster_by"] == "process"
            assert request.url.params["limit"] == "10"
            return httpx.Response(
                200,
                json={
                    "clusters": [
                        {
                            "cluster_by": "process",
                            "cluster_key": "device-11:proc-guid-1",
                            "label": "device-11 / powershell.exe",
                            "event_count": 3,
                        }
                    ],
                    "filters": {"case_id": "case-1", "cluster_by": "process", "limit": 10},
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/endpoint-timeline":
            assert request.url.params["limit"] == "10"
            assert request.url.params["process_guid"] == "proc-guid-1"
            return httpx.Response(
                200,
                json={
                    "events": [
                        {
                            "event_id": "evt-proc-1",
                            "event_type": "endpoint.telemetry.process",
                            "recorded_at": "2026-03-31T00:00:00+00:00",
                        }
                    ],
                    "filters": {"case_id": "case-1", "limit": 10, "process_guid": "proc-guid-1"},
                },
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/endpoint-timeline/clusters/case":
            payload = cast(dict[str, Any], json.loads(request.content))
            assert payload["cluster_by"] == "process"
            assert payload["cluster_key"] == "device-11:proc-guid-1"
            assert payload["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-timeline-cluster-1",
                    "title": "Investigate endpoint timeline device-11 / proc-guid-1",
                    "summary": "Endpoint timeline investigation",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": ["evt-proc-1", "evt-conn-1", "evt-file-1"],
                    "observables": ["device:device-11", "process_guid:proc-guid-1"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/rule-alert-groups/device-11:proc-guid-1":
            return httpx.Response(
                200,
                json={
                    "group": {
                        "group_key": "device-11:proc-guid-1",
                        "title": "device-11:proc-guid-1",
                        "alerts": [{"alert_id": "alert-11", "source_event_ids": ["evt-proc-1", "evt-conn-1", "evt-file-1"]}],
                        "open_case_ids": [],
                        "open_case_count": 0,
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/rule-alert-groups/case":
            payload = cast(dict[str, Any], json.loads(request.content))
            assert payload["group_key"] == "device-11:proc-guid-1"
            assert payload["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-rule-alert-1",
                    "title": "Investigate endpoint timeline device-11:proc-guid-1",
                    "summary": "Endpoint timeline investigation",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": ["evt-proc-1", "evt-conn-1", "evt-file-1"],
                    "observables": ["device:device-11", "process_guid:proc-guid-1"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/rule-evidence-groups/device-11":
            return httpx.Response(
                200,
                json={
                    "group": {
                        "group_key": "device-11",
                        "title": "device-11",
                        "events": [{"event_id": "evt-proc-1"}, {"event_id": "evt-conn-1"}, {"event_id": "evt-file-1"}],
                        "open_case_ids": [],
                        "open_case_count": 0,
                    }
                },
            )
        if request.method == "POST" and request.url.path == "/soc/cases/case-1/rule-evidence-groups/case":
            payload = cast(dict[str, Any], json.loads(request.content))
            assert payload["group_key"] == "device-11"
            assert payload["assignee"] == "tier2"
            return httpx.Response(
                200,
                json={
                    "case_id": "case-rule-evidence-1",
                    "title": "Investigate endpoint timeline device-11",
                    "summary": "Endpoint timeline investigation",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": ["evt-proc-1", "evt-conn-1", "evt-file-1"],
                    "observables": ["device:device-11", "process_guid:proc-guid-1"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/soc/cases/case-1/endpoint-timeline/clusters/device-11:proc-guid-1":
            assert request.url.params["cluster_by"] == "process"
            return httpx.Response(
                200,
                json={
                    "cluster": {
                        "cluster_key": "device-11:proc-guid-1",
                        "cluster_by": "process",
                        "label": "device-11 / powershell.exe",
                        "event_count": 3,
                        "device_ids": ["device-11"],
                        "process_guids": ["proc-guid-1"],
                        "process_names": ["powershell.exe"],
                        "remote_ips": ["8.8.8.8"],
                        "open_case_ids": [],
                        "open_case_count": 0,
                    }
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    transport = httpx.MockTransport(handler)
    soc = RemoteSecurityOperationsClient(base_url="https://manager.local", bearer_token="operator-token", transport=transport)
    tracker = RemoteTrackerIntelClient(base_url="https://manager.local", bearer_token="operator-token", transport=transport)
    packet = RemotePacketMonitorClient(base_url="https://manager.local", bearer_token="operator-token", transport=transport)
    network = RemoteNetworkMonitorClient(base_url="https://manager.local", bearer_token="operator-token", transport=transport)

    assert tracker.feed_status()["domain_count"] == 12
    assert tracker.refresh_feed_cache()["status"] == "refreshed"
    assert packet.list_recent_sessions(limit=10)[0]["session_key"] == "packet-session:1"
    assert packet.list_telemetry_sessions(limit=10)[0]["details"]["session_key"] == "packet-session:1"
    assert network.list_recent_observations(limit=10)[0]["remote_ip"] == "8.8.8.8"
    assert network.list_telemetry_connections(limit=10)[0]["details"]["remote_ip"] == "8.8.8.8"
    assert network.list_combined_evidence(limit=10)[0]["open_case_count"] == 1
    assert soc.list_endpoint_process_telemetry(limit=10, process_guid="proc-guid-1", signer_name="Unknown")[0].details["process_name"] == "powershell.exe"
    assert soc.list_endpoint_file_telemetry(limit=10, signer_name="Unknown")[0].details["filename"] == "payload.dll"
    assert soc.list_endpoint_connection_telemetry(limit=10, process_guid="proc-guid-1", remote_ip="8.8.8.8")[0].details["remote_ip"] == "8.8.8.8"
    assert soc.list_endpoint_timeline(limit=10, process_guid="proc-guid-1", remote_ip="8.8.8.8")["timeline"][1]["event_type"] == "endpoint.telemetry.connection"
    assert soc.list_endpoint_timeline_clusters(limit=10, cluster_by="process", device_id="device-11")["clusters"][0]["cluster_key"] == "device-11:proc-guid-1"
    assert soc.get_endpoint_timeline_cluster(cluster_by="process", cluster_key="device-11:proc-guid-1", process_guid="proc-guid-1")["event_count"] == 3
    assert soc.create_case_from_endpoint_timeline(
        device_id="device-11",
        process_guid="proc-guid-1",
        assignee="tier2",
    ).case_id == "case-timeline-1"
    assert soc.list_detection_rule_alert_groups("endpoint_timeline_execution_chain")[0]["group_key"] == "device-11:proc-guid-1"
    assert soc.get_detection_rule_alert_group("endpoint_timeline_execution_chain", "device-11:proc-guid-1")["alerts"][0]["alert_id"] == "alert-11"
    assert soc.list_detection_rule_evidence_groups("endpoint_timeline_execution_chain")[0]["group_key"] == "device-11"
    assert soc.get_detection_rule_evidence_group("endpoint_timeline_execution_chain", "device-11")["events"][2]["event_id"] == "evt-file-1"
    assert soc.list_case_rule_alert_groups("case-1")[0]["group_key"] == "device-11:proc-guid-1"
    assert soc.get_case_rule_alert_group("case-1", "device-11:proc-guid-1")["alerts"][0]["alert_id"] == "alert-11"
    assert soc.create_case_from_case_rule_alert_group(
        "case-1",
        group_key="device-11:proc-guid-1",
        assignee="tier2",
    ).case_id == "case-rule-alert-1"
    assert soc.list_case_rule_evidence_groups("case-1")[0]["group_key"] == "device-11"
    assert soc.get_case_rule_evidence_group("case-1", "device-11")["events"][2]["event_id"] == "evt-file-1"
    assert soc.create_case_from_case_rule_evidence_group(
        "case-1",
        group_key="device-11",
        assignee="tier2",
    ).case_id == "case-rule-evidence-1"
    assert soc.list_case_endpoint_timeline("case-1", limit=10, process_guid="proc-guid-1")["events"][0]["event_id"] == "evt-proc-1"
    assert soc.get_case_endpoint_timeline_cluster("case-1", cluster_by="process", cluster_key="device-11:proc-guid-1")["event_count"] == 3
    assert soc.create_case_from_case_endpoint_timeline_cluster(
        "case-1",
        cluster_by="process",
        cluster_key="device-11:proc-guid-1",
        assignee="tier2",
    ).case_id == "case-timeline-cluster-1"
    assert soc.list_case_endpoint_timeline_clusters("case-1", cluster_by="process", limit=10)["clusters"][0]["cluster_key"] == "device-11:proc-guid-1"


def test_remote_security_operations_client_routes_platform_node_actions_over_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = cast(dict[str, Any], json.loads(request.content)) if request.content else {}
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/acknowledge":
            assert payload["acknowledged_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "acknowledged_by": "tier2"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/suppress":
            assert payload["minutes"] == 30
            assert payload["suppressed_by"] == "tier2"
            assert payload["scopes"] == ["remote_node_health"]
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "suppressed_until": "2026-03-31T01:00:00+00:00"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/maintenance":
            assert payload["minutes"] == 45
            assert payload["started_by"] == "tier2"
            assert payload["services"] == ["packet_monitor"]
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "maintenance_status": "requested"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/refresh":
            assert payload["requested_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "refresh_status": "requested"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/drain":
            assert payload["drained_by"] == "tier2"
            assert payload["services"] == ["packet_monitor", "network_monitor"]
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "drain_status": "requested"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/actions/refresh/retry":
            assert payload["acted_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "refresh_status": "requested"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/actions/drain/cancel":
            assert payload["acted_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "drain_status": "cancelled"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/clear-suppression":
            return httpx.Response(200, json={"node": {"node_name": "sensor-a"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/clear-maintenance":
            return httpx.Response(200, json={"node": {"node_name": "sensor-a"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/ready":
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "drain_status": "inactive"}})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemoteSecurityOperationsClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    assert client.acknowledge_platform_node("sensor-a", acknowledged_by="tier2")["acknowledged_by"] == "tier2"
    assert client.suppress_platform_node(
        "sensor-a",
        minutes=30,
        suppressed_by="tier2",
        scopes=["remote_node_health"],
    )["node_name"] == "sensor-a"
    assert client.start_platform_node_maintenance(
        "sensor-a",
        minutes=45,
        maintenance_by="tier2",
        services=["packet_monitor"],
    )["maintenance_status"] == "requested"
    assert client.request_platform_node_refresh("sensor-a", requested_by="tier2")["refresh_status"] == "requested"
    assert client.start_platform_node_drain(
        "sensor-a",
        drained_by="tier2",
        services=["packet_monitor", "network_monitor"],
    )["drain_status"] == "requested"
    assert client.retry_platform_node_action("sensor-a", action="refresh", requested_by="tier2")["refresh_status"] == "requested"
    assert client.cancel_platform_node_action("sensor-a", action="drain", cancelled_by="tier2")["drain_status"] == "cancelled"
    assert client.clear_platform_node_suppression("sensor-a")["node_name"] == "sensor-a"
    assert client.clear_platform_node_maintenance("sensor-a")["node_name"] == "sensor-a"
    assert client.clear_platform_node_drain("sensor-a")["drain_status"] == "inactive"


def test_remote_platform_client_reads_remote_nodes_and_detail_over_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/platform/nodes":
            return httpx.Response(
                200,
                json={
                    "topology": {
                        "remote_nodes": [
                            {"node_name": "sensor-a", "status": "healthy"},
                            {"node_name": "search-a", "status": "degraded"},
                        ]
                    }
                },
            )
        if request.method == "GET" and request.url.path == "/platform/nodes/sensor-a":
            return httpx.Response(
                200,
                json={"node": {"node_name": "sensor-a", "status": "healthy", "open_case_count": 1}},
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemotePlatformClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    nodes = client.list_remote_nodes(limit=10)
    detail = client.get_platform_node_detail("sensor-a")

    assert [node["node_name"] for node in nodes] == ["sensor-a", "search-a"]
    assert detail["open_case_count"] == 1


def test_remote_platform_client_routes_platform_node_actions_over_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = cast(dict[str, Any], json.loads(request.content)) if request.content else {}
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/acknowledge":
            assert payload["acknowledged_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "acknowledged_by": "tier2"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/suppress":
            assert payload["minutes"] == 30
            assert payload["suppressed_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/clear-suppression":
            return httpx.Response(200, json={"node": {"node_name": "sensor-a"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/maintenance":
            assert payload["minutes"] == 45
            assert payload["started_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "maintenance_status": "requested"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/clear-maintenance":
            return httpx.Response(200, json={"node": {"node_name": "sensor-a"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/refresh":
            assert payload["requested_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "refresh_status": "requested"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/drain":
            assert payload["drained_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "drain_status": "requested"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/ready":
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "drain_status": "inactive"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/actions/refresh/retry":
            assert payload["acted_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "refresh_status": "requested"}})
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/actions/drain/cancel":
            assert payload["acted_by"] == "tier2"
            return httpx.Response(200, json={"node": {"node_name": "sensor-a", "drain_status": "cancelled"}})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemotePlatformClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    assert client.acknowledge_platform_node("sensor-a", acknowledged_by="tier2")["acknowledged_by"] == "tier2"
    assert client.suppress_platform_node("sensor-a", minutes=30, suppressed_by="tier2")["node_name"] == "sensor-a"
    assert client.clear_platform_node_suppression("sensor-a")["node_name"] == "sensor-a"
    assert client.start_platform_node_maintenance("sensor-a", minutes=45, maintenance_by="tier2")["maintenance_status"] == "requested"
    assert client.clear_platform_node_maintenance("sensor-a")["node_name"] == "sensor-a"
    assert client.request_platform_node_refresh("sensor-a", requested_by="tier2")["refresh_status"] == "requested"
    assert client.start_platform_node_drain("sensor-a", drained_by="tier2")["drain_status"] == "requested"
    assert client.clear_platform_node_drain("sensor-a")["drain_status"] == "inactive"
    assert client.retry_platform_node_action("sensor-a", action="refresh", requested_by="tier2")["refresh_status"] == "requested"
    assert client.cancel_platform_node_action("sensor-a", action="drain", cancelled_by="tier2")["drain_status"] == "cancelled"


def test_remote_platform_client_creates_and_resolves_remote_node_cases_over_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/platform/nodes/sensor-a/case":
            return httpx.Response(
                200,
                json={
                    "case_id": "case-1",
                    "title": "Investigate remote node sensor-a",
                    "summary": "Remote node investigation",
                    "severity": "high",
                    "status": "open",
                    "linked_alert_ids": [],
                    "source_event_ids": [],
                    "observables": ["node:sensor-a"],
                    "assignee": "tier2",
                    "notes": [],
                    "created_at": "2026-03-31T00:00:00+00:00",
                    "updated_at": "2026-03-31T00:00:00+00:00",
                },
            )
        if request.method == "GET" and request.url.path == "/platform/nodes/sensor-a/cases":
            return httpx.Response(
                200,
                json={
                    "node_name": "sensor-a",
                    "cases": [
                        {
                            "case_id": "case-1",
                            "title": "Investigate remote node sensor-a",
                            "summary": "Remote node investigation",
                            "severity": "high",
                            "status": "open",
                            "linked_alert_ids": [],
                            "source_event_ids": [],
                            "observables": ["node:sensor-a"],
                            "assignee": "tier2",
                            "notes": [],
                            "created_at": "2026-03-31T00:00:00+00:00",
                            "updated_at": "2026-03-31T00:00:00+00:00",
                        }
                    ],
                },
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = RemotePlatformClient(
        base_url="https://manager.local",
        bearer_token="operator-token",
        transport=httpx.MockTransport(handler),
    )

    case = client.create_case_from_remote_node({"node_name": "sensor-a"})
    cases = client.resolve_remote_node_cases({"node_name": "sensor-a"})

    assert case.case_id == "case-1"
    assert [item.case_id for item in cases] == ["case-1"]
