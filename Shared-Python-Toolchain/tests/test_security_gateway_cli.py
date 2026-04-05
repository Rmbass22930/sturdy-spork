from typer.testing import CliRunner
import json

from security_gateway import cli


runner = CliRunner()


def test_report_list_command_runs(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli.settings, "report_output_dir", str(tmp_path / "reports"))
    result = runner.invoke(cli.app, ["report-list"])

    assert result.exit_code == 0
    assert "'reports': []" in result.stdout


def test_report_pdf_command_accepts_filters(monkeypatch, tmp_path) -> None:
    calls = []

    def fake_write(output, **kwargs):
        calls.append((output, kwargs))
        target = tmp_path / "reports" / "filtered.pdf"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"%PDF-sample")
        return target

    monkeypatch.setattr(cli.report_builder, "write_summary_pdf", fake_write)
    result = runner.invoke(
        cli.app,
        [
            "report-pdf",
            "--max-events", "12",
            "--time-window-hours", "24",
            "--min-risk-score", "60",
            "--no-events",
        ],
    )

    assert result.exit_code == 0
    assert calls
    _, kwargs = calls[0]
    assert kwargs["max_events"] == 12
    assert kwargs["time_window_hours"] == 24.0
    assert kwargs["min_risk_score"] == 60.0
    assert kwargs["include_recent_events"] is False


def test_soc_dashboard_command_uses_local_dashboard_by_default(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(cli.settings, "platform_manager_url", None)
    monkeypatch.setattr(cli, "run_soc_dashboard", lambda manager=None: calls.append(("local", manager)))
    monkeypatch.setattr(
        cli,
        "run_remote_soc_dashboard",
        lambda **kwargs: calls.append(("remote", kwargs)),
    )

    result = runner.invoke(cli.app, ["soc-dashboard"])

    assert result.exit_code == 0
    assert calls == [("local", None)]


def test_soc_dashboard_command_uses_configured_remote_dashboard(monkeypatch) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(cli.settings, "platform_manager_url", "https://manager.local")
    monkeypatch.setattr(cli.settings, "platform_manager_bearer_token", "operator-token")
    monkeypatch.setattr(cli.settings, "platform_manager_timeout_seconds", 7.5)
    monkeypatch.setattr(cli, "run_soc_dashboard", lambda manager=None: (_ for _ in ()).throw(AssertionError("local dashboard should not be used")))
    monkeypatch.setattr(cli, "run_remote_soc_dashboard", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(cli.app, ["soc-dashboard"])

    assert result.exit_code == 0
    assert calls == [
        {
            "base_url": "https://manager.local",
            "bearer_token": "operator-token",
            "timeout_seconds": 7.5,
        }
    ]


def test_soc_dashboard_command_errors_when_remote_requested_without_url(monkeypatch) -> None:
    monkeypatch.setattr(cli.settings, "platform_manager_url", None)

    result = runner.invoke(cli.app, ["soc-dashboard", "--remote"])

    assert result.exit_code == 1
    assert "no manager url is configured" in result.stderr.lower()


def test_soc_dashboard_command_errors_when_nonlocal_remote_has_no_token(monkeypatch) -> None:
    monkeypatch.setattr(cli.settings, "platform_manager_url", "https://manager.local")
    monkeypatch.setattr(cli.settings, "platform_manager_bearer_token", None)

    result = runner.invoke(cli.app, ["soc-dashboard"])

    assert result.exit_code == 1
    assert "no bearer token is configured" in result.stderr.lower()


def test_soc_remote_dashboard_command_reads_dashboard(monkeypatch) -> None:
    class Client:
        def dashboard(self) -> dict[str, object]:
            return {"summary": {"open_alerts": 1}}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "dashboard"])

    assert result.exit_code == 0
    assert "'open_alerts': 1" in result.stdout


def test_soc_remote_get_alert_command_reads_alert(monkeypatch) -> None:
    class Client:
        def get_alert(self, alert_id: str) -> dict[str, object]:
            assert alert_id == "alert-11"
            return {"alert_id": "alert-11", "status": "open"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "get-alert", "alert-11"])

    assert result.exit_code == 0
    assert "'alert_id': 'alert-11'" in result.stdout


def test_soc_remote_list_alerts_command_reads_alerts(monkeypatch) -> None:
    class Client:
        def list_alerts(self, **kwargs: object) -> list[dict[str, object]]:
            assert getattr(kwargs["severity"], "value", None) == "high"
            assert kwargs["assignee"] == "tier2"
            assert kwargs["limit"] == 25
            assert str(kwargs["correlation_rule"]) == "endpoint_timeline_execution_chain"
            assert kwargs["linked_case_state"] == "linked"
            assert kwargs["sort"] == "severity_desc"
            return [{"alert_id": "alert-11", "status": "open"}]

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "list-alerts",
            "--severity",
            "high",
            "--assignee",
            "tier2",
            "--limit",
            "25",
            "--correlation-rule",
            "endpoint_timeline_execution_chain",
            "--linked-case-state",
            "linked",
            "--sort",
            "severity_desc",
        ],
    )

    assert result.exit_code == 0
    assert "'alert_id': 'alert-11'" in result.stdout


def test_soc_remote_list_cases_command_reads_cases(monkeypatch) -> None:
    class Client:
        def list_cases(self, **kwargs: object) -> list[dict[str, object]]:
            assert getattr(kwargs["status"], "value", None) == "open"
            assert getattr(kwargs["severity"], "value", None) == "critical"
            assert kwargs["assignee"] == "tier2"
            assert kwargs["sort"] == "severity_desc"
            return [{"case_id": "case-11", "status": "open"}]

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        ["soc-remote", "list-cases", "--status", "open", "--severity", "critical", "--assignee", "tier2", "--sort", "severity_desc"],
    )

    assert result.exit_code == 0
    assert "'case_id': 'case-11'" in result.stdout


def test_soc_remote_case_entity_commands_read_linked_entities_and_timeline(monkeypatch) -> None:
    class Client:
        def list_case_linked_alerts(self, case_id: str) -> list[dict[str, object]]:
            assert case_id == "case-11"
            return [{"alert_id": "alert-11"}]

        def list_case_source_events(self, case_id: str) -> list[dict[str, object]]:
            assert case_id == "case-11"
            return [{"event_id": "evt-11"}]

        def list_case_endpoint_timeline(self, case_id: str, **kwargs: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert kwargs["process_guid"] == "proc-guid-11"
            return {"events": [{"event_id": "evt-11"}], "event_count": 1}

        def list_case_rule_alerts(self, case_id: str, group_key: str) -> list[dict[str, object]]:
            assert case_id == "case-11"
            assert group_key == "alert-group-11"
            return [{"alert_id": "alert-21"}]

        def list_case_rule_evidence_events(self, case_id: str, group_key: str) -> list[dict[str, object]]:
            assert case_id == "case-11"
            assert group_key == "evidence-group-11"
            return [{"event_id": "evt-21"}]

        def list_case_endpoint_lineage_events(self, case_id: str, **kwargs: object) -> list[dict[str, object]]:
            assert case_id == "case-11"
            assert kwargs["cluster_key"] == "lineage-11"
            assert kwargs["limit"] == 25
            return [{"event_id": "evt-lineage-11"}]

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    alerts_result = runner.invoke(cli.app, ["soc-remote", "list-case-alerts", "case-11"])
    events_result = runner.invoke(cli.app, ["soc-remote", "list-case-events", "case-11"])
    timeline_result = runner.invoke(
        cli.app,
        ["soc-remote", "list-case-timeline-events", "case-11", "--process-guid", "proc-guid-11"],
    )
    rule_alerts_result = runner.invoke(
        cli.app,
        ["soc-remote", "list-case-rule-alerts", "case-11", "alert-group-11"],
    )
    rule_evidence_result = runner.invoke(
        cli.app,
        ["soc-remote", "list-case-rule-evidence-events", "case-11", "evidence-group-11"],
    )
    lineage_result = runner.invoke(
        cli.app,
        ["soc-remote", "list-case-lineage-events", "case-11", "lineage-11", "--limit", "25"],
    )

    assert alerts_result.exit_code == 0
    assert "'alert_id': 'alert-11'" in alerts_result.stdout
    assert events_result.exit_code == 0
    assert "'event_id': 'evt-11'" in events_result.stdout
    assert timeline_result.exit_code == 0
    assert "'event_id': 'evt-11'" in timeline_result.stdout
    assert rule_alerts_result.exit_code == 0
    assert "'alert_id': 'alert-21'" in rule_alerts_result.stdout
    assert rule_evidence_result.exit_code == 0
    assert "'event_id': 'evt-21'" in rule_evidence_result.stdout
    assert lineage_result.exit_code == 0
    assert "'event_id': 'evt-lineage-11'" in lineage_result.stdout


def test_soc_remote_get_rule_command_reads_rule(monkeypatch) -> None:
    class Client:
        def get_detection_rule(self, rule_id: str) -> dict[str, object]:
            assert rule_id == "endpoint_timeline_execution_chain"
            return {"rule_id": rule_id, "enabled": True}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "get-rule", "endpoint_timeline_execution_chain"])

    assert result.exit_code == 0
    assert "'rule_id': 'endpoint_timeline_execution_chain'" in result.stdout


def test_soc_remote_list_rule_groups_command_reads_alert_groups(monkeypatch) -> None:
    class Client:
        def list_detection_rule_alert_groups(self, rule_id: str) -> list[dict[str, object]]:
            assert rule_id == "endpoint_timeline_execution_chain"
            return [{"group_key": "device-11:proc-guid-11", "alert_count": 1}]

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "list-rule-groups", "endpoint_timeline_execution_chain"])

    assert result.exit_code == 0
    assert "'group_key': 'device-11:proc-guid-11'" in result.stdout


def test_soc_remote_list_rule_groups_command_rejects_invalid_kind(monkeypatch) -> None:
    class Client:
        def list_detection_rule_alert_groups(self, rule_id: str) -> list[dict[str, object]]:
            raise AssertionError("should not be called")

        def list_detection_rule_evidence_groups(self, rule_id: str) -> list[dict[str, object]]:
            raise AssertionError("should not be called")

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "list-rule-groups", "endpoint_timeline_execution_chain", "--kind", "bad"])

    assert result.exit_code == 1
    assert "must be 'alerts' or 'evidence'" in result.stderr


def test_soc_remote_event_index_and_endpoint_query_commands(monkeypatch) -> None:
    class Client:
        def query_events(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["close_reason"] == "idle-timeout"
            assert kwargs["reject_code"] == "access-reject"
            assert kwargs["limit"] == 15
            return [{"event_id": "evt-ops-11"}]

        def hunt(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["close_reason"] == "idle-timeout"
            assert kwargs["reject_code"] == "access-reject"
            assert kwargs["facet_limit"] == 4
            return {"match_count": 1, "events": [{"event_id": "evt-hunt-11"}]}

        def get_event_index_status(self) -> dict[str, object]:
            return {"status": "ready", "event_count": 9}

        def rebuild_event_index(self) -> dict[str, object]:
            return {"status": "rebuilt", "event_count": 9}

        def query_endpoint_telemetry(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["document_type"] == "endpoint.telemetry.file"
            assert kwargs["parent_process_name"] == "cmd.exe"
            assert kwargs["artifact_path"] == "C:/Temp/payload.dll"
            assert kwargs["local_ip"] == "10.0.0.5"
            assert kwargs["limit"] == 25
            return {"match_count": 1, "events": [{"event_id": "evt-11"}]}

        def create_case_from_endpoint_query(self, payload: object) -> dict[str, object]:
            assert getattr(payload, "artifact_path", None) == "C:/Temp/payload.dll"
            assert getattr(payload, "operation", None) == "write"
            assert getattr(payload, "assignee", None) == "tier2"
            return {"case_id": "case-endpoint-query-11"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    query_events_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "query-events",
            "--close-reason",
            "idle-timeout",
            "--reject-code",
            "access-reject",
            "--limit",
            "15",
        ],
    )
    hunt_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "hunt",
            "--close-reason",
            "idle-timeout",
            "--reject-code",
            "access-reject",
            "--facet-limit",
            "4",
        ],
    )
    status_result = runner.invoke(cli.app, ["soc-remote", "event-index-status"])
    rebuild_result = runner.invoke(cli.app, ["soc-remote", "rebuild-event-index"])
    endpoint_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "query-endpoint-telemetry",
            "--document-type",
            "endpoint.telemetry.file",
            "--parent-process-name",
            "cmd.exe",
            "--artifact-path",
            "C:/Temp/payload.dll",
            "--local-ip",
            "10.0.0.5",
            "--limit",
            "25",
        ],
    )
    endpoint_case_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-endpoint-query",
            "--artifact-path",
            "C:/Temp/payload.dll",
            "--operation",
            "write",
            "--assignee",
            "tier2",
        ],
    )

    assert query_events_result.exit_code == 0
    assert "'event_id': 'evt-ops-11'" in query_events_result.stdout
    assert hunt_result.exit_code == 0
    assert "'event_id': 'evt-hunt-11'" in hunt_result.stdout
    assert status_result.exit_code == 0
    assert "'status': 'ready'" in status_result.stdout
    assert rebuild_result.exit_code == 0
    assert "'status': 'rebuilt'" in rebuild_result.stdout
    assert endpoint_result.exit_code == 0
    assert "'event_id': 'evt-11'" in endpoint_result.stdout
    assert endpoint_case_result.exit_code == 0
    assert "'case_id': 'case-endpoint-query-11'" in endpoint_case_result.stdout


def test_soc_remote_network_flow_and_packet_capture_commands(monkeypatch) -> None:
    class Client:
        def list_network_telemetry_flows(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["process_name"] == "svchost.exe"
            assert kwargs["flow_id"] == "flow:tcp:8.8.8.8:51000:10.0.0.5:8443:4242"
            assert kwargs["service_name"] == "https-alt"
            assert kwargs["application_protocol"] == "https-alt"
            assert kwargs["local_port"] == 8443
            return {"flows": [{"event_id": "flow-11"}]}

        def list_packet_capture_artifacts(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["limit"] == 15
            assert kwargs["remote_ip"] == "8.8.8.8"
            assert kwargs["protocol"] == "tcp"
            return {"captures": [{"capture_id": "cap-11"}]}

        def get_packet_capture_artifact(self, capture_id: str) -> dict[str, object]:
            assert capture_id == "cap-11"
            return {"capture": {"capture_id": "cap-11"}}

        def get_packet_capture_text(self, capture_id: str) -> dict[str, object]:
            assert capture_id == "cap-11"
            return {"capture_id": "cap-11", "text": "packet text"}

        def create_case_from_packet_capture(self, capture_id: str, payload: object) -> dict[str, object]:
            assert capture_id == "cap-11"
            assert getattr(payload, "session_key", None) == "packet-session:8.8.8.8"
            assert getattr(payload, "assignee", None) == "tier2"
            return {"case_id": "case-capture-11"}

        def list_network_telemetry_dns(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["remote_ip"] == "8.8.8.8"
            assert kwargs["limit"] == 10
            return [{"event_id": "dns-11"}]

        def list_network_telemetry_http(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["hostname"] == "example.test"
            return [{"event_id": "http-11"}]

        def list_network_telemetry_tls(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["hostname"] == "example.test"
            assert kwargs["limit"] == 5
            return [{"event_id": "tls-11"}]

        def list_network_telemetry_certificates(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["hostname"] == "example.test"
            return [{"event_id": "cert-11"}]

        def list_network_telemetry_proxy(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["username"] == "tier1"
            return [{"event_id": "proxy-11"}]

        def list_network_telemetry_auth(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["username"] == "tier1"
            return [{"event_id": "auth-11"}]

        def list_network_telemetry_vpn(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["username"] == "tier1"
            return [{"event_id": "vpn-11"}]

        def list_network_telemetry_dhcp(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["assigned_ip"] == "10.0.0.25"
            return [{"event_id": "dhcp-11"}]

        def list_network_telemetry_directory_auth(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["username"] == "tier1"
            return [{"event_id": "dirauth-11"}]

        def list_network_telemetry_radius(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["username"] == "tier1"
            return [{"event_id": "radius-11"}]

        def list_network_telemetry_nac(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["device_id"] == "device-11"
            return [{"event_id": "nac-11"}]

        def list_packet_sessions(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["remote_ip"] == "8.8.8.8"
            assert kwargs["limit"] == 12
            return [{"session_key": "packet-session:8.8.8.8"}]

        def list_network_evidence(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["remote_ip"] == "8.8.8.8"
            assert kwargs["limit"] == 8
            return [{"remote_ip": "8.8.8.8"}]

        def list_identity_correlations(self, **kwargs: object) -> list[dict[str, object]]:
            assert kwargs["severity"] == "high"
            assert kwargs["limit"] == 6
            return [{"alert_id": "alert-identity-11"}]

        def get_event(self, event_id: str) -> dict[str, object]:
            assert event_id == "evt-ops-11"
            return {"event_id": "evt-ops-11", "title": "Auth failures"}

        def list_cases_for_event(self, event_id: str) -> list[dict[str, object]]:
            assert event_id == "evt-ops-11"
            return [{"case_id": "case-event-11"}]

        def open_event_case(self, event_id: str) -> dict[str, object]:
            assert event_id == "evt-ops-11"
            return {"case_id": "case-event-11"}

        def create_case_from_event(self, event_id: str, **kwargs: object) -> dict[str, object]:
            assert event_id == "evt-ops-11"
            assert kwargs["assignee"] == "tier2"
            assert kwargs["severity"] == "high"
            return {"case_id": "case-event-11"}

        def create_case_from_packet_session(self, session_payload: object, payload: object) -> dict[str, object]:
            assert getattr(payload, "session_key", None) == "packet-session:8.8.8.8"
            assert getattr(payload, "assignee", None) == "tier2"
            assert getattr(session_payload, "get", lambda *_args, **_kwargs: None)("remote_ip") == "8.8.8.8"
            return {"case_id": "case-session-11"}

        def create_case_from_network_evidence(self, evidence_payload: object, payload: object) -> dict[str, object]:
            assert getattr(payload, "remote_ip", None) == "8.8.8.8"
            assert getattr(payload, "assignee", None) == "tier2"
            assert getattr(evidence_payload, "get", lambda *_args, **_kwargs: None)("remote_ip") == "8.8.8.8"
            return {"case_id": "case-evidence-11"}

        def promote_alert_to_case(self, alert_id: str, payload: object) -> dict[str, object]:
            assert alert_id == "alert-identity-11"
            assert getattr(payload, "assignee", None) == "tier2"
            assert getattr(payload, "acted_by", None) == "analyst"
            return {"case": {"case_id": "case-identity-11"}}

        def get_alert(self, alert_id: str) -> dict[str, object]:
            assert alert_id == "alert-identity-11"
            return {"alert_id": "alert-identity-11", "linked_case_id": "case-identity-11"}

        def get_case(self, case_id: str) -> dict[str, object]:
            assert case_id == "case-identity-11"
            return {"case_id": "case-identity-11"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    flow_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "list-network-flows",
            "--process-name",
            "svchost.exe",
            "--flow-id",
            "flow:tcp:8.8.8.8:51000:10.0.0.5:8443:4242",
            "--service-name",
            "https-alt",
            "--application-protocol",
            "https-alt",
            "--local-port",
            "8443",
        ],
    )
    dns_result = runner.invoke(cli.app, ["soc-remote", "list-network-dns", "--remote-ip", "8.8.8.8", "--limit", "10"])
    http_result = runner.invoke(cli.app, ["soc-remote", "list-network-http", "--hostname", "example.test"])
    tls_result = runner.invoke(cli.app, ["soc-remote", "list-network-tls", "--hostname", "example.test", "--limit", "5"])
    cert_result = runner.invoke(cli.app, ["soc-remote", "list-network-certificates", "--hostname", "example.test"])
    proxy_result = runner.invoke(cli.app, ["soc-remote", "list-network-proxy", "--username", "tier1"])
    auth_result = runner.invoke(cli.app, ["soc-remote", "list-network-auth", "--username", "tier1"])
    vpn_result = runner.invoke(cli.app, ["soc-remote", "list-network-vpn", "--username", "tier1"])
    dhcp_result = runner.invoke(cli.app, ["soc-remote", "list-network-dhcp", "--assigned-ip", "10.0.0.25"])
    dirauth_result = runner.invoke(cli.app, ["soc-remote", "list-network-directory-auth", "--username", "tier1"])
    radius_result = runner.invoke(cli.app, ["soc-remote", "list-network-radius", "--username", "tier1"])
    nac_result = runner.invoke(cli.app, ["soc-remote", "list-network-nac", "--device-id", "device-11"])
    packet_sessions_result = runner.invoke(cli.app, ["soc-remote", "list-packet-sessions", "--remote-ip", "8.8.8.8", "--limit", "12"])
    network_evidence_result = runner.invoke(cli.app, ["soc-remote", "list-network-evidence", "--remote-ip", "8.8.8.8", "--limit", "8"])
    identity_correlations_result = runner.invoke(cli.app, ["soc-remote", "list-identity-correlations", "--severity", "high", "--limit", "6"])
    get_event_result = runner.invoke(cli.app, ["soc-remote", "get-event", "evt-ops-11"])
    list_event_cases_result = runner.invoke(cli.app, ["soc-remote", "list-event-cases", "evt-ops-11"])
    open_event_case_result = runner.invoke(cli.app, ["soc-remote", "open-event-case", "evt-ops-11"])
    list_capture_result = runner.invoke(
        cli.app,
        ["soc-remote", "list-packet-captures", "--limit", "15", "--remote-ip", "8.8.8.8", "--protocol", "tcp"],
    )
    get_capture_result = runner.invoke(cli.app, ["soc-remote", "get-packet-capture", "cap-11"])
    text_capture_result = runner.invoke(cli.app, ["soc-remote", "get-packet-capture-text", "cap-11"])
    create_case_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-packet-capture",
            "cap-11",
            "--session-key",
            "packet-session:8.8.8.8",
            "--assignee",
            "tier2",
        ],
    )
    create_session_case_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-packet-session",
            "packet-session:8.8.8.8",
            "--remote-ip",
            "8.8.8.8",
            "--assignee",
            "tier2",
        ],
    )
    create_evidence_case_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-network-evidence",
            "8.8.8.8",
            "--assignee",
            "tier2",
        ],
    )
    create_event_case_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-event",
            "evt-ops-11",
            "--assignee",
            "tier2",
            "--severity",
            "high",
        ],
    )
    create_identity_case_result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-identity-correlation",
            "alert-identity-11",
            "--assignee",
            "tier2",
            "--acted-by",
            "analyst",
        ],
    )
    open_identity_case_result = runner.invoke(cli.app, ["soc-remote", "open-identity-correlation-case", "alert-identity-11"])

    assert flow_result.exit_code == 0
    assert "'event_id': 'flow-11'" in flow_result.stdout
    assert dns_result.exit_code == 0
    assert "'event_id': 'dns-11'" in dns_result.stdout
    assert http_result.exit_code == 0
    assert "'event_id': 'http-11'" in http_result.stdout
    assert tls_result.exit_code == 0
    assert "'event_id': 'tls-11'" in tls_result.stdout
    assert cert_result.exit_code == 0
    assert "'event_id': 'cert-11'" in cert_result.stdout
    assert proxy_result.exit_code == 0
    assert "'event_id': 'proxy-11'" in proxy_result.stdout
    assert auth_result.exit_code == 0
    assert "'event_id': 'auth-11'" in auth_result.stdout
    assert vpn_result.exit_code == 0
    assert "'event_id': 'vpn-11'" in vpn_result.stdout
    assert dhcp_result.exit_code == 0
    assert "'event_id': 'dhcp-11'" in dhcp_result.stdout
    assert dirauth_result.exit_code == 0
    assert "'event_id': 'dirauth-11'" in dirauth_result.stdout
    assert radius_result.exit_code == 0
    assert "'event_id': 'radius-11'" in radius_result.stdout
    assert nac_result.exit_code == 0
    assert "'event_id': 'nac-11'" in nac_result.stdout
    assert packet_sessions_result.exit_code == 0
    assert "packet-session:8.8.8.8" in packet_sessions_result.stdout
    assert network_evidence_result.exit_code == 0
    assert "'remote_ip': '8.8.8.8'" in network_evidence_result.stdout
    assert identity_correlations_result.exit_code == 0
    assert "alert-identity-11" in identity_correlations_result.stdout
    assert get_event_result.exit_code == 0
    assert "'event_id': 'evt-ops-11'" in get_event_result.stdout
    assert list_event_cases_result.exit_code == 0
    assert "'case_id': 'case-event-11'" in list_event_cases_result.stdout
    assert open_event_case_result.exit_code == 0
    assert "'case_id': 'case-event-11'" in open_event_case_result.stdout
    assert list_capture_result.exit_code == 0
    assert "'capture_id': 'cap-11'" in list_capture_result.stdout
    assert get_capture_result.exit_code == 0
    assert "'capture_id': 'cap-11'" in get_capture_result.stdout
    assert text_capture_result.exit_code == 0
    assert "packet text" in text_capture_result.stdout
    assert create_case_result.exit_code == 0
    assert "'case_id': 'case-capture-11'" in create_case_result.stdout
    assert create_session_case_result.exit_code == 0
    assert "'case_id': 'case-session-11'" in create_session_case_result.stdout
    assert create_evidence_case_result.exit_code == 0
    assert "'case_id': 'case-evidence-11'" in create_evidence_case_result.stdout
    assert create_event_case_result.exit_code == 0
    assert "'case_id': 'case-event-11'" in create_event_case_result.stdout
    assert create_identity_case_result.exit_code == 0
    assert "'case_id': 'case-identity-11'" in create_identity_case_result.stdout
    assert open_identity_case_result.exit_code == 0
    assert "'case_id': 'case-identity-11'" in open_identity_case_result.stdout


def test_soc_remote_list_hunt_clusters_command_reads_clusters(monkeypatch) -> None:
    class Client:
        def list_hunt_telemetry_clusters(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["cluster_by"] == "device_id"
            assert kwargs["device_id"] == "device-11"
            assert kwargs["process_guid"] == "proc-guid-11"
            assert kwargs["remote_ip"] == "8.8.8.8"
            assert kwargs["limit"] == 25
            return {"clusters": [{"cluster_key": "device-11", "event_count": 3}]}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "list-hunt-clusters",
            "--cluster-by",
            "device_id",
            "--device-id",
            "device-11",
            "--process-guid",
            "proc-guid-11",
            "--remote-ip",
            "8.8.8.8",
            "--limit",
            "25",
        ],
    )

    assert result.exit_code == 0
    assert "'cluster_key': 'device-11'" in result.stdout


def test_soc_remote_get_hunt_cluster_command_reads_cluster(monkeypatch) -> None:
    class Client:
        def get_hunt_telemetry_cluster(self, cluster_key: str, **kwargs: object) -> dict[str, object]:
            assert cluster_key == "remote-ip-11"
            assert kwargs["cluster_by"] == "remote_ip"
            assert kwargs["limit"] == 10
            return {"cluster_key": cluster_key, "event_count": 3}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        ["soc-remote", "get-hunt-cluster", "remote-ip-11", "--cluster-by", "remote_ip", "--limit", "10"],
    )

    assert result.exit_code == 0
    assert "'cluster_key': 'remote-ip-11'" in result.stdout


def test_soc_remote_list_timeline_clusters_command_reads_clusters(monkeypatch) -> None:
    class Client:
        def list_endpoint_timeline_clusters(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["cluster_by"] == "remote_ip"
            assert kwargs["limit"] == 20
            return {"clusters": [{"cluster_key": "timeline-11", "event_count": 4}]}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        ["soc-remote", "list-timeline-clusters", "--cluster-by", "remote_ip", "--limit", "20"],
    )

    assert result.exit_code == 0
    assert "'cluster_key': 'timeline-11'" in result.stdout


def test_soc_remote_get_timeline_cluster_command_reads_cluster(monkeypatch) -> None:
    class Client:
        def get_endpoint_timeline_cluster(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["cluster_key"] == "timeline-11"
            assert kwargs["cluster_by"] == "process"
            assert kwargs["device_id"] == "device-11"
            assert kwargs["process_name"] == "powershell.exe"
            assert kwargs["remote_ip"] == "8.8.8.8"
            assert kwargs["limit"] == 12
            return {"cluster_key": "timeline-11", "event_count": 4}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "get-timeline-cluster",
            "timeline-11",
            "--cluster-by",
            "process",
            "--device-id",
            "device-11",
            "--process-name",
            "powershell.exe",
            "--remote-ip",
            "8.8.8.8",
            "--limit",
            "12",
        ],
    )

    assert result.exit_code == 0
    assert "'cluster_key': 'timeline-11'" in result.stdout


def test_soc_remote_list_lineage_clusters_command_reads_clusters(monkeypatch) -> None:
    class Client:
        def list_endpoint_lineage_clusters(self, **kwargs: object) -> dict[str, object]:
            assert kwargs["limit"] == 15
            return {"clusters": [{"cluster_key": "lineage-11", "event_count": 5}]}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "list-lineage-clusters", "--limit", "15"])

    assert result.exit_code == 0
    assert "'cluster_key': 'lineage-11'" in result.stdout


def test_soc_remote_get_lineage_cluster_command_reads_cluster(monkeypatch) -> None:
    class Client:
        def get_endpoint_lineage_cluster(self, cluster_key: str, **kwargs: object) -> dict[str, object]:
            assert cluster_key == "lineage-11"
            assert kwargs["device_id"] == "device-11"
            assert kwargs["process_guid"] == "proc-guid-11"
            assert kwargs["limit"] == 18
            return {"cluster_key": cluster_key, "event_count": 5}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "get-lineage-cluster",
            "lineage-11",
            "--device-id",
            "device-11",
            "--process-guid",
            "proc-guid-11",
            "--limit",
            "18",
        ],
    )

    assert result.exit_code == 0
    assert "'cluster_key': 'lineage-11'" in result.stdout


def test_soc_remote_case_cluster_commands_read_and_promote_clusters(monkeypatch) -> None:
    class Client:
        def list_case_hunt_telemetry_clusters(self, case_id: str, **kwargs: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert kwargs["cluster_by"] == "remote_ip"
            return {"clusters": [{"cluster_key": "hunt-11"}]}

        def get_case_hunt_telemetry_cluster(self, case_id: str, **kwargs: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert kwargs["cluster_key"] == "hunt-11"
            return {"cluster_key": "hunt-11"}

        def create_case_from_case_hunt_telemetry_cluster(self, case_id: str, payload: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert getattr(payload, "cluster_key", None) == "hunt-11"
            return {"case_id": "case-hunt-22"}

        def list_case_endpoint_timeline_clusters(self, case_id: str, **kwargs: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert kwargs["cluster_by"] == "process"
            return {"clusters": [{"cluster_key": "timeline-11"}]}

        def get_case_endpoint_timeline_cluster(self, case_id: str, **kwargs: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert kwargs["cluster_key"] == "timeline-11"
            return {"cluster_key": "timeline-11"}

        def create_case_from_case_endpoint_timeline_cluster(self, case_id: str, payload: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert getattr(payload, "cluster_key", None) == "timeline-11"
            return {"case_id": "case-timeline-22"}

        def list_case_endpoint_lineage_clusters(self, case_id: str, **kwargs: object) -> dict[str, object]:
            assert case_id == "case-11"
            return {"clusters": [{"cluster_key": "lineage-11"}]}

        def get_case_endpoint_lineage_cluster(self, case_id: str, **kwargs: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert kwargs["cluster_key"] == "lineage-11"
            return {"cluster_key": "lineage-11"}

        def create_case_from_case_endpoint_lineage_cluster(self, case_id: str, payload: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert getattr(payload, "cluster_key", None) == "lineage-11"
            return {"case_id": "case-lineage-22"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    commands = [
        (["soc-remote", "list-case-hunt-clusters", "case-11"], "hunt-11"),
        (["soc-remote", "get-case-hunt-cluster", "case-11", "hunt-11"], "hunt-11"),
        (["soc-remote", "create-case-from-case-hunt-cluster", "case-11", "hunt-11"], "case-hunt-22"),
        (["soc-remote", "list-case-timeline-clusters", "case-11"], "timeline-11"),
        (["soc-remote", "get-case-timeline-cluster", "case-11", "timeline-11"], "timeline-11"),
        (["soc-remote", "create-case-from-case-timeline-cluster", "case-11", "timeline-11"], "case-timeline-22"),
        (["soc-remote", "list-case-lineage-clusters", "case-11"], "lineage-11"),
        (["soc-remote", "get-case-lineage-cluster", "case-11", "lineage-11"], "lineage-11"),
        (["soc-remote", "create-case-from-case-lineage-cluster", "case-11", "lineage-11"], "case-lineage-22"),
    ]

    for argv, needle in commands:
        result = runner.invoke(cli.app, argv)
        assert result.exit_code == 0
        assert needle in result.stdout


def test_soc_remote_case_rule_group_commands_read_and_promote_groups(monkeypatch) -> None:
    class Client:
        def list_case_rule_alert_groups(self, case_id: str) -> list[dict[str, object]]:
            assert case_id == "case-11"
            return [{"group_key": "alert-group-11"}]

        def get_case_rule_alert_group(self, case_id: str, group_key: str) -> dict[str, object]:
            assert case_id == "case-11"
            assert group_key == "alert-group-11"
            return {"group_key": group_key}

        def create_case_from_case_rule_alert_group(self, case_id: str, payload: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert getattr(payload, "group_key", None) == "alert-group-11"
            return {"case_id": "case-alert-group-22"}

        def list_case_rule_evidence_groups(self, case_id: str) -> list[dict[str, object]]:
            assert case_id == "case-11"
            return [{"group_key": "evidence-group-11"}]

        def get_case_rule_evidence_group(self, case_id: str, group_key: str) -> dict[str, object]:
            assert case_id == "case-11"
            assert group_key == "evidence-group-11"
            return {"group_key": group_key}

        def create_case_from_case_rule_evidence_group(self, case_id: str, payload: object) -> dict[str, object]:
            assert case_id == "case-11"
            assert getattr(payload, "group_key", None) == "evidence-group-11"
            return {"case_id": "case-evidence-group-22"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    commands = [
        (["soc-remote", "list-case-rule-groups", "case-11"], "alert-group-11"),
        (["soc-remote", "get-case-rule-group", "case-11", "alert-group-11"], "alert-group-11"),
        (["soc-remote", "create-case-from-case-rule-group", "case-11", "alert-group-11"], "case-alert-group-22"),
        (["soc-remote", "list-case-rule-groups", "case-11", "--kind", "evidence"], "evidence-group-11"),
        (["soc-remote", "get-case-rule-group", "case-11", "evidence-group-11", "--kind", "evidence"], "evidence-group-11"),
        (["soc-remote", "create-case-from-case-rule-group", "case-11", "evidence-group-11", "--kind", "evidence"], "case-evidence-group-22"),
    ]

    for argv, needle in commands:
        result = runner.invoke(cli.app, argv)
        assert result.exit_code == 0
        assert needle in result.stdout


def test_soc_remote_case_rule_group_commands_reject_invalid_kind(monkeypatch) -> None:
    class Client:
        def list_case_rule_alert_groups(self, case_id: str) -> list[dict[str, object]]:
            raise AssertionError("should not be called")

        def list_case_rule_evidence_groups(self, case_id: str) -> list[dict[str, object]]:
            raise AssertionError("should not be called")

        def get_case_rule_alert_group(self, case_id: str, group_key: str) -> dict[str, object]:
            raise AssertionError("should not be called")

        def get_case_rule_evidence_group(self, case_id: str, group_key: str) -> dict[str, object]:
            raise AssertionError("should not be called")

        def create_case_from_case_rule_alert_group(self, case_id: str, payload: object) -> dict[str, object]:
            raise AssertionError("should not be called")

        def create_case_from_case_rule_evidence_group(self, case_id: str, payload: object) -> dict[str, object]:
            raise AssertionError("should not be called")

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    for argv in [
        ["soc-remote", "list-case-rule-groups", "case-11", "--kind", "bad"],
        ["soc-remote", "get-case-rule-group", "case-11", "group-11", "--kind", "bad"],
        ["soc-remote", "create-case-from-case-rule-group", "case-11", "group-11", "--kind", "bad"],
    ]:
        result = runner.invoke(cli.app, argv)
        assert result.exit_code == 1
        assert "must be 'alerts' or 'evidence'" in result.stderr


def test_soc_remote_dashboard_command_emits_json(monkeypatch) -> None:
    class Client:
        def dashboard(self) -> dict[str, object]:
            return {"summary": {"open_alerts": 1}}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "dashboard", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["summary"]["open_alerts"] == 1


def test_linear_forms_cli_commands_manage_registry(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli, "linear_forms", cli.LinearAsksFormRegistry(tmp_path / "linear_forms.json"))

    upsert = runner.invoke(
        cli.app,
        [
            "linear-forms",
            "upsert",
            "bug-report",
            "https://linear.app/example/forms/bug-report",
            "--title",
            "Bug report",
            "--category",
            "Engineering",
            "--team",
            "Platform",
        ],
    )
    listed = runner.invoke(cli.app, ["linear-forms", "list"])
    removed = runner.invoke(cli.app, ["linear-forms", "remove", "bug-report"])

    assert upsert.exit_code == 0
    assert "'form_key': 'bug-report'" in upsert.stdout
    assert listed.exit_code == 0
    assert "'title': 'Bug report'" in listed.stdout
    assert removed.exit_code == 0
    assert "'status': 'deleted'" in removed.stdout


def test_docker_resources_cli_commands_read_catalog() -> None:
    listed = runner.invoke(cli.app, ["docker-resources", "list"])
    detail = runner.invoke(cli.app, ["docker-resources", "get", "sandboxes-2026-03-31"])

    assert listed.exit_code == 0
    assert "offload-ga-2026-04-02" in listed.stdout
    assert detail.exit_code == 0
    assert "Docker Sandboxes for agent execution" in detail.stdout


def test_soc_remote_cluster_commands_emit_json(monkeypatch) -> None:
    class Client:
        def list_hunt_telemetry_clusters(self, **kwargs: object) -> dict[str, object]:
            return {"clusters": [{"cluster_key": "device-11"}]}

        def create_case_from_case_rule_alert_group(self, case_id: str, payload: object) -> dict[str, object]:
            return {"case_id": "case-alert-group-22"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    list_result = runner.invoke(cli.app, ["soc-remote", "list-hunt-clusters", "--json"])
    create_result = runner.invoke(
        cli.app,
        ["soc-remote", "create-case-from-case-rule-group", "case-11", "alert-group-11", "--json"],
    )

    assert list_result.exit_code == 0
    assert json.loads(list_result.stdout)["clusters"][0]["cluster_key"] == "device-11"
    assert create_result.exit_code == 0
    assert json.loads(create_result.stdout)["case_id"] == "case-alert-group-22"


def test_soc_remote_ack_alert_command_updates_alert(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []

    class Client:
        def update_alert(self, alert_id: str, payload: object) -> dict[str, object]:
            calls.append((alert_id, payload))
            return {"alert_id": alert_id, "status": "acknowledged"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "ack-alert", "alert-11", "--assignee", "tier2"])

    assert result.exit_code == 0
    assert calls and calls[0][0] == "alert-11"
    assert "'status': 'acknowledged'" in result.stdout


def test_soc_remote_set_case_status_command_updates_case(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []

    class Client:
        def update_case(self, case_id: str, payload: object) -> dict[str, object]:
            calls.append((case_id, payload))
            return {"case_id": case_id, "status": "investigating"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(cli.app, ["soc-remote", "set-case-status", "case-11", "investigating", "--assignee", "tier2"])

    assert result.exit_code == 0
    assert calls and calls[0][0] == "case-11"
    assert "'status': 'investigating'" in result.stdout


def test_soc_remote_create_case_from_rule_group_command_promotes_group(monkeypatch) -> None:
    class Client:
        def create_case_from_detection_rule_alert_group(self, rule_id: str, payload: object) -> dict[str, object]:
            assert rule_id == "endpoint_timeline_execution_chain"
            assert getattr(payload, "group_key", None) == "device-11:proc-guid-11"
            assert getattr(payload, "assignee", None) == "tier2"
            return {"case_id": "case-rule-group-11", "status": "open"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-rule-group",
            "endpoint_timeline_execution_chain",
            "device-11:proc-guid-11",
            "--assignee",
            "tier2",
        ],
    )

    assert result.exit_code == 0
    assert "'case_id': 'case-rule-group-11'" in result.stdout


def test_soc_remote_create_case_from_hunt_cluster_command_promotes_cluster(monkeypatch) -> None:
    class Client:
        def promote_hunt_telemetry_cluster(
            self,
            cluster_key: str,
            *,
            cluster_by: str = "remote_ip",
            assignee: str | None = None,
        ) -> dict[str, object]:
            assert cluster_key == "remote-ip-11"
            assert cluster_by == "remote_ip"
            assert assignee == "tier2"
            return {"case_id": "case-hunt-11", "status": "open"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-hunt-cluster",
            "remote-ip-11",
            "--cluster-by",
            "remote_ip",
            "--assignee",
            "tier2",
        ],
    )

    assert result.exit_code == 0
    assert "'case_id': 'case-hunt-11'" in result.stdout


def test_soc_remote_create_case_from_timeline_cluster_command_promotes_cluster(monkeypatch) -> None:
    class Client:
        def promote_endpoint_timeline_cluster(
            self,
            cluster_key: str,
            *,
            cluster_by: str = "process",
            assignee: str | None = None,
        ) -> dict[str, object]:
            assert cluster_key == "timeline-11"
            assert cluster_by == "process"
            assert assignee == "tier2"
            return {"case_id": "case-timeline-11", "status": "open"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-timeline-cluster",
            "timeline-11",
            "--cluster-by",
            "process",
            "--assignee",
            "tier2",
        ],
    )

    assert result.exit_code == 0
    assert "'case_id': 'case-timeline-11'" in result.stdout


def test_soc_remote_create_case_from_lineage_cluster_command_promotes_cluster(monkeypatch) -> None:
    class Client:
        def promote_endpoint_lineage_cluster(
            self,
            cluster_key: str,
            *,
            assignee: str | None = None,
        ) -> dict[str, object]:
            assert cluster_key == "lineage-11"
            assert assignee == "tier2"
            return {"case_id": "case-lineage-11", "status": "open"}

    monkeypatch.setattr(cli, "_remote_investigation_client", lambda **kwargs: Client())

    result = runner.invoke(
        cli.app,
        [
            "soc-remote",
            "create-case-from-lineage-cluster",
            "lineage-11",
            "--assignee",
            "tier2",
        ],
    )

    assert result.exit_code == 0
    assert "'case_id': 'case-lineage-11'" in result.stdout


def test_launch_uses_report_browser_when_frozen_without_args(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "_select_frozen_action", lambda: "report-browser")
    monkeypatch.setattr(cli, "run_report_browser", lambda builder=None: calls.append("browser"))
    monkeypatch.setattr(cli, "app", lambda *args, **kwargs: calls.append("app"))

    cli.launch()

    assert calls == ["browser"]


def test_launch_uses_soc_dashboard_when_selected(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "_select_frozen_action", lambda: "soc-dashboard")
    monkeypatch.setattr(cli, "_open_configured_soc_dashboard", lambda **kwargs: calls.append("dashboard"))
    monkeypatch.setattr(cli, "run_report_browser", lambda builder=None: calls.append("browser"))

    cli.launch()

    assert calls == ["dashboard"]


def test_launch_uses_cli_when_args_present(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe", "report-list"])
    monkeypatch.setattr(cli, "run_report_browser", lambda builder=None: calls.append("browser"))
    monkeypatch.setattr(cli, "app", lambda *args, **kwargs: calls.append("app"))

    cli.launch()

    assert calls == ["app"]


def test_launch_runs_uninstaller_when_selected(monkeypatch, tmp_path) -> None:
    calls = []
    uninstaller = tmp_path / "SecurityGateway-Uninstall.exe"
    uninstaller.write_text("stub")
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "_select_frozen_action", lambda: "uninstall")
    monkeypatch.setattr(cli, "_resolve_uninstaller_path", lambda: uninstaller)
    monkeypatch.setattr(cli, "_launch_uninstaller", lambda target: calls.append(target))

    cli.launch()

    assert calls == [uninstaller]


def test_launch_exits_when_uninstaller_is_missing(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "_select_frozen_action", lambda: "uninstall")
    monkeypatch.setattr(cli, "_resolve_uninstaller_path", lambda: None)

    try:
        cli.launch()
    except cli.typer.Exit as exc:
        assert exc.exit_code == 1
    else:  # pragma: no cover - defensive assertion path
        raise AssertionError("Expected launch() to raise typer.Exit when uninstaller is missing")
