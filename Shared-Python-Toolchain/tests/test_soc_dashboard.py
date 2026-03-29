from security_gateway.soc_dashboard import SocDashboard


def test_format_status_line_includes_open_workloads_and_top_events() -> None:
    dashboard = {
        "summary": {"open_alerts": 3, "open_cases": 2},
        "top_event_types": {"policy.access_decision": 4, "privacy.tracker_block": 3},
    }

    line = SocDashboard._format_status_line(dashboard)

    assert "Open alerts: 3" in line
    assert "Open cases: 2" in line
    assert "policy.access_decision: 4" in line
    assert "privacy.tracker_block: 3" in line


def test_format_status_line_handles_empty_event_types() -> None:
    dashboard = {
        "summary": {"open_alerts": 0, "open_cases": 0},
        "top_event_types": {},
    }

    line = SocDashboard._format_status_line(dashboard)

    assert line.endswith("Top event types: none")
