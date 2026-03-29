from security_gateway.soc_dashboard import SocDashboard
from security_gateway.models import SocAlertStatus, SocCaseStatus, SocSeverity


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


def test_alert_query_kwargs_use_unassigned_open_alert_defaults() -> None:
    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.alert_severity_var = type("Var", (), {"get": lambda self: "high"})()
    dashboard.alert_link_state_var = type("Var", (), {"get": lambda self: "unlinked"})()
    dashboard.alert_sort_var = type("Var", (), {"get": lambda self: "severity_desc"})()

    kwargs = dashboard._alert_query_kwargs()

    assert kwargs["status"] is SocAlertStatus.open
    assert kwargs["severity"] is SocSeverity.high
    assert kwargs["assignee"] == "unassigned"
    assert kwargs["linked_case_state"] == "unlinked"
    assert kwargs["sort"] == "severity_desc"
    assert kwargs["limit"] == 25


def test_case_query_kwargs_allow_all_statuses() -> None:
    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.case_status_var = type("Var", (), {"get": lambda self: "all"})()
    dashboard.case_sort_var = type("Var", (), {"get": lambda self: "updated_desc"})()

    kwargs = dashboard._case_query_kwargs()

    assert kwargs["status"] is None
    assert kwargs["sort"] == "updated_desc"
    assert kwargs["limit"] == 25


def test_case_status_parser_understands_investigating() -> None:
    assert SocDashboard._parse_case_status("investigating") is SocCaseStatus.investigating
