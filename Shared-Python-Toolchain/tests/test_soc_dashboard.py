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


def test_selected_tree_item_id_returns_first_selection() -> None:
    tree = type("Tree", (), {"selection": lambda self: ("alert-123",)})()
    assert SocDashboard._selected_tree_item_id(tree) == "alert-123"


def test_selected_tree_item_id_handles_empty_selection() -> None:
    tree = type("Tree", (), {"selection": lambda self: ()})()
    assert SocDashboard._selected_tree_item_id(tree) is None


def test_build_promote_payload_uses_alert_defaults() -> None:
    alert = type(
        "Alert",
        (),
        {
            "title": "Privileged access denied",
            "summary": "Analyst review needed.",
            "severity": SocSeverity.high,
            "assignee": "tier1-analyst",
        },
    )()

    payload = SocDashboard._build_promote_payload(alert)

    assert payload.title == "Investigate Privileged access denied"
    assert payload.summary == "Analyst review needed."
    assert payload.severity is SocSeverity.high
    assert payload.case_status is SocCaseStatus.investigating
    assert payload.alert_status is SocAlertStatus.acknowledged
    assert payload.assignee == "tier1-analyst"


def test_build_case_update_payload_for_note() -> None:
    payload = SocDashboard._build_case_update_payload(field="note", value="Investigating suspicious login")
    assert payload.note == "Investigating suspicious login"
    assert payload.observable is None


def test_build_case_update_payload_for_observable() -> None:
    payload = SocDashboard._build_case_update_payload(field="observable", value="203.0.113.55")
    assert payload.observable == "203.0.113.55"
    assert payload.note is None


def test_format_case_detail_includes_notes_and_observables() -> None:
    text = SocDashboard._format_case_detail(
        {
            "case_id": "case-123",
            "title": "Investigate denied access",
            "status": "investigating",
            "severity": "high",
            "assignee": "tier2-analyst",
            "summary": "Analyst review required.",
            "observables": ["203.0.113.55", "vpn-admin"],
            "notes": ["Owner assigned.", "IP added to case."],
        }
    )
    assert "Case: case-123" in text
    assert "- 203.0.113.55" in text
    assert "- vpn-admin" in text
    assert "- Owner assigned." in text


def test_format_case_detail_handles_empty_lists() -> None:
    text = SocDashboard._format_case_detail(
        {
            "case_id": "case-456",
            "title": "Empty case",
            "status": "open",
            "severity": "medium",
            "summary": "No enrichment yet.",
            "observables": [],
            "notes": [],
        }
    )
    assert "Observables:\n- none" in text
    assert "Notes:\n- none" in text
