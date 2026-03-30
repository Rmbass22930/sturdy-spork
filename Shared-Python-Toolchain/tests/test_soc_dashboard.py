from security_gateway.soc_dashboard import SocDashboard
from security_gateway.models import SocAlertStatus, SocCaseStatus, SocSeverity


def test_format_status_line_includes_open_workloads_and_top_events() -> None:
    dashboard = {
        "summary": {"open_alerts": 3, "open_cases": 2},
        "top_event_types": {"policy.access_decision": 4, "privacy.tracker_block": 3},
    }

    line = SocDashboard._format_status_line(dashboard, host_findings_count=2)

    assert "Open alerts: 3" in line
    assert "Open cases: 2" in line
    assert "Host findings: 2" in line
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

    payload = SocDashboard._build_promote_payload(alert, acted_by="tier1-analyst")

    assert payload.title == "Investigate Privileged access denied"
    assert payload.summary == "Analyst review needed."
    assert payload.severity is SocSeverity.high
    assert payload.case_status is SocCaseStatus.investigating
    assert payload.alert_status is SocAlertStatus.acknowledged
    assert payload.assignee == "tier1-analyst"
    assert payload.acted_by == "tier1-analyst"
    assert payload.existing_case_id is None


def test_build_promote_payload_can_target_existing_case() -> None:
    alert = type(
        "Alert",
        (),
        {
            "title": "Repeated tracker activity",
            "summary": "Link into active incident.",
            "severity": SocSeverity.medium,
            "assignee": None,
        },
    )()

    payload = SocDashboard._build_promote_payload(alert, existing_case_id="case-123")

    assert payload.existing_case_id == "case-123"
    assert payload.title == "Investigate Repeated tracker activity"


def test_build_alert_update_payload_for_status_and_actor() -> None:
    payload = SocDashboard._build_alert_update_payload(field="status", value="acknowledged", acted_by="tier2-analyst")
    assert payload.status is SocAlertStatus.acknowledged
    assert payload.acted_by == "tier2-analyst"


def test_build_alert_update_payload_for_assignee() -> None:
    payload = SocDashboard._build_alert_update_payload(field="assignee", value="queue-a")
    assert payload.assignee == "queue-a"
    assert payload.status is None


def test_build_alert_update_payload_for_note() -> None:
    payload = SocDashboard._build_alert_update_payload(field="note", value="Initial queue triage complete.")
    assert payload.note == "Initial queue triage complete."
    assert payload.assignee is None


def test_build_case_update_payload_for_note() -> None:
    payload = SocDashboard._build_case_update_payload(field="note", value="Investigating suspicious login")
    assert payload.note == "Investigating suspicious login"
    assert payload.observable is None


def test_build_case_update_payload_for_observable() -> None:
    payload = SocDashboard._build_case_update_payload(field="observable", value="203.0.113.55")
    assert payload.observable == "203.0.113.55"
    assert payload.note is None


def test_build_case_update_payload_for_assignee() -> None:
    payload = SocDashboard._build_case_update_payload(field="assignee", value="tier2-analyst")
    assert payload.assignee == "tier2-analyst"
    assert payload.status is None


def test_build_case_update_payload_for_status() -> None:
    payload = SocDashboard._build_case_update_payload(field="status", value="contained")
    assert payload.status is SocCaseStatus.contained
    assert payload.assignee is None


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


def test_format_alert_detail_includes_assignment_and_actor_fields() -> None:
    text = SocDashboard._format_alert_detail(
        {
            "alert_id": "alert-123",
            "title": "Repeated tracker activity",
            "status": "acknowledged",
            "severity": "high",
            "category": "correlation",
            "assignee": "tier1-analyst",
            "linked_case_id": "case-999",
            "acknowledged_by": "tier1-analyst",
            "escalated_by": "tier2-analyst",
            "correlation_rule": "tracker-repeat",
            "source_event_ids": ["event-1", "event-2"],
            "summary": "Correlation threshold exceeded.",
            "notes": ["Initial triage complete."],
        }
    )
    assert "Alert: alert-123" in text
    assert "Category: correlation" in text
    assert "Assignee: tier1-analyst" in text
    assert "Linked Case: case-999" in text
    assert "Acknowledged By: tier1-analyst" in text
    assert "Escalated By: tier2-analyst" in text
    assert "Correlation Rule: tracker-repeat" in text
    assert "Source Events: 2" in text
    assert "- Initial triage complete." in text


def test_format_source_events_includes_underlying_event_context() -> None:
    text = SocDashboard._format_source_events(
        {"alert_id": "alert-123", "title": "Repeated tracker activity"},
        [
            {
                "event_id": "evt-1",
                "event_type": "privacy.tracker_block",
                "severity": "high",
                "created_at": "2026-03-29T19:00:00+00:00",
                "title": "Tracker blocked",
                "summary": "Blocked beacon.example.test",
            }
        ],
    )
    assert "Alert: alert-123" in text
    assert "Event: evt-1" in text
    assert "Type: privacy.tracker_block" in text
    assert "Summary: Blocked beacon.example.test" in text


def test_format_source_events_handles_missing_rows() -> None:
    text = SocDashboard._format_source_events(
        {"alert_id": "alert-456", "title": "Missing event linkage"},
        [],
    )
    assert "No source events were found for this alert." in text


def test_format_case_linked_activity_includes_alerts_and_events() -> None:
    text = SocDashboard._format_case_linked_activity(
        {"case_id": "case-123", "title": "Investigate repeated tracker activity"},
        [
            {
                "alert_id": "alert-1",
                "severity": "high",
                "status": "acknowledged",
                "title": "Repeated tracker activity",
            }
        ],
        [
            {
                "event_id": "evt-1",
                "event_type": "privacy.tracker_block",
                "severity": "high",
                "title": "Tracker blocked",
            }
        ],
    )
    assert "Case: case-123" in text
    assert "Linked Alerts:" in text
    assert "- alert-1: high | acknowledged | Repeated tracker activity" in text
    assert "Source Events:" in text
    assert "- evt-1: privacy.tracker_block | high | Tracker blocked" in text


def test_format_case_linked_activity_handles_empty_state() -> None:
    text = SocDashboard._format_case_linked_activity(
        {"case_id": "case-456", "title": "Empty case"},
        [],
        [],
    )
    assert "Linked Alerts:" in text
    assert "Source Events:" in text
    assert text.count("- none") == 2


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


def test_format_host_detail_includes_snapshot_and_details() -> None:
    text = SocDashboard._format_host_detail(
        {
            "key": "firewall-disabled",
            "title": "Windows firewall profile disabled",
            "severity": "critical",
            "resolved": False,
            "summary": "One or more firewall profiles are disabled on the monitored host.",
            "details": {"disabled_profiles": ["public", "private"]},
            "snapshot": {
                "system_drive": "C:",
                "disk_free_percent": 42.5,
                "defender_running": True,
                "firewall_disabled_profiles": ["public", "private"],
            },
            "last_checked_at": "2026-03-29T20:10:00+00:00",
        }
    )
    assert "Finding: firewall-disabled" in text
    assert "Severity: critical" in text
    assert "- disabled_profiles: ['public', 'private']" in text
    assert "- system_drive: C:" in text
    assert "- checked_at: 2026-03-29T20:10:00+00:00" in text
