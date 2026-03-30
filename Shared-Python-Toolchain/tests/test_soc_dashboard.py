from typing import Any, cast

from security_gateway.soc_dashboard import SocDashboard
from security_gateway.models import SocAlertStatus, SocCaseStatus, SocSeverity


def test_format_status_line_includes_open_workloads_and_top_events() -> None:
    dashboard = {
        "summary": {"open_alerts": 3, "open_cases": 2},
        "workload": {"stale_assigned_alerts": 1, "stale_active_cases": 4},
        "assignee_workload": [{"assignee": "tier1", "open_alerts": 2, "active_cases": 1}],
        "top_event_types": {"policy.access_decision": 4, "privacy.tracker_block": 3},
    }

    line = SocDashboard._format_status_line(dashboard, host_findings_count=2)

    assert "Open alerts: 3" in line
    assert "Open cases: 2" in line
    assert "Host findings: 2" in line
    assert "Stale assigned alerts: 1" in line
    assert "Stale active cases: 4" in line
    assert "Loaded assignees: 1" in line
    assert "policy.access_decision: 4" in line
    assert "privacy.tracker_block: 3" in line


def test_format_status_line_handles_empty_event_types() -> None:
    dashboard = {
        "summary": {"open_alerts": 0, "open_cases": 0},
        "workload": {},
        "assignee_workload": [],
        "top_event_types": {},
    }

    line = SocDashboard._format_status_line(dashboard)

    assert line.endswith("Top event types: none")


def test_format_workload_detail_includes_assignees_and_aging() -> None:
    dashboard = {
        "assignee_workload": [
            {"assignee": "tier1", "open_alerts": 3, "active_cases": 1, "stale_alerts": 1, "stale_cases": 0},
            {"assignee": "unassigned", "open_alerts": 2, "active_cases": 0, "stale_alerts": 0, "stale_cases": 0},
        ],
        "aging_buckets": {
            "alerts": {"0-4h": 1, "4-24h": 2, "24-72h": 3, "72h+": 4},
            "cases": {"0-4h": 5, "4-24h": 6, "24-72h": 7, "72h+": 8},
        },
    }

    text = SocDashboard._format_workload_detail(dashboard)

    assert "tier1: alerts=3, cases=1, stale alerts=1, stale cases=0" in text
    assert "unassigned: alerts=2, cases=0, stale alerts=0, stale cases=0" in text
    assert "Alert Aging:" in text
    assert "- 72h+: 4" in text
    assert "Case Aging:" in text
    assert "- 24-72h: 7" in text


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
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "tier1-triage"})()
    dashboard.case_status_var = type("Var", (), {"get": lambda self: "all"})()
    dashboard.case_sort_var = type("Var", (), {"get": lambda self: "updated_desc"})()

    kwargs = dashboard._case_query_kwargs()

    assert kwargs["status"] is None
    assert kwargs["sort"] == "updated_desc"
    assert kwargs["limit"] == 25


def test_preset_values_for_tier2_investigation() -> None:
    preset = SocDashboard._preset_values("tier2-investigation")

    assert preset == {
        "alert_severity": "high",
        "alert_link_state": "linked",
        "alert_sort": "updated_desc",
        "case_status": "investigating",
        "case_sort": "severity_desc",
    }


def test_preset_values_for_my_queue() -> None:
    preset = SocDashboard._preset_values("my-queue")

    assert preset == {
        "alert_severity": "all",
        "alert_link_state": "all",
        "alert_sort": "updated_desc",
        "case_status": "all",
        "case_sort": "updated_desc",
    }


def test_preset_values_for_unassigned() -> None:
    preset = SocDashboard._preset_values("unassigned")

    assert preset == {
        "alert_severity": "all",
        "alert_link_state": "unlinked",
        "alert_sort": "updated_desc",
        "case_status": "all",
        "case_sort": "updated_desc",
    }


def test_preset_values_for_needs_attention() -> None:
    preset = SocDashboard._preset_values("needs-attention")

    assert preset == {
        "alert_severity": "all",
        "alert_link_state": "unlinked",
        "alert_sort": "updated_asc",
        "case_status": "all",
        "case_sort": "updated_asc",
    }


def test_preset_values_for_handoff() -> None:
    preset = SocDashboard._preset_values("handoff")

    assert preset == {
        "alert_severity": "all",
        "alert_link_state": "all",
        "alert_sort": "updated_asc",
        "case_status": "all",
        "case_sort": "updated_asc",
    }


def test_apply_queue_preset_updates_filter_variables_and_refreshes() -> None:
    class Var:
        def __init__(self, value: str):
            self.value = value

        def get(self) -> str:
            return self.value

        def set(self, value: str) -> None:
            self.value = value

    dashboard = cast(Any, SocDashboard.__new__(SocDashboard))
    dashboard.queue_preset_var = Var("containment")
    dashboard.alert_severity_var = Var("all")
    dashboard.alert_link_state_var = Var("unlinked")
    dashboard.alert_sort_var = Var("severity_desc")
    dashboard.case_status_var = Var("all")
    dashboard.case_sort_var = Var("updated_desc")
    refresh_calls: list[str] = []
    dashboard.refresh = lambda: refresh_calls.append("refresh")

    dashboard.apply_queue_preset()

    assert dashboard.alert_severity_var.get() == "critical"
    assert dashboard.alert_link_state_var.get() == "all"
    assert dashboard.alert_sort_var.get() == "severity_desc"
    assert dashboard.case_status_var.get() == "contained"
    assert dashboard.case_sort_var.get() == "updated_desc"
    assert refresh_calls == ["refresh"]


def test_alert_query_kwargs_use_analyst_identity_for_my_queue() -> None:
    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "my-queue"})()
    dashboard.alert_severity_var = type("Var", (), {"get": lambda self: "all"})()
    dashboard.alert_link_state_var = type("Var", (), {"get": lambda self: "all"})()
    dashboard.alert_sort_var = type("Var", (), {"get": lambda self: "updated_desc"})()
    dashboard.analyst_identity_var = type("Var", (), {"get": lambda self: "tier2-analyst"})()

    kwargs = dashboard._alert_query_kwargs()

    assert kwargs["assignee"] == "tier2-analyst"
    assert kwargs["linked_case_state"] is None


def test_alert_query_kwargs_use_unassigned_for_unassigned_view() -> None:
    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "unassigned"})()
    dashboard.alert_severity_var = type("Var", (), {"get": lambda self: "all"})()
    dashboard.alert_link_state_var = type("Var", (), {"get": lambda self: "unlinked"})()
    dashboard.alert_sort_var = type("Var", (), {"get": lambda self: "updated_desc"})()

    kwargs = dashboard._alert_query_kwargs()

    assert kwargs["assignee"] == "unassigned"


def test_case_query_kwargs_use_analyst_identity_for_my_queue() -> None:
    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "my-queue"})()
    dashboard.case_status_var = type("Var", (), {"get": lambda self: "all"})()
    dashboard.case_sort_var = type("Var", (), {"get": lambda self: "updated_desc"})()
    dashboard.analyst_identity_var = type("Var", (), {"get": lambda self: "tier2-analyst"})()

    kwargs = dashboard._case_query_kwargs()

    assert kwargs["assignee"] == "tier2-analyst"


def test_case_query_kwargs_use_unassigned_for_unassigned_view() -> None:
    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "unassigned"})()
    dashboard.case_status_var = type("Var", (), {"get": lambda self: "all"})()
    dashboard.case_sort_var = type("Var", (), {"get": lambda self: "updated_desc"})()

    kwargs = dashboard._case_query_kwargs()

    assert kwargs["assignee"] == "unassigned"


def test_alert_rows_for_needs_attention_use_stale_triage_alerts() -> None:
    def get_alert(_self: object, alert_id: str) -> dict[str, str]:
        fetched.append(alert_id)
        return {"alert_id": alert_id}

    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "needs-attention"})()
    fetched: list[str] = []
    dashboard.manager = type(
        "Manager",
        (),
        {
            "get_alert": get_alert,
            "query_alerts": lambda self, **kwargs: [],
        },
    )()

    rows = dashboard._alert_rows_for_view(
        {
            "triage": {
                "stale_open_alerts": [
                    {"alert_id": "alert-1"},
                    {"alert_id": "alert-2"},
                ]
            }
        }
    )

    assert fetched == ["alert-1", "alert-2"]
    assert rows == [{"alert_id": "alert-1"}, {"alert_id": "alert-2"}]


def test_case_rows_for_needs_attention_use_oldest_open_cases() -> None:
    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "needs-attention"})()
    dashboard.manager = type(
        "Manager",
        (),
        {
            "list_cases": lambda self: [
                type("Case", (), {"case_id": "case-closed", "status": SocCaseStatus.closed, "updated_at": 30})(),
                type("Case", (), {"case_id": "case-newer", "status": SocCaseStatus.investigating, "updated_at": 20})(),
                type("Case", (), {"case_id": "case-older", "status": SocCaseStatus.open, "updated_at": 10})(),
            ],
            "query_cases": lambda self, **kwargs: [],
        },
    )()

    rows = dashboard._case_rows_for_view({"triage": {}})

    assert [row.case_id for row in rows] == ["case-older", "case-newer"]


def test_alert_rows_for_handoff_use_stale_assigned_alerts() -> None:
    def get_alert(_self: object, alert_id: str) -> dict[str, str]:
        fetched.append(alert_id)
        return {"alert_id": alert_id}

    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "handoff"})()
    fetched: list[str] = []
    dashboard.manager = type(
        "Manager",
        (),
        {
            "get_alert": get_alert,
            "query_alerts": lambda self, **kwargs: [],
        },
    )()

    rows = dashboard._alert_rows_for_view(
        {
            "triage": {
                "assigned_stale_alerts": [
                    {"alert_id": "alert-a"},
                    {"alert_id": "alert-b"},
                ]
            }
        }
    )

    assert fetched == ["alert-a", "alert-b"]
    assert rows == [{"alert_id": "alert-a"}, {"alert_id": "alert-b"}]


def test_case_rows_for_handoff_use_stale_active_cases() -> None:
    def get_case(_self: object, case_id: str) -> dict[str, str]:
        fetched.append(case_id)
        return {"case_id": case_id}

    dashboard = SocDashboard.__new__(SocDashboard)
    dashboard.queue_preset_var = type("Var", (), {"get": lambda self: "handoff"})()
    fetched: list[str] = []
    dashboard.manager = type(
        "Manager",
        (),
        {
            "get_case": get_case,
            "query_cases": lambda self, **kwargs: [],
        },
    )()

    rows = dashboard._case_rows_for_view(
        {
            "triage": {
                "stale_active_cases": [
                    {"case_id": "case-a"},
                    {"case_id": "case-b"},
                ]
            }
        }
    )

    assert fetched == ["case-a", "case-b"]
    assert rows == [{"case_id": "case-a"}, {"case_id": "case-b"}]


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
                "details": {
                    "details": {
                        "finding_type": "suspicious_remote_ip",
                        "abnormal_reason": "repeat_threshold_exceeded",
                        "local_ports": [8443],
                        "remote_ports": [53123, 53124],
                        "hit_count": 3,
                        "evidence": {
                            "retention_mode": "compact_evidence_only",
                            "sample_count": 1,
                            "sample_connections": [
                                {
                                    "state": "ESTABLISHED",
                                    "remote_ip": "1.1.1.1",
                                    "remote_port": 53123,
                                    "local_ip": "192.168.1.10",
                                    "local_port": 8443,
                                }
                            ],
                        },
                    }
                },
            }
        ],
    )
    assert "Alert: alert-123" in text
    assert "Event: evt-1" in text
    assert "Type: privacy.tracker_block" in text
    assert "Summary: Blocked beacon.example.test" in text
    assert "Compact Evidence:" in text
    assert "Reason: repeat_threshold_exceeded" in text
    assert "Sample Connections:" in text
    assert "1.1.1.1:53123 -> 192.168.1.10:8443" in text


def test_format_monitor_evidence_block_handles_packet_endpoint_samples() -> None:
    text = SocDashboard._format_monitor_evidence_block(
        {
            "details": {
                "abnormal_reason": "baseline_exceeded",
                "packet_count": 7,
                "local_ports": [3389],
                "remote_ports": [51000],
                "evidence": {
                    "retention_mode": "compact_evidence_only",
                    "sample_count": 1,
                    "sample_packet_endpoints": [
                        {
                            "protocol": "TCP",
                            "remote_ip": "8.8.8.8",
                            "remote_port": 51000,
                            "local_ip": "192.168.1.10",
                            "local_port": 3389,
                        }
                    ],
                },
            }
        }
    )

    assert "Compact Evidence:" in text
    assert "Reason: baseline_exceeded" in text
    assert "Sample Endpoints:" in text
    assert "TCP 8.8.8.8:51000 -> 192.168.1.10:3389" in text


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
