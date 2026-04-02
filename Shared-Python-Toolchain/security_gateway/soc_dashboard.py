"""Tk dashboard for Security Gateway SOC operations."""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping, cast

try:
    import tkinter as tk
    from tkinter import messagebox, simpledialog, ttk
except Exception:  # pragma: no cover
    tk = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    simpledialog = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]

from .alerts import alert_manager
from .audit import AuditLogger
from .config import settings
from .dashboard_view_state import (
    DashboardViewStateClient,
    HttpDashboardViewStateClient,
    build_dashboard_view_state_client,
)
from .models import (
    SocAlertPromoteCaseRequest,
    SocAlertStatus,
    SocAlertUpdate,
    SocCaseTelemetryClusterCaseRequest,
    SocCaseEndpointTimelineClusterCaseRequest,
    SocCaseRuleGroupCaseRequest,
    SocCaseCreate,
    SocEndpointTimelineCaseRequest,
    SocCaseStatus,
    SocCaseUpdate,
    SocDashboardViewStateUpdate,
    SocDetectionRuleUpdate,
    SocNetworkEvidenceCaseRequest,
    SocPacketSessionCaseRequest,
    SocSeverity,
    SocTelemetryClusterCaseRequest,
)
from .network_monitor import NetworkMonitor
from .packet_monitor import PacketMonitor
from .remote_soc_client import (
    RemoteNetworkMonitorClient,
    RemotePacketMonitorClient,
    RemotePlatformClient,
    RemoteSecurityOperationsClient,
    RemoteTrackerIntelClient,
)
from .platform import (
    cancel_platform_node_action,
    clear_platform_node_drain,
    clear_platform_node_maintenance,
    request_platform_node_refresh,
    retry_platform_node_action,
    start_platform_node_drain,
    clear_platform_node_suppression,
    start_platform_node_maintenance,
    suppress_platform_node,
    update_platform_node_metadata,
)
from .soc import SecurityOperationsManager
from .tracker_intel import TrackerIntel


def _center_window(root: Any, width: int, height: int) -> None:
    screen_width = int(root.winfo_screenwidth())
    screen_height = int(root.winfo_screenheight())
    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)
    root.geometry(f"{width}x{height}+{x}+{y}")


class SocDashboard:
    QUEUE_PRESETS: dict[str, dict[str, str]] = {
        "custom": {},
        "tier1-triage": {
            "alert_severity": "all",
            "alert_link_state": "unlinked",
            "alert_sort": "severity_desc",
            "case_status": "all",
            "case_sort": "updated_desc",
        },
        "tier2-investigation": {
            "alert_severity": "high",
            "alert_link_state": "linked",
            "alert_sort": "updated_desc",
            "case_status": "investigating",
            "case_sort": "severity_desc",
        },
        "containment": {
            "alert_severity": "critical",
            "alert_link_state": "all",
            "alert_sort": "severity_desc",
            "case_status": "contained",
            "case_sort": "updated_desc",
        },
        "review-closed": {
            "alert_severity": "all",
            "alert_link_state": "all",
            "alert_sort": "updated_desc",
            "case_status": "closed",
            "case_sort": "updated_desc",
        },
        "unassigned": {
            "alert_severity": "all",
            "alert_link_state": "unlinked",
            "alert_sort": "updated_desc",
            "case_status": "all",
            "case_sort": "updated_desc",
        },
        "needs-attention": {
            "alert_severity": "all",
            "alert_link_state": "unlinked",
            "alert_sort": "updated_asc",
            "case_status": "all",
            "case_sort": "updated_asc",
        },
        "handoff": {
            "alert_severity": "all",
            "alert_link_state": "all",
            "alert_sort": "updated_asc",
            "case_status": "all",
            "case_sort": "updated_asc",
        },
        "operational": {
            "alert_severity": "all",
            "alert_link_state": "all",
            "alert_sort": "updated_desc",
            "case_status": "all",
            "case_sort": "updated_desc",
        },
        "my-queue": {
            "alert_severity": "all",
            "alert_link_state": "all",
            "alert_sort": "updated_desc",
            "case_status": "all",
            "case_sort": "updated_desc",
        },
    }

    def __init__(
        self,
        manager: Any | None = None,
        dashboard_view_state_client: DashboardViewStateClient | None = None,
        tracker_intel: Any | None = None,
        packet_monitor: Any | None = None,
        network_monitor: Any | None = None,
        platform_client: Any | None = None,
    ):
        if tk is None or ttk is None:
            raise RuntimeError("Tk SOC dashboard is unavailable on this machine.")
        self.manager = manager or SecurityOperationsManager(
            event_log_path=settings.soc_event_log_path,
            alert_store_path=settings.soc_alert_store_path,
            case_store_path=settings.soc_case_store_path,
            audit_logger=AuditLogger(settings.audit_log_path),
            alert_manager=alert_manager,
        )
        self.dashboard_view_state_client = dashboard_view_state_client or build_dashboard_view_state_client(
            manager=self.manager,
            path=settings.soc_dashboard_view_state_path,
        )
        self.tracker_intel = tracker_intel or TrackerIntel(
            extra_domains_path=settings.tracker_domain_list_path,
            feed_cache_path=settings.tracker_feed_cache_path,
            feed_urls=settings.tracker_feed_urls,
            stale_after_hours=settings.tracker_feed_stale_hours,
            disabled_feed_urls=settings.tracker_feed_disabled_urls,
            min_domains_per_source=settings.tracker_feed_min_domains_per_source,
            min_total_domains=settings.tracker_feed_min_total_domains,
            replace_ratio_floor=settings.tracker_feed_replace_ratio_floor,
            verify_tls=settings.tracker_feed_verify_tls,
            ca_bundle_path=settings.tracker_feed_ca_bundle_path,
        )
        self.packet_monitor = packet_monitor or PacketMonitor(
            state_path=settings.packet_monitor_state_path,
            sample_seconds=settings.packet_monitor_sample_seconds,
            min_packet_count=settings.packet_monitor_min_packet_count,
            anomaly_multiplier=settings.packet_monitor_anomaly_multiplier,
            learning_samples=settings.packet_monitor_learning_samples,
            pkt_size=settings.packet_monitor_capture_bytes,
            sensitive_ports=settings.packet_monitor_sensitive_ports,
        )
        self.network_monitor = network_monitor or NetworkMonitor(
            state_path=settings.network_monitor_state_path,
            suspicious_repeat_threshold=settings.network_monitor_repeat_threshold,
            dos_hit_threshold=settings.network_monitor_dos_hit_threshold,
            dos_syn_threshold=settings.network_monitor_dos_syn_threshold,
            dos_port_span_threshold=settings.network_monitor_dos_port_span_threshold,
            sensitive_ports=settings.network_monitor_sensitive_ports,
        )
        self.platform_client = platform_client
        self.root = tk.Tk()
        self.root.title("Security Gateway SOC Dashboard")
        self.root.configure(bg="#eef4ff")
        _center_window(self.root, 1420, 900)
        self.root.minsize(1180, 720)
        self.queue_preset_var = tk.StringVar(value="tier1-triage")
        self.alert_severity_var = tk.StringVar(value="all")
        self.alert_link_state_var = tk.StringVar(value="unlinked")
        self.alert_sort_var = tk.StringVar(value="severity_desc")
        self.case_status_var = tk.StringVar(value="all")
        self.case_sort_var = tk.StringVar(value="updated_desc")
        self.analyst_identity_var = tk.StringVar(value="local-analyst")
        self.workload_assignee_var = tk.StringVar(value="all")
        self.alert_age_bucket_var = tk.StringVar(value="all")
        self.case_age_bucket_var = tk.StringVar(value="all")
        self.hunt_cluster_mode_var = tk.StringVar(value="remote_ip")
        self.hunt_cluster_value_var = tk.StringVar(value="")
        self.saved_hunt_cluster_mode: str | None = None
        self.saved_hunt_cluster_value: str | None = None
        self.saved_hunt_cluster_key: str | None = None
        self.saved_hunt_cluster_action: str | None = None
        self.operational_reason_filter: str | None = None
        self.saved_operational_reason_filter: str | None = None
        self.alert_rows_by_id: dict[str, dict[str, Any]] = {}
        self.case_rows_by_id: dict[str, dict[str, Any]] = {}
        self.event_rows_by_id: dict[str, dict[str, Any]] = {}
        self.correlation_rows_by_id: dict[str, dict[str, Any]] = {}
        self.all_alert_rows_by_id: dict[str, dict[str, Any]] = {}
        self.host_rows_by_key: dict[str, dict[str, Any]] = {}
        self._latest_dashboard: dict[str, Any] = {}
        self._build_ui()
        self.refresh()

    def run(self) -> None:
        self.root.mainloop()

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:  # pragma: no cover
            pass
        style.configure("SOC.TFrame", background="#eef4ff")
        style.configure("SOC.TLabel", background="#eef4ff", foreground="#24364a", font=("Segoe UI", 10))
        style.configure("SOC.Header.TLabel", background="#eef4ff", foreground="#0f2f57", font=("Segoe UI", 18, "bold"))
        style.configure("SOC.Sub.TLabel", background="#eef4ff", foreground="#35506d", font=("Segoe UI", 10, "bold"))
        style.configure("SOC.TLabelframe", background="#eef4ff")
        style.configure("SOC.TLabelframe.Label", background="#eef4ff", foreground="#0f2f57", font=("Segoe UI", 10, "bold"))
        style.configure("SOC.Treeview", rowheight=24)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        header = ttk.Frame(self.root, padding=(18, 18, 18, 10), style="SOC.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Security Gateway SOC Dashboard", style="SOC.Header.TLabel").grid(row=0, column=0, sticky="w")
        self.status_var = tk.StringVar(value="Loading SOC data...")
        ttk.Label(header, textvariable=self.status_var, style="SOC.Sub.TLabel").grid(row=1, column=0, sticky="w", pady=(6, 0))
        identity_controls = ttk.Frame(header, style="SOC.TFrame")
        identity_controls.grid(row=0, column=1, rowspan=2, sticky="e")
        ttk.Label(identity_controls, text="Queue View", style="SOC.TLabel").grid(row=0, column=0, sticky="e", padx=(0, 6))
        preset_combo = ttk.Combobox(
            identity_controls,
            textvariable=self.queue_preset_var,
            values=("tier1-triage", "tier2-investigation", "containment", "review-closed", "unassigned", "needs-attention", "handoff", "operational", "my-queue", "custom"),
            state="readonly",
            width=18,
        )
        preset_combo.grid(row=0, column=1, sticky="e", padx=(0, 12))
        preset_combo.bind("<<ComboboxSelected>>", lambda _event: self.apply_queue_preset())
        ttk.Label(identity_controls, text="Analyst", style="SOC.TLabel").grid(row=0, column=2, sticky="e", padx=(0, 6))
        ttk.Entry(identity_controls, textvariable=self.analyst_identity_var, width=18).grid(row=0, column=3, sticky="e", padx=(0, 12))
        ttk.Button(identity_controls, text="Apply View", command=self.apply_queue_preset).grid(row=0, column=4, sticky="e", padx=(0, 8))
        ttk.Button(identity_controls, text="Refresh", command=self.refresh).grid(row=0, column=5, sticky="e")

        summary = ttk.Frame(self.root, padding=(18, 0, 18, 12), style="SOC.TFrame")
        summary.grid(row=1, column=0, sticky="ew")
        for index in range(11):
            summary.columnconfigure(index, weight=1)
        self.summary_vars = {
            "events_total": tk.StringVar(value="0"),
            "alerts_total": tk.StringVar(value="0"),
            "open_alerts": tk.StringVar(value="0"),
            "cases_total": tk.StringVar(value="0"),
            "open_cases": tk.StringVar(value="0"),
            "host_findings": tk.StringVar(value="0"),
            "hunt_clusters": tk.StringVar(value="0"),
            "operational_alerts": tk.StringVar(value="0"),
            "operational_cases": tk.StringVar(value="0"),
            "stale_assigned_alerts": tk.StringVar(value="0"),
            "stale_active_cases": tk.StringVar(value="0"),
        }
        self.summary_label_vars = {
            "events_total": tk.StringVar(value="Events"),
            "alerts_total": tk.StringVar(value="Alerts"),
            "open_alerts": tk.StringVar(value="Open Alerts"),
            "cases_total": tk.StringVar(value="Cases"),
            "open_cases": tk.StringVar(value="Open Cases"),
            "host_findings": tk.StringVar(value="Host Findings"),
            "hunt_clusters": tk.StringVar(value="Hunt Clusters"),
            "operational_alerts": tk.StringVar(value="Operational Alerts"),
            "operational_cases": tk.StringVar(value="Operational Cases"),
            "stale_assigned_alerts": tk.StringVar(value="Stale Assigned Alerts"),
            "stale_active_cases": tk.StringVar(value="Stale Active Cases"),
        }
        cards = [
            ("Events", "events_total", "#dbeafe"),
            ("Alerts", "alerts_total", "#fde68a"),
            ("Open Alerts", "open_alerts", "#fecaca"),
            ("Cases", "cases_total", "#d1fae5"),
            ("Open Cases", "open_cases", "#ddd6fe"),
            ("Host Findings", "host_findings", "#fee2e2"),
            ("Hunt Clusters", "hunt_clusters", "#e9d5ff"),
            ("Operational Alerts", "operational_alerts", "#e0f2fe"),
            ("Operational Cases", "operational_cases", "#dcfce7"),
            ("Stale Assigned Alerts", "stale_assigned_alerts", "#fde2e2"),
            ("Stale Active Cases", "stale_active_cases", "#ede9fe"),
        ]
        for column, (label, key, bg) in enumerate(cards):
            self._build_summary_card(summary, row=0, column=column, label=label, key=key, bg=bg)

        body = ttk.Frame(self.root, padding=(18, 0, 18, 18), style="SOC.TFrame")
        body.grid(row=2, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.columnconfigure(2, weight=1)
        body.rowconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)
        body.rowconfigure(2, weight=0)

        self.alert_tree = self._build_tree(
            body,
            row=0,
            column=0,
            title="Alert Queue",
            columns=("severity", "title", "updated"),
            headings={"severity": "Severity", "title": "Title", "updated": "Updated"},
            controls=self._build_alert_controls,
        )
        self.alert_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_alert_detail())
        self.alert_tree.bind("<Return>", lambda _event: self.view_alert_source_events())
        self.alert_tree.bind("<Button-3>", self._show_alert_context_menu)
        self.case_tree = self._build_tree(
            body,
            row=0,
            column=1,
            title="Active Cases",
            columns=("status", "severity", "title", "assignee"),
            headings={"status": "Status", "severity": "Severity", "title": "Title", "assignee": "Assignee"},
            controls=self._build_case_controls,
        )
        self.case_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_case_detail())
        self.case_tree.bind("<Return>", lambda _event: self.view_case_linked_activity())
        self.case_tree.bind("<Button-3>", self._show_case_context_menu)
        self.host_tree = self._build_tree(
            body,
            row=0,
            column=2,
            title="Host Monitor Findings",
            columns=("severity", "title", "checked"),
            headings={"severity": "Severity", "title": "Title", "checked": "Checked"},
        )
        self.host_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_host_detail())
        self.host_tree.bind("<Return>", lambda _event: self.view_host_related_activity())
        self.host_tree.bind("<Button-3>", self._show_host_context_menu)
        self.correlation_tree = self._build_tree(
            body,
            row=1,
            column=0,
            title="Recent Correlations",
            columns=("rule", "severity", "title", "events"),
            headings={"rule": "Rule", "severity": "Severity", "title": "Title", "events": "Events"},
        )
        self.correlation_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_correlation_detail())
        self.correlation_tree.bind("<Double-1>", lambda _event: self._open_selected_correlation())
        self.correlation_tree.bind("<Return>", lambda _event: self.open_selected_correlation_action())
        self.correlation_tree.bind("<Button-3>", self._show_correlation_context_menu)
        self.event_tree = self._build_tree(
            body,
            row=1,
            column=1,
            title="Recent Events",
            columns=("type", "severity", "title", "created"),
            headings={"type": "Type", "severity": "Severity", "title": "Title", "created": "Created"},
        )
        self.event_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_recent_event_detail())
        self.event_tree.bind("<Double-1>", lambda _event: self._open_selected_recent_event())
        self.event_tree.bind("<Return>", lambda _event: self.open_selected_recent_event_action())
        self.event_tree.bind("<Button-3>", self._show_recent_event_context_menu)
        ops_frame = ttk.LabelFrame(body, text="Ownership, Aging And Activity", padding=(10, 10), style="SOC.TLabelframe")
        ops_frame.grid(row=1, column=2, sticky="nsew", padx=(8, 0), pady=(8, 0))
        ops_frame.columnconfigure(0, weight=1)
        ops_frame.rowconfigure(1, weight=1)
        ops_controls = ttk.Frame(ops_frame, style="SOC.TFrame")
        ops_controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(ops_controls, text="Assignee", style="SOC.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.workload_assignee_combo = ttk.Combobox(
            ops_controls,
            textvariable=self.workload_assignee_var,
            values=("all",),
            state="readonly",
            width=18,
        )
        self.workload_assignee_combo.grid(row=0, column=1, sticky="w", padx=(0, 12))
        ttk.Label(ops_controls, text="Alert Age", style="SOC.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 6))
        ttk.Combobox(
            ops_controls,
            textvariable=self.alert_age_bucket_var,
            values=("all", "0-4h", "4-24h", "24-72h", "72h+"),
            state="readonly",
            width=10,
        ).grid(row=0, column=3, sticky="w", padx=(0, 12))
        ttk.Label(ops_controls, text="Case Age", style="SOC.TLabel").grid(row=0, column=4, sticky="w", padx=(0, 6))
        ttk.Combobox(
            ops_controls,
            textvariable=self.case_age_bucket_var,
            values=("all", "0-4h", "4-24h", "24-72h", "72h+"),
            state="readonly",
            width=10,
        ).grid(row=0, column=5, sticky="w", padx=(0, 12))
        ttk.Button(ops_controls, text="Acknowledge Stale Alerts", command=self.acknowledge_stale_alerts).grid(
            row=0, column=6, sticky="w"
        )
        ttk.Button(ops_controls, text="Reassign Stale Alerts", command=self.reassign_stale_alerts).grid(
            row=0, column=7, sticky="w", padx=(8, 0)
        )
        ttk.Button(ops_controls, text="Reassign Stale Cases", command=self.reassign_stale_cases).grid(
            row=0, column=8, sticky="w", padx=(8, 0)
        )
        ttk.Button(ops_controls, text="View Alert Bucket", command=self.view_alert_age_bucket).grid(
            row=0, column=9, sticky="w", padx=(12, 0)
        )
        ttk.Button(ops_controls, text="View Case Bucket", command=self.view_case_age_bucket).grid(
            row=0, column=10, sticky="w", padx=(8, 0)
        )
        ttk.Button(ops_controls, text="Assign Alert Bucket", command=self.assign_alert_age_bucket).grid(
            row=0, column=11, sticky="w", padx=(12, 0)
        )
        ttk.Button(ops_controls, text="Promote Alert Bucket", command=self.promote_alert_age_bucket).grid(
            row=0, column=12, sticky="w", padx=(8, 0)
        )
        ttk.Button(ops_controls, text="Assign Case Bucket", command=self.assign_case_age_bucket).grid(
            row=0, column=13, sticky="w", padx=(8, 0)
        )
        ttk.Button(ops_controls, text="Export Current View", command=self.export_current_dashboard_view).grid(
            row=0, column=14, sticky="w", padx=(12, 0)
        )
        ttk.Button(ops_controls, text="View Tracker Blocks", command=self.view_recent_tracker_blocks).grid(
            row=1, column=9, columnspan=2, sticky="w", padx=(12, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Refresh Tracker Feeds", command=self.refresh_tracker_feeds).grid(
            row=1, column=11, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Tracker Feed Details", command=self.show_tracker_feed_details).grid(
            row=1, column=13, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Packet Sessions", command=self.view_packet_sessions).grid(
            row=2, column=9, columnspan=2, sticky="w", padx=(12, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Network Evidence", command=self.view_network_evidence).grid(
            row=2, column=11, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Promote Network Evidence", command=self.promote_network_evidence_to_case).grid(
            row=2, column=13, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Promote Packet Session", command=self.promote_packet_session_to_case).grid(
            row=2, column=15, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Detection Rules", command=self.view_detection_rules).grid(
            row=2, column=17, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Packet Correlations", command=self.view_packet_overlap_correlations).grid(
            row=2, column=18, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Operational Alerts", command=self.view_operational_alerts).grid(
            row=2, column=19, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Operational Cases", command=self.view_operational_cases).grid(
            row=2, column=20, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Acknowledge Operational", command=self.acknowledge_selected_operational_alert).grid(
            row=2, column=21, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Promote Operational", command=self.promote_selected_operational_alert).grid(
            row=2, column=22, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Open Operational Case", command=self.open_selected_operational_case).grid(
            row=2, column=23, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Investigating Operational Case", command=self.mark_selected_operational_case_investigating).grid(
            row=2, column=24, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Close Operational Case", command=self.close_selected_operational_case).grid(
            row=2, column=25, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Clear Operational Pressure", command=self.clear_operational_case_pressure).grid(
            row=2, column=26, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Operational Case Alerts", command=self.view_operational_case_alerts).grid(
            row=2, column=27, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Clear Operational Filter", command=self.clear_operational_reason_filter).grid(
            row=2, column=28, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Toggle Detection Rule", command=self.toggle_detection_rule).grid(
            row=2, column=29, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Update Detection Param", command=self.update_detection_rule_parameter).grid(
            row=2, column=30, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Rule Alerts", command=self.view_detection_rule_alerts).grid(
            row=2, column=31, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Rule Evidence", command=self.view_detection_rule_evidence).grid(
            row=2, column=32, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Endpoint Timeline", command=self.view_endpoint_timeline).grid(
            row=2, column=33, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Timeline Clusters", command=self.view_endpoint_timeline_clusters).grid(
            row=2, column=34, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Promote Timeline Slice", command=self.promote_endpoint_timeline_to_case).grid(
            row=2, column=35, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Hunt Clusters", command=self.view_hunt_telemetry_clusters).grid(
            row=2, column=36, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Promote Hunt Cluster", command=self.promote_hunt_telemetry_cluster_to_case).grid(
            row=2, column=37, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Label(ops_controls, text="Hunt Cluster", style="SOC.TLabel").grid(row=5, column=9, sticky="w", padx=(12, 0), pady=(8, 0))
        ttk.Combobox(
            ops_controls,
            textvariable=self.hunt_cluster_mode_var,
            values=("remote_ip", "device_id", "process_guid"),
            state="readonly",
            width=12,
        ).grid(row=5, column=10, sticky="w", padx=(8, 0), pady=(8, 0))
        ttk.Entry(ops_controls, textvariable=self.hunt_cluster_value_var, width=24).grid(
            row=5, column=11, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Apply Hunt Filter", command=self.apply_hunt_cluster_filter).grid(
            row=5, column=13, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Clear Hunt Filter", command=self.clear_hunt_cluster_filter).grid(
            row=5, column=15, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Open Selected Correlation", command=self.open_selected_correlation_action).grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Open Selected Event", command=self.open_selected_recent_event_action).grid(
            row=1, column=3, columnspan=3, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Clear Activity Focus", command=self.clear_activity_focus).grid(
            row=1, column=6, columnspan=3, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Remote Nodes", command=self.view_remote_nodes).grid(
            row=3, column=9, columnspan=2, sticky="w", padx=(12, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Node Action History", command=self.view_remote_node_action_history).grid(
            row=3, column=11, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Node Pressure", command=self.view_remote_node_action_pressure).grid(
            row=3, column=13, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Refresh Remote Nodes", command=self.refresh_remote_nodes).grid(
            row=3, column=15, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Acknowledge Node", command=self.acknowledge_remote_node).grid(
            row=3, column=17, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Escalate Node", command=self.escalate_remote_node).grid(
            row=3, column=19, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Suppress Node", command=self.suppress_remote_node).grid(
            row=3, column=21, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Clear Node Suppression", command=self.clear_remote_node_suppression).grid(
            row=3, column=23, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Node Maintenance", command=self.start_remote_node_maintenance).grid(
            row=4, column=9, columnspan=2, sticky="w", padx=(12, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Clear Maintenance", command=self.clear_remote_node_maintenance).grid(
            row=4, column=11, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Request Node Refresh", command=self.request_remote_node_refresh).grid(
            row=4, column=13, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Drain Node", command=self.drain_remote_node).grid(
            row=4, column=15, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Mark Node Ready", command=self.mark_remote_node_ready).grid(
            row=4, column=17, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Retry Node Action", command=self.retry_remote_node_action).grid(
            row=4, column=19, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Cancel Node Action", command=self.cancel_remote_node_action).grid(
            row=4, column=21, columnspan=2, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        self.ops_detail_text = tk.Text(
            ops_frame,
            height=14,
            wrap="word",
            bg="#f5f8ff",
            fg="#24364a",
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=10,
        )
        self.ops_detail_text.grid(row=1, column=0, sticky="nsew")
        self.ops_detail_text.configure(state="disabled")
        detail_row = ttk.Frame(body, style="SOC.TFrame")
        detail_row.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
        detail_row.columnconfigure(0, weight=1)
        detail_row.columnconfigure(1, weight=1)
        detail_row.columnconfigure(2, weight=1)
        detail_row.rowconfigure(0, weight=1)

        alert_detail_frame = ttk.LabelFrame(detail_row, text="Alert Details", padding=(10, 10), style="SOC.TLabelframe")
        alert_detail_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        alert_detail_frame.columnconfigure(0, weight=1)
        alert_detail_frame.rowconfigure(1, weight=1)
        alert_detail_controls = ttk.Frame(alert_detail_frame, style="SOC.TFrame")
        alert_detail_controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(alert_detail_controls, text="Copy Alert Detail", command=self.copy_selected_alert_detail).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(alert_detail_controls, text="Save Alert Detail", command=self.save_selected_alert_detail).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        ttk.Button(alert_detail_controls, text="Open Linked Case", command=self.open_linked_case_from_alert_detail).grid(
            row=0, column=2, sticky="w", padx=(8, 0)
        )
        self.alert_detail_text = tk.Text(
            alert_detail_frame,
            height=10,
            wrap="word",
            bg="#fff8f3",
            fg="#24364a",
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=10,
        )
        self.alert_detail_text.grid(row=1, column=0, sticky="nsew")
        self.alert_detail_text.configure(state="disabled")

        detail_frame = ttk.LabelFrame(detail_row, text="Case Details", padding=(10, 10), style="SOC.TLabelframe")
        detail_frame.grid(row=0, column=1, sticky="nsew")
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(1, weight=1)
        case_detail_controls = ttk.Frame(detail_frame, style="SOC.TFrame")
        case_detail_controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(case_detail_controls, text="Copy Case Detail", command=self.copy_selected_case_detail).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(case_detail_controls, text="Save Case Detail", command=self.save_selected_case_detail).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        self.case_detail_text = tk.Text(
            detail_frame,
            height=10,
            wrap="word",
            bg="#f8fbff",
            fg="#24364a",
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=10,
        )
        self.case_detail_text.grid(row=1, column=0, sticky="nsew")
        self.case_detail_text.configure(state="disabled")

        host_detail_frame = ttk.LabelFrame(detail_row, text="Host Monitor Details", padding=(10, 10), style="SOC.TLabelframe")
        host_detail_frame.grid(row=0, column=2, sticky="nsew")
        host_detail_frame.columnconfigure(0, weight=1)
        host_detail_frame.rowconfigure(1, weight=1)
        host_detail_controls = ttk.Frame(host_detail_frame, style="SOC.TFrame")
        host_detail_controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(host_detail_controls, text="Copy Host Detail", command=self.copy_selected_host_detail).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(host_detail_controls, text="Save Host Detail", command=self.save_selected_host_detail).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        ttk.Button(host_detail_controls, text="View Related Activity", command=self.view_host_related_activity).grid(
            row=0, column=2, sticky="w", padx=(8, 0)
        )
        self.host_detail_text = tk.Text(
            host_detail_frame,
            height=10,
            wrap="word",
            bg="#fff5f5",
            fg="#24364a",
            font=("Consolas", 10),
            relief="flat",
            padx=10,
            pady=10,
        )
        self.host_detail_text.grid(row=1, column=0, sticky="nsew")
        self.host_detail_text.configure(state="disabled")

    def _build_tree(
        self,
        parent: Any,
        *,
        row: int,
        column: int,
        title: str,
        columns: Sequence[str],
        headings: dict[str, str],
        controls: Callable[[Any], None] | None = None,
    ) -> Any:
        frame = ttk.LabelFrame(parent, text=title, padding=(10, 10), style="SOC.TLabelframe")
        frame.grid(row=row, column=column, sticky="nsew", padx=(0 if column == 0 else 8, 0), pady=(0 if row == 0 else 8, 0))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        if controls is not None:
            controls(frame)
        tree = ttk.Treeview(frame, columns=list(columns), show="headings", style="SOC.Treeview")
        tree.grid(row=1, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        scrollbar.grid(row=1, column=1, sticky="ns")
        tree.configure(yscrollcommand=scrollbar.set)
        for name in columns:
            tree.heading(name, text=headings[name])
            tree.column(name, anchor="w", width=180 if name != "title" else 320)
        return tree

    def _build_summary_card(self, parent: Any, *, row: int, column: int, label: str, key: str, bg: str) -> None:
        card = tk.Frame(parent, bg=bg, bd=0, highlightthickness=0, padx=14, pady=14, cursor="hand2")
        card.grid(row=row, column=column, sticky="nsew", padx=(0 if column == 0 else 8, 0))
        title_var = getattr(self, "summary_label_vars", {}).get(key)
        if title_var is None:
            title = tk.Label(card, text=label, font=("Segoe UI", 10, "bold"), bg=bg, fg="#1f2937", cursor="hand2")
        else:
            title = tk.Label(card, textvariable=title_var, font=("Segoe UI", 10, "bold"), bg=bg, fg="#1f2937", cursor="hand2")
        title.pack(anchor="w")
        value = tk.Label(card, textvariable=self.summary_vars[key], font=("Segoe UI", 22, "bold"), bg=bg, fg="#0f2f57", cursor="hand2")
        value.pack(anchor="w", pady=(8, 0))

        def handle_click(_event: Any) -> None:
            self.open_summary_drilldown(key)

        def handle_enter(_event: Any) -> None:
            card.configure(highlightbackground="#4f7cff", highlightthickness=1)

        def handle_leave(_event: Any) -> None:
            card.configure(highlightthickness=0)

        for widget in (card, title, value):
            widget.bind("<Button-1>", handle_click)
            widget.bind("<Enter>", handle_enter)
            widget.bind("<Leave>", handle_leave)

    def _build_alert_controls(self, parent: Any) -> None:
        controls = ttk.Frame(parent, style="SOC.TFrame")
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(controls, text="Severity", style="SOC.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Combobox(
            controls,
            textvariable=self.alert_severity_var,
            values=("all", "critical", "high", "medium", "low"),
            state="readonly",
            width=10,
        ).grid(row=0, column=1, sticky="w", padx=(0, 12))
        ttk.Label(controls, text="Case", style="SOC.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 6))
        ttk.Combobox(
            controls,
            textvariable=self.alert_link_state_var,
            values=("unlinked", "linked", "all"),
            state="readonly",
            width=10,
        ).grid(row=0, column=3, sticky="w", padx=(0, 12))
        ttk.Label(controls, text="Sort", style="SOC.TLabel").grid(row=0, column=4, sticky="w", padx=(0, 6))
        ttk.Combobox(
            controls,
            textvariable=self.alert_sort_var,
            values=("severity_desc", "updated_desc", "updated_asc", "severity_asc"),
            state="readonly",
            width=14,
        ).grid(row=0, column=5, sticky="w", padx=(0, 12))
        ttk.Button(controls, text="Apply", command=self.refresh).grid(row=0, column=6, sticky="w")
        ttk.Button(controls, text="Assign", command=self.assign_selected_alert).grid(row=0, column=7, sticky="w", padx=(12, 0))
        ttk.Button(controls, text="Acknowledge", command=self.acknowledge_selected_alert).grid(
            row=0,
            column=8,
            sticky="w",
            padx=(8, 0),
        )
        ttk.Button(controls, text="Close", command=self.close_selected_alert).grid(row=0, column=9, sticky="w", padx=(8, 0))
        ttk.Button(controls, text="Add Note", command=self.add_alert_note).grid(row=0, column=10, sticky="w", padx=(8, 0))
        ttk.Button(controls, text="View Source Events", command=self.view_alert_source_events).grid(
            row=0,
            column=11,
            sticky="w",
            padx=(8, 0),
        )
        ttk.Button(controls, text="Link To Selected Case", command=self.link_alert_to_selected_case).grid(
            row=0,
            column=12,
            sticky="w",
            padx=(12, 0),
        )
        ttk.Button(controls, text="Promote To New Case", command=self.promote_selected_alert).grid(
            row=0,
            column=13,
            sticky="w",
            padx=(8, 0),
        )

    def _build_case_controls(self, parent: Any) -> None:
        controls = ttk.Frame(parent, style="SOC.TFrame")
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(controls, text="Status", style="SOC.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Combobox(
            controls,
            textvariable=self.case_status_var,
            values=("all", "open", "investigating", "contained", "closed"),
            state="readonly",
            width=14,
        ).grid(row=0, column=1, sticky="w", padx=(0, 12))
        ttk.Label(controls, text="Sort", style="SOC.TLabel").grid(row=0, column=2, sticky="w", padx=(0, 6))
        ttk.Combobox(
            controls,
            textvariable=self.case_sort_var,
            values=("updated_desc", "severity_desc", "updated_asc", "severity_asc"),
            state="readonly",
            width=14,
        ).grid(row=0, column=3, sticky="w", padx=(0, 12))
        ttk.Button(controls, text="Apply", command=self.refresh).grid(row=0, column=4, sticky="w")
        ttk.Button(controls, text="Assign", command=self.assign_selected_case).grid(row=0, column=5, sticky="w", padx=(12, 0))
        ttk.Button(controls, text="Investigating", command=self.mark_case_investigating).grid(
            row=0,
            column=6,
            sticky="w",
            padx=(8, 0),
        )
        ttk.Button(controls, text="Contained", command=self.mark_case_contained).grid(row=0, column=7, sticky="w", padx=(8, 0))
        ttk.Button(controls, text="Close", command=self.close_selected_case).grid(row=0, column=8, sticky="w", padx=(8, 0))
        ttk.Button(controls, text="Add Note", command=self.add_case_note).grid(row=0, column=9, sticky="w", padx=(12, 0))
        ttk.Button(controls, text="View Linked Activity", command=self.view_case_linked_activity).grid(
            row=0,
            column=10,
            sticky="w",
            padx=(8, 0),
        )
        ttk.Button(controls, text="Add Observable", command=self.add_case_observable).grid(
            row=0,
            column=11,
            sticky="w",
            padx=(8, 0),
        )

    def apply_queue_preset(self) -> None:
        preset_name = self.queue_preset_var.get() or "custom"
        preset = self._preset_values(preset_name)
        if str(preset_name).strip().lower() != "operational":
            self.operational_reason_filter = None
        elif self.operational_reason_filter is None:
            restored_filter = self._persisted_operational_reason_filter()
            self.operational_reason_filter = restored_filter
            self.saved_operational_reason_filter = restored_filter
        if preset:
            self.alert_severity_var.set(preset["alert_severity"])
            self.alert_link_state_var.set(preset["alert_link_state"])
            self.alert_sort_var.set(preset["alert_sort"])
            self.case_status_var.set(preset["case_status"])
            self.case_sort_var.set(preset["case_sort"])
        self.refresh()

    @staticmethod
    def _normalize_hunt_cluster_mode(value: str | None) -> str:
        normalized = str(value or "").strip()
        return normalized if normalized in {"remote_ip", "device_id", "process_guid"} else "remote_ip"

    @staticmethod
    def _normalize_hunt_cluster_action(value: str | None) -> str:
        normalized = str(value or "").strip()
        return normalized if normalized in {"events", "existing_case", "case", "details"} else "events"

    def refresh(self) -> None:
        dashboard = cast(dict[str, Any], self.manager.dashboard())
        view_state = cast(dict[str, Any], dashboard.get("view_state") or {})
        if getattr(self, "saved_operational_reason_filter", None) is None:
            saved_filter = str(view_state.get("operational_reason_filter") or "").strip() or None
            self.saved_operational_reason_filter = saved_filter
            if self._selected_preset_name() == "operational" and self.operational_reason_filter is None:
                self.operational_reason_filter = saved_filter
        if getattr(self, "saved_hunt_cluster_mode", None) is None:
            saved_hunt_mode = self._normalize_hunt_cluster_mode(cast(str | None, view_state.get("hunt_cluster_mode")))
            saved_hunt_value = str(view_state.get("hunt_cluster_value") or "").strip() or None
            self.saved_hunt_cluster_mode = saved_hunt_mode
            self.saved_hunt_cluster_value = saved_hunt_value
            if hasattr(self, "hunt_cluster_mode_var"):
                self.hunt_cluster_mode_var.set(saved_hunt_mode)
            if hasattr(self, "hunt_cluster_value_var"):
                self.hunt_cluster_value_var.set(saved_hunt_value or "")
        if getattr(self, "saved_hunt_cluster_key", None) is None:
            self.saved_hunt_cluster_key = str(view_state.get("hunt_cluster_key") or "").strip() or None
        if getattr(self, "saved_hunt_cluster_action", None) is None:
            self.saved_hunt_cluster_action = self._normalize_hunt_cluster_action(
                cast(str | None, view_state.get("hunt_cluster_action"))
            )
        self._latest_dashboard = dashboard
        summary = cast(dict[str, Any], dashboard["summary"])
        workload = cast(dict[str, Any], dashboard.get("workload") or {})
        triage = cast(dict[str, list[dict[str, Any]]], dashboard["triage"])
        dashboard["tracker_feed_status"] = self.tracker_intel.feed_status()
        packet_sessions = self._collect_packet_sessions()
        network_observations = self.network_monitor.list_recent_observations(limit=100)
        all_alerts = self.manager.list_alerts()
        operational_alerts = [
            item
            for item in all_alerts
            if str(item.category or "").casefold() == "operational"
        ]
        operational_alert_count = len(operational_alerts)
        operational_case_count = len(self._operational_cases())
        operational_reason_counts = dict(
            Counter(
                self._operational_route_reason(getattr(item, "correlation_key", None))
                for item in operational_alerts
            )
        )
        dashboard["operational_status"] = {
            "alert_count": operational_alert_count,
            "case_count": operational_case_count,
            "reason_counts": operational_reason_counts,
            "active_filter": self.operational_reason_filter,
            "saved_filter": getattr(self, "saved_operational_reason_filter", None),
        }
        dashboard["view_state"] = {
            **view_state,
            "operational_reason_filter": getattr(self, "saved_operational_reason_filter", None),
            "hunt_cluster_mode": getattr(self, "saved_hunt_cluster_mode", None) or "remote_ip",
            "hunt_cluster_value": getattr(self, "saved_hunt_cluster_value", None),
            "hunt_cluster_key": getattr(self, "saved_hunt_cluster_key", None),
            "hunt_cluster_action": getattr(self, "saved_hunt_cluster_action", None) or "events",
        }
        dashboard["packet_session_status"] = {
            "session_count": len(packet_sessions),
            "recent_sessions": packet_sessions[:10],
        }
        dashboard["network_evidence_status"] = {
            "observation_count": len(network_observations),
            "recent_observations": network_observations[:10],
            "combined_evidence": self._collect_network_evidence(packet_sessions=packet_sessions, observations=network_observations)[:10],
        }
        host_state = self._load_host_monitor_state()
        host_findings = cast(list[dict[str, Any]], host_state.get("active_findings") or [])
        alert_rows = self._alert_rows_for_view(dashboard)
        case_rows = self._case_rows_for_view(dashboard)
        all_events = self.manager.list_events(limit=500)
        active_hunt_cluster_mode, active_hunt_cluster_filters = self._active_hunt_telemetry_cluster_filters()
        active_hunt_cluster_value = str(active_hunt_cluster_filters.get(active_hunt_cluster_mode) or "").strip()
        remote_ip_hunt_clusters = self._collect_hunt_telemetry_clusters(cluster_by="remote_ip", limit=100)
        device_hunt_clusters = self._collect_hunt_telemetry_clusters(cluster_by="device_id", limit=100)
        process_hunt_clusters = self._collect_hunt_telemetry_clusters(cluster_by="process_guid", limit=100)
        dashboard["hunt_cluster_status"] = {
            "count": len(remote_ip_hunt_clusters),
            "cluster_mode_counts": {
                "remote_ip": len(remote_ip_hunt_clusters),
                "device_id": len(device_hunt_clusters),
                "process_guid": len(process_hunt_clusters),
            },
            "active_mode": active_hunt_cluster_mode,
            "active_value": active_hunt_cluster_value or None,
            "recent_clusters": remote_ip_hunt_clusters[:5],
        }
        for key, value in self.summary_vars.items():
            if key == "host_findings":
                value.set(str(len(host_findings)))
            elif key == "hunt_clusters":
                value.set(str(len(remote_ip_hunt_clusters)))
            elif key == "operational_alerts":
                value.set(str(operational_alert_count))
            elif key == "operational_cases":
                value.set(str(operational_case_count))
            elif key in workload:
                value.set(str(workload.get(key, 0)))
            else:
                value.set(str(summary.get(key, 0)))
        active_operational_filter = str(self.operational_reason_filter or "").strip()
        if hasattr(self, "summary_label_vars"):
            operational_alerts_label = cast(dict[str, Any], self.summary_label_vars).get("operational_alerts")
            if operational_alerts_label is not None and hasattr(operational_alerts_label, "set"):
                operational_alerts_label.set(
                    self._format_operational_summary_label("Operational Alerts", active_operational_filter)
                )
            operational_cases_label = cast(dict[str, Any], self.summary_label_vars).get("operational_cases")
            if operational_cases_label is not None and hasattr(operational_cases_label, "set"):
                operational_cases_label.set(
                    self._format_operational_summary_label("Operational Cases", active_operational_filter)
                )
        self.status_var.set(self._format_status_line(dashboard, host_findings_count=len(host_findings)))
        self._populate_tree(
            self.alert_tree,
            [item.model_dump(mode="json") for item in alert_rows],
            lambda item: (item["severity"], item["title"], item["updated_at"]),
            item_id_key="alert_id",
        )
        self.alert_rows_by_id = {item["alert_id"]: item for item in [item.model_dump(mode="json") for item in alert_rows]}
        self.all_alert_rows_by_id = {item.alert_id: item.model_dump(mode="json") for item in all_alerts}
        self._populate_tree(
            self.case_tree,
            [item.model_dump(mode="json") for item in case_rows],
            lambda item: (item["status"], item["severity"], item["title"], item.get("assignee") or "-"),
            item_id_key="case_id",
        )
        self.case_rows_by_id = {item["case_id"]: item for item in [item.model_dump(mode="json") for item in case_rows]}
        self.event_rows_by_id = {item.event_id: item.model_dump(mode="json") for item in all_events}
        self._refresh_alert_detail()
        self._refresh_case_detail()
        self._populate_tree(
            self.host_tree,
            host_findings,
            lambda item: (
                str(item.get("severity", "-")),
                str(item.get("title", "-")),
                str(host_state.get("last_checked_at") or "-"),
            ),
            item_id_key="key",
        )
        self.host_rows_by_key = {
            str(item["key"]): {
                **item,
                "last_checked_at": host_state.get("last_checked_at"),
                "snapshot": host_state.get("snapshot") or {},
            }
            for item in host_findings
            if item.get("key")
        }
        self._refresh_host_detail()
        self._populate_tree(
            self.correlation_tree,
            triage["recent_correlations"],
            lambda item: (
                item.get("correlation_rule") or "-",
                item["severity"],
                item["title"],
                str(len(item.get("source_event_ids") or [])),
            ),
            item_id_key="alert_id",
        )
        self.correlation_rows_by_id = {
            str(item["alert_id"]): item for item in triage["recent_correlations"] if item.get("alert_id")
        }
        self._populate_tree(
            self.event_tree,
            cast(list[dict[str, Any]], summary["recent_events"]),
            lambda item: (item["event_type"], item["severity"], item["title"], item["created_at"]),
            item_id_key="event_id",
        )
        self._refresh_workload_assignee_options(dashboard)
        self._set_ops_detail_text(self._format_workload_detail(dashboard))
        self._refresh_correlation_detail()

    def _populate_tree(
        self,
        tree: Any,
        rows: Sequence[dict[str, Any]],
        row_builder: Callable[[dict[str, Any]], tuple[str, ...] | tuple[str, str, str] | tuple[str, str, str, str]],
        item_id_key: str | None = None,
    ) -> None:
        for item in tree.get_children():
            tree.delete(item)
        for index, row in enumerate(rows):
            item_id = str(row[item_id_key]) if item_id_key is not None else f"row-{index}"
            tree.insert("", "end", iid=item_id, values=row_builder(row))

    def promote_selected_alert(self) -> None:
        alert_id = self._selected_tree_item_id(self.alert_tree)
        if alert_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Alert Selected", "Select an alert from the queue before promoting it.")
            return

        alert = self.manager.get_alert(alert_id)
        actor = self._current_analyst_identity()
        _, case = self.manager.promote_alert_to_case(
            alert_id,
            payload=self._build_promote_payload(alert, acted_by=actor),
        )
        if messagebox is not None:
            messagebox.showinfo(
                "Case Created",
                f"Promoted alert {alert_id} into case {case.case_id}.",
            )
        self.refresh()

    def link_alert_to_selected_case(self) -> None:
        alert_id = self._selected_tree_item_id(self.alert_tree)
        case_id = self._selected_tree_item_id(self.case_tree)
        if alert_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Alert Selected", "Select an alert before linking it to a case.")
            return
        if case_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Case Selected", "Select a case before linking an alert into it.")
            return
        alert = self.manager.get_alert(alert_id)
        _, case = self.manager.promote_alert_to_case(
            alert_id,
            payload=self._build_promote_payload(
                alert,
                acted_by=self._current_analyst_identity(),
                existing_case_id=case_id,
            ),
        )
        if messagebox is not None:
            messagebox.showinfo(
                "Alert Linked",
                f"Linked alert {alert_id} into case {case.case_id}.",
            )
        self.refresh()
        self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def assign_selected_alert(self) -> None:
        self._prompt_selected_record_update(
            tree=self.alert_tree,
            rows_by_id=self.alert_rows_by_id,
            missing_selection_title="No Alert Selected",
            missing_selection_message="Select an alert before assigning it.",
            missing_record_title="Alert Unavailable",
            missing_record_message="The selected alert is no longer available in the current view.",
            prompt_title="Assign Alert",
            prompt_message="Enter the analyst or queue for the selected alert:",
            apply_update=lambda alert_id, value, _payload: self.manager.update_alert(
                alert_id,
                self._build_alert_update_payload(field="assignee", value=value, acted_by=self._current_analyst_identity()),
            ),
            refresh_detail=self._refresh_alert_detail,
        )

    def acknowledge_selected_alert(self) -> None:
        self._apply_alert_status("acknowledged", "Alert Acknowledged")

    def close_selected_alert(self) -> None:
        self._apply_alert_status("closed", "Alert Closed")

    def add_alert_note(self) -> None:
        self._prompt_alert_update(
            field="note",
            title="Add Alert Note",
            prompt="Enter a note for the selected alert:",
        )

    def view_alert_source_events(self) -> None:
        selected = self._require_selected_record(
            tree=self.alert_tree,
            rows_by_id=self.alert_rows_by_id,
            missing_selection_title="No Alert Selected",
            missing_selection_message="Select an alert before viewing source events.",
            missing_record_title="Alert Unavailable",
            missing_record_message="The selected alert is no longer available in the current view.",
        )
        if selected is None:
            return
        _alert_id, alert_payload = selected
        source_events = self._resolve_source_events(alert_payload)
        selected_event = self._select_summary_record("event", source_events, title="Source Events")
        if selected_event is None:
            self._show_info_dialog("Source Events", self._format_source_events(alert_payload, source_events))
            return
        self._pivot_from_event(selected_event)

    def add_case_note(self) -> None:
        self._prompt_case_update(
            field="note",
            title="Add Case Note",
            prompt="Enter a note for the selected case:",
        )

    def add_case_observable(self) -> None:
        self._prompt_case_update(
            field="observable",
            title="Add Case Observable",
            prompt="Enter an observable for the selected case:",
        )

    def acknowledge_stale_alerts(self) -> None:
        stale_alert_ids = self._stale_alert_ids()
        actor = self._current_analyst_identity()
        self._apply_bulk_record_updates(
            record_ids=stale_alert_ids,
            empty_title="No Stale Alerts",
            empty_message="There are no assigned stale alerts to acknowledge.",
            apply_update=lambda alert_id: self.manager.update_alert(
                alert_id,
                self._build_alert_update_payload(field="status", value="acknowledged", acted_by=actor),
            ),
            success_title="Stale Alerts Updated",
            success_message=lambda count: f"Acknowledged {count} stale alerts.",
        )

    def reassign_stale_alerts(self) -> None:
        stale_alert_ids = self._stale_alert_ids()
        self._prompt_bulk_assignee_update(
            record_ids=stale_alert_ids,
            empty_title="No Stale Alerts",
            empty_message="There are no assigned stale alerts to reassign.",
            prompt_title="Reassign Stale Alerts",
            prompt_message="Enter the analyst or queue for the stale alerts:",
            apply_update=lambda alert_id, assignee: self.manager.update_alert(
                alert_id,
                self._build_alert_update_payload(field="assignee", value=assignee),
            ),
            success_title="Stale Alerts Reassigned",
            success_message=lambda count: f"Reassigned {count} stale alerts.",
        )

    def reassign_stale_cases(self) -> None:
        stale_case_ids = self._stale_case_ids()
        self._prompt_bulk_assignee_update(
            record_ids=stale_case_ids,
            empty_title="No Stale Cases",
            empty_message="There are no stale active cases to reassign.",
            prompt_title="Reassign Stale Cases",
            prompt_message="Enter the analyst or queue for the stale cases:",
            apply_update=lambda case_id, assignee: self.manager.update_case(
                case_id,
                self._build_case_update_payload(field="assignee", value=assignee),
            ),
            success_title="Stale Cases Reassigned",
            success_message=lambda count: f"Reassigned {count} stale cases.",
        )

    def view_alert_age_bucket(self) -> None:
        bucket = self.alert_age_bucket_var.get().strip() or "all"
        rows = self._age_bucket_alert_rows(bucket)
        if messagebox is not None:
            messagebox.showinfo("Alert Aging Bucket", self._format_age_bucket_records("alert", bucket, rows))

    def view_case_age_bucket(self) -> None:
        bucket = self.case_age_bucket_var.get().strip() or "all"
        rows = self._age_bucket_case_rows(bucket)
        if messagebox is not None:
            messagebox.showinfo("Case Aging Bucket", self._format_age_bucket_records("case", bucket, rows))

    def assign_alert_age_bucket(self) -> None:
        bucket = self.alert_age_bucket_var.get().strip() or "all"
        rows = self._age_bucket_alert_rows(bucket)
        if not rows:
            if messagebox is not None:
                messagebox.showinfo("No Alerts", "No alerts matched the selected age bucket.")
            return
        rows = self._select_age_bucket_rows("alert", bucket, rows, id_key="alert_id")
        if not rows:
            return
        self._prompt_bulk_assignee_update(
            record_ids=[str(row.get("alert_id") or "") for row in rows],
            empty_title="No Alerts",
            empty_message="No alerts matched the selected age bucket.",
            prompt_title="Assign Alert Bucket",
            prompt_message="Enter the analyst or queue for the selected alert bucket:",
            apply_update=lambda alert_id, assignee: self.manager.update_alert(
                alert_id,
                self._build_alert_update_payload(field="assignee", value=assignee),
            ),
            success_title="Alert Bucket Assigned",
            success_message=lambda count: f"Assigned {count} alerts from the selected rows.",
        )

    def promote_alert_age_bucket(self) -> None:
        bucket = self.alert_age_bucket_var.get().strip() or "all"
        rows = self._age_bucket_alert_rows(bucket)
        if not rows:
            if messagebox is not None:
                messagebox.showinfo("No Alerts", "No alerts matched the selected age bucket.")
            return
        rows = self._select_age_bucket_rows("alert", bucket, rows, id_key="alert_id")
        if not rows:
            return
        self._promote_alert_rows_to_selected_case(
            rows=rows,
            missing_case_title="No Case Selected",
            missing_case_message="Select a case before promoting the alert bucket.",
            success_title="Alert Bucket Promoted",
            success_message=lambda promoted, case_id: f"Linked {promoted} alerts into case {case_id}.",
        )

    def assign_case_age_bucket(self) -> None:
        bucket = self.case_age_bucket_var.get().strip() or "all"
        rows = self._age_bucket_case_rows(bucket)
        if not rows:
            if messagebox is not None:
                messagebox.showinfo("No Cases", "No cases matched the selected age bucket.")
            return
        rows = self._select_age_bucket_rows("case", bucket, rows, id_key="case_id")
        if not rows:
            return
        self._prompt_bulk_assignee_update(
            record_ids=[str(row.get("case_id") or "") for row in rows],
            empty_title="No Cases",
            empty_message="No cases matched the selected age bucket.",
            prompt_title="Assign Case Bucket",
            prompt_message="Enter the analyst or queue for the selected case bucket:",
            apply_update=lambda case_id, assignee: self.manager.update_case(
                case_id,
                self._build_case_update_payload(field="assignee", value=assignee),
            ),
            success_title="Case Bucket Assigned",
            success_message=lambda count: f"Assigned {count} cases from the selected rows.",
        )

    def view_case_linked_activity(self) -> None:
        selected = self._require_selected_record(
            tree=self.case_tree,
            rows_by_id=self.case_rows_by_id,
            missing_selection_title="No Case Selected",
            missing_selection_message="Select a case before viewing linked activity.",
            missing_record_title="Case Unavailable",
            missing_record_message="The selected case is no longer available in the current view.",
        )
        if selected is None:
            return
        _case_id, case_payload = selected
        linked_alerts = self._resolve_linked_alerts(case_payload)
        source_events = self._resolve_case_source_events(case_payload)
        case_timeline_clusters = self._resolve_case_endpoint_timeline_clusters(case_payload, source_events=source_events)
        hunt_available = bool(case_payload.get("observables") or source_events)
        timeline_filters: dict[str, Any] = {}
        if not case_timeline_clusters:
            timeline_filters = self._endpoint_timeline_filters_from_case(case_payload, source_events=source_events)
        grouped_rule_alerts = self._resolve_case_rule_alert_groups(case_payload, linked_alerts)
        grouped_rule_evidence = self._resolve_case_rule_evidence_groups(case_payload, source_events)
        choice = self._call_case_activity_pivot(
            case_payload,
            linked_alerts=linked_alerts,
            source_events=source_events,
            timeline_available=bool(case_timeline_clusters or timeline_filters),
            hunt_available=hunt_available,
            grouped_rule_alerts=grouped_rule_alerts,
            grouped_rule_evidence=grouped_rule_evidence,
        )
        if choice == "alerts":
            selected_alert = self._select_summary_record("alert", linked_alerts, title="Linked Alerts")
            if selected_alert is None:
                self._show_info_dialog("Case Linked Activity", self._format_case_linked_activity(case_payload, linked_alerts, source_events))
                return
            self._pivot_from_alert(selected_alert)
            return
        if choice == "events":
            selected_event = self._select_summary_record("event", source_events, title="Source Events")
            if selected_event is None:
                self._show_info_dialog("Case Linked Activity", self._format_case_linked_activity(case_payload, linked_alerts, source_events))
                return
            self._pivot_from_event(selected_event)
            return
        if choice == "timeline":
            if case_timeline_clusters:
                self._pivot_from_case_timeline_clusters(case_payload, linked_alerts, source_events, case_timeline_clusters)
                return
            if timeline_filters:
                self._pivot_from_endpoint_timeline(case_payload, timeline_filters=timeline_filters)
            return
        if choice == "hunt":
            self._pivot_from_case_hunt_telemetry_clusters(case_payload, linked_alerts, source_events)
            return
        if choice == "rule_alerts":
            self._pivot_from_case_rule_alert_groups(case_payload, grouped_rule_alerts, linked_alerts, source_events)
            return
        if choice == "rule_evidence":
            self._pivot_from_case_rule_evidence_groups(case_payload, grouped_rule_evidence, linked_alerts, source_events)
            return
        self._show_info_dialog("Case Linked Activity", self._format_case_linked_activity(case_payload, linked_alerts, source_events))

    def view_host_related_activity(self) -> None:
        selected = self._require_selected_record(
            tree=self.host_tree,
            rows_by_id=self.host_rows_by_key,
            missing_selection_title="No Host Finding Selected",
            missing_selection_message="Select a host finding before viewing related activity.",
            missing_record_title="Host Finding Unavailable",
            missing_record_message="The selected host finding is no longer available.",
        )
        if selected is None:
            return
        _finding_key, finding_payload = selected
        related_events = self._resolve_host_events(finding_payload)
        if not related_events:
            self._show_info_dialog("Host Finding Activity", self._format_host_detail(finding_payload))
            return
        selected_event = self._select_summary_record("event", related_events, title="Host Finding Events")
        if selected_event is None:
            self._show_info_dialog("Host Finding Activity", self._format_summary_records("event", related_events, limit=30))
            return
        self._pivot_from_event(selected_event)

    def assign_selected_case(self) -> None:
        self._prompt_selected_record_update(
            tree=self.case_tree,
            rows_by_id=self.case_rows_by_id,
            missing_selection_title="No Case Selected",
            missing_selection_message="Select a case before assigning it.",
            missing_record_title="Case Unavailable",
            missing_record_message="The selected case is no longer available in the current view.",
            prompt_title="Assign Case",
            prompt_message="Enter the analyst or queue for the selected case:",
            apply_update=lambda case_id, value, _payload: self.manager.update_case(
                case_id,
                self._build_case_update_payload(field="assignee", value=value),
            ),
            refresh_detail=self._refresh_case_detail,
        )

    def mark_case_investigating(self) -> None:
        self._apply_case_status("investigating", "Case Updated")

    def mark_case_contained(self) -> None:
        self._apply_case_status("contained", "Case Updated")

    def close_selected_case(self) -> None:
        self._apply_case_status("closed", "Case Updated")

    def _apply_alert_status(self, status_value: str, title: str) -> None:
        self._apply_selected_record_update(
            tree=self.alert_tree,
            rows_by_id=self.alert_rows_by_id,
            missing_selection_title="No Alert Selected",
            missing_selection_message="Select an alert before applying a status update.",
            missing_record_title="Alert Unavailable",
            missing_record_message="The selected alert is no longer available in the current view.",
            update=lambda alert_id, _payload: self.manager.update_alert(
                alert_id,
                self._build_alert_update_payload(
                    field="status",
                    value=status_value,
                    acted_by=self._current_analyst_identity(),
                ),
            ),
            refresh_detail=self._refresh_alert_detail,
            success_title=title,
            success_message=lambda alert_id: f"Updated alert {alert_id} to {status_value}.",
        )

    def _prompt_alert_update(self, *, field: str, title: str, prompt: str) -> None:
        self._prompt_selected_record_update(
            tree=self.alert_tree,
            rows_by_id=self.alert_rows_by_id,
            missing_selection_title="No Alert Selected",
            missing_selection_message="Select an alert before applying an update.",
            missing_record_title="Alert Unavailable",
            missing_record_message="The selected alert is no longer available in the current view.",
            prompt_title=title,
            prompt_message=prompt,
            apply_update=lambda alert_id, value, _payload: self.manager.update_alert(
                alert_id,
                self._build_alert_update_payload(
                    field=field,
                    value=value,
                    acted_by=self._current_analyst_identity(),
                ),
            ),
            refresh_detail=self._refresh_alert_detail,
        )

    def _apply_case_status(self, status_value: str, title: str) -> None:
        self._apply_selected_record_update(
            tree=self.case_tree,
            rows_by_id=self.case_rows_by_id,
            missing_selection_title="No Case Selected",
            missing_selection_message="Select a case before applying a status update.",
            missing_record_title="Case Unavailable",
            missing_record_message="The selected case is no longer available in the current view.",
            update=lambda case_id, _payload: self.manager.update_case(
                case_id,
                self._build_case_update_payload(field="status", value=status_value),
            ),
            refresh_detail=self._refresh_case_detail,
            success_title=title,
            success_message=lambda case_id: f"Updated case {case_id} to {status_value}.",
        )

    def _alert_query_kwargs(self) -> dict[str, Any]:
        severity = self._parse_severity(self.alert_severity_var.get())
        linked_case_state = self.alert_link_state_var.get()
        assignee = "unassigned"
        preset_name = self._selected_preset_name()
        if preset_name == "my-queue":
            assignee = self._current_analyst_identity() or "unassigned"
        elif preset_name == "unassigned":
            assignee = "unassigned"
        return {
            "status": SocAlertStatus.open,
            "severity": severity,
            "assignee": assignee,
            "linked_case_state": None if linked_case_state == "all" else linked_case_state,
            "sort": self.alert_sort_var.get() or "severity_desc",
            "limit": 25,
        }

    def _case_query_kwargs(self) -> dict[str, Any]:
        status_value = self.case_status_var.get()
        query: dict[str, Any] = {
            "status": self._parse_case_status(status_value),
            "sort": self.case_sort_var.get() or "updated_desc",
            "limit": 25,
        }
        preset_name = self._selected_preset_name()
        if preset_name == "my-queue":
            query["assignee"] = self._current_analyst_identity() or "unassigned"
        elif preset_name == "unassigned":
            query["assignee"] = "unassigned"
        return query

    @staticmethod
    def _selected_tree_item_id(tree: Any) -> str | None:
        selection = tree.selection()
        if not selection:
            return None
        selected = selection[0]
        return str(selected) if selected else None

    def _prompt_case_update(self, *, field: str, title: str, prompt: str) -> None:
        self._prompt_selected_record_update(
            tree=self.case_tree,
            rows_by_id=self.case_rows_by_id,
            missing_selection_title="No Case Selected",
            missing_selection_message="Select a case before applying an update.",
            missing_record_title="Case Unavailable",
            missing_record_message="The selected case is no longer available in the current view.",
            prompt_title=title,
            prompt_message=prompt,
            apply_update=lambda case_id, value, _payload: self.manager.update_case(
                case_id,
                self._build_case_update_payload(field=field, value=value),
            ),
            refresh_detail=self._refresh_case_detail,
        )

    def open_summary_drilldown(self, metric_key: str) -> None:
        handlers: dict[str, Callable[[], None]] = {
            "events_total": self._show_events_summary_drilldown,
            "alerts_total": self._show_all_alerts_summary_drilldown,
            "open_alerts": self._show_open_alerts_summary_drilldown,
            "cases_total": self._show_all_cases_summary_drilldown,
            "open_cases": self._show_open_cases_summary_drilldown,
            "host_findings": self._show_host_findings_summary_drilldown,
            "hunt_clusters": self._show_hunt_clusters_summary_drilldown,
            "operational_alerts": self._show_operational_alerts_summary_drilldown,
            "operational_cases": self._show_operational_cases_summary_drilldown,
            "stale_assigned_alerts": self._show_stale_alerts_summary_drilldown,
            "stale_active_cases": self._show_stale_cases_summary_drilldown,
        }
        handler = handlers.get(metric_key)
        if handler is not None:
            handler()

    def _show_events_summary_drilldown(self) -> None:
        events = [item.model_dump(mode="json") for item in self.manager.list_events(limit=50)]
        selected = self._select_summary_record("event", events, title="Events")
        if selected is None:
            return
        self._pivot_from_event(selected)

    def _pivot_from_event(self, event_payload: dict[str, Any]) -> None:
        related_alerts = self._resolve_event_alerts(event_payload)
        related_cases = self._resolve_event_cases(event_payload)
        choice = self._choose_event_pivot(event_payload, related_alerts=related_alerts, related_cases=related_cases)
        if choice == "alerts":
            selected_alert = self._select_summary_record_or_show_info(
                "alert",
                related_alerts,
                title="Related Alerts",
                info_title="Related Alerts",
                limit=30,
            )
            if selected_alert is None:
                return
            self._pivot_from_alert(selected_alert)
        elif choice == "cases":
            selected_case = self._select_summary_record_or_show_info(
                "case",
                related_cases,
                title="Related Cases",
                info_title="Related Cases",
                limit=30,
            )
            if selected_case is None:
                return
            self._pivot_from_case(selected_case)
        else:
            self._show_info_dialog("Event Details", self._format_summary_records("event", [event_payload], limit=1))

    def _pivot_from_alert(self, alert_payload: dict[str, Any]) -> None:
        source_events = self._resolve_source_events(alert_payload)
        linked_case_id = str(alert_payload.get("linked_case_id") or "")
        linked_case = self.case_rows_by_id.get(linked_case_id) if linked_case_id else None
        timeline_filters = self._endpoint_timeline_filters_from_alert(
            alert_payload,
            source_events=source_events,
            linked_case=linked_case,
        )
        choice = self._choose_alert_pivot(
            alert_payload,
            source_events=source_events,
            linked_case=linked_case,
            timeline_available=bool(timeline_filters),
        )
        if choice == "events":
            selected_event = self._select_summary_record_or_show_info(
                "event",
                source_events,
                title="Source Events",
                info_title="Alert Details",
                info_text=self._format_alert_detail(alert_payload),
            )
            if selected_event is None:
                return
            self._pivot_from_event(selected_event)
            return
        if choice == "timeline" and timeline_filters:
            self._pivot_from_alert_timeline(alert_payload, timeline_filters=timeline_filters)
            return
        if choice == "case" and linked_case is not None:
            self._pivot_from_case(linked_case)
            return
        self._show_info_dialog("Alert Details", self._format_alert_detail(alert_payload))

    def _pivot_from_case(self, case_payload: dict[str, Any]) -> None:
        linked_alerts = self._resolve_linked_alerts(case_payload)
        source_events = self._resolve_case_source_events(case_payload)
        case_timeline_clusters = self._resolve_case_endpoint_timeline_clusters(case_payload, source_events=source_events)
        hunt_available = bool(case_payload.get("observables") or source_events)
        timeline_filters: dict[str, Any] = {}
        if not case_timeline_clusters:
            timeline_filters = self._endpoint_timeline_filters_from_case(case_payload, source_events=source_events)
        grouped_rule_alerts = self._resolve_case_rule_alert_groups(case_payload, linked_alerts)
        grouped_rule_evidence = self._resolve_case_rule_evidence_groups(case_payload, source_events)
        choice = self._call_case_activity_pivot(
            case_payload,
            linked_alerts=linked_alerts,
            source_events=source_events,
            timeline_available=bool(case_timeline_clusters or timeline_filters),
            hunt_available=hunt_available,
            grouped_rule_alerts=grouped_rule_alerts,
            grouped_rule_evidence=grouped_rule_evidence,
        )
        if choice == "alerts":
            selected_alert = self._select_summary_record_or_show_info(
                "alert",
                linked_alerts,
                title="Linked Alerts",
                info_title="Case Linked Activity",
                info_text=self._format_case_linked_activity(case_payload, linked_alerts, source_events),
            )
            if selected_alert is None:
                return
            self._pivot_from_alert(selected_alert)
            return
        if choice == "events":
            selected_event = self._select_summary_record_or_show_info(
                "event",
                source_events,
                title="Source Events",
                info_title="Case Linked Activity",
                info_text=self._format_case_linked_activity(case_payload, linked_alerts, source_events),
            )
            if selected_event is None:
                return
            self._pivot_from_event(selected_event)
            return
        if choice == "timeline":
            if case_timeline_clusters:
                self._pivot_from_case_timeline_clusters(case_payload, linked_alerts, source_events, case_timeline_clusters)
                return
            if timeline_filters:
                self._pivot_from_endpoint_timeline(case_payload, timeline_filters=timeline_filters)
            return
        if choice == "hunt":
            self._pivot_from_case_hunt_telemetry_clusters(case_payload, linked_alerts, source_events)
            return
        if choice == "rule_alerts":
            self._pivot_from_case_rule_alert_groups(case_payload, grouped_rule_alerts, linked_alerts, source_events)
            return
        if choice == "rule_evidence":
            self._pivot_from_case_rule_evidence_groups(case_payload, grouped_rule_evidence, linked_alerts, source_events)
            return
        self._show_info_dialog("Case Details", self._format_case_detail(case_payload))

    def _show_all_alerts_summary_drilldown(self) -> None:
        self._navigate_summary_view(
            preset_name="custom",
            focus_target="alerts",
            alert_severity="all",
            alert_link_state="all",
            alert_sort="updated_desc",
        )

    def _show_open_alerts_summary_drilldown(self) -> None:
        self._navigate_summary_view(
            preset_name="custom",
            focus_target="alerts",
            alert_severity="all",
            alert_link_state="all",
            alert_sort="updated_desc",
        )

    def _show_all_cases_summary_drilldown(self) -> None:
        self._navigate_summary_view(
            preset_name="custom",
            focus_target="cases",
            case_status="all",
            case_sort="updated_desc",
        )

    def _show_open_cases_summary_drilldown(self) -> None:
        self._navigate_summary_view(
            preset_name="custom",
            focus_target="cases",
            case_status="open",
            case_sort="updated_desc",
        )

    def _show_host_findings_summary_drilldown(self) -> None:
        self.refresh()
        self._focus_tree_widget(self.host_tree)
        if not self.host_tree.selection() and self.host_tree.get_children():
            self.host_tree.selection_set(self.host_tree.get_children()[0])
            self._refresh_host_detail()

    def _show_hunt_clusters_summary_drilldown(self) -> None:
        self.view_hunt_telemetry_clusters()

    def _show_operational_alerts_summary_drilldown(self) -> None:
        choice = self._choose_operational_summary_reason("alerts")
        if choice == "cancel":
            return
        self._set_operational_reason_filter(None if choice == "all" else choice)
        self._navigate_summary_view(preset_name="operational", focus_target="alerts")

    def _show_operational_cases_summary_drilldown(self) -> None:
        choice = self._choose_operational_summary_reason("cases")
        if choice == "cancel":
            return
        self._set_operational_reason_filter(None if choice == "all" else choice)
        self._navigate_summary_view(preset_name="operational", focus_target="cases")

    def clear_operational_reason_filter(self) -> None:
        self._set_operational_reason_filter(None)
        self.refresh()

    def apply_hunt_cluster_filter(self) -> None:
        mode = self._selected_hunt_telemetry_cluster_mode()
        value = str(self.hunt_cluster_value_var.get().strip() if hasattr(self, "hunt_cluster_value_var") else "")
        self._set_hunt_telemetry_cluster_filter(mode, value or None)
        self.refresh()

    def clear_hunt_cluster_filter(self) -> None:
        self._set_hunt_telemetry_cluster_filter("remote_ip", None)
        self.refresh()

    def _refresh_correlation_detail(self) -> None:
        alert_id = self._selected_tree_item_id(self.correlation_tree)
        if alert_id is None:
            self._refresh_activity_detail(None)
            return
        correlation_payload = self.correlation_rows_by_id.get(alert_id)
        if correlation_payload is None:
            self._refresh_activity_detail("Selected correlation is no longer available.")
            return
        if hasattr(self, "event_tree"):
            self.event_tree.selection_remove(self.event_tree.selection())
        self._refresh_activity_detail(self._format_correlation_detail(correlation_payload))

    def _refresh_recent_event_detail(self) -> None:
        event_id = self._selected_tree_item_id(self.event_tree)
        if event_id is None:
            self._refresh_activity_detail(None)
            return
        event_payload = self.event_rows_by_id.get(event_id)
        if event_payload is None:
            self._refresh_activity_detail("Selected recent event is no longer available.")
            return
        if hasattr(self, "correlation_tree"):
            self.correlation_tree.selection_remove(self.correlation_tree.selection())
        self._refresh_activity_detail(self._format_recent_event_detail(event_payload))

    def _open_selected_correlation(self) -> None:
        alert_id = self._selected_tree_item_id(self.correlation_tree)
        if alert_id is None:
            return
        alert_payload = self.correlation_rows_by_id.get(alert_id)
        if alert_payload is None:
            return
        self._pivot_from_alert(alert_payload)

    def _open_selected_recent_event(self) -> None:
        event_id = self._selected_tree_item_id(self.event_tree)
        if event_id is None:
            return
        event_payload = self.event_rows_by_id.get(event_id)
        if event_payload is None:
            return
        self._pivot_from_event(event_payload)

    def open_selected_correlation_action(self) -> None:
        if self._selected_tree_item_id(self.correlation_tree) is None:
            self._show_info_dialog("Recent Correlations", "Select a correlation row to open its alert workflow.")
            return
        self._open_selected_correlation()

    def open_selected_recent_event_action(self) -> None:
        if self._selected_tree_item_id(self.event_tree) is None:
            self._show_info_dialog("Recent Events", "Select an event row to open its event workflow.")
            return
        self._open_selected_recent_event()

    def _show_correlation_context_menu(self, event: Any) -> None:
        if self._select_tree_row_at_pointer(self.correlation_tree, event) is None or tk is None:
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Open Selected Correlation", command=self.open_selected_correlation_action)
        menu.add_separator()
        menu.add_command(label="Clear Activity Focus", command=self.clear_activity_focus)
        menu.tk_popup(event.x_root, event.y_root)

    def _show_recent_event_context_menu(self, event: Any) -> None:
        if self._select_tree_row_at_pointer(self.event_tree, event) is None or tk is None:
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Open Selected Event", command=self.open_selected_recent_event_action)
        menu.add_separator()
        menu.add_command(label="Clear Activity Focus", command=self.clear_activity_focus)
        menu.tk_popup(event.x_root, event.y_root)

    def _show_alert_context_menu(self, event: Any) -> None:
        if self._select_tree_row_at_pointer(self.alert_tree, event) is None or tk is None:
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Assign Alert", command=self.assign_selected_alert)
        menu.add_command(label="Acknowledge Alert", command=self.acknowledge_selected_alert)
        menu.add_command(label="Close Alert", command=self.close_selected_alert)
        menu.add_separator()
        menu.add_command(label="Add Alert Note", command=self.add_alert_note)
        menu.add_command(label="View Source Events", command=self.view_alert_source_events)
        menu.add_command(label="Promote To New Case", command=self.promote_selected_alert)
        menu.tk_popup(event.x_root, event.y_root)

    def _show_case_context_menu(self, event: Any) -> None:
        if self._select_tree_row_at_pointer(self.case_tree, event) is None or tk is None:
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Assign Case", command=self.assign_selected_case)
        menu.add_command(label="Mark Investigating", command=self.mark_case_investigating)
        menu.add_command(label="Mark Contained", command=self.mark_case_contained)
        menu.add_command(label="Close Case", command=self.close_selected_case)
        menu.add_separator()
        menu.add_command(label="Add Case Note", command=self.add_case_note)
        menu.add_command(label="Add Observable", command=self.add_case_observable)
        menu.add_command(label="View Linked Activity", command=self.view_case_linked_activity)
        menu.tk_popup(event.x_root, event.y_root)

    def _show_host_context_menu(self, event: Any) -> None:
        if self._select_tree_row_at_pointer(self.host_tree, event) is None or tk is None:
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="View Related Activity", command=self.view_host_related_activity)
        menu.add_command(label="Refresh Host Detail", command=self._refresh_host_detail)
        menu.tk_popup(event.x_root, event.y_root)

    @staticmethod
    def _select_tree_row_at_pointer(tree: Any, event: Any) -> str | None:
        row_id = tree.identify_row(event.y)
        if not row_id:
            return None
        tree.selection_set(row_id)
        if hasattr(tree, "focus"):
            tree.focus(row_id)
        return str(row_id)

    def clear_activity_focus(self) -> None:
        if hasattr(self, "correlation_tree"):
            self.correlation_tree.selection_remove(self.correlation_tree.selection())
        if hasattr(self, "event_tree"):
            self.event_tree.selection_remove(self.event_tree.selection())
        self._refresh_activity_detail(None)

    def _refresh_activity_detail(self, activity_text: str | None) -> None:
        base = self._format_workload_detail(self._latest_dashboard) if getattr(self, "_latest_dashboard", None) else "No workload data loaded."
        if activity_text:
            self._set_ops_detail_text(f"{base}\n\nSelected Activity:\n{activity_text}")
            return
        self._set_ops_detail_text(base)

    def _show_stale_alerts_summary_drilldown(self) -> None:
        self._navigate_summary_view(preset_name="handoff", focus_target="alerts")

    def _show_stale_cases_summary_drilldown(self) -> None:
        self._navigate_summary_view(preset_name="handoff", focus_target="cases")

    def _show_info_dialog(self, title: str, body: str) -> None:
        if messagebox is not None:
            messagebox.showinfo(title, body)

    def _select_summary_record(
        self,
        kind: str,
        rows: Sequence[dict[str, Any]],
        *,
        title: str,
    ) -> dict[str, Any] | None:
        if not rows:
            self._show_info_dialog(title, f"No {kind} records are available.")
            return None
        if tk is None or not hasattr(self, "root"):
            return dict(rows[0])
        if len(rows) == 1:
            return dict(rows[0])

        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg="#eef4ff")
        dialog.transient(self.root)
        dialog.grab_set()
        _center_window(dialog, 920, 560)
        dialog.minsize(800, 460)
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(1, weight=1)

        tk.Label(
            dialog,
            text=f"Select {kind.title()} Record",
            bg="#eef4ff",
            fg="#0f2f57",
            font=("Segoe UI", 14, "bold"),
            anchor="w",
            padx=16,
            pady=12,
        ).grid(row=0, column=0, sticky="ew")

        list_frame = tk.Frame(dialog, bg="#eef4ff", padx=16, pady=4)
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        listbox = tk.Listbox(
            list_frame,
            selectmode=tk.SINGLE,
            activestyle="none",
            bg="#ffffff",
            fg="#24364a",
            font=("Consolas", 10),
            relief="flat",
            highlightthickness=1,
        )
        listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        listbox.configure(yscrollcommand=scrollbar.set)

        for row in rows:
            listbox.insert("end", self._format_summary_selection_label(kind, row))
        listbox.selection_set(0)

        selected_index = 0

        def use_selected() -> None:
            nonlocal selected_index
            selection = listbox.curselection()
            if selection:
                selected_index = int(selection[0])
            dialog.destroy()

        def cancel_selection() -> None:
            nonlocal selected_index
            selected_index = -1
            dialog.destroy()

        controls = tk.Frame(dialog, bg="#eef4ff", padx=16, pady=12)
        controls.grid(row=2, column=0, sticky="ew")
        tk.Button(controls, text="Cancel", command=cancel_selection, width=12).pack(side="right")
        tk.Button(controls, text="Open", command=use_selected, width=12).pack(side="right", padx=(0, 8))
        dialog.bind("<Escape>", lambda _event: cancel_selection())
        dialog.bind("<Return>", lambda _event: use_selected())
        self.root.wait_window(dialog)
        if not (0 <= selected_index < len(rows)):
            return None
        return dict(rows[selected_index])

    def _select_summary_record_or_show_info(
        self,
        kind: str,
        rows: Sequence[dict[str, Any]],
        *,
        title: str,
        info_title: str,
        info_text: str | None = None,
        info_kind: str | None = None,
        info_rows: Sequence[dict[str, Any]] | None = None,
        limit: int = 50,
    ) -> dict[str, Any] | None:
        selected = self._select_summary_record(kind, rows, title=title)
        if selected is not None:
            return selected
        if info_text is None:
            info_text = self._format_summary_records(info_kind or kind, info_rows if info_rows is not None else rows, limit=limit)
        self._show_info_dialog(info_title, info_text)
        return None

    def view_recent_tracker_blocks(self) -> None:
        tracker_events = [
            event.model_dump(mode="json")
            for event in self.manager.list_events(limit=200)
            if event.event_type == "privacy.tracker_block"
        ]
        selected = self._select_summary_record_or_show_info(
            "tracker_block",
            tracker_events[:50],
            title="Recent Tracker Blocks",
            info_title="Recent Tracker Blocks",
            limit=50,
        )
        if selected is None:
            return
        self._pivot_from_event(selected)

    def refresh_tracker_feeds(self) -> None:
        try:
            result = self.tracker_intel.refresh_feed_cache()
        except Exception as exc:  # noqa: BLE001
            if messagebox is not None:
                messagebox.showerror("Refresh Tracker Feeds", str(exc))
            return
        self.refresh()
        if messagebox is not None:
            domain_count = int(result.get("domain_count") or 0)
            messagebox.showinfo("Refresh Tracker Feeds", f"Tracker feeds refreshed. Domains loaded: {domain_count}.")

    def show_tracker_feed_details(self) -> None:
        status = cast(dict[str, Any], getattr(self, "_latest_dashboard", {}).get("tracker_feed_status") or self.tracker_intel.feed_status())
        lines = [
            "Tracker Feed Details:",
            "",
            f"Cache Path: {status.get('cache_path') or '-'}",
            f"Domain Count: {status.get('domain_count', 0)}",
            f"Updated At: {status.get('updated_at') or '-'}",
            f"Last Refresh Attempted At: {status.get('last_refresh_attempted_at') or '-'}",
            f"Last Refresh Result: {status.get('last_refresh_result') or 'unknown'}",
            f"Last Error: {status.get('last_error') or 'none'}",
            f"Stale: {status.get('is_stale', False)}",
            f"Age Hours: {status.get('age_hours') if status.get('age_hours') is not None else '-'}",
            f"TLS Verification: {status.get('verify_tls', True)}",
            "",
            "Active Feed URLs:",
        ]
        active_urls = cast(list[str], status.get("active_feed_urls") or [])
        if active_urls:
            lines.extend(f"- {url}" for url in active_urls)
        else:
            lines.append("- none")
        lines.extend(["", "Source Results:"])
        sources = cast(list[dict[str, Any]], status.get("sources") or [])
        if sources:
            lines.extend(
                f"- {item.get('url', '-')}: domains={item.get('domain_count', 0)}"
                for item in sources[:20]
            )
        else:
            lines.append("- none")
        lines.extend(["", "Failures:"])
        failures = cast(list[dict[str, Any]], status.get("failures") or [])
        if failures:
            lines.extend(
                f"- {item.get('url', '-')}: {item.get('error', '-')}"
                for item in failures[:20]
            )
        else:
            lines.append("- none")
        self._show_info_dialog("Tracker Feed Details", "\n".join(lines))

    def view_packet_sessions(self) -> None:
        sessions = self._collect_packet_sessions(limit=50)
        selected = self._select_summary_record_or_show_info(
            "packet_session",
            sessions,
            title="Packet Sessions",
            info_title="Packet Sessions",
            limit=50,
        )
        if selected is None:
            return
        self._pivot_from_packet_session(selected)

    def view_network_evidence(self) -> None:
        evidence_rows = self._collect_network_evidence()
        selected = self._select_summary_record_or_show_info(
            "network_evidence",
            evidence_rows,
            title="Network Evidence",
            info_title="Network Evidence",
            limit=50,
        )
        if selected is None:
            return
        self._pivot_from_network_evidence(selected)

    def view_endpoint_timeline(self) -> None:
        timeline_rows = self._collect_endpoint_timeline(limit=100)
        selected = self._select_summary_record_or_show_info(
            "endpoint_timeline",
            timeline_rows,
            title="Endpoint Timeline",
            info_title="Endpoint Timeline",
            limit=50,
        )
        if selected is None:
            return
        self._pivot_from_event(selected)

    def view_endpoint_timeline_clusters(self) -> None:
        cluster_by = self._choose_endpoint_timeline_cluster_mode()
        clusters = self._collect_endpoint_timeline_clusters(cluster_by=cluster_by, limit=100)
        selected = self._select_summary_record_or_show_info(
            "endpoint_timeline_cluster",
            clusters,
            title="Endpoint Timeline Clusters",
            info_title="Endpoint Timeline Clusters",
            limit=50,
        )
        if selected is None:
            return
        selected = self._resolve_endpoint_timeline_cluster_detail(selected)
        open_case_ids = [str(item) for item in cast(list[Any], selected.get("open_case_ids") or []) if str(item)]
        if self._handle_existing_case_guard(
            open_case_ids=open_case_ids,
            context_label=f"Endpoint timeline cluster {selected.get('label', selected.get('cluster_key', '-'))}",
        ):
            return
        timeline_rows = self._resolve_endpoint_timeline_cluster_events(selected)
        event_selected = self._select_summary_record_or_show_info(
            "endpoint_timeline",
            timeline_rows,
            title="Endpoint Timeline",
            info_title="Endpoint Timeline",
            info_text=self._format_endpoint_timeline_cluster_detail(selected),
            limit=50,
        )
        if event_selected is None:
            return
        self._pivot_from_event(event_selected)

    def view_hunt_telemetry_clusters(self) -> None:
        cluster_by, cluster_filters = self._active_hunt_telemetry_cluster_filters()
        clusters = self._collect_hunt_telemetry_clusters(cluster_by=cluster_by, limit=100, **cluster_filters)
        saved_cluster_key = str(getattr(self, "saved_hunt_cluster_key", "") or "").strip()
        selected = next(
            (dict(item) for item in clusters if str(item.get("cluster_key") or "").strip() == saved_cluster_key),
            None,
        )
        if selected is None:
            selected = self._select_summary_record_or_show_info(
                "hunt_telemetry_cluster",
                clusters,
                title="Hunt Telemetry Clusters",
                info_title="Hunt Telemetry Clusters",
                limit=50,
            )
        if selected is None:
            return
        selected = self._resolve_hunt_telemetry_cluster_detail(selected)
        self._handle_hunt_telemetry_cluster_selection(selected)

    def view_remote_nodes(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        self._show_info_dialog("Remote Node", self._format_remote_node_detail(self._resolve_remote_node_detail(selected)))

    def view_remote_node_action_history(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        if not remote_nodes:
            self._show_info_dialog("Node Action History", "No remote nodes available.")
            return
        filter_choice = self._choose_action_dialog(
            title="Node Action History",
            summary="Choose a node action history filter.",
            actions=[
                ("Failed", "failed", 12),
                ("Retried", "retried", 12),
                ("Cancelled", "cancelled", 12),
                ("Requested", "requested", 12),
            ],
            default_choice="all",
            no_tk_choice="failed",
            width=520,
            height=180,
            min_width=460,
            min_height=160,
            detail_label="All Nodes",
            detail_width=12,
        )
        filtered = self._filter_remote_nodes_by_action_history(remote_nodes, filter_choice)
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            filtered,
            title="Node Action History",
            info_title="Node Action History",
        )
        if selected is None:
            return
        self._show_info_dialog("Node Action History", self._format_remote_node_detail(self._resolve_remote_node_detail(selected)))

    def view_remote_node_action_pressure(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        if not remote_nodes:
            self._show_info_dialog("Node Action Pressure", "No remote nodes available.")
            return
        filter_choice = self._choose_action_dialog(
            title="Node Action Pressure",
            summary="Choose a remote node pressure filter.",
            actions=[
                ("Repeat Failures", "repeated_failures", 16),
                ("Retry Pressure", "retry_pressure", 14),
                ("Stuck Actions", "stuck_actions", 14),
            ],
            default_choice="all_active",
            no_tk_choice="all_active",
            width=540,
            height=190,
            min_width=480,
            min_height=170,
            detail_label="All Active",
            detail_width=12,
        )
        filtered = self._filter_remote_nodes_by_action_pressure(remote_nodes, filter_choice)
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            filtered,
            title="Node Action Pressure",
            info_title="Node Action Pressure",
        )
        if selected is None:
            return
        if self._handle_existing_case_choice(
            open_case_ids=[str(item) for item in cast(list[Any], selected.get("open_case_ids") or []) if str(item)],
            context_label=f"Node action pressure on {selected.get('node_name', '-')}",
            context_details=[
                f"Status: {selected.get('status', 'unknown')}",
                f"Repeat failures: {bool(selected.get('repeated_failure_active'))}",
                f"Retry pressure: {bool(selected.get('retry_pressure_active'))}",
                f"Stuck actions: {bool(selected.get('stuck_actions_active'))}",
            ],
            no_action_label="view node detail",
        ):
            return
        self._show_info_dialog("Node Action Pressure", self._format_remote_node_detail(self._resolve_remote_node_detail(selected)))

    def refresh_remote_nodes(self) -> None:
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo("Remote Nodes Refreshed", "Reloaded current remote node topology.")

    def acknowledge_remote_node(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        analyst = self._current_analyst_identity() or "operator"
        node_name = str(selected.get("node_name") or "")
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "acknowledge_platform_node"):
            updated = cast(dict[str, Any], platform_client.acknowledge_platform_node(node_name, acknowledged_by=analyst))
        elif manager is not None and hasattr(manager, "acknowledge_platform_node"):
            updated = cast(dict[str, Any], manager.acknowledge_platform_node(node_name, acknowledged_by=analyst))
        else:
            updated = update_platform_node_metadata(
                node_name,
                {
                    "acknowledged_at": datetime.now(UTC).isoformat(),
                    "acknowledged_by": analyst,
                },
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Remote Node Acknowledged",
                f"Acknowledged {updated.get('node_name', '-')}"
                f" as {analyst}.",
            )

    def suppress_remote_node(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        analyst = self._current_analyst_identity() or "operator"
        minutes = 60
        reason = None
        if simpledialog is not None:
            entered_minutes = simpledialog.askinteger(
                "Suppress Remote Node",
                f"Suppress node pressure for {selected.get('node_name', '-')} for how many minutes?",
                initialvalue=60,
                minvalue=1,
                maxvalue=10_080,
            )
            if entered_minutes is None:
                return
            minutes = entered_minutes
            reason = simpledialog.askstring(
                "Suppress Remote Node",
                "Suppression reason (optional):",
                initialvalue="maintenance window",
            )
        node_name = str(selected.get("node_name") or "")
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "suppress_platform_node"):
            updated = cast(
                dict[str, Any],
                platform_client.suppress_platform_node(
                    node_name,
                    minutes=minutes,
                    suppressed_by=analyst,
                    reason=reason,
                    scopes=["remote_node_health"],
                ),
            )
        elif manager is not None and hasattr(manager, "suppress_platform_node"):
            updated = cast(
                dict[str, Any],
                manager.suppress_platform_node(
                    node_name,
                    minutes=minutes,
                    suppressed_by=analyst,
                    reason=reason,
                    scopes=["remote_node_health"],
                ),
            )
        else:
            updated = suppress_platform_node(
                node_name,
                minutes=minutes,
                suppressed_by=analyst,
                reason=reason,
                scopes=["remote_node_health"],
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Remote Node Suppressed",
                f"Suppressed {updated.get('node_name', '-')} for {minutes} minutes.",
            )

    def clear_remote_node_suppression(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        analyst = self._current_analyst_identity() or "operator"
        node_name = str(selected.get("node_name") or "")
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "clear_platform_node_suppression"):
            updated = cast(dict[str, Any], platform_client.clear_platform_node_suppression(node_name))
        elif manager is not None and hasattr(manager, "clear_platform_node_suppression"):
            updated = cast(dict[str, Any], manager.clear_platform_node_suppression(node_name))
        else:
            updated = clear_platform_node_suppression(
                node_name,
                cleared_by=analyst,
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Node Suppression Cleared",
                f"Cleared suppression for {updated.get('node_name', '-')}.",
            )

    def start_remote_node_maintenance(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        analyst = self._current_analyst_identity() or "operator"
        minutes = 60
        reason = None
        services: list[str] = []
        if simpledialog is not None:
            entered_minutes = simpledialog.askinteger(
                "Node Maintenance",
                f"Put {selected.get('node_name', '-')} into maintenance for how many minutes?",
                initialvalue=60,
                minvalue=1,
                maxvalue=10_080,
            )
            if entered_minutes is None:
                return
            minutes = entered_minutes
            service_text = simpledialog.askstring(
                "Node Maintenance",
                "Services in maintenance (comma separated, optional):",
                initialvalue="packet_monitor",
            )
            services = [item.strip() for item in (service_text or "").split(",") if item.strip()]
            reason = simpledialog.askstring(
                "Node Maintenance",
                "Maintenance reason (optional):",
                initialvalue="maintenance window",
            )
        node_name = str(selected.get("node_name") or "")
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "start_platform_node_maintenance"):
            updated = cast(
                dict[str, Any],
                platform_client.start_platform_node_maintenance(
                    node_name,
                    minutes=minutes,
                    maintenance_by=analyst,
                    reason=reason,
                    services=services,
                ),
            )
        elif manager is not None and hasattr(manager, "start_platform_node_maintenance"):
            updated = cast(
                dict[str, Any],
                manager.start_platform_node_maintenance(
                    node_name,
                    minutes=minutes,
                    maintenance_by=analyst,
                    reason=reason,
                    services=services,
                ),
            )
        else:
            updated = start_platform_node_maintenance(
                node_name,
                minutes=minutes,
                maintenance_by=analyst,
                reason=reason,
                services=services,
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Node Maintenance Started",
                f"Started maintenance for {updated.get('node_name', '-')} for {minutes} minutes.",
            )

    def clear_remote_node_maintenance(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        node_name = str(selected.get("node_name") or "")
        analyst = self._current_analyst_identity() or "operator"
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "clear_platform_node_maintenance"):
            updated = cast(dict[str, Any], platform_client.clear_platform_node_maintenance(node_name))
        elif manager is not None and hasattr(manager, "clear_platform_node_maintenance"):
            updated = cast(dict[str, Any], manager.clear_platform_node_maintenance(node_name))
        else:
            updated = clear_platform_node_maintenance(
                node_name,
                cleared_by=analyst,
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Node Maintenance Cleared",
                f"Cleared maintenance for {updated.get('node_name', '-')}.",
            )

    def request_remote_node_refresh(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        analyst = self._current_analyst_identity() or "operator"
        reason = None
        if simpledialog is not None:
            reason = simpledialog.askstring(
                "Request Node Refresh",
                "Refresh request reason (optional):",
                initialvalue="refresh health and service state",
            )
        node_name = str(selected.get("node_name") or "")
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "request_platform_node_refresh"):
            updated = cast(
                dict[str, Any],
                platform_client.request_platform_node_refresh(node_name, requested_by=analyst, reason=reason),
            )
        elif manager is not None and hasattr(manager, "request_platform_node_refresh"):
            updated = cast(
                dict[str, Any],
                manager.request_platform_node_refresh(node_name, requested_by=analyst, reason=reason),
            )
        else:
            updated = request_platform_node_refresh(
                node_name,
                requested_by=analyst,
                reason=reason,
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Node Refresh Requested",
                f"Requested refresh for {updated.get('node_name', '-')}.",
            )

    def drain_remote_node(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        analyst = self._current_analyst_identity() or "operator"
        reason = None
        services: list[str] = []
        if simpledialog is not None:
            service_text = simpledialog.askstring(
                "Drain Node",
                "Services to drain (comma separated, optional):",
                initialvalue="packet_monitor,network_monitor",
            )
            services = [item.strip() for item in (service_text or "").split(",") if item.strip()]
            reason = simpledialog.askstring(
                "Drain Node",
                "Drain reason (optional):",
                initialvalue="maintenance window",
            )
        node_name = str(selected.get("node_name") or "")
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "start_platform_node_drain"):
            updated = cast(
                dict[str, Any],
                platform_client.start_platform_node_drain(
                    node_name,
                    drained_by=analyst,
                    reason=reason,
                    services=services,
                ),
            )
        elif manager is not None and hasattr(manager, "start_platform_node_drain"):
            updated = cast(
                dict[str, Any],
                manager.start_platform_node_drain(
                    node_name,
                    drained_by=analyst,
                    reason=reason,
                    services=services,
                ),
            )
        else:
            updated = start_platform_node_drain(
                node_name,
                drained_by=analyst,
                reason=reason,
                services=services,
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Node Drained",
                f"Marked {updated.get('node_name', '-')} as drained.",
            )

    def mark_remote_node_ready(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        node_name = str(selected.get("node_name") or "")
        analyst = self._current_analyst_identity() or "operator"
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "clear_platform_node_drain"):
            updated = cast(dict[str, Any], platform_client.clear_platform_node_drain(node_name))
        elif manager is not None and hasattr(manager, "clear_platform_node_drain"):
            updated = cast(dict[str, Any], manager.clear_platform_node_drain(node_name))
        else:
            updated = clear_platform_node_drain(
                node_name,
                cleared_by=analyst,
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Node Ready",
                f"Marked {updated.get('node_name', '-')} as ready.",
            )

    def retry_remote_node_action(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        retryable: list[tuple[str, str, int]] = []
        if bool(selected.get("maintenance_retriable")) or str(selected.get("maintenance_status") or "") == "failed":
            retryable.append(("Retry Maintenance", "maintenance", 18))
        if bool(selected.get("refresh_retriable")) or str(selected.get("refresh_status") or "") == "failed":
            retryable.append(("Retry Refresh", "refresh", 16))
        if bool(selected.get("drain_retriable")) or str(selected.get("drain_status") or "") == "failed":
            retryable.append(("Retry Drain", "drain", 14))
        if not retryable:
            if messagebox is not None:
                messagebox.showinfo(
                    "Retry Node Action",
                    f"{selected.get('node_name', '-')} has no failed retriable actions.",
                )
            return
        choice = self._choose_action_dialog(
            title="Retry Node Action",
            summary=(
                f"Retry a failed action for {selected.get('node_name', '-')}.\n\n"
                f"Available retries: {', '.join(value for _label, value, _width in retryable)}"
            ),
            actions=retryable,
            default_choice="cancel",
            no_tk_choice=retryable[0][1],
            width=480,
            height=190,
            min_width=420,
            min_height=170,
            detail_label="Cancel",
            detail_width=10,
        )
        if choice == "cancel":
            return
        analyst = self._current_analyst_identity() or "operator"
        node_name = str(selected.get("node_name") or "")
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "retry_platform_node_action"):
            updated = cast(
                dict[str, Any],
                platform_client.retry_platform_node_action(node_name, action=choice, requested_by=analyst),
            )
        elif manager is not None and hasattr(manager, "retry_platform_node_action"):
            updated = cast(
                dict[str, Any],
                manager.retry_platform_node_action(node_name, action=choice, requested_by=analyst),
            )
        else:
            updated = retry_platform_node_action(
                node_name,
                action=choice,
                requested_by=analyst,
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Node Action Retried",
                f"Requeued {choice} for {updated.get('node_name', '-')}.",
            )

    def cancel_remote_node_action(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        cancellable: list[tuple[str, str, int]] = []
        if str(selected.get("maintenance_status") or "") in {"requested", "acknowledged"}:
            cancellable.append(("Cancel Maintenance", "maintenance", 19))
        if str(selected.get("refresh_status") or "") in {"requested", "acknowledged"}:
            cancellable.append(("Cancel Refresh", "refresh", 16))
        if str(selected.get("drain_status") or "") in {"requested", "acknowledged"}:
            cancellable.append(("Cancel Drain", "drain", 14))
        if not cancellable:
            if messagebox is not None:
                messagebox.showinfo(
                    "Cancel Node Action",
                    f"{selected.get('node_name', '-')} has no pending cancellable actions.",
                )
            return
        choice = self._choose_action_dialog(
            title="Cancel Node Action",
            summary=(
                f"Cancel a pending action for {selected.get('node_name', '-')}.\n\n"
                f"Available cancellations: {', '.join(value for _label, value, _width in cancellable)}"
            ),
            actions=cancellable,
            default_choice="cancel",
            no_tk_choice=cancellable[0][1],
            width=500,
            height=190,
            min_width=440,
            min_height=170,
            detail_label="Cancel",
            detail_width=10,
        )
        if choice == "cancel":
            return
        analyst = self._current_analyst_identity() or "operator"
        node_name = str(selected.get("node_name") or "")
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "cancel_platform_node_action"):
            updated = cast(
                dict[str, Any],
                platform_client.cancel_platform_node_action(node_name, action=choice, cancelled_by=analyst),
            )
        elif manager is not None and hasattr(manager, "cancel_platform_node_action"):
            updated = cast(
                dict[str, Any],
                manager.cancel_platform_node_action(node_name, action=choice, cancelled_by=analyst),
            )
        else:
            updated = cancel_platform_node_action(
                node_name,
                action=choice,
                cancelled_by=analyst,
                path=settings.platform_node_registry_path,
            )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Node Action Cancelled",
                f"Cancelled {choice} for {updated.get('node_name', '-')}.",
            )

    def escalate_remote_node(self) -> None:
        remote_nodes = self._collect_remote_nodes()
        selected = self._select_summary_record_or_show_info(
            "remote_node",
            remote_nodes,
            title="Remote Nodes",
            info_title="Remote Nodes",
        )
        if selected is None:
            return
        open_case_ids = [str(item) for item in cast(list[Any], selected.get("open_case_ids") or []) if str(item)]
        if self._handle_existing_case_choice(
            open_case_ids=open_case_ids,
            context_label=f"Remote node {selected.get('node_name', '-')}",
            context_details=[
                f"Status: {selected.get('status', 'unknown')}",
                f"Open case count: {len(open_case_ids)}",
            ],
            no_action_label="create another case",
        ):
            return
        platform_client = getattr(self, "platform_client", None)
        manager = getattr(self, "manager", None)
        if platform_client is not None and hasattr(platform_client, "create_case_from_remote_node"):
            case = platform_client.create_case_from_remote_node(selected)
        else:
            assert manager is not None
            case = manager.create_case_from_remote_node(selected)
        self.refresh()
        self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()
        if messagebox is not None:
            messagebox.showinfo("Case Created", f"Created case {case.case_id} for remote node {selected.get('node_name', '-')}.")

    def view_detection_rules(self) -> None:
        selected = self._select_detection_rule()
        if selected is None:
            return
        related_alerts = [item.model_dump(mode="json") for item in self.manager.query_alerts(correlation_rule=str(selected.get("rule_id") or ""), limit=50)]
        grouped_alerts = self._group_rule_alerts(related_alerts)
        open_case_ids = sorted(
            {
                str(case_id)
                for group in grouped_alerts
                for case_id in cast(list[Any], group.get("open_case_ids") or [])
                if str(case_id)
            }
        )
        related_case_ids = sorted(
            {
                str(case_id)
                for group in grouped_alerts
                for case_id in cast(list[Any], group.get("related_case_ids") or [])
                if str(case_id)
            }
        )
        selected = dict(selected)
        selected["related_case_ids"] = related_case_ids
        selected["open_case_ids"] = open_case_ids
        selected["open_case_count"] = len(open_case_ids)
        if self._handle_existing_case_guard(
            open_case_ids=open_case_ids,
            context_label=f"Detection rule {selected.get('rule_id', '-')}",
        ):
            return
        self._show_info_dialog("Detection Rule", self._format_detection_rule_detail(selected))

    def toggle_detection_rule(self) -> None:
        selected = self._select_detection_rule()
        if selected is None:
            return
        rule_id = str(selected.get("rule_id") or "")
        enabled = bool(selected.get("enabled"))
        updated = self.manager.update_detection_rule(rule_id, SocDetectionRuleUpdate(enabled=not enabled))
        if messagebox is not None:
            state = "enabled" if updated.enabled else "disabled"
            messagebox.showinfo("Detection Rule Updated", f"Rule {updated.rule_id} is now {state}.")
        self.refresh()

    def update_detection_rule_parameter(self) -> None:
        selected = self._select_detection_rule()
        if selected is None:
            return
        if simpledialog is None:
            return
        rule_id = str(selected.get("rule_id") or "")
        parameter_name = simpledialog.askstring(
            "Update Detection Parameter",
            "Enter the parameter name to update:",
            parent=self.root,
        )
        if not parameter_name:
            return
        parameter_value = simpledialog.askstring(
            "Update Detection Parameter",
            f"Enter the value for {parameter_name}:",
            parent=self.root,
        )
        if parameter_value is None:
            return
        updated = self.manager.update_detection_rule(
            rule_id,
            SocDetectionRuleUpdate(parameters={parameter_name: self._coerce_detection_parameter(parameter_value)}),
        )
        if messagebox is not None:
            messagebox.showinfo(
                "Detection Rule Updated",
                f"Updated {updated.rule_id} parameter {parameter_name} to {updated.parameters.get(parameter_name)!r}.",
            )
        self.refresh()

    def view_packet_overlap_correlations(self) -> None:
        alerts = [
            item.model_dump(mode="json")
            for item in self.manager.query_alerts(correlation_rule="packet_network_remote_overlap", limit=50)
        ]
        selected = self._select_summary_record_or_show_info(
            "alert",
            alerts,
            title="Packet Correlations",
            info_title="Packet Correlations",
            limit=50,
        )
        if selected is None:
            return
        self._pivot_from_alert(selected)

    def view_operational_alerts(self) -> None:
        alerts = [
            self._annotate_operational_alert(item).model_dump(mode="json")
            for item in self.manager.list_alerts()
            if str(item.category or "").casefold() == "operational"
        ][:50]
        selected = self._select_summary_record_or_show_info(
            "alert",
            alerts,
            title="Operational Alerts",
            info_title="Operational Alerts",
            limit=50,
        )
        if selected is None:
            return
        self._pivot_from_alert(selected)

    def view_operational_cases(self) -> None:
        cases = [item.model_dump(mode="json") for item in self._operational_cases()]
        selected = self._select_summary_record_or_show_info(
            "case",
            cases,
            title="Operational Cases",
            info_title="Operational Cases",
            limit=50,
        )
        if selected is None:
            return
        self._pivot_from_case(selected)

    def acknowledge_selected_operational_alert(self) -> None:
        selected = self._require_selected_operational_alert()
        if selected is None:
            return
        alert_id, _payload = selected
        self.manager.update_alert(
            alert_id,
            self._build_alert_update_payload(
                field="status",
                value="acknowledged",
                acted_by=self._current_analyst_identity(),
            ),
        )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo("Operational Alert Acknowledged", f"Acknowledged operational alert {alert_id}.")

    def promote_selected_operational_alert(self) -> None:
        selected = self._require_selected_operational_alert()
        if selected is None:
            return
        alert_id, alert_payload = selected
        if str(alert_payload.get("linked_case_id") or ""):
            if self._open_linked_case_for_alert(
                alert_payload=alert_payload,
                dialog_title="Open Operational Case",
                missing_link_message="The selected operational alert is not linked to a case.",
                missing_case_message="The linked operational case is not available in the current view.",
            ):
                return
        alert = self.manager.get_alert(alert_id)
        _, case = self.manager.promote_alert_to_case(
            alert_id,
            payload=self._build_promote_payload(
                alert,
                acted_by=self._current_analyst_identity(),
            ),
        )
        self.refresh()
        self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()
        if messagebox is not None:
            messagebox.showinfo("Operational Case Created", f"Created case {case.case_id} from operational alert {alert_id}.")

    def open_selected_operational_case(self) -> None:
        selected = self._require_selected_operational_alert()
        if selected is None:
            return
        _alert_id, alert_payload = selected
        self._open_linked_case_for_alert(
            alert_payload=alert_payload,
            dialog_title="Open Operational Case",
            missing_link_message="The selected operational alert is not linked to a case.",
            missing_case_message="The linked operational case is not available in the current view.",
        )

    def mark_selected_operational_case_investigating(self) -> None:
        selected = self._require_selected_operational_case()
        if selected is None:
            return
        case_id, _case_payload = selected
        self.manager.update_case(
            case_id,
            self._build_case_update_payload(field="status", value="investigating"),
        )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo("Operational Case Updated", f"Marked operational case {case_id} as investigating.")

    def close_selected_operational_case(self) -> None:
        selected = self._require_selected_operational_case()
        if selected is None:
            return
        case_id, _case_payload = selected
        self.manager.update_case(
            case_id,
            self._build_case_update_payload(field="status", value="closed"),
        )
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo("Operational Case Updated", f"Closed operational case {case_id}.")

    def clear_operational_case_pressure(self) -> None:
        selected = self._require_selected_operational_case()
        if selected is None:
            return
        case_id, case_payload = selected
        updated = 0
        for alert_id in self._operational_alert_ids_for_case(case_payload):
            self.manager.update_alert(
                alert_id,
                self._build_alert_update_payload(
                    field="status",
                    value="acknowledged",
                    acted_by=self._current_analyst_identity(),
                ),
            )
            updated += 1
        self.refresh()
        if messagebox is not None:
            messagebox.showinfo(
                "Operational Pressure Cleared",
                f"Acknowledged {updated} operational alerts linked to case {case_id}.",
            )

    def view_operational_case_alerts(self) -> None:
        selected = self._require_selected_operational_case()
        if selected is None:
            return
        _case_id, case_payload = selected
        alert_rows = [
            alert
            for alert_id in self._operational_alert_ids_for_case(case_payload)
            for alert in [self.all_alert_rows_by_id.get(alert_id)]
            if alert is not None
        ]
        selected_alert = self._select_summary_record_or_show_info(
            "alert",
            alert_rows,
            title="Operational Case Alerts",
            info_title="Operational Case Alerts",
            limit=50,
        )
        if selected_alert is None:
            return
        self._pivot_from_alert(selected_alert)

    def view_detection_rule_alerts(self) -> None:
        selected_rule = self._select_detection_rule()
        if selected_rule is None:
            return
        rule_id = str(selected_rule.get("rule_id") or "")
        grouped_alerts = self._resolve_detection_rule_alert_groups(rule_id)
        selected_group = self._select_summary_record_or_show_info(
            "alert_group",
            grouped_alerts,
            title=f"Alert Groups for {rule_id}",
            info_title=f"Alerts for {rule_id}",
            limit=50,
        )
        if selected_group is None:
            return
        selected_group = self._resolve_detection_rule_alert_group_detail(rule_id, selected_group)
        if self._handle_existing_case_guard(
            open_case_ids=[str(item) for item in cast(list[Any], selected_group.get("open_case_ids") or []) if str(item)],
            context_label=f"Alert group {selected_group.get('group_key', rule_id)}",
        ):
            return
        group_alerts = cast(list[dict[str, Any]], selected_group.get("alerts") or [])
        source_events = self._collect_rule_source_events(group_alerts)
        timeline_filters = self._endpoint_timeline_filters_from_alert_group(selected_group, source_events=source_events)
        choice = self._choose_rule_group_pivot(
            title=f"Alert Group {selected_group.get('group_key', rule_id)}",
            grouped_label="alerts",
            grouped_count=len(group_alerts),
            timeline_available=bool(timeline_filters),
        )
        if choice == "case" and timeline_filters:
            self._promote_rule_group_to_endpoint_timeline_case(selected_group, timeline_filters=timeline_filters)
            return
        if choice == "timeline" and timeline_filters:
            self._pivot_from_rule_group_timeline(
                selected_group,
                timeline_filters=timeline_filters,
                info_title=f"Alerts for {selected_group.get('group_key', rule_id)}",
            )
            return
        selected_alert = self._select_summary_record_or_show_info(
            "alert",
            group_alerts,
            title=f"Alerts for {selected_group.get('group_key', rule_id)}",
            info_title=f"Alerts for {selected_group.get('group_key', rule_id)}",
            limit=50,
        )
        if selected_alert is None:
            return
        self._pivot_from_alert(selected_alert)

    def view_detection_rule_evidence(self) -> None:
        selected_rule = self._select_detection_rule()
        if selected_rule is None:
            return
        rule_id = str(selected_rule.get("rule_id") or "")
        grouped_evidence = self._resolve_detection_rule_evidence_groups(rule_id)
        selected_group = self._select_summary_record_or_show_info(
            "evidence_group",
            grouped_evidence,
            title=f"Evidence Groups for {rule_id}",
            info_title=f"Evidence for {rule_id}",
            limit=50,
        )
        if selected_group is None:
            return
        selected_group = self._resolve_detection_rule_evidence_group_detail(rule_id, selected_group)
        if self._handle_existing_case_guard(
            open_case_ids=[str(item) for item in cast(list[Any], selected_group.get("open_case_ids") or []) if str(item)],
            context_label=f"Evidence group {selected_group.get('group_key', rule_id)}",
        ):
            return
        group_events = cast(list[dict[str, Any]], selected_group.get("events") or [])
        timeline_filters = self._endpoint_timeline_filters_from_evidence_group(selected_group, source_events=group_events)
        choice = self._choose_rule_group_pivot(
            title=f"Evidence Group {selected_group.get('group_key', rule_id)}",
            grouped_label="events",
            grouped_count=len(group_events),
            timeline_available=bool(timeline_filters),
        )
        if choice == "case" and timeline_filters:
            self._promote_rule_group_to_endpoint_timeline_case(selected_group, timeline_filters=timeline_filters)
            return
        if choice == "timeline" and timeline_filters:
            self._pivot_from_rule_group_timeline(
                selected_group,
                timeline_filters=timeline_filters,
                info_title=f"Evidence for {selected_group.get('group_key', rule_id)}",
            )
            return
        selected_event = self._select_summary_record_or_show_info(
            "event",
            group_events,
            title=f"Evidence for {selected_group.get('group_key', rule_id)}",
            info_title=f"Evidence for {selected_group.get('group_key', rule_id)}",
            limit=50,
        )
        if selected_event is None:
            return
        self._pivot_from_event(selected_event)

    def _pivot_from_packet_session(self, session_payload: dict[str, Any]) -> None:
        remote_ip = str(session_payload.get("remote_ip") or "")
        if not remote_ip:
            self._show_info_dialog("Packet Session", self._format_packet_session_detail(session_payload))
            return
        related_events = [
            item.model_dump(mode="json")
            for item in self.manager.query_events(text=remote_ip, limit=100)
            if item.event_type in {"packet.monitor.finding", "packet.monitor.recovered", "network.monitor.finding", "network.monitor.recovered"}
        ]
        selected = self._select_summary_record_or_show_info(
            "event",
            related_events,
            title="Packet Session Events",
            info_title="Packet Session",
            info_text=self._format_packet_session_detail(session_payload),
        )
        if selected is None:
            return
        self._pivot_from_event(selected)

    def _pivot_from_network_evidence(self, evidence_payload: dict[str, Any]) -> None:
        related_events = self._resolve_network_evidence_events(evidence_payload)
        related_alerts = self._resolve_network_evidence_alerts(related_events)
        related_cases = self._resolve_network_evidence_cases(related_events)
        packet_session = cast(dict[str, Any] | None, evidence_payload.get("packet_session"))
        choice = self._choose_network_evidence_pivot(
            evidence_payload,
            related_events=related_events,
            related_alerts=related_alerts,
            related_cases=related_cases,
            packet_session=packet_session,
        )
        if choice == "events":
            selected = self._select_summary_record_or_show_info(
                "event",
                related_events,
                title="Network Evidence Events",
                info_title="Network Evidence",
                info_text=self._format_network_evidence_detail(evidence_payload),
            )
            if selected is None:
                return
            self._pivot_from_event(selected)
            return
        if choice == "alerts":
            selected = self._select_summary_record_or_show_info(
                "alert",
                related_alerts,
                title="Network Evidence Alerts",
                info_title="Network Evidence",
                info_text=self._format_network_evidence_detail(evidence_payload),
            )
            if selected is None:
                return
            self._pivot_from_alert(selected)
            return
        if choice == "cases":
            selected = self._select_summary_record_or_show_info(
                "case",
                related_cases,
                title="Network Evidence Cases",
                info_title="Network Evidence",
                info_text=self._format_network_evidence_detail(evidence_payload),
            )
            if selected is None:
                return
            self._pivot_from_case(selected)
            return
        if choice == "session" and packet_session is not None:
            self._pivot_from_packet_session(packet_session)
            return
        if choice == "details":
            self._show_info_dialog("Network Evidence", self._format_network_evidence_detail(evidence_payload))
            return
        self._show_info_dialog("Network Evidence", self._format_network_evidence_detail(evidence_payload))

    def _collect_network_evidence(
        self,
        *,
        packet_sessions: Sequence[dict[str, Any]] | None = None,
        observations: Sequence[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        if packet_sessions is None and observations is None:
            remote_collector = getattr(self.network_monitor, "list_combined_evidence", None)
            if callable(remote_collector):
                return [dict(item) for item in cast(list[dict[str, Any]], remote_collector(limit=100))]
        session_rows = list(packet_sessions) if packet_sessions is not None else self.packet_monitor.list_recent_sessions(limit=100)
        observation_rows = list(observations) if observations is not None else self.network_monitor.list_recent_observations(limit=100)
        combined: dict[str, dict[str, Any]] = {}
        for item in observation_rows:
            remote_ip = str(item.get("remote_ip") or "")
            if not remote_ip:
                continue
            combined[remote_ip] = {
                "remote_ip": remote_ip,
                "title": f"Network evidence for {remote_ip}",
                "severity": "medium" if item.get("sensitive_ports") else "low",
                "last_seen_at": item.get("last_seen_at"),
                "observation": item,
                "packet_session": None,
            }
        for item in session_rows:
            remote_ip = str(item.get("remote_ip") or "")
            if not remote_ip:
                continue
            record = combined.setdefault(
                remote_ip,
                {
                    "remote_ip": remote_ip,
                    "title": f"Network evidence for {remote_ip}",
                    "severity": "medium",
                    "last_seen_at": item.get("last_seen_at"),
                    "observation": None,
                    "packet_session": None,
                },
            )
            record["packet_session"] = item
            session_last_seen = str(item.get("last_seen_at") or "")
            if session_last_seen > str(record.get("last_seen_at") or ""):
                record["last_seen_at"] = item.get("last_seen_at")
            if item.get("sensitive_ports"):
                record["severity"] = "high"
        rows = list(combined.values())
        for row in rows:
            source_events = self._resolve_network_evidence_events(row)
            related_cases = self._resolve_network_evidence_cases(source_events)
            row["related_alert_ids"] = [item.get("alert_id") for item in self._resolve_network_evidence_alerts(source_events) if item.get("alert_id")]
            row["related_case_ids"] = [item.get("case_id") for item in related_cases if item.get("case_id")]
            row["open_case_ids"] = [
                item.get("case_id")
                for item in related_cases
                if item.get("case_id") and str(item.get("status") or "") != SocCaseStatus.closed.value
            ]
            row["open_case_count"] = len(cast(list[str], row["open_case_ids"]))
            if row["open_case_count"]:
                row["title"] = f"Network evidence for {row.get('remote_ip', '-')} (open cases: {row['open_case_count']})"
        rows.sort(key=lambda row: str(row.get("last_seen_at") or ""), reverse=True)
        return rows

    def _collect_packet_sessions(self, *, limit: int = 100) -> list[dict[str, Any]]:
        rows = [dict(item) for item in self.packet_monitor.list_recent_sessions(limit=limit)]
        for row in rows:
            source_events = self._resolve_packet_session_events(row)
            related_cases = self._resolve_network_evidence_cases(source_events)
            related_alerts = self._resolve_network_evidence_alerts(source_events)
            row["related_alert_ids"] = [item.get("alert_id") for item in related_alerts if item.get("alert_id")]
            row["related_case_ids"] = [item.get("case_id") for item in related_cases if item.get("case_id")]
            row["open_case_ids"] = [
                item.get("case_id")
                for item in related_cases
                if item.get("case_id") and str(item.get("status") or "") != SocCaseStatus.closed.value
            ]
            row["open_case_count"] = len(cast(list[str], row["open_case_ids"]))
            remote_ip = str(row.get("remote_ip") or "-")
            if row["open_case_count"]:
                row["remote_ip_display"] = f"{remote_ip} [open:{row['open_case_count']}]"
            else:
                row["remote_ip_display"] = remote_ip
        return rows

    def _collect_endpoint_timeline(self, *, limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        if not hasattr(self.manager, "list_endpoint_timeline"):
            return []
        rows = [
            self._normalize_endpoint_timeline_row(item)
            for item in cast(list[Any], self.manager.list_endpoint_timeline(limit=limit, **filters))
        ]
        return rows

    def _collect_case_endpoint_timeline(
        self,
        case_payload: Mapping[str, Any],
        *,
        limit: int = 100,
        **filters: Any,
    ) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        if case_id and manager is not None and hasattr(manager, "list_case_endpoint_timeline"):
            payload = cast(dict[str, Any], manager.list_case_endpoint_timeline(case_id, limit=limit, **filters))
            return [
                self._normalize_endpoint_timeline_row(item)
                for item in cast(list[Any], payload.get("events") or [])
            ]
        return self._collect_endpoint_timeline(limit=limit, **filters)

    def _collect_endpoint_timeline_clusters(self, *, cluster_by: str = "process", limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        if not hasattr(self.manager, "list_endpoint_timeline_clusters"):
            if hasattr(self.manager, "cluster_endpoint_timeline"):
                rows = cast(list[dict[str, Any]], self.manager.cluster_endpoint_timeline(cluster_by=cluster_by, limit=limit, **filters))
            else:
                return []
        else:
            payload = cast(dict[str, Any], self.manager.list_endpoint_timeline_clusters(cluster_by=cluster_by, limit=limit, **filters))
            rows = [dict(item) for item in cast(list[dict[str, Any]], payload.get("clusters") or [])]
        for row in rows:
            label = str(row.get("label") or row.get("cluster_key") or "-")
            open_case_count = int(row.get("open_case_count") or 0)
            row["title"] = f"{label} (open cases: {open_case_count})" if open_case_count else label
        return rows

    def _resolve_endpoint_timeline_cluster_detail(self, cluster_payload: Mapping[str, Any]) -> dict[str, Any]:
        manager = getattr(self, "manager", None)
        cluster_key = str(cluster_payload.get("cluster_key") or "")
        cluster_by = str(cluster_payload.get("cluster_by") or "process")
        if cluster_key and manager is not None and hasattr(manager, "get_endpoint_timeline_cluster"):
            filters: dict[str, Any] = {"cluster_by": cluster_by}
            device_ids = cast(list[str], cluster_payload.get("device_ids") or [])
            process_names = cast(list[str], cluster_payload.get("process_names") or [])
            process_guids = cast(list[str], cluster_payload.get("process_guids") or [])
            remote_ips = cast(list[str], cluster_payload.get("remote_ips") or [])
            if device_ids:
                filters["device_id"] = device_ids[0]
            if process_guids:
                filters["process_guid"] = process_guids[0]
            elif process_names:
                filters["process_name"] = process_names[0]
            if cluster_by == "remote_ip" and remote_ips:
                filters["remote_ip"] = remote_ips[0]
            payload = cast(dict[str, Any], manager.get_endpoint_timeline_cluster(cluster_key=cluster_key, **filters) or {})
            if payload:
                label = str(payload.get("label") or payload.get("cluster_key") or "-")
                open_case_count = int(payload.get("open_case_count") or 0)
                payload["title"] = f"{label} (open cases: {open_case_count})" if open_case_count else label
                return dict(payload)
        return dict(cluster_payload)

    def _collect_hunt_telemetry_clusters(self, *, cluster_by: str = "remote_ip", limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        if manager is None or not hasattr(manager, "list_hunt_telemetry_clusters"):
            return []
        rows = [dict(item) for item in cast(list[dict[str, Any]], manager.list_hunt_telemetry_clusters(cluster_by=cluster_by, limit=limit, **filters))]
        for row in rows:
            label = str(row.get("label") or row.get("cluster_key") or "-")
            open_case_count = int(row.get("open_case_count") or 0)
            row["title"] = f"{label} (open cases: {open_case_count})" if open_case_count else label
        return rows

    def _selected_hunt_telemetry_cluster_mode(self) -> str:
        variable = getattr(self, "hunt_cluster_mode_var", None)
        if variable is None or not hasattr(variable, "get"):
            return self._normalize_hunt_cluster_mode(getattr(self, "saved_hunt_cluster_mode", None))
        return self._normalize_hunt_cluster_mode(str(variable.get() or "").strip())

    def _active_hunt_telemetry_cluster_filters(self) -> tuple[str, dict[str, Any]]:
        cluster_by = self._selected_hunt_telemetry_cluster_mode()
        variable = getattr(self, "hunt_cluster_value_var", None)
        filter_value = str(variable.get() or "").strip() if variable is not None and hasattr(variable, "get") else ""
        filters: dict[str, Any] = {}
        if filter_value:
            filters[cluster_by] = filter_value
        return cluster_by, filters

    def _set_hunt_telemetry_cluster_filter(self, mode: str | None, value: str | None) -> None:
        normalized_mode = self._normalize_hunt_cluster_mode(mode)
        normalized_value = str(value or "").strip() or None
        self.saved_hunt_cluster_mode = normalized_mode
        self.saved_hunt_cluster_value = normalized_value
        if hasattr(self, "hunt_cluster_mode_var"):
            self.hunt_cluster_mode_var.set(normalized_mode)
        if hasattr(self, "hunt_cluster_value_var"):
            self.hunt_cluster_value_var.set(normalized_value or "")
        latest = cast(dict[str, Any], getattr(self, "_latest_dashboard", None) or {})
        if latest:
            view_state = cast(dict[str, Any], latest.get("view_state") or {})
            latest["view_state"] = {
                **view_state,
                "hunt_cluster_mode": normalized_mode,
                "hunt_cluster_value": normalized_value,
            }
        self._persist_dashboard_view_state()

    def _set_hunt_telemetry_cluster_selection(self, cluster_key: str | None, action: str | None = None) -> None:
        normalized_key = str(cluster_key or "").strip() or None
        normalized_action = self._normalize_hunt_cluster_action(action)
        self.saved_hunt_cluster_key = normalized_key
        self.saved_hunt_cluster_action = normalized_action
        latest = cast(dict[str, Any], getattr(self, "_latest_dashboard", None) or {})
        if latest:
            view_state = cast(dict[str, Any], latest.get("view_state") or {})
            latest["view_state"] = {
                **view_state,
                "hunt_cluster_key": normalized_key,
                "hunt_cluster_action": normalized_action,
            }
        self._persist_dashboard_view_state()

    def _resolve_hunt_telemetry_cluster_detail(self, cluster_payload: Mapping[str, Any]) -> dict[str, Any]:
        manager = getattr(self, "manager", None)
        cluster_key = str(cluster_payload.get("cluster_key") or "")
        cluster_by = str(cluster_payload.get("cluster_by") or "remote_ip")
        if not cluster_key or manager is None:
            return dict(cluster_payload)
        filters: dict[str, Any] = {"cluster_by": cluster_by}
        for field, key in (
            ("device_ids", "device_id"),
            ("process_names", "process_name"),
            ("process_guids", "process_guid"),
            ("remote_ips", "remote_ip"),
            ("signers", "signer_name"),
            ("filenames", "filename"),
            ("session_keys", "session_key"),
        ):
            values = cast(list[str], cluster_payload.get(field) or [])
            if values:
                filters[key] = values[0]
        if hasattr(manager, "get_hunt_telemetry_cluster"):
            payload = cast(dict[str, Any], manager.get_hunt_telemetry_cluster(cluster_key, **filters) or {})
        elif hasattr(manager, "resolve_hunt_telemetry_cluster"):
            payload = cast(dict[str, Any], manager.resolve_hunt_telemetry_cluster(cluster_key=cluster_key, **filters) or {})
        else:
            payload = {}
        if payload:
            label = str(payload.get("label") or payload.get("cluster_key") or "-")
            open_case_count = int(payload.get("open_case_count") or 0)
            payload["title"] = f"{label} (open cases: {open_case_count})" if open_case_count else label
            return dict(payload)
        return dict(cluster_payload)

    def _collect_remote_nodes(self) -> list[dict[str, Any]]:
        platform_client = getattr(self, "platform_client", None)
        if platform_client is not None and hasattr(platform_client, "list_remote_nodes"):
            rows = [dict(item) for item in cast(list[dict[str, Any]], platform_client.list_remote_nodes(limit=500))]
        else:
            dashboard = cast(dict[str, Any], getattr(self, "_latest_dashboard", None) or self.manager.dashboard())
            platform = cast(dict[str, Any], dashboard.get("platform") or {})
            topology = cast(dict[str, Any], platform.get("topology") or {})
            rows = [dict(item) for item in cast(list[dict[str, Any]], topology.get("remote_nodes") or [])]
        for row in rows:
            platform_client = getattr(self, "platform_client", None)
            if platform_client is not None and hasattr(platform_client, "resolve_remote_node_cases"):
                resolved_cases = platform_client.resolve_remote_node_cases(row)
            else:
                resolved_cases = self.manager.resolve_remote_node_cases(row)
            related_cases = [item.model_dump(mode="json") for item in resolved_cases]
            row["related_case_ids"] = [item.get("case_id") for item in related_cases if item.get("case_id")]
            row["open_case_ids"] = [
                item.get("case_id")
                for item in related_cases
                if item.get("case_id") and str(item.get("status") or "") != SocCaseStatus.closed.value
            ]
            row["open_case_count"] = len(cast(list[str], row["open_case_ids"]))
            metadata = cast(dict[str, Any], row.get("metadata") or {})
            row["acknowledged_by"] = metadata.get("acknowledged_by")
            row["acknowledged_at"] = metadata.get("acknowledged_at")
            row["action_history"] = [
                dict(item)
                for item in cast(list[Any], metadata.get("action_history") or [])
                if isinstance(item, dict)
            ]
            suppressed_until = str(metadata.get("suppressed_until") or "")
            suppressed = False
            if suppressed_until:
                try:
                    suppressed = datetime.fromisoformat(suppressed_until) > datetime.now(UTC)
                except ValueError:
                    suppressed = False
            row["suppressed_until"] = metadata.get("suppressed_until")
            row["suppressed_by"] = metadata.get("suppressed_by")
            row["suppression_reason"] = metadata.get("suppression_reason")
            pressure_suppressions = cast(list[dict[str, Any]], metadata.get("pressure_suppressions") or [])
            active_scopes: list[str] = []
            for item in pressure_suppressions:
                if not isinstance(item, dict):
                    continue
                suppressed_scope_until = str(item.get("suppressed_until") or "")
                try:
                    if suppressed_scope_until and datetime.fromisoformat(suppressed_scope_until) > datetime.now(UTC):
                        active_scopes.extend([str(scope) for scope in cast(list[Any], item.get("scopes") or []) if str(scope)])
                except ValueError:
                    continue
            row["suppression_scopes"] = sorted(set(active_scopes))
            row["suppressed"] = suppressed or bool(active_scopes)
            maintenance_state = cast(dict[str, Any], row.get("maintenance") or {})
            maintenance_until = str(metadata.get("maintenance_until") or "")
            maintenance_active = bool(maintenance_state.get("active"))
            if not maintenance_active and not maintenance_state:
                if maintenance_until:
                    try:
                        maintenance_active = datetime.fromisoformat(maintenance_until) > datetime.now(UTC)
                    except ValueError:
                        maintenance_active = False
            row["maintenance_active"] = maintenance_active
            row["maintenance_until"] = metadata.get("maintenance_until")
            row["maintenance_by"] = metadata.get("maintenance_by")
            row["maintenance_reason"] = metadata.get("maintenance_reason")
            row["maintenance_services"] = [str(item) for item in cast(list[Any], metadata.get("maintenance_services") or []) if str(item)]
            maintenance_status = cast(dict[str, Any], row.get("maintenance") or {}).get("status")
            if not maintenance_status:
                if metadata.get("maintenance_failed_at"):
                    maintenance_status = "failed"
                elif maintenance_until and maintenance_active and metadata.get("maintenance_acknowledged_at"):
                    maintenance_status = "acknowledged"
                elif maintenance_until and maintenance_active:
                    maintenance_status = "requested"
                elif metadata.get("maintenance_completed_at"):
                    maintenance_status = "completed"
                else:
                    maintenance_status = "inactive"
            row["maintenance_status"] = str(maintenance_status)
            row["maintenance_acknowledged_at"] = metadata.get("maintenance_acknowledged_at")
            row["maintenance_completed_at"] = metadata.get("maintenance_completed_at")
            row["maintenance_result"] = metadata.get("maintenance_result")
            row["maintenance_completion_note"] = metadata.get("maintenance_completion_note")
            row["maintenance_failed_at"] = metadata.get("maintenance_failed_at")
            row["maintenance_last_error"] = metadata.get("maintenance_last_error")
            row["maintenance_retry_count"] = int(metadata.get("maintenance_retry_count") or 0)
            row["maintenance_retriable"] = bool(metadata.get("maintenance_retriable"))
            row["refresh_pending"] = bool(metadata.get("refresh_pending"))
            refresh_status = cast(dict[str, Any], row.get("refresh") or {}).get("status")
            if not refresh_status:
                if metadata.get("refresh_pending") and metadata.get("refresh_acknowledged_at"):
                    refresh_status = "acknowledged"
                elif metadata.get("refresh_failed_at"):
                    refresh_status = "failed"
                elif metadata.get("refresh_pending"):
                    refresh_status = "requested"
                elif metadata.get("refresh_completed_at") or metadata.get("refresh_fulfilled_at"):
                    refresh_status = "completed"
                else:
                    refresh_status = "inactive"
            row["refresh_status"] = str(refresh_status)
            row["refresh_requested_at"] = metadata.get("refresh_requested_at")
            row["refresh_requested_by"] = metadata.get("refresh_requested_by")
            row["refresh_request_reason"] = metadata.get("refresh_request_reason")
            row["refresh_acknowledged_at"] = metadata.get("refresh_acknowledged_at")
            row["refresh_completed_at"] = metadata.get("refresh_completed_at")
            row["refresh_fulfilled_at"] = metadata.get("refresh_fulfilled_at")
            row["refresh_result"] = metadata.get("refresh_result")
            row["refresh_completion_note"] = metadata.get("refresh_completion_note")
            row["refresh_failed_at"] = metadata.get("refresh_failed_at")
            row["refresh_last_error"] = metadata.get("refresh_last_error")
            row["refresh_retry_count"] = int(metadata.get("refresh_retry_count") or 0)
            row["refresh_retriable"] = bool(metadata.get("refresh_retriable"))
            drain_state = cast(dict[str, Any], row.get("drain") or {})
            row["drained"] = bool(drain_state.get("active"))
            if not row["drained"] and not drain_state:
                row["drained"] = bool(metadata.get("drain_at"))
            drain_status = drain_state.get("status")
            if not drain_status:
                if metadata.get("drain_at") and metadata.get("drain_acknowledged_at"):
                    drain_status = "acknowledged"
                elif metadata.get("drain_failed_at"):
                    drain_status = "failed"
                elif metadata.get("drain_at"):
                    drain_status = "requested"
                elif metadata.get("drain_completed_at"):
                    drain_status = "completed"
                else:
                    drain_status = "inactive"
            row["drain_status"] = str(drain_status)
            row["drain_at"] = metadata.get("drain_at")
            row["drained_by"] = metadata.get("drained_by")
            row["drain_reason"] = metadata.get("drain_reason")
            row["drain_services"] = [str(item) for item in cast(list[Any], metadata.get("drain_services") or []) if str(item)]
            row["drain_requested_at"] = metadata.get("drain_requested_at")
            row["drain_acknowledged_at"] = metadata.get("drain_acknowledged_at")
            row["drain_completed_at"] = metadata.get("drain_completed_at")
            row["drain_result"] = metadata.get("drain_result")
            row["drain_completion_note"] = metadata.get("drain_completion_note")
            row["drain_failed_at"] = metadata.get("drain_failed_at")
            row["drain_last_error"] = metadata.get("drain_last_error")
            row["drain_retry_count"] = int(metadata.get("drain_retry_count") or 0)
            row["drain_retriable"] = bool(metadata.get("drain_retriable"))
            row["action_failures"] = [
                name
                for name, status in (
                    ("maintenance", row["maintenance_status"]),
                    ("refresh", row["refresh_status"]),
                    ("drain", row["drain_status"]),
                )
                if str(status) == "failed"
            ]
            action_pressure = cast(dict[str, Any], row.get("action_pressure") or {})
            if not action_pressure:
                action_pressure = self._derive_remote_node_action_pressure(row, history=cast(list[dict[str, Any]], row["action_history"]))
            row["action_pressure"] = action_pressure
            row["repeated_failures"] = cast(dict[str, int], action_pressure.get("repeated_failures") or {})
            row["retry_pressure"] = cast(dict[str, int], action_pressure.get("retry_pressure") or {})
            row["stuck_actions"] = cast(list[dict[str, Any]], action_pressure.get("stuck_actions") or [])
            row["repeated_failure_active"] = bool(
                row.get("repeated_failure_active") or action_pressure.get("repeated_failure_active")
            )
            row["retry_pressure_active"] = bool(
                row.get("retry_pressure_active") or action_pressure.get("retry_pressure_active")
            )
            row["stuck_actions_active"] = bool(
                row.get("stuck_actions_active") or action_pressure.get("stuck_actions_active")
            )
            title = str(row.get("node_name") or "-")
            if row["open_case_count"]:
                title = f"{title} (open cases: {row['open_case_count']})"
            if row["suppressed"]:
                title = f"{title} [suppressed]"
            if row["maintenance_active"]:
                title = f"{title} [maintenance]"
            if row["refresh_pending"]:
                title = f"{title} [refresh requested]"
            if row["drained"]:
                title = f"{title} [drained]"
            if row["action_failures"]:
                title = f"{title} [action failed]"
            if row["repeated_failure_active"]:
                title = f"{title} [repeat failures]"
            if row["retry_pressure_active"]:
                title = f"{title} [retry pressure]"
            if row["stuck_actions_active"]:
                title = f"{title} [action stuck]"
            row["title"] = title
        return rows

    def _resolve_remote_node_detail(self, node_payload: dict[str, Any]) -> dict[str, Any]:
        platform_client = getattr(self, "platform_client", None)
        node_name = str(node_payload.get("node_name") or "")
        if not node_name or platform_client is None or not hasattr(platform_client, "get_platform_node_detail"):
            return node_payload
        detail = cast(dict[str, Any], platform_client.get_platform_node_detail(node_name))
        return detail or node_payload

    @staticmethod
    def _derive_remote_node_action_pressure(
        row: dict[str, Any],
        *,
        history: Sequence[dict[str, Any]],
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        window_start = now - timedelta(hours=max(settings.soc_remote_node_action_history_window_hours, 0.0))
        recent_history: list[dict[str, Any]] = []
        for item in history:
            if not isinstance(item, dict):
                continue
            timestamp = str(item.get("at") or "").strip()
            if not timestamp:
                continue
            try:
                parsed = datetime.fromisoformat(timestamp)
            except ValueError:
                continue
            if parsed >= window_start:
                recent_history.append(item)
        repeated_failures = {
            action: count
            for action, count in Counter(
                str(item.get("action") or "").strip()
                for item in recent_history
                if str(item.get("transition") or "").strip().casefold() == "failed"
                and str(item.get("action") or "").strip()
            ).items()
            if count >= max(settings.soc_remote_node_action_failure_repeat_threshold, 1)
        }
        retry_pressure = {
            action: count
            for action, count in Counter(
                str(item.get("action") or "").strip()
                for item in recent_history
                if str(item.get("transition") or "").strip().casefold() == "retried"
                and str(item.get("action") or "").strip()
            ).items()
            if count >= max(settings.soc_remote_node_action_retry_threshold, 1)
        }
        stuck_actions: list[dict[str, Any]] = []
        for action_name in ("refresh", "maintenance", "drain"):
            status = str(row.get(f"{action_name}_status") or "").strip().casefold()
            if status not in {"requested", "acknowledged"}:
                continue
            started_at = str(row.get(f"{action_name}_acknowledged_at") or row.get(f"{action_name}_requested_at") or "").strip()
            if not started_at:
                continue
            try:
                parsed_started = datetime.fromisoformat(started_at)
            except ValueError:
                continue
            age_minutes = round((now - parsed_started).total_seconds() / 60.0, 1)
            if age_minutes < max(settings.soc_remote_node_action_stuck_minutes, 0.0):
                continue
            stuck_actions.append(
                {
                    "action": action_name,
                    "status": status,
                    "age_minutes": age_minutes,
                    "requested_at": row.get(f"{action_name}_requested_at"),
                    "acknowledged_at": row.get(f"{action_name}_acknowledged_at"),
                }
            )
        stuck_actions.sort(key=lambda item: (-cast(float, item["age_minutes"]), str(item["action"])))
        return {
            "repeated_failures": dict(sorted(repeated_failures.items())),
            "retry_pressure": dict(sorted(retry_pressure.items())),
            "stuck_actions": stuck_actions,
            "repeated_failure_active": bool(repeated_failures),
            "retry_pressure_active": bool(retry_pressure),
            "stuck_actions_active": bool(stuck_actions),
        }

    @staticmethod
    def _filter_remote_nodes_by_action_history(
        rows: Sequence[dict[str, Any]],
        filter_choice: str,
    ) -> list[dict[str, Any]]:
        normalized = filter_choice.strip().casefold()
        if normalized in {"", "all"}:
            return [dict(item) for item in rows]
        filtered: list[dict[str, Any]] = []
        for row in rows:
            if normalized == "failed" and cast(list[str], row.get("action_failures") or []):
                filtered.append(dict(row))
                continue
            history = cast(list[dict[str, Any]], row.get("action_history") or [])
            if any(str(item.get("transition") or "").casefold() == normalized for item in history if isinstance(item, dict)):
                filtered.append(dict(row))
        return filtered

    @staticmethod
    def _filter_remote_nodes_by_action_pressure(
        rows: Sequence[dict[str, Any]],
        filter_choice: str,
    ) -> list[dict[str, Any]]:
        normalized = filter_choice.strip().casefold()
        if normalized in {"", "all", "all_active"}:
            return [
                dict(item)
                for item in rows
                if bool(item.get("repeated_failure_active"))
                or bool(item.get("retry_pressure_active"))
                or bool(item.get("stuck_actions_active"))
            ]
        if normalized == "repeated_failures":
            return [dict(item) for item in rows if bool(item.get("repeated_failure_active"))]
        if normalized == "retry_pressure":
            return [dict(item) for item in rows if bool(item.get("retry_pressure_active"))]
        if normalized == "stuck_actions":
            return [dict(item) for item in rows if bool(item.get("stuck_actions_active"))]
        return []

    def _resolve_network_evidence_events(self, evidence_payload: dict[str, Any]) -> list[dict[str, Any]]:
        remote_ip = str(evidence_payload.get("remote_ip") or "")
        if not remote_ip or not hasattr(self.manager, "query_events"):
            return []
        return [
            item.model_dump(mode="json")
            for item in self.manager.query_events(text=remote_ip, limit=100)
            if item.event_type in {"packet.monitor.finding", "packet.monitor.recovered", "network.monitor.finding", "network.monitor.recovered"}
        ]

    def _resolve_network_evidence_alerts(self, related_events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        unique_alerts: dict[str, dict[str, Any]] = {}
        for event_payload in related_events:
            for alert_payload in self._resolve_event_alerts(event_payload):
                alert_id = str(alert_payload.get("alert_id") or "")
                if alert_id and alert_id not in unique_alerts:
                    unique_alerts[alert_id] = alert_payload
        return list(unique_alerts.values())

    def _resolve_network_evidence_cases(self, related_events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        unique_cases: dict[str, dict[str, Any]] = {}
        for event_payload in related_events:
            for case_payload in self._resolve_event_cases(event_payload):
                case_id = str(case_payload.get("case_id") or "")
                if case_id and case_id not in unique_cases:
                    unique_cases[case_id] = case_payload
        return list(unique_cases.values())

    def _select_detection_rule(self) -> dict[str, Any] | None:
        rules = [item.model_dump(mode="json") for item in self.manager.list_detection_rules()]
        selected = self._select_summary_record("detection_rule", rules, title="Detection Rules")
        if selected is None:
            self._show_info_dialog("Detection Rules", self._format_summary_records("detection_rule", rules, limit=50))
            return None
        rule_id = str(selected.get("rule_id") or "")
        if not rule_id:
            self._show_info_dialog("Detection Rules", "The selected rule is missing a rule id.")
            return None
        return selected

    def _collect_rule_source_events(self, alert_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        unique_events: dict[str, dict[str, Any]] = {}
        for alert_payload in alert_rows:
            for event_payload in self._resolve_source_events(alert_payload):
                event_id = str(event_payload.get("event_id") or "")
                if event_id and event_id not in unique_events:
                    unique_events[event_id] = event_payload
        return list(unique_events.values())

    def _group_rule_evidence(self, source_events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for event_payload in source_events:
            group_key = self._rule_evidence_group_key(event_payload)
            entry = grouped.setdefault(
                group_key,
                {
                    "group_key": group_key,
                    "event_count": 0,
                    "severity": event_payload.get("severity", "-"),
                    "title": event_payload.get("title", "-"),
                    "events": [],
                    "related_case_ids": [],
                    "open_case_ids": [],
                    "open_case_count": 0,
                },
            )
            entry["event_count"] = int(entry.get("event_count", 0)) + 1
            cast(list[dict[str, Any]], entry["events"]).append(event_payload)
            if self._severity_rank(str(event_payload.get("severity", "low"))) > self._severity_rank(str(entry.get("severity", "low"))):
                entry["severity"] = event_payload.get("severity", "-")
            related_cases = self._resolve_network_evidence_cases(cast(list[dict[str, Any]], entry["events"]))
            related_case_ids = [item.get("case_id") for item in related_cases if item.get("case_id")]
            open_case_ids = [
                item.get("case_id")
                for item in related_cases
                if item.get("case_id") and str(item.get("status") or "") != SocCaseStatus.closed.value
            ]
            entry["related_case_ids"] = related_case_ids
            entry["open_case_ids"] = open_case_ids
            entry["open_case_count"] = len(open_case_ids)
            if open_case_ids:
                entry["title"] = f"{group_key} (open cases: {len(open_case_ids)})"
            else:
                entry["title"] = group_key
        groups = list(grouped.values())
        groups.sort(
            key=lambda item: (
                -self._severity_rank(str(item.get("severity", "low"))),
                -int(item.get("event_count", 0)),
                str(item.get("group_key", "")),
            )
        )
        return groups

    def _group_rule_alerts(self, alert_rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for alert_payload in alert_rows:
            group_key = str(
                alert_payload.get("correlation_key")
                or alert_payload.get("linked_case_id")
                or alert_payload.get("correlation_rule")
                or alert_payload.get("alert_id")
                or "ungrouped"
            )
            entry = grouped.setdefault(
                group_key,
                {
                    "group_key": group_key,
                    "alert_count": 0,
                    "severity": alert_payload.get("severity", "-"),
                    "title": group_key,
                    "alerts": [],
                    "related_case_ids": [],
                    "open_case_ids": [],
                    "open_case_count": 0,
                },
            )
            entry["alert_count"] = int(entry.get("alert_count", 0)) + 1
            cast(list[dict[str, Any]], entry["alerts"]).append(alert_payload)
            if self._severity_rank(str(alert_payload.get("severity", "low"))) > self._severity_rank(str(entry.get("severity", "low"))):
                entry["severity"] = alert_payload.get("severity", "-")
            related_case_ids = sorted(
                {
                    str(item.get("linked_case_id") or "")
                    for item in cast(list[dict[str, Any]], entry["alerts"])
                    if str(item.get("linked_case_id") or "")
                }
            )
            open_case_ids: list[str] = []
            for case_id in related_case_ids:
                existing_case = self._resolve_case_for_network_evidence([case_id])
                if existing_case is None:
                    continue
                if str(existing_case.get("status") or "") != SocCaseStatus.closed.value:
                    open_case_ids.append(case_id)
            entry["related_case_ids"] = related_case_ids
            entry["open_case_ids"] = open_case_ids
            entry["open_case_count"] = len(open_case_ids)
            if open_case_ids:
                entry["title"] = f"{group_key} (open cases: {len(open_case_ids)})"
            else:
                entry["title"] = group_key
        groups = list(grouped.values())
        groups.sort(
            key=lambda item: (
                -self._severity_rank(str(item.get("severity", "low"))),
                -int(item.get("alert_count", 0)),
                str(item.get("group_key", "")),
            )
        )
        return groups

    @staticmethod
    def _rule_evidence_group_key(event_payload: dict[str, Any]) -> str:
        details = event_payload.get("details")
        nested = details.get("details") if isinstance(details, dict) else None
        if isinstance(nested, dict):
            for key in ("remote_ip", "hostname", "filename", "artifact_path", "session_key", "key"):
                value = nested.get(key)
                if isinstance(value, str) and value:
                    return value
        if isinstance(details, dict):
            for key in ("source_ip", "hostname", "filename", "device_id", "resource"):
                value = details.get(key)
                if isinstance(value, str) and value:
                    return value
        return str(event_payload.get("event_type") or "ungrouped")

    @staticmethod
    def _severity_rank(value: str) -> int:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return order.get(value.casefold(), 0)

    def promote_packet_session_to_case(self) -> None:
        sessions = self.packet_monitor.list_recent_sessions(limit=50)
        selected = self._select_summary_record("packet_session", sessions, title="Packet Sessions")
        if selected is None:
            self._show_info_dialog(
                "Packet Sessions",
                self._format_summary_records("packet_session", sessions, limit=50),
            )
            return
        related_events = self._resolve_packet_session_events(selected)
        related_cases = self._resolve_network_evidence_cases(related_events)
        open_case_ids = [
            str(item.get("case_id") or "")
            for item in related_cases
            if str(item.get("case_id") or "") and str(item.get("status") or "") != SocCaseStatus.closed.value
        ]
        if self._handle_existing_case_choice(
            open_case_ids=open_case_ids,
            context_label=f"Packet session for {selected.get('remote_ip', '-')}",
            context_details=[
                f"Session key: {selected.get('session_key', '-')}",
                f"Open case count: {len(open_case_ids)}",
            ],
            no_action_label="create another case",
        ):
            return
        if hasattr(self.manager, "create_case_from_packet_session"):
            request_payload = SocPacketSessionCaseRequest(
                session_key=str(selected.get("session_key") or ""),
                assignee=self._current_analyst_identity(),
            )
            case = self.manager.create_case_from_packet_session(selected, request_payload)
        else:
            case_payload = self._build_packet_session_case_payload(
                selected,
                source_events=related_events,
                assignee=self._current_analyst_identity(),
            )
            case = self.manager.create_case(case_payload)
        if messagebox is not None:
            messagebox.showinfo("Case Created", f"Created case {case.case_id} from packet session {selected.get('remote_ip', '-')}.")
        self.refresh()
        self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def promote_network_evidence_to_case(self) -> None:
        evidence_rows = self._collect_network_evidence()
        selected = self._select_summary_record("network_evidence", evidence_rows, title="Network Evidence")
        if selected is None:
            self._show_info_dialog(
                "Network Evidence",
                self._format_summary_records("network_evidence", evidence_rows, limit=50),
            )
            return
        open_case_ids = [str(item) for item in cast(list[Any], selected.get("open_case_ids") or []) if str(item)]
        if self._handle_existing_case_choice(
            open_case_ids=open_case_ids,
            context_label=f"Network evidence for {selected.get('remote_ip', '-')}",
            context_details=[
                f"Remote IP: {selected.get('remote_ip', '-')}",
                f"Open case count: {len(open_case_ids)}",
            ],
            no_action_label="create another case",
        ):
            return
        if hasattr(self.manager, "create_case_from_network_evidence"):
            request_payload = SocNetworkEvidenceCaseRequest(
                remote_ip=str(selected.get("remote_ip") or ""),
                assignee=self._current_analyst_identity(),
            )
            case = self.manager.create_case_from_network_evidence(selected, request_payload)
        else:
            source_events = self._resolve_network_evidence_events(selected)
            case_payload = self._build_network_evidence_case_payload(
                selected,
                source_events=source_events,
                linked_alerts=self._resolve_network_evidence_alerts(source_events),
                assignee=self._current_analyst_identity(),
            )
            case = self.manager.create_case(case_payload)
        if messagebox is not None:
            messagebox.showinfo("Case Created", f"Created case {case.case_id} from network evidence {selected.get('remote_ip', '-')}.")
        self.refresh()
        self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def promote_endpoint_timeline_to_case(self) -> None:
        cluster_by = self._choose_endpoint_timeline_cluster_mode()
        clusters = self._collect_endpoint_timeline_clusters(cluster_by=cluster_by, limit=100)
        selected = self._select_summary_record("endpoint_timeline_cluster", clusters, title="Endpoint Timeline Clusters")
        if selected is None:
            self._show_info_dialog(
                "Endpoint Timeline Clusters",
                self._format_summary_records("endpoint_timeline_cluster", clusters, limit=50),
            )
            return
        selected = self._resolve_endpoint_timeline_cluster_detail(selected)
        open_case_ids = [str(item) for item in cast(list[Any], selected.get("open_case_ids") or []) if str(item)]
        if self._handle_existing_case_choice(
            open_case_ids=open_case_ids,
            context_label=f"Endpoint timeline cluster {selected.get('label', selected.get('cluster_key', '-'))}",
            context_details=[
                f"Cluster: {selected.get('cluster_key', '-')}",
                f"Events: {selected.get('event_count', 0)}",
                f"Open case count: {len(open_case_ids)}",
            ],
            no_action_label="create another case",
        ):
            return
        request_payload = self._build_endpoint_timeline_case_request(selected)
        if hasattr(self.manager, "create_case_from_endpoint_timeline"):
            case = self.manager.create_case_from_endpoint_timeline(request_payload)
        else:
            case = self.manager.create_case(self._build_endpoint_timeline_case_payload(selected))
        if messagebox is not None:
            messagebox.showinfo(
                "Case Created",
                f"Created case {case.case_id} from endpoint timeline {selected.get('label', selected.get('cluster_key', '-'))}.",
            )
        self.refresh()
        self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def promote_hunt_telemetry_cluster_to_case(self) -> None:
        cluster_by, cluster_filters = self._active_hunt_telemetry_cluster_filters()
        clusters = self._collect_hunt_telemetry_clusters(cluster_by=cluster_by, limit=100, **cluster_filters)
        selected = self._select_summary_record("hunt_telemetry_cluster", clusters, title="Hunt Telemetry Clusters")
        if selected is None:
            self._show_info_dialog(
                "Hunt Telemetry Clusters",
                self._format_summary_records("hunt_telemetry_cluster", clusters, limit=50),
            )
            return
        selected = self._resolve_hunt_telemetry_cluster_detail(selected)
        self._create_case_from_hunt_telemetry_cluster(selected)

    def _handle_hunt_telemetry_cluster_selection(self, cluster_payload: Mapping[str, Any]) -> None:
        action = self._choose_hunt_telemetry_cluster_action(cluster_payload)
        self._set_hunt_telemetry_cluster_selection(str(cluster_payload.get("cluster_key") or ""), action)
        if action == "existing_case":
            self._open_hunt_telemetry_cluster_existing_case(cluster_payload)
            return
        if action == "case":
            self._create_case_from_hunt_telemetry_cluster(cluster_payload)
            return
        if action == "details":
            self._show_info_dialog("Hunt Telemetry Cluster", self._format_hunt_telemetry_cluster_detail(dict(cluster_payload)))
            return
        self._open_hunt_telemetry_cluster_events(cluster_payload)

    def _choose_hunt_telemetry_cluster_action(self, cluster_payload: Mapping[str, Any]) -> str:
        open_case_ids = [str(item) for item in cast(list[Any], cluster_payload.get("open_case_ids") or []) if str(item)]
        actions: list[tuple[str, str, int]] = [("Open Events", "events", 14), ("Create Case", "case", 14)]
        if open_case_ids:
            actions.insert(1, ("Open Existing Case", "existing_case", 18))
        actions.append(("View Details", "details", 14))
        default_choice = self._normalize_hunt_cluster_action(getattr(self, "saved_hunt_cluster_action", None))
        if default_choice == "existing_case" and not open_case_ids:
            default_choice = "events"
        choice = self._choose_action_dialog(
            title="Hunt Telemetry Cluster",
            summary=(
                f"Choose an action for {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}.\n\n"
                f"Cluster by: {cluster_payload.get('cluster_by', '-')}\n"
                f"Events: {cluster_payload.get('event_count', 0)}\n"
                f"Open cases: {len(open_case_ids)}"
            ),
            actions=actions,
            default_choice=default_choice,
            no_tk_choice=default_choice,
            width=520,
            height=220,
            min_width=480,
            min_height=190,
            detail_label="Action",
            detail_width=14,
        )
        return choice if choice in {"events", "existing_case", "case", "details"} else "events"

    def _open_hunt_telemetry_cluster_existing_case(self, cluster_payload: Mapping[str, Any]) -> None:
        open_case_ids = [str(item) for item in cast(list[Any], cluster_payload.get("open_case_ids") or []) if str(item)]
        if not open_case_ids:
            return
        existing_case = self._resolve_case_for_network_evidence(open_case_ids)
        if existing_case is None:
            return
        self._pivot_from_case(existing_case)

    def _open_hunt_telemetry_cluster_events(self, cluster_payload: Mapping[str, Any]) -> None:
        event_rows = self._resolve_hunt_telemetry_cluster_events(dict(cluster_payload))
        event_selected = self._select_summary_record_or_show_info(
            "event",
            event_rows,
            title="Hunt Cluster Events",
            info_title="Hunt Cluster Events",
            info_text=self._format_hunt_telemetry_cluster_detail(dict(cluster_payload)),
            limit=50,
        )
        if event_selected is None:
            return
        self._pivot_from_event(event_selected)

    def _create_case_from_hunt_telemetry_cluster(self, cluster_payload: Mapping[str, Any]) -> None:
        selected = dict(cluster_payload)
        open_case_ids = [str(item) for item in cast(list[Any], selected.get("open_case_ids") or []) if str(item)]
        if self._handle_existing_case_choice(
            open_case_ids=open_case_ids,
            context_label=f"Hunt telemetry cluster {selected.get('label', selected.get('cluster_key', '-'))}",
            context_details=[
                f"Cluster: {selected.get('cluster_key', '-')}",
                f"Events: {selected.get('event_count', 0)}",
                f"Open case count: {len(open_case_ids)}",
            ],
            no_action_label="create another case",
        ):
            return
        request_payload = self._build_hunt_telemetry_cluster_case_request(selected)
        if hasattr(self.manager, "create_case_from_hunt_telemetry_cluster"):
            case = self.manager.create_case_from_hunt_telemetry_cluster(request_payload)
        elif hasattr(self.manager, "create_case_from_telemetry_cluster"):
            case = self.manager.create_case_from_telemetry_cluster(request_payload)
        else:
            case = self.manager.create_case(self._build_hunt_telemetry_cluster_case_payload(selected))
        if messagebox is not None:
            messagebox.showinfo(
                "Case Created",
                f"Created case {case.case_id} from hunt telemetry cluster {selected.get('label', selected.get('cluster_key', '-'))}.",
            )
        self.refresh()
        self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def _resolve_case_for_network_evidence(self, case_ids: Sequence[str]) -> dict[str, Any] | None:
        for case_id in case_ids:
            existing = self.case_rows_by_id.get(case_id)
            if existing is not None:
                return existing
            if hasattr(self.manager, "get_case"):
                try:
                    return self.manager.get_case(case_id).model_dump(mode="json")
                except Exception:
                    continue
        return None

    def _handle_existing_case_choice(
        self,
        *,
        open_case_ids: Sequence[str],
        context_label: str,
        context_details: Sequence[str] = (),
        no_action_label: str = "continue",
    ) -> bool:
        if not open_case_ids:
            return False
        choice: bool | None = False
        if messagebox is not None:
            details = "\n".join(detail for detail in context_details if detail)
            if details:
                details = f"{details}\n\n"
            choice = messagebox.askyesnocancel(
                "Open Existing Case",
                (
                    f"{context_label} already has {len(open_case_ids)} open case(s).\n\n"
                    f"{details}"
                    "Yes: open the existing case\n"
                    f"No: {no_action_label}\n"
                    "Cancel: stop"
                ),
            )
        if choice is None:
            return True
        if choice is True:
            existing_case = self._resolve_case_for_network_evidence(open_case_ids)
            if existing_case is not None:
                self._pivot_from_case(existing_case)
                return True
        return False

    def _handle_existing_case_guard(self, *, open_case_ids: Sequence[str], context_label: str) -> bool:
        return self._handle_existing_case_choice(
            open_case_ids=open_case_ids,
            context_label=context_label,
            context_details=[f"Open case count: {len(open_case_ids)}"],
            no_action_label="continue",
        )

    def _choose_action_dialog(
        self,
        *,
        title: str,
        summary: str,
        actions: Sequence[tuple[str, str, int]],
        default_choice: str,
        no_tk_choice: str,
        width: int,
        height: int,
        min_width: int,
        min_height: int,
        detail_label: str,
        detail_width: int,
    ) -> str:
        if tk is None or not hasattr(self, "root"):
            return no_tk_choice

        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.configure(bg="#eef4ff")
        dialog.transient(self.root)
        dialog.grab_set()
        _center_window(dialog, width, height)
        dialog.minsize(min_width, min_height)
        choice = default_choice
        tk.Label(dialog, text=summary, bg="#eef4ff", fg="#24364a", justify="left", anchor="w", padx=16, pady=16).pack(fill="both", expand=True)

        controls = tk.Frame(dialog, bg="#eef4ff", padx=16, pady=12)
        controls.pack(fill="x")

        def set_choice(value: str) -> None:
            nonlocal choice
            choice = value
            dialog.destroy()

        def build_choice_handler(selected_value: str) -> Callable[[], None]:
            return lambda: set_choice(selected_value)

        for index, (label, value, button_width) in enumerate(actions):
            tk.Button(controls, text=label, command=build_choice_handler(value), width=button_width).pack(
                side="left",
                padx=(8, 0) if index > 0 else (0, 0),
            )
        tk.Button(controls, text=detail_label, command=lambda: set_choice(default_choice), width=detail_width).pack(side="right")
        dialog.bind("<Escape>", lambda _event: set_choice(default_choice))
        self.root.wait_window(dialog)
        return choice

    def _choose_event_pivot(
        self,
        event_payload: dict[str, Any],
        *,
        related_alerts: Sequence[dict[str, Any]],
        related_cases: Sequence[dict[str, Any]],
    ) -> str:
        if not related_alerts and not related_cases:
            return "details"
        event_id = str(event_payload.get("event_id") or "-")
        event_title = str(event_payload.get("title") or "-")
        summary = (
            f"Event: {event_id}\n"
            f"Title: {event_title}\n\n"
            f"Related alerts: {len(related_alerts)}\n"
            f"Related cases: {len(related_cases)}"
        )
        actions: list[tuple[str, str, int]] = []
        if related_alerts:
            actions.append(("Open Related Alerts", "alerts", 18))
        if related_cases:
            actions.append(("Open Related Cases", "cases", 18))
        return self._choose_action_dialog(
            title="Event Actions",
            summary=summary,
            actions=actions,
            default_choice="details",
            no_tk_choice="alerts" if related_alerts else "cases",
            width=620,
            height=260,
            min_width=540,
            min_height=220,
            detail_label="Event Details",
            detail_width=14,
        )

    def _choose_alert_pivot(
        self,
        alert_payload: dict[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
        linked_case: dict[str, Any] | None,
        timeline_available: bool = False,
    ) -> str:
        has_linked_case = linked_case is not None
        if not source_events and not has_linked_case and not timeline_available:
            return "details"
        alert_id = str(alert_payload.get("alert_id") or "-")
        alert_title = str(alert_payload.get("title") or "-")
        summary = (
            f"Alert: {alert_id}\n"
            f"Title: {alert_title}\n\n"
            f"Source events: {len(source_events)}\n"
            f"Linked case: {'yes' if has_linked_case else 'no'}\n"
            f"Endpoint timeline: {'yes' if timeline_available else 'no'}"
        )
        actions: list[tuple[str, str, int]] = []
        if source_events:
            actions.append(("Open Source Events", "events", 18))
        if timeline_available:
            actions.append(("Open Endpoint Timeline", "timeline", 20))
        if has_linked_case:
            actions.append(("Open Linked Case", "case", 18))
        return self._choose_action_dialog(
            title="Alert Actions",
            summary=summary,
            actions=actions,
            default_choice="details",
            no_tk_choice="events" if source_events else ("timeline" if timeline_available else "case"),
            width=620,
            height=260,
            min_width=540,
            min_height=220,
            detail_label="Alert Details",
            detail_width=14,
        )

    def _call_case_activity_pivot(
        self,
        case_payload: dict[str, Any],
        *,
        linked_alerts: Sequence[dict[str, Any]],
        source_events: Sequence[dict[str, Any]],
        timeline_available: bool = False,
        hunt_available: bool = False,
        grouped_rule_alerts: Sequence[dict[str, Any]] = (),
        grouped_rule_evidence: Sequence[dict[str, Any]] = (),
    ) -> str:
        try:
            return self._choose_case_activity_pivot(
                case_payload,
                linked_alerts=linked_alerts,
                source_events=source_events,
                timeline_available=timeline_available,
                hunt_available=hunt_available,
                grouped_rule_alerts=grouped_rule_alerts,
                grouped_rule_evidence=grouped_rule_evidence,
            )
        except TypeError:
            return self._choose_case_activity_pivot(
                case_payload,
                linked_alerts=linked_alerts,
                source_events=source_events,
                timeline_available=timeline_available,
                grouped_rule_alerts=grouped_rule_alerts,
                grouped_rule_evidence=grouped_rule_evidence,
            )

    def _choose_case_activity_pivot(
        self,
        case_payload: dict[str, Any],
        *,
        linked_alerts: Sequence[dict[str, Any]],
        source_events: Sequence[dict[str, Any]],
        timeline_available: bool = False,
        hunt_available: bool = False,
        grouped_rule_alerts: Sequence[dict[str, Any]] = (),
        grouped_rule_evidence: Sequence[dict[str, Any]] = (),
    ) -> str:
        if not linked_alerts and not source_events and not timeline_available and not hunt_available and not grouped_rule_alerts and not grouped_rule_evidence:
            return "details"
        case_id = str(case_payload.get("case_id") or "-")
        case_title = str(case_payload.get("title") or "-")
        summary = (
            f"Case: {case_id}\n"
            f"Title: {case_title}\n\n"
            f"Linked alerts: {len(linked_alerts)}\n"
            f"Source events: {len(source_events)}\n"
            f"Endpoint timeline: {'yes' if timeline_available else 'no'}\n"
            f"Hunt telemetry: {'yes' if hunt_available else 'no'}\n"
            f"Rule alert groups: {len(grouped_rule_alerts)}\n"
            f"Rule evidence groups: {len(grouped_rule_evidence)}"
        )
        actions: list[tuple[str, str, int]] = []
        if linked_alerts:
            actions.append(("Open Linked Alerts", "alerts", 18))
        if source_events:
            actions.append(("Open Source Events", "events", 18))
        if timeline_available:
            actions.append(("Open Endpoint Timeline", "timeline", 20))
        if hunt_available:
            actions.append(("Open Hunt Clusters", "hunt", 18))
        if grouped_rule_alerts:
            actions.append(("Open Rule Alert Groups", "rule_alerts", 20))
        if grouped_rule_evidence:
            actions.append(("Open Rule Evidence Groups", "rule_evidence", 22))
        return self._choose_action_dialog(
            title="Case Activity",
            summary=summary,
            actions=actions,
            default_choice="details",
            no_tk_choice="alerts" if linked_alerts else ("events" if source_events else ("timeline" if timeline_available else "hunt")),
            width=620,
            height=260,
            min_width=540,
            min_height=220,
            detail_label="Activity Details",
            detail_width=14,
        )

    def _group_case_rule_alerts(self, linked_alerts: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        rule_alerts = [item for item in linked_alerts if str(item.get("correlation_rule") or "")]
        return self._group_rule_alerts(rule_alerts)

    def _group_case_rule_evidence(self, source_events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        endpoint_events = [item for item in source_events if str(item.get("event_type") or "").startswith("endpoint.telemetry.")]
        return self._group_rule_evidence(endpoint_events)

    def _resolve_detection_rule_alert_groups(self, rule_id: str) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        if manager is not None and hasattr(manager, "list_detection_rule_alert_groups"):
            payload = cast(list[dict[str, Any]], manager.list_detection_rule_alert_groups(rule_id) or [])
            if payload:
                return [dict(item) for item in payload]
        alerts = [item.model_dump(mode="json") for item in self.manager.query_alerts(correlation_rule=rule_id, limit=50)]
        return self._group_rule_alerts(alerts)

    def _resolve_detection_rule_alert_group_detail(
        self,
        rule_id: str,
        group_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        manager = getattr(self, "manager", None)
        group_key = str(group_payload.get("group_key") or "")
        if rule_id and group_key and manager is not None and hasattr(manager, "get_detection_rule_alert_group"):
            payload = cast(dict[str, Any], manager.get_detection_rule_alert_group(rule_id, group_key) or {})
            if payload:
                return dict(payload)
        return dict(group_payload)

    def _resolve_detection_rule_evidence_groups(self, rule_id: str) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        if manager is not None and hasattr(manager, "list_detection_rule_evidence_groups"):
            payload = cast(list[dict[str, Any]], manager.list_detection_rule_evidence_groups(rule_id) or [])
            if payload:
                return [dict(item) for item in payload]
        alert_rows = [item.model_dump(mode="json") for item in self.manager.query_alerts(correlation_rule=rule_id, limit=50)]
        source_events = self._collect_rule_source_events(alert_rows)
        return self._group_rule_evidence(source_events)

    def _resolve_detection_rule_evidence_group_detail(
        self,
        rule_id: str,
        group_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        manager = getattr(self, "manager", None)
        group_key = str(group_payload.get("group_key") or "")
        if rule_id and group_key and manager is not None and hasattr(manager, "get_detection_rule_evidence_group"):
            payload = cast(dict[str, Any], manager.get_detection_rule_evidence_group(rule_id, group_key) or {})
            if payload:
                return dict(payload)
        return dict(group_payload)

    def _resolve_case_rule_alert_groups(
        self,
        case_payload: Mapping[str, Any],
        linked_alerts: Sequence[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        if case_id and manager is not None and hasattr(manager, "list_case_rule_alert_groups"):
            payload = cast(list[dict[str, Any]], manager.list_case_rule_alert_groups(case_id) or [])
            if payload:
                return [dict(item) for item in payload]
        return self._group_case_rule_alerts(linked_alerts)

    def _resolve_case_rule_alert_group_detail(
        self,
        case_payload: Mapping[str, Any],
        group_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        group_key = str(group_payload.get("group_key") or "")
        if case_id and group_key and manager is not None and hasattr(manager, "get_case_rule_alert_group"):
            payload = cast(dict[str, Any], manager.get_case_rule_alert_group(case_id, group_key) or {})
            if payload:
                return dict(payload)
        return dict(group_payload)

    def _resolve_case_rule_evidence_groups(
        self,
        case_payload: Mapping[str, Any],
        source_events: Sequence[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        if case_id and manager is not None and hasattr(manager, "list_case_rule_evidence_groups"):
            payload = cast(list[dict[str, Any]], manager.list_case_rule_evidence_groups(case_id) or [])
            if payload:
                return [dict(item) for item in payload]
        return self._group_case_rule_evidence(source_events)

    def _resolve_case_rule_evidence_group_detail(
        self,
        case_payload: Mapping[str, Any],
        group_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        group_key = str(group_payload.get("group_key") or "")
        if case_id and group_key and manager is not None and hasattr(manager, "get_case_rule_evidence_group"):
            payload = cast(dict[str, Any], manager.get_case_rule_evidence_group(case_id, group_key) or {})
            if payload:
                return dict(payload)
        return dict(group_payload)

    def _resolve_case_endpoint_timeline_clusters(
        self,
        case_payload: Mapping[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
        cluster_by: str = "process",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        if case_id and manager is not None and hasattr(manager, "list_case_endpoint_timeline_clusters"):
            payload = cast(
                dict[str, Any],
                manager.list_case_endpoint_timeline_clusters(case_id, cluster_by=cluster_by, limit=limit),
            )
            rows = [dict(item) for item in cast(list[dict[str, Any]], payload.get("clusters") or [])]
            for row in rows:
                label = str(row.get("label") or row.get("cluster_key") or "-")
                open_case_count = int(row.get("open_case_count") or 0)
                row["title"] = f"{label} (open cases: {open_case_count})" if open_case_count else label
            return rows
        return []

    def _resolve_case_endpoint_timeline_cluster_detail(
        self,
        case_payload: Mapping[str, Any],
        cluster_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        cluster_key = str(cluster_payload.get("cluster_key") or "")
        cluster_by = str(cluster_payload.get("cluster_by") or "process")
        if case_id and cluster_key and manager is not None and hasattr(manager, "get_case_endpoint_timeline_cluster"):
            payload = cast(
                dict[str, Any],
                manager.get_case_endpoint_timeline_cluster(case_id, cluster_by=cluster_by, cluster_key=cluster_key) or {},
            )
            if payload:
                label = str(payload.get("label") or payload.get("cluster_key") or "-")
                open_case_count = int(payload.get("open_case_count") or 0)
                payload["title"] = f"{label} (open cases: {open_case_count})" if open_case_count else label
                return dict(payload)
        return dict(cluster_payload)

    def _resolve_case_hunt_telemetry_clusters(
        self,
        case_payload: Mapping[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
        cluster_by: str = "remote_ip",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        if case_id and manager is not None and hasattr(manager, "list_case_hunt_telemetry_clusters"):
            payload = cast(
                dict[str, Any],
                manager.list_case_hunt_telemetry_clusters(case_id, cluster_by=cluster_by, limit=limit),
            )
            rows = [dict(item) for item in cast(list[dict[str, Any]], payload.get("clusters") or [])]
            for row in rows:
                label = str(row.get("label") or row.get("cluster_key") or "-")
                open_case_count = int(row.get("open_case_count") or 0)
                row["title"] = f"{label} (open cases: {open_case_count})" if open_case_count else label
            return rows
        filters = self._case_hunt_telemetry_filters_from_case(case_payload, source_events=source_events, cluster_by=cluster_by)
        return self._collect_hunt_telemetry_clusters(cluster_by=cluster_by, limit=limit, **filters)

    def _resolve_case_hunt_telemetry_cluster_detail(
        self,
        case_payload: Mapping[str, Any],
        cluster_payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        cluster_key = str(cluster_payload.get("cluster_key") or "")
        cluster_by = str(cluster_payload.get("cluster_by") or "remote_ip")
        if case_id and cluster_key and manager is not None and hasattr(manager, "get_case_hunt_telemetry_cluster"):
            payload = cast(
                dict[str, Any],
                manager.get_case_hunt_telemetry_cluster(case_id, cluster_by=cluster_by, cluster_key=cluster_key) or {},
            )
            if payload:
                label = str(payload.get("label") or payload.get("cluster_key") or "-")
                open_case_count = int(payload.get("open_case_count") or 0)
                payload["title"] = f"{label} (open cases: {open_case_count})" if open_case_count else label
                return dict(payload)
        return self._resolve_hunt_telemetry_cluster_detail(cluster_payload)

    def _pivot_from_case_timeline_clusters(
        self,
        case_payload: dict[str, Any],
        linked_alerts: Sequence[dict[str, Any]],
        source_events: Sequence[dict[str, Any]],
        timeline_clusters: Sequence[dict[str, Any]],
    ) -> None:
        selected_cluster = self._select_summary_record_or_show_info(
            "endpoint_timeline_cluster",
            timeline_clusters,
            title="Endpoint Timeline Clusters",
            info_title="Case Linked Activity",
            info_text=self._format_case_linked_activity(case_payload, linked_alerts, source_events),
            limit=50,
        )
        if selected_cluster is None:
            return
        selected_cluster = self._resolve_case_endpoint_timeline_cluster_detail(case_payload, selected_cluster)
        choice = self._choose_action_dialog(
            title=f"Endpoint Timeline Cluster {selected_cluster.get('cluster_key', '-')}",
            summary=(
                f"Cluster: {selected_cluster.get('cluster_key', '-')}\n"
                f"Events: {selected_cluster.get('event_count', 0)}\n"
                f"Open case count: {int(selected_cluster.get('open_case_count') or 0)}"
            ),
            actions=[("Open Timeline", "timeline", 16), ("Create Timeline Case", "case", 18)],
            default_choice="details",
            no_tk_choice="timeline",
            width=620,
            height=240,
            min_width=540,
            min_height=200,
            detail_label="Cluster Details",
            detail_width=14,
        )
        if choice == "case":
            if self._handle_existing_case_choice(
                open_case_ids=[str(item) for item in cast(list[Any], selected_cluster.get("open_case_ids") or []) if str(item)],
                context_label=f"Endpoint timeline cluster {selected_cluster.get('label', selected_cluster.get('cluster_key', '-'))}",
                context_details=[
                    f"Cluster: {selected_cluster.get('cluster_key', '-')}",
                    f"Events: {selected_cluster.get('event_count', 0)}",
                    f"Open case count: {int(selected_cluster.get('open_case_count') or 0)}",
                ],
                no_action_label="create another case",
            ):
                return
            self._promote_case_timeline_cluster_to_case(case_payload, selected_cluster)
            return
        timeline_rows = self._resolve_case_timeline_cluster_events(case_payload, selected_cluster)
        selected_event = self._select_summary_record_or_show_info(
            "endpoint_timeline",
            timeline_rows,
            title="Endpoint Timeline",
            info_title="Case Linked Activity",
            info_text=self._format_endpoint_timeline_cluster_detail(selected_cluster),
            limit=50,
        )
        if selected_event is None:
            return
        self._pivot_from_event(selected_event)

    def _promote_case_timeline_cluster_to_case(
        self,
        case_payload: Mapping[str, Any],
        cluster_payload: Mapping[str, Any],
    ) -> None:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        assignee = self._current_analyst_identity()
        if case_id and manager is not None and hasattr(manager, "create_case_from_case_endpoint_timeline_cluster"):
            cluster_request = SocCaseEndpointTimelineClusterCaseRequest(
                cluster_by=str(cluster_payload.get("cluster_by") or "process"),
                cluster_key=str(cluster_payload.get("cluster_key") or ""),
                assignee=assignee,
            )
            case = manager.create_case_from_case_endpoint_timeline_cluster(case_id, cluster_request)
        elif manager is not None and hasattr(manager, "create_case_from_endpoint_timeline"):
            timeline_request = self._build_endpoint_timeline_case_request(dict(cluster_payload))
            case = manager.create_case_from_endpoint_timeline(timeline_request)
        else:
            case = self.manager.create_case(self._build_endpoint_timeline_case_payload(dict(cluster_payload), assignee=assignee))
        if messagebox is not None:
            messagebox.showinfo(
                "Case Created",
                f"Created case {case.case_id} from endpoint timeline cluster {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}.",
            )
        self.refresh()
        if hasattr(self, "case_tree"):
            self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def _pivot_from_case_hunt_telemetry_clusters(
        self,
        case_payload: dict[str, Any],
        linked_alerts: Sequence[dict[str, Any]],
        source_events: Sequence[dict[str, Any]],
    ) -> None:
        cluster_by = self._choose_hunt_telemetry_cluster_mode()
        clusters = self._resolve_case_hunt_telemetry_clusters(
            case_payload,
            source_events=source_events,
            cluster_by=cluster_by,
            limit=100,
        )
        selected_cluster = self._select_summary_record_or_show_info(
            "hunt_telemetry_cluster",
            clusters,
            title="Hunt Telemetry Clusters",
            info_title="Case Linked Activity",
            info_text=self._format_case_linked_activity(case_payload, linked_alerts, source_events),
            limit=50,
        )
        if selected_cluster is None:
            return
        selected_cluster = self._resolve_case_hunt_telemetry_cluster_detail(case_payload, selected_cluster)
        choice = self._choose_action_dialog(
            title=f"Hunt Cluster {selected_cluster.get('cluster_key', '-')}",
            summary=(
                f"Cluster: {selected_cluster.get('cluster_key', '-')}\n"
                f"Mode: {selected_cluster.get('cluster_by', '-')}\n"
                f"Events: {selected_cluster.get('event_count', 0)}\n"
                f"Open case count: {int(selected_cluster.get('open_case_count') or 0)}"
            ),
            actions=[("Open Events", "events", 14), ("Create Cluster Case", "case", 18)],
            default_choice="details",
            no_tk_choice="events",
            width=620,
            height=240,
            min_width=540,
            min_height=200,
            detail_label="Cluster Details",
            detail_width=14,
        )
        if choice == "case":
            if self._handle_existing_case_choice(
                open_case_ids=[str(item) for item in cast(list[Any], selected_cluster.get("open_case_ids") or []) if str(item)],
                context_label=f"Hunt telemetry cluster {selected_cluster.get('label', selected_cluster.get('cluster_key', '-'))}",
                context_details=[
                    f"Cluster: {selected_cluster.get('cluster_key', '-')}",
                    f"Mode: {selected_cluster.get('cluster_by', '-')}",
                    f"Events: {selected_cluster.get('event_count', 0)}",
                    f"Open case count: {int(selected_cluster.get('open_case_count') or 0)}",
                ],
                no_action_label="create another case",
            ):
                return
            self._promote_case_hunt_telemetry_cluster_to_case(case_payload, selected_cluster)
            return
        event_rows = self._resolve_hunt_telemetry_cluster_events(selected_cluster)
        selected_event = self._select_summary_record_or_show_info(
            "event",
            event_rows,
            title="Hunt Cluster Events",
            info_title="Case Linked Activity",
            info_text=self._format_hunt_telemetry_cluster_detail(selected_cluster),
            limit=50,
        )
        if selected_event is None:
            return
        self._pivot_from_event(selected_event)

    def _promote_case_hunt_telemetry_cluster_to_case(
        self,
        case_payload: Mapping[str, Any],
        cluster_payload: Mapping[str, Any],
    ) -> None:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        assignee = self._current_analyst_identity()
        if case_id and manager is not None and hasattr(manager, "create_case_from_case_hunt_telemetry_cluster"):
            case_cluster_request = SocCaseTelemetryClusterCaseRequest(
                cluster_by=str(cluster_payload.get("cluster_by") or "remote_ip"),
                cluster_key=str(cluster_payload.get("cluster_key") or ""),
                assignee=assignee,
            )
            case = manager.create_case_from_case_hunt_telemetry_cluster(case_id, case_cluster_request)
        elif manager is not None and hasattr(manager, "create_case_from_hunt_telemetry_cluster"):
            hunt_cluster_request = self._build_hunt_telemetry_cluster_case_request(dict(cluster_payload))
            case = manager.create_case_from_hunt_telemetry_cluster(hunt_cluster_request)
        elif manager is not None and hasattr(manager, "create_case_from_telemetry_cluster"):
            hunt_cluster_request = self._build_hunt_telemetry_cluster_case_request(dict(cluster_payload))
            case = manager.create_case_from_telemetry_cluster(hunt_cluster_request)
        else:
            case = self.manager.create_case(self._build_hunt_telemetry_cluster_case_payload(dict(cluster_payload), assignee=assignee))
        if messagebox is not None:
            messagebox.showinfo(
                "Case Created",
                f"Created case {case.case_id} from hunt telemetry cluster {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}.",
            )
        self.refresh()
        if hasattr(self, "case_tree"):
            self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def _pivot_from_case_rule_alert_groups(
        self,
        case_payload: dict[str, Any],
        grouped_rule_alerts: Sequence[dict[str, Any]],
        linked_alerts: Sequence[dict[str, Any]],
        source_events: Sequence[dict[str, Any]],
    ) -> None:
        selected_group = self._select_summary_record_or_show_info(
            "alert_group",
            grouped_rule_alerts,
            title="Rule Alert Groups",
            info_title="Case Linked Activity",
            info_text=self._format_case_linked_activity(case_payload, linked_alerts, source_events),
        )
        if selected_group is None:
            return
        selected_group = self._resolve_case_rule_alert_group_detail(case_payload, selected_group)
        group_alerts = cast(list[dict[str, Any]], selected_group.get("alerts") or [])
        group_source_events = self._collect_rule_source_events(group_alerts)
        timeline_filters = self._endpoint_timeline_filters_from_alert_group(selected_group, source_events=group_source_events)
        choice = self._choose_rule_group_pivot(
            title=f"Rule Alert Group {selected_group.get('group_key', '-')}",
            grouped_label="alerts",
            grouped_count=len(group_alerts),
            timeline_available=bool(timeline_filters),
        )
        if choice == "case" and timeline_filters:
            if self._handle_existing_case_choice(
                open_case_ids=[str(item) for item in cast(list[Any], selected_group.get("open_case_ids") or []) if str(item)],
                context_label=f"Rule alert group {selected_group.get('group_key', '-')}",
                context_details=[
                    f"Group: {selected_group.get('group_key', '-')}",
                    f"Alerts: {len(group_alerts)}",
                    f"Open case count: {int(selected_group.get('open_case_count') or 0)}",
                ],
                no_action_label="create another case",
            ):
                return
            self._promote_case_rule_alert_group_to_case(case_payload, selected_group, timeline_filters=timeline_filters)
            return
        if choice == "timeline" and timeline_filters:
            self._pivot_from_rule_group_timeline(
                selected_group,
                timeline_filters=timeline_filters,
                info_title="Rule Alert Groups",
            )
            return
        selected_alert = self._select_summary_record_or_show_info(
            "alert",
            group_alerts,
            title=f"Alerts for {selected_group.get('group_key', '-')}",
            info_title="Rule Alert Groups",
            info_text=self._format_summary_records("alert_group", [selected_group], limit=1),
            limit=50,
        )
        if selected_alert is None:
            return
        self._pivot_from_alert(selected_alert)

    def _pivot_from_case_rule_evidence_groups(
        self,
        case_payload: dict[str, Any],
        grouped_rule_evidence: Sequence[dict[str, Any]],
        linked_alerts: Sequence[dict[str, Any]],
        source_events: Sequence[dict[str, Any]],
    ) -> None:
        selected_group = self._select_summary_record_or_show_info(
            "evidence_group",
            grouped_rule_evidence,
            title="Rule Evidence Groups",
            info_title="Case Linked Activity",
            info_text=self._format_case_linked_activity(case_payload, linked_alerts, source_events),
        )
        if selected_group is None:
            return
        selected_group = self._resolve_case_rule_evidence_group_detail(case_payload, selected_group)
        group_events = cast(list[dict[str, Any]], selected_group.get("events") or [])
        timeline_filters = self._endpoint_timeline_filters_from_evidence_group(selected_group, source_events=group_events)
        choice = self._choose_rule_group_pivot(
            title=f"Rule Evidence Group {selected_group.get('group_key', '-')}",
            grouped_label="events",
            grouped_count=len(group_events),
            timeline_available=bool(timeline_filters),
        )
        if choice == "case" and timeline_filters:
            if self._handle_existing_case_choice(
                open_case_ids=[str(item) for item in cast(list[Any], selected_group.get("open_case_ids") or []) if str(item)],
                context_label=f"Rule evidence group {selected_group.get('group_key', '-')}",
                context_details=[
                    f"Group: {selected_group.get('group_key', '-')}",
                    f"Events: {len(group_events)}",
                    f"Open case count: {int(selected_group.get('open_case_count') or 0)}",
                ],
                no_action_label="create another case",
            ):
                return
            self._promote_case_rule_evidence_group_to_case(case_payload, selected_group, timeline_filters=timeline_filters)
            return
        if choice == "timeline" and timeline_filters:
            self._pivot_from_rule_group_timeline(
                selected_group,
                timeline_filters=timeline_filters,
                info_title="Rule Evidence Groups",
            )
            return
        selected_event = self._select_summary_record_or_show_info(
            "event",
            group_events,
            title=f"Evidence for {selected_group.get('group_key', '-')}",
            info_title="Rule Evidence Groups",
            info_text=self._format_summary_records("evidence_group", [selected_group], limit=1),
            limit=50,
        )
        if selected_event is None:
            return
        self._pivot_from_event(selected_event)

    def _choose_rule_group_pivot(
        self,
        *,
        title: str,
        grouped_label: str,
        grouped_count: int,
        timeline_available: bool,
    ) -> str:
        if not timeline_available:
            return "grouped"
        summary = (
            f"{title}\n\n"
            f"Grouped {grouped_label}: {grouped_count}\n"
            f"Endpoint timeline: {'yes' if timeline_available else 'no'}"
        )
        return self._choose_action_dialog(
            title=title,
            summary=summary,
            actions=[
                (f"Open Grouped {grouped_label.title()}", "grouped", 22),
                ("Open Endpoint Timeline", "timeline", 20),
                ("Create Timeline Case", "case", 18),
            ],
            default_choice="details",
            no_tk_choice="grouped",
            width=620,
            height=220,
            min_width=540,
            min_height=180,
            detail_label="Group Details",
            detail_width=14,
        )

    def _choose_network_evidence_pivot(
        self,
        evidence_payload: dict[str, Any],
        *,
        related_events: Sequence[dict[str, Any]],
        related_alerts: Sequence[dict[str, Any]],
        related_cases: Sequence[dict[str, Any]],
        packet_session: dict[str, Any] | None,
    ) -> str:
        has_packet_session = packet_session is not None
        if not related_events and not related_alerts and not related_cases and not has_packet_session:
            return "details"
        remote_ip = str(evidence_payload.get("remote_ip") or "-")
        summary = (
            f"Remote IP: {remote_ip}\n"
            f"Severity: {evidence_payload.get('severity', '-')}\n\n"
            f"Related events: {len(related_events)}\n"
            f"Related alerts: {len(related_alerts)}\n"
            f"Related cases: {len(related_cases)}\n"
            f"Open cases: {int(evidence_payload.get('open_case_count') or 0)}\n"
            f"Packet session: {'yes' if has_packet_session else 'no'}"
        )
        actions: list[tuple[str, str, int]] = []
        if related_alerts:
            actions.append(("Open Related Alerts", "alerts", 18))
        if related_cases:
            actions.append(("Open Related Cases", "cases", 18))
        if has_packet_session:
            actions.append(("Open Packet Session", "session", 18))
        if related_events:
            actions.append(("Open Events", "events", 14))
        if related_alerts:
            no_tk_choice = "alerts"
        elif related_cases:
            no_tk_choice = "cases"
        elif has_packet_session:
            no_tk_choice = "session"
        elif related_events:
            no_tk_choice = "events"
        else:
            no_tk_choice = "details"
        return self._choose_action_dialog(
            title="Network Evidence Actions",
            summary=summary,
            actions=actions,
            default_choice="details",
            no_tk_choice=no_tk_choice,
            width=640,
            height=280,
            min_width=560,
            min_height=240,
            detail_label="Evidence Details",
            detail_width=16,
        )

    def _resolve_event_alerts(self, event_payload: dict[str, Any]) -> list[dict[str, Any]]:
        event_id = str(event_payload.get("event_id") or "")
        if not event_id:
            return []
        alert_rows = cast(dict[str, dict[str, Any]], getattr(self, "all_alert_rows_by_id", {}))
        return [
            alert
            for alert in alert_rows.values()
            if event_id in cast(list[str], alert.get("source_event_ids") or [])
        ]

    def _resolve_event_cases(self, event_payload: dict[str, Any]) -> list[dict[str, Any]]:
        event_id = str(event_payload.get("event_id") or "")
        manager = getattr(self, "manager", None)
        if not event_id or manager is None or not hasattr(manager, "list_cases"):
            return []
        all_cases = [item.model_dump(mode="json") for item in manager.list_cases()]
        return [
            case
            for case in all_cases
            if event_id in cast(list[str], case.get("source_event_ids") or [])
        ]

    @staticmethod
    def _endpoint_timeline_field_value(payload: Mapping[str, Any], field: str) -> str | None:
        value = payload.get(field)
        if value not in (None, ""):
            return str(value)
        details = payload.get("details")
        if isinstance(details, Mapping):
            detail_value = details.get(field)
            if detail_value not in (None, ""):
                return str(detail_value)
        return None

    def _endpoint_timeline_filters_from_case(
        self,
        case_payload: Mapping[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {}
        observable_fields = {
            "device": "device_id",
            "process_name": "process_name",
            "process_guid": "process_guid",
            "remote_ip": "remote_ip",
            "signer": "signer_name",
            "sha256": "sha256",
        }
        observables = [str(item).strip() for item in cast(list[Any], case_payload.get("observables") or []) if str(item).strip()]
        for observable in observables:
            prefix, separator, raw_value = observable.partition(":")
            if separator:
                target_field = observable_fields.get(prefix.strip().casefold())
                value = raw_value.strip()
                if target_field and value and target_field not in filters:
                    filters[target_field] = value
                    continue
            try:
                remote_ip = str(ip_address(observable))
            except ValueError:
                continue
            filters.setdefault("remote_ip", remote_ip)
        for source_event in source_events:
            normalized = self._normalize_endpoint_timeline_row(source_event)
            event_type = str(normalized.get("event_type") or "")
            if not event_type.startswith("endpoint.telemetry."):
                continue
            for field in ("device_id", "process_guid", "process_name", "remote_ip", "signer_name", "sha256"):
                if field in filters:
                    continue
                field_value = self._endpoint_timeline_field_value(normalized, field)
                if field_value:
                    filters[field] = field_value
        return filters

    def _case_hunt_telemetry_filters_from_case(
        self,
        case_payload: Mapping[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
        cluster_by: str | None = None,
    ) -> dict[str, Any]:
        filters = self._endpoint_timeline_filters_from_case(case_payload, source_events=source_events)
        observable_fields = {
            "filename": "filename",
            "artifact_path": "artifact_path",
            "session": "session_key",
            "session_key": "session_key",
        }
        observables = [str(item).strip() for item in cast(list[Any], case_payload.get("observables") or []) if str(item).strip()]
        for observable in observables:
            prefix, separator, raw_value = observable.partition(":")
            if not separator:
                continue
            target_field = observable_fields.get(prefix.strip().casefold())
            value = raw_value.strip()
            if target_field and value and target_field not in filters:
                filters[target_field] = value
        for source_event in source_events:
            normalized = self._normalize_endpoint_timeline_row(source_event)
            for field in ("device_id", "process_guid", "process_name", "remote_ip", "signer_name", "sha256", "filename", "artifact_path", "session_key"):
                if field in filters:
                    continue
                field_value = self._endpoint_timeline_field_value(normalized, field)
                if field_value:
                    filters[field] = field_value
        if cluster_by == "remote_ip":
            remote_ip = filters.get("remote_ip")
            filters = {key: value for key, value in {"remote_ip": remote_ip}.items() if value}
        elif cluster_by == "device_id":
            device_id = filters.get("device_id")
            filters = {key: value for key, value in {"device_id": device_id}.items() if value}
        elif any(filters.get(key) for key in ("process_guid", "process_name", "sha256")):
            filters.pop("remote_ip", None)
        return filters

    def _endpoint_timeline_filters_from_alert(
        self,
        alert_payload: Mapping[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
        linked_case: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if linked_case is not None:
            return self._endpoint_timeline_filters_from_case(linked_case, source_events=source_events)
        return self._endpoint_timeline_filters_from_case({"observables": []}, source_events=source_events)

    def _endpoint_timeline_filters_from_alert_group(
        self,
        group_payload: Mapping[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
    ) -> dict[str, Any]:
        alerts = cast(list[dict[str, Any]], group_payload.get("alerts") or [])
        linked_case: Mapping[str, Any] | None = None
        for alert_payload in alerts:
            linked_case_id = str(alert_payload.get("linked_case_id") or "")
            if not linked_case_id:
                continue
            linked_case = self.case_rows_by_id.get(linked_case_id)
            if linked_case is not None:
                break
        representative_alert = alerts[0] if alerts else {}
        return self._endpoint_timeline_filters_from_alert(
            representative_alert,
            source_events=source_events,
            linked_case=linked_case,
        )

    def _endpoint_timeline_filters_from_evidence_group(
        self,
        group_payload: Mapping[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
    ) -> dict[str, Any]:
        return self._endpoint_timeline_filters_from_case({"observables": []}, source_events=source_events)

    def _summarize_rule_group_timeline(
        self,
        group_payload: Mapping[str, Any],
        *,
        timeline_rows: Sequence[dict[str, Any]],
    ) -> dict[str, Any]:
        alerts = cast(list[dict[str, Any]], group_payload.get("alerts") or [])
        related_alert_ids = [str(item.get("alert_id")) for item in alerts if str(item.get("alert_id") or "")]
        return {
            "cluster_key": group_payload.get("group_key", "-"),
            "label": group_payload.get("title", group_payload.get("group_key", "-")),
            "cluster_by": "rule_group",
            "event_count": len(timeline_rows),
            "event_ids": [str(item.get("event_id")) for item in timeline_rows if str(item.get("event_id") or "")],
            "event_types": dict(Counter(str(item.get("event_type") or "-") for item in timeline_rows)),
            "device_ids": sorted(
                {
                    str(value)
                    for item in timeline_rows
                    for value in [self._endpoint_timeline_field_value(item, "device_id")]
                    if value
                }
            ),
            "process_names": sorted(
                {
                    str(value)
                    for item in timeline_rows
                    for value in [self._endpoint_timeline_field_value(item, "process_name")]
                    if value
                }
            ),
            "process_guids": sorted(
                {
                    str(value)
                    for item in timeline_rows
                    for value in [self._endpoint_timeline_field_value(item, "process_guid")]
                    if value
                }
            ),
            "remote_ips": sorted(
                {
                    str(value)
                    for item in timeline_rows
                    for value in [self._endpoint_timeline_field_value(item, "remote_ip")]
                    if value
                }
            ),
            "filenames": sorted(
                {
                    str(value)
                    for item in timeline_rows
                    for value in [self._endpoint_timeline_field_value(item, "filename")]
                    if value
                }
            ),
            "related_alert_ids": related_alert_ids,
            "related_case_ids": group_payload.get("related_case_ids") or [],
            "open_case_ids": group_payload.get("open_case_ids") or [],
            "open_case_count": group_payload.get("open_case_count") or 0,
        }

    def _build_endpoint_timeline_case_request_from_rule_group(
        self,
        group_payload: Mapping[str, Any],
        *,
        timeline_filters: Mapping[str, Any],
    ) -> SocEndpointTimelineCaseRequest:
        group_label = str(group_payload.get("title") or group_payload.get("group_key") or "-")
        limit = max(int(group_payload.get("event_count") or group_payload.get("alert_count") or 0), 1)
        payload: dict[str, Any] = {
            "device_id": timeline_filters.get("device_id"),
            "process_name": timeline_filters.get("process_name"),
            "process_guid": timeline_filters.get("process_guid"),
            "remote_ip": timeline_filters.get("remote_ip"),
            "signer_name": timeline_filters.get("signer_name"),
            "sha256": timeline_filters.get("sha256"),
            "title": f"Investigate endpoint timeline {group_label}",
            "summary": f"Investigate endpoint-backed rule group {group_label}.",
            "severity": SocSeverity.high.value,
            "limit": limit,
            "assignee": self._current_analyst_identity(),
        }
        return SocEndpointTimelineCaseRequest.model_validate(payload)

    def _promote_rule_group_to_endpoint_timeline_case(
        self,
        group_payload: Mapping[str, Any],
        *,
        timeline_filters: Mapping[str, Any],
    ) -> None:
        request_payload = self._build_endpoint_timeline_case_request_from_rule_group(
            group_payload,
            timeline_filters=timeline_filters,
        )
        if hasattr(self.manager, "create_case_from_endpoint_timeline"):
            case = self.manager.create_case_from_endpoint_timeline(request_payload)
        else:
            timeline_rows = self._collect_endpoint_timeline(limit=request_payload.limit, **timeline_filters)
            timeline_summary = self._summarize_rule_group_timeline(group_payload, timeline_rows=timeline_rows)
            case = self.manager.create_case(self._build_endpoint_timeline_case_payload(timeline_summary))
        if messagebox is not None:
            messagebox.showinfo(
                "Case Created",
                f"Created case {case.case_id} from rule group {group_payload.get('group_key', '-')}.",
            )
        self.refresh()
        if hasattr(self, "case_tree"):
            self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def _promote_case_rule_alert_group_to_case(
        self,
        case_payload: Mapping[str, Any],
        group_payload: Mapping[str, Any],
        *,
        timeline_filters: Mapping[str, Any],
    ) -> None:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        assignee = self._current_analyst_identity()
        if case_id and manager is not None and hasattr(manager, "create_case_from_case_rule_alert_group"):
            request_payload = SocCaseRuleGroupCaseRequest(
                group_key=str(group_payload.get("group_key") or ""),
                assignee=assignee,
            )
            case = manager.create_case_from_case_rule_alert_group(case_id, request_payload)
        else:
            self._promote_rule_group_to_endpoint_timeline_case(group_payload, timeline_filters=timeline_filters)
            return
        if messagebox is not None:
            messagebox.showinfo(
                "Case Created",
                f"Created case {case.case_id} from case rule alert group {group_payload.get('group_key', '-')}.",
            )
        self.refresh()
        if hasattr(self, "case_tree"):
            self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def _promote_case_rule_evidence_group_to_case(
        self,
        case_payload: Mapping[str, Any],
        group_payload: Mapping[str, Any],
        *,
        timeline_filters: Mapping[str, Any],
    ) -> None:
        manager = getattr(self, "manager", None)
        case_id = str(case_payload.get("case_id") or "")
        assignee = self._current_analyst_identity()
        if case_id and manager is not None and hasattr(manager, "create_case_from_case_rule_evidence_group"):
            request_payload = SocCaseRuleGroupCaseRequest(
                group_key=str(group_payload.get("group_key") or ""),
                assignee=assignee,
            )
            case = manager.create_case_from_case_rule_evidence_group(case_id, request_payload)
        else:
            self._promote_rule_group_to_endpoint_timeline_case(group_payload, timeline_filters=timeline_filters)
            return
        if messagebox is not None:
            messagebox.showinfo(
                "Case Created",
                f"Created case {case.case_id} from case rule evidence group {group_payload.get('group_key', '-')}.",
            )
        self.refresh()
        if hasattr(self, "case_tree"):
            self.case_tree.selection_set(case.case_id)
        self._refresh_case_detail()

    def _pivot_from_rule_group_timeline(
        self,
        group_payload: Mapping[str, Any],
        *,
        timeline_filters: Mapping[str, Any],
        info_title: str,
    ) -> None:
        timeline_rows = self._collect_endpoint_timeline(limit=100, **timeline_filters)
        timeline_summary = self._summarize_rule_group_timeline(group_payload, timeline_rows=timeline_rows)
        selected_event = self._select_summary_record_or_show_info(
            "endpoint_timeline",
            timeline_rows,
            title="Endpoint Timeline",
            info_title=info_title,
            info_text=self._format_endpoint_timeline_cluster_detail(timeline_summary),
            limit=50,
        )
        if selected_event is None:
            return
        self._pivot_from_event(selected_event)

    def _pivot_from_alert_timeline(
        self,
        alert_payload: dict[str, Any],
        *,
        timeline_filters: Mapping[str, Any],
    ) -> None:
        timeline_rows = self._collect_endpoint_timeline(limit=100, **timeline_filters)
        selected_event = self._select_summary_record_or_show_info(
            "endpoint_timeline",
            timeline_rows,
            title="Endpoint Timeline",
            info_title="Alert Details",
            info_text=self._format_alert_detail(alert_payload),
            limit=50,
        )
        if selected_event is None:
            return
        self._pivot_from_event(selected_event)

    def _pivot_from_endpoint_timeline(
        self,
        case_payload: dict[str, Any],
        *,
        timeline_filters: Mapping[str, Any],
    ) -> None:
        timeline_rows = self._collect_case_endpoint_timeline(case_payload, limit=100, **timeline_filters)
        linked_alerts = self._resolve_linked_alerts(case_payload)
        source_events = self._resolve_case_source_events(case_payload)
        selected_event = self._select_summary_record_or_show_info(
            "endpoint_timeline",
            timeline_rows,
            title="Endpoint Timeline",
            info_title="Case Linked Activity",
            info_text=self._format_case_linked_activity(
                case_payload,
                linked_alerts,
                source_events,
                endpoint_timeline=timeline_rows,
            ),
            limit=50,
        )
        if selected_event is None:
            return
        self._pivot_from_event(selected_event)

    def _resolve_case_timeline_cluster_events(
        self,
        case_payload: Mapping[str, Any],
        cluster_payload: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        filters: dict[str, Any] = {}
        device_ids = cast(list[str], cluster_payload.get("device_ids") or [])
        process_names = cast(list[str], cluster_payload.get("process_names") or [])
        process_guids = cast(list[str], cluster_payload.get("process_guids") or [])
        remote_ips = cast(list[str], cluster_payload.get("remote_ips") or [])
        if device_ids:
            filters["device_id"] = device_ids[0]
        if process_guids:
            filters["process_guid"] = process_guids[0]
        elif process_names:
            filters["process_name"] = process_names[0]
        if str(cluster_payload.get("cluster_by") or "") == "remote_ip" and remote_ips:
            filters["remote_ip"] = remote_ips[0]
        limit = max(int(cluster_payload.get("event_count") or 0), 1)
        return self._collect_case_endpoint_timeline(case_payload, limit=limit, **filters)

    def _resolve_endpoint_timeline_cluster_events(self, cluster_payload: dict[str, Any]) -> list[dict[str, Any]]:
        manager = getattr(self, "manager", None)
        if manager is None or not hasattr(manager, "list_endpoint_timeline"):
            return []
        filters: dict[str, Any] = {"limit": max(int(cluster_payload.get("event_count") or 0), 1)}
        device_ids = cast(list[str], cluster_payload.get("device_ids") or [])
        process_names = cast(list[str], cluster_payload.get("process_names") or [])
        process_guids = cast(list[str], cluster_payload.get("process_guids") or [])
        remote_ips = cast(list[str], cluster_payload.get("remote_ips") or [])
        if device_ids:
            filters["device_id"] = device_ids[0]
        if process_guids:
            filters["process_guid"] = process_guids[0]
        elif process_names:
            filters["process_name"] = process_names[0]
        if str(cluster_payload.get("cluster_by") or "") == "remote_ip" and remote_ips:
            filters["remote_ip"] = remote_ips[0]
        return [
            self._normalize_endpoint_timeline_row(item)
            for item in cast(list[Any], manager.list_endpoint_timeline(**filters))
        ]

    def _resolve_hunt_telemetry_cluster_events(self, cluster_payload: Mapping[str, Any]) -> list[dict[str, Any]]:
        if cluster_payload.get("events"):
            return [dict(item) for item in cast(list[dict[str, Any]], cluster_payload.get("events") or [])]
        resolved = self._resolve_hunt_telemetry_cluster_detail(cluster_payload)
        if resolved.get("events"):
            return [dict(item) for item in cast(list[dict[str, Any]], resolved.get("events") or [])]
        return []

    def _choose_endpoint_timeline_cluster_mode(self) -> str:
        choice = self._choose_action_dialog(
            title="Endpoint Timeline Cluster Mode",
            summary="Choose how to cluster the endpoint timeline.",
            actions=[
                ("Process", "process", 12),
            ],
            default_choice="remote_ip",
            no_tk_choice="process",
            width=460,
            height=170,
            min_width=420,
            min_height=150,
            detail_label="Remote IP",
            detail_width=12,
        )
        return choice if choice in {"process", "remote_ip"} else "process"

    def _choose_hunt_telemetry_cluster_mode(self) -> str:
        choice = self._choose_action_dialog(
            title="Telemetry Cluster Mode",
            summary="Choose how to cluster normalized hunt telemetry.",
            actions=[
                ("Remote IP", "remote_ip", 12),
                ("Device", "device_id", 12),
                ("Process GUID", "process_guid", 12),
            ],
            default_choice="remote_ip",
            no_tk_choice="remote_ip",
            width=500,
            height=190,
            min_width=460,
            min_height=170,
            detail_label="Remote IP",
            detail_width=12,
        )
        return choice if choice in {"remote_ip", "device_id", "process_guid"} else "remote_ip"

    def _resolve_packet_session_events(self, session_payload: dict[str, Any]) -> list[dict[str, Any]]:
        if hasattr(self.manager, "resolve_packet_session_events"):
            return [item.model_dump(mode="json") for item in self.manager.resolve_packet_session_events(session_payload)]
        remote_ip = str(session_payload.get("remote_ip") or "")
        if not remote_ip:
            return []
        return [
            item.model_dump(mode="json")
            for item in self.manager.query_events(text=remote_ip, limit=100)
            if item.event_type in {"packet.monitor.finding", "packet.monitor.recovered", "network.monitor.finding", "network.monitor.recovered"}
        ]

    def _navigate_summary_view(
        self,
        *,
        preset_name: str,
        focus_target: str,
        alert_severity: str | None = None,
        alert_link_state: str | None = None,
        alert_sort: str | None = None,
        case_status: str | None = None,
        case_sort: str | None = None,
    ) -> None:
        self.queue_preset_var.set(preset_name)
        if alert_severity is not None:
            self.alert_severity_var.set(alert_severity)
        if alert_link_state is not None:
            self.alert_link_state_var.set(alert_link_state)
        if alert_sort is not None:
            self.alert_sort_var.set(alert_sort)
        if case_status is not None:
            self.case_status_var.set(case_status)
        if case_sort is not None:
            self.case_sort_var.set(case_sort)
        self.refresh()
        if focus_target == "alerts":
            self._focus_tree_widget(self.alert_tree)
        elif focus_target == "cases":
            self._focus_tree_widget(self.case_tree)
        elif focus_target == "host":
            self._focus_tree_widget(self.host_tree)

    @staticmethod
    def _focus_tree_widget(tree: Any) -> None:
        focus_method = getattr(tree, "focus_set", None)
        if callable(focus_method):
            focus_method()
        children_method = getattr(tree, "get_children", None)
        selection_method = getattr(tree, "selection_set", None)
        if callable(children_method) and callable(selection_method):
            children = list(children_method())
            if children:
                selection_method(children[0])

    @staticmethod
    def _build_promote_payload(
        alert: Any,
        *,
        acted_by: str | None = None,
        existing_case_id: str | None = None,
    ) -> SocAlertPromoteCaseRequest:
        assignee = getattr(alert, "assignee", None)
        payload: dict[str, Any] = {
            "title": f"Investigate {alert.title}",
            "summary": alert.summary,
            "severity": alert.severity.value,
            "case_status": "investigating",
            "alert_status": "acknowledged",
        }
        if assignee:
            payload["assignee"] = assignee
        if acted_by:
            payload["acted_by"] = acted_by
        if existing_case_id:
            payload["existing_case_id"] = existing_case_id
        return SocAlertPromoteCaseRequest.model_validate(payload)

    @staticmethod
    def _build_case_update_payload(*, field: str, value: str) -> SocCaseUpdate:
        if field == "note":
            return SocCaseUpdate(note=value)
        if field == "observable":
            return SocCaseUpdate(observable=value)
        if field == "assignee":
            return SocCaseUpdate(assignee=value)
        if field == "status":
            return SocCaseUpdate(status=SocCaseStatus(value))
        raise ValueError(f"Unsupported case update field: {field}")

    @staticmethod
    def _build_packet_session_case_payload(
        session_payload: dict[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
        assignee: str | None = None,
    ) -> SocCaseCreate:
        remote_ip = str(session_payload.get("remote_ip") or "unknown-remote")
        sensitive_ports = [int(item) for item in cast(list[Any], session_payload.get("sensitive_ports") or [])]
        severity = SocSeverity.critical if sensitive_ports else SocSeverity.high
        packet_count = int(session_payload.get("total_packets") or session_payload.get("last_packet_count") or 0)
        observables: list[str] = [remote_ip, str(session_payload.get("session_key") or f"packet-session:{remote_ip}")]
        observables.extend(f"protocol:{item}" for item in cast(list[Any], session_payload.get("protocols") or []))
        observables.extend(f"local_port:{int(item)}" for item in cast(list[Any], session_payload.get("local_ports") or []))
        observables.extend(f"remote_port:{int(item)}" for item in cast(list[Any], session_payload.get("remote_ports") or [])[:10])
        payload: dict[str, Any] = {
            "title": f"Investigate packet session {remote_ip}",
            "summary": f"Investigate compact packet session evidence for {remote_ip}. Total packets observed: {packet_count}.",
            "severity": severity.value,
            "source_event_ids": [str(item.get("event_id")) for item in source_events if item.get("event_id")],
            "observables": observables,
        }
        if assignee:
            payload["assignee"] = assignee
        return SocCaseCreate.model_validate(payload)

    @staticmethod
    def _build_network_evidence_case_payload(
        evidence_payload: dict[str, Any],
        *,
        source_events: Sequence[dict[str, Any]],
        linked_alerts: Sequence[dict[str, Any]],
        assignee: str | None = None,
    ) -> SocCaseCreate:
        remote_ip = str(evidence_payload.get("remote_ip") or "unknown-remote")
        observation = cast(dict[str, Any], evidence_payload.get("observation") or {})
        packet_session = cast(dict[str, Any], evidence_payload.get("packet_session") or {})
        sensitive_ports = [int(item) for item in cast(list[Any], observation.get("sensitive_ports") or [])]
        local_ports = [int(item) for item in cast(list[Any], observation.get("local_ports") or [])]
        remote_ports = [int(item) for item in cast(list[Any], observation.get("remote_ports") or [])[:10]]
        protocols = [str(item) for item in cast(list[Any], packet_session.get("protocols") or [])]
        severity = SocSeverity.critical if sensitive_ports else SocSeverity.high
        total_hits = int(observation.get("total_hits") or 0)
        total_packets = int(packet_session.get("total_packets") or packet_session.get("last_packet_count") or 0)
        observables: list[str] = [remote_ip]
        session_key = str(packet_session.get("session_key") or "")
        if session_key:
            observables.append(session_key)
        observables.extend(f"local_port:{item}" for item in local_ports)
        observables.extend(f"remote_port:{item}" for item in remote_ports)
        observables.extend(f"sensitive_port:{item}" for item in sensitive_ports)
        observables.extend(f"protocol:{item}" for item in protocols)
        payload: dict[str, Any] = {
            "title": f"Investigate network evidence {remote_ip}",
            "summary": f"Investigate combined network evidence for {remote_ip}. Observation hits: {total_hits}. Packet count: {total_packets}.",
            "severity": severity.value,
            "source_event_ids": [str(item.get("event_id")) for item in source_events if item.get("event_id")],
            "linked_alert_ids": [str(item.get("alert_id")) for item in linked_alerts if item.get("alert_id")],
            "observables": observables,
        }
        if assignee:
            payload["assignee"] = assignee
        return SocCaseCreate.model_validate(payload)

    @staticmethod
    def _build_endpoint_timeline_case_payload(cluster_payload: dict[str, Any], *, assignee: str | None = None) -> SocCaseCreate:
        source_event_ids = [str(item) for item in cast(list[Any], cluster_payload.get("event_ids") or []) if str(item)]
        linked_alert_ids = [str(item) for item in cast(list[Any], cluster_payload.get("related_alert_ids") or []) if str(item)]
        observables: list[str] = []
        observables.extend(f"device:{item}" for item in cast(list[Any], cluster_payload.get("device_ids") or []) if str(item))
        observables.extend(f"process_name:{item}" for item in cast(list[Any], cluster_payload.get("process_names") or []) if str(item))
        observables.extend(f"process_guid:{item}" for item in cast(list[Any], cluster_payload.get("process_guids") or []) if str(item))
        observables.extend(f"remote_ip:{item}" for item in cast(list[Any], cluster_payload.get("remote_ips") or []) if str(item))
        observables.extend(f"filename:{item}" for item in cast(list[Any], cluster_payload.get("filenames") or []) if str(item))
        payload: dict[str, Any] = {
            "title": f"Investigate endpoint timeline {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}",
            "summary": (
                f"Investigate endpoint timeline cluster {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}. "
                f"Event count: {cluster_payload.get('event_count', 0)}. "
                f"Window: {cluster_payload.get('first_seen_at', '-')} to {cluster_payload.get('last_seen_at', '-')}."
            ),
            "severity": SocSeverity.high.value,
            "source_event_ids": source_event_ids,
            "linked_alert_ids": linked_alert_ids,
            "observables": observables,
        }
        if assignee:
            payload["assignee"] = assignee
        return SocCaseCreate.model_validate(payload)

    def _build_endpoint_timeline_case_request(self, cluster_payload: dict[str, Any]) -> SocEndpointTimelineCaseRequest:
        payload: dict[str, Any] = {
            "device_id": next(iter(cast(list[str], cluster_payload.get("device_ids") or [])), None),
            "process_name": next(iter(cast(list[str], cluster_payload.get("process_names") or [])), None),
            "process_guid": next(iter(cast(list[str], cluster_payload.get("process_guids") or [])), None),
            "remote_ip": next(iter(cast(list[str], cluster_payload.get("remote_ips") or [])), None),
            "title": f"Investigate endpoint timeline {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}",
            "summary": (
                f"Investigate endpoint timeline cluster {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}. "
                f"Event count: {cluster_payload.get('event_count', 0)}."
            ),
            "severity": SocSeverity.high.value,
            "limit": max(int(cluster_payload.get("event_count") or 0), 1),
            "assignee": self._current_analyst_identity(),
        }
        return SocEndpointTimelineCaseRequest.model_validate(payload)

    @staticmethod
    def _build_hunt_telemetry_cluster_case_payload(cluster_payload: dict[str, Any], *, assignee: str | None = None) -> SocCaseCreate:
        source_event_ids = [str(item) for item in cast(list[Any], cluster_payload.get("event_ids") or []) if str(item)]
        linked_alert_ids = [str(item) for item in cast(list[Any], cluster_payload.get("related_alert_ids") or []) if str(item)]
        observables: list[str] = [f"cluster:{cluster_payload.get('cluster_by', '-')}:"
                                  f"{cluster_payload.get('cluster_key', '-')}"]
        observables.extend(f"device:{item}" for item in cast(list[Any], cluster_payload.get("device_ids") or []) if str(item))
        observables.extend(f"process_name:{item}" for item in cast(list[Any], cluster_payload.get("process_names") or []) if str(item))
        observables.extend(f"process_guid:{item}" for item in cast(list[Any], cluster_payload.get("process_guids") or []) if str(item))
        observables.extend(f"remote_ip:{item}" for item in cast(list[Any], cluster_payload.get("remote_ips") or []) if str(item))
        observables.extend(f"filename:{item}" for item in cast(list[Any], cluster_payload.get("filenames") or []) if str(item))
        observables.extend(f"session:{item}" for item in cast(list[Any], cluster_payload.get("session_keys") or []) if str(item))
        observables.extend(f"signer:{item}" for item in cast(list[Any], cluster_payload.get("signers") or []) if str(item))
        payload: dict[str, Any] = {
            "title": f"Investigate {cluster_payload.get('cluster_by', 'telemetry')} cluster {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}",
            "summary": (
                f"Investigate hunt telemetry cluster {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}. "
                f"Event count: {cluster_payload.get('event_count', 0)}. "
                f"Window: {cluster_payload.get('first_seen_at', '-')} to {cluster_payload.get('last_seen_at', '-')}."
            ),
            "severity": str(cluster_payload.get("severity") or SocSeverity.high.value),
            "source_event_ids": source_event_ids,
            "linked_alert_ids": linked_alert_ids,
            "observables": observables,
        }
        if assignee:
            payload["assignee"] = assignee
        return SocCaseCreate.model_validate(payload)

    def _build_hunt_telemetry_cluster_case_request(self, cluster_payload: dict[str, Any]) -> SocTelemetryClusterCaseRequest:
        payload: dict[str, Any] = {
            "cluster_by": str(cluster_payload.get("cluster_by") or "remote_ip"),
            "cluster_key": str(cluster_payload.get("cluster_key") or ""),
            "device_id": next(iter(cast(list[str], cluster_payload.get("device_ids") or [])), None),
            "process_name": next(iter(cast(list[str], cluster_payload.get("process_names") or [])), None),
            "process_guid": next(iter(cast(list[str], cluster_payload.get("process_guids") or [])), None),
            "remote_ip": next(iter(cast(list[str], cluster_payload.get("remote_ips") or [])), None),
            "filename": next(iter(cast(list[str], cluster_payload.get("filenames") or [])), None),
            "session_key": next(iter(cast(list[str], cluster_payload.get("session_keys") or [])), None),
            "signer_name": next(iter(cast(list[str], cluster_payload.get("signers") or [])), None),
            "title": f"Investigate {cluster_payload.get('cluster_by', 'telemetry')} cluster {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}",
            "summary": (
                f"Investigate hunt telemetry cluster {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}. "
                f"Event count: {cluster_payload.get('event_count', 0)}."
            ),
            "severity": str(cluster_payload.get("severity") or SocSeverity.high.value),
            "assignee": self._current_analyst_identity(),
        }
        return SocTelemetryClusterCaseRequest.model_validate(payload)

    def _build_remote_node_case_payload(self, node_payload: dict[str, Any]) -> SocCaseCreate:
        node_name = str(node_payload.get("node_name") or "unknown-node")
        node_role = str(node_payload.get("node_role") or "unknown")
        node_status = str(node_payload.get("status") or "unknown")
        service_health = cast(dict[str, Any], node_payload.get("service_health") or {})
        services = cast(dict[str, dict[str, Any]], service_health.get("services") or {})
        affected_services = [
            name
            for name, item in services.items()
            if bool(item.get("enabled")) and str(item.get("status") or "unknown") in {"degraded", "pending"}
        ]
        observables = [f"node:{node_name}", f"role:{node_role}", f"node_status:{node_status}"]
        observables.extend(f"service:{name}" for name in affected_services[:10])
        metadata = cast(dict[str, Any], node_payload.get("metadata") or {})
        notes: list[str] = []
        if metadata.get("acknowledged_by"):
            notes.append(
                f"Acknowledged by {metadata.get('acknowledged_by')} at {metadata.get('acknowledged_at') or '-'}."
            )
        payload: dict[str, Any] = {
            "title": f"Investigate remote node {node_name}",
            "summary": (
                f"Investigate remote node {node_name} ({node_role}) with status {node_status}. "
                f"Affected services: {', '.join(affected_services) if affected_services else 'none reported'}."
            ),
            "severity": (SocSeverity.high if node_status in {"degraded", "stale"} else SocSeverity.medium).value,
            "observables": observables,
            "notes": notes,
        }
        assignee = self._current_analyst_identity()
        if assignee:
            payload["assignee"] = assignee
        return SocCaseCreate.model_validate(payload)

    @staticmethod
    def _format_detection_rule_detail(rule_payload: dict[str, Any]) -> str:
        _related_alerts, related_cases, open_cases = SocDashboard._format_investigation_counts(rule_payload)
        return (
            f"Detection Rule: {rule_payload.get('rule_id', '-')}\n"
            f"Title: {rule_payload.get('title', '-')}\n"
            f"Category: {rule_payload.get('category', '-')}\n"
            f"Enabled: {rule_payload.get('enabled', False)}\n"
            f"Hit Count: {rule_payload.get('hit_count', 0)}\n"
            f"Open Alerts: {rule_payload.get('open_alert_count', 0)}\n"
            f"{related_cases}\n"
            f"{open_cases}\n"
            f"Last Match: {rule_payload.get('last_match_at') or '-'}\n"
            f"Parameters: {json.dumps(rule_payload.get('parameters') or {}, sort_keys=True)}\n\n"
            f"Description:\n{rule_payload.get('description', '-')}"
        )

    @staticmethod
    def _format_remote_node_detail(node_payload: dict[str, Any]) -> str:
        service_health = cast(dict[str, Any], node_payload.get("service_health") or {})
        services = cast(dict[str, dict[str, Any]], service_health.get("services") or {})
        metadata = cast(dict[str, Any], node_payload.get("metadata") or {})
        related_alerts, related_cases, open_cases = SocDashboard._format_investigation_counts(node_payload)
        suppressed = bool(node_payload.get("suppressed"))
        suppressed_until = node_payload.get("suppressed_until") or metadata.get("suppressed_until") or "-"
        suppressed_by = node_payload.get("suppressed_by") or metadata.get("suppressed_by") or "-"
        suppression_reason = node_payload.get("suppression_reason") or metadata.get("suppression_reason") or "-"
        suppression_scopes = ", ".join(cast(list[str], node_payload.get("suppression_scopes") or [])) or "-"
        maintenance_active = bool(node_payload.get("maintenance_active"))
        maintenance_status = node_payload.get("maintenance_status") or cast(dict[str, Any], node_payload.get("maintenance") or {}).get("status") or "-"
        maintenance_until = node_payload.get("maintenance_until") or metadata.get("maintenance_until") or "-"
        maintenance_by = node_payload.get("maintenance_by") or metadata.get("maintenance_by") or "-"
        maintenance_reason = node_payload.get("maintenance_reason") or metadata.get("maintenance_reason") or "-"
        maintenance_services = ", ".join(cast(list[str], node_payload.get("maintenance_services") or [])) or "-"
        maintenance_acknowledged_at = node_payload.get("maintenance_acknowledged_at") or metadata.get("maintenance_acknowledged_at") or "-"
        maintenance_completed_at = node_payload.get("maintenance_completed_at") or metadata.get("maintenance_completed_at") or "-"
        maintenance_result = node_payload.get("maintenance_result") or metadata.get("maintenance_result") or "-"
        maintenance_completion_note = node_payload.get("maintenance_completion_note") or metadata.get("maintenance_completion_note") or "-"
        maintenance_failed_at = node_payload.get("maintenance_failed_at") or metadata.get("maintenance_failed_at") or "-"
        maintenance_last_error = node_payload.get("maintenance_last_error") or metadata.get("maintenance_last_error") or "-"
        maintenance_retry_count = node_payload.get("maintenance_retry_count") or metadata.get("maintenance_retry_count") or 0
        maintenance_retriable = node_payload.get("maintenance_retriable")
        if maintenance_retriable is None:
            maintenance_retriable = metadata.get("maintenance_retriable", False)
        refresh_pending = bool(node_payload.get("refresh_pending"))
        refresh_status = node_payload.get("refresh_status") or cast(dict[str, Any], node_payload.get("refresh") or {}).get("status") or "-"
        refresh_requested_at = node_payload.get("refresh_requested_at") or metadata.get("refresh_requested_at") or "-"
        refresh_requested_by = node_payload.get("refresh_requested_by") or metadata.get("refresh_requested_by") or "-"
        refresh_request_reason = node_payload.get("refresh_request_reason") or metadata.get("refresh_request_reason") or "-"
        refresh_acknowledged_at = node_payload.get("refresh_acknowledged_at") or metadata.get("refresh_acknowledged_at") or "-"
        refresh_completed_at = node_payload.get("refresh_completed_at") or metadata.get("refresh_completed_at") or "-"
        refresh_fulfilled_at = node_payload.get("refresh_fulfilled_at") or metadata.get("refresh_fulfilled_at") or "-"
        refresh_result = node_payload.get("refresh_result") or metadata.get("refresh_result") or "-"
        refresh_completion_note = node_payload.get("refresh_completion_note") or metadata.get("refresh_completion_note") or "-"
        refresh_failed_at = node_payload.get("refresh_failed_at") or metadata.get("refresh_failed_at") or "-"
        refresh_last_error = node_payload.get("refresh_last_error") or metadata.get("refresh_last_error") or "-"
        refresh_retry_count = node_payload.get("refresh_retry_count") or metadata.get("refresh_retry_count") or 0
        refresh_retriable = node_payload.get("refresh_retriable")
        if refresh_retriable is None:
            refresh_retriable = metadata.get("refresh_retriable", False)
        drained = bool(node_payload.get("drained"))
        drain_status = node_payload.get("drain_status") or cast(dict[str, Any], node_payload.get("drain") or {}).get("status") or "-"
        drain_requested_at = node_payload.get("drain_requested_at") or metadata.get("drain_requested_at") or "-"
        drain_at = node_payload.get("drain_at") or metadata.get("drain_at") or "-"
        drain_acknowledged_at = node_payload.get("drain_acknowledged_at") or metadata.get("drain_acknowledged_at") or "-"
        drain_completed_at = node_payload.get("drain_completed_at") or metadata.get("drain_completed_at") or "-"
        drain_result = node_payload.get("drain_result") or metadata.get("drain_result") or "-"
        drain_completion_note = node_payload.get("drain_completion_note") or metadata.get("drain_completion_note") or "-"
        drain_failed_at = node_payload.get("drain_failed_at") or metadata.get("drain_failed_at") or "-"
        drain_last_error = node_payload.get("drain_last_error") or metadata.get("drain_last_error") or "-"
        drain_retry_count = node_payload.get("drain_retry_count") or metadata.get("drain_retry_count") or 0
        drain_retriable = node_payload.get("drain_retriable")
        if drain_retriable is None:
            drain_retriable = metadata.get("drain_retriable", False)
        drained_by = node_payload.get("drained_by") or metadata.get("drained_by") or "-"
        drain_reason = node_payload.get("drain_reason") or metadata.get("drain_reason") or "-"
        drain_services = ", ".join(cast(list[str], node_payload.get("drain_services") or [])) or "-"
        action_failures = ", ".join(cast(list[str], node_payload.get("action_failures") or [])) or "-"
        action_pressure = cast(dict[str, Any], node_payload.get("action_pressure") or {})
        repeated_failures = ", ".join(
            f"{action} x{count}" for action, count in cast(dict[str, int], action_pressure.get("repeated_failures") or {}).items()
        ) or "-"
        retry_pressure = ", ".join(
            f"{action} x{count}" for action, count in cast(dict[str, int], action_pressure.get("retry_pressure") or {}).items()
        ) or "-"
        stuck_action_lines = [
            f"- {item.get('action', '-')} status={item.get('status', '-')}, age={item.get('age_minutes', '-')}m"
            for item in cast(list[dict[str, Any]], action_pressure.get("stuck_actions") or [])
            if isinstance(item, dict)
        ] or ["- none"]
        action_history_rows = cast(list[dict[str, Any]], node_payload.get("action_history") or metadata.get("action_history") or [])
        action_history_lines = [
            (
                f"- {item.get('at', '-')}: {item.get('action', '-')}/{item.get('transition', '-')}"
                f" actor={item.get('actor', '-')}"
                + (f" result={item.get('result')}" if item.get("result") is not None else "")
                + (f" note={item.get('note')}" if item.get("note") else "")
            )
            for item in action_history_rows[-10:]
            if isinstance(item, dict)
        ] or ["- none"]
        service_lines = [
            f"- {name}: status={item.get('status', 'unknown')}, enabled={item.get('enabled', False)}"
            for name, item in services.items()
        ] or ["- none"]
        metadata_lines = [f"- {key}: {value}" for key, value in metadata.items()] or ["- none"]
        return (
            f"Remote Node: {node_payload.get('node_name', '-')}\n"
            f"Role: {node_payload.get('node_role', '-')}\n"
            f"Status: {node_payload.get('status', 'unknown')}\n"
            f"Last Seen: {node_payload.get('last_seen_at', '-')}\n"
            f"{related_alerts}\n"
            f"{related_cases}\n"
            f"{open_cases}\n"
            f"Suppressed: {suppressed}\n"
            f"Suppressed Until: {suppressed_until}\n"
            f"Suppressed By: {suppressed_by}\n"
            f"Suppression Reason: {suppression_reason}\n"
            f"Suppression Scopes: {suppression_scopes}\n"
            f"Action Failures: {action_failures}\n"
            f"Repeated Failures: {repeated_failures}\n"
            f"Retry Pressure: {retry_pressure}\n"
            f"Maintenance Active: {maintenance_active}\n"
            f"Maintenance Status: {maintenance_status}\n"
            f"Maintenance Until: {maintenance_until}\n"
            f"Maintenance By: {maintenance_by}\n"
            f"Maintenance Reason: {maintenance_reason}\n"
            f"Maintenance Services: {maintenance_services}\n"
            f"Maintenance Acknowledged At: {maintenance_acknowledged_at}\n"
            f"Maintenance Completed At: {maintenance_completed_at}\n"
            f"Maintenance Result: {maintenance_result}\n"
            f"Maintenance Completion Note: {maintenance_completion_note}\n"
            f"Maintenance Failed At: {maintenance_failed_at}\n"
            f"Maintenance Last Error: {maintenance_last_error}\n"
            f"Maintenance Retry Count: {maintenance_retry_count}\n"
            f"Maintenance Retriable: {maintenance_retriable}\n"
            f"Refresh Pending: {refresh_pending}\n"
            f"Refresh Status: {refresh_status}\n"
            f"Refresh Requested At: {refresh_requested_at}\n"
            f"Refresh Requested By: {refresh_requested_by}\n"
            f"Refresh Request Reason: {refresh_request_reason}\n"
            f"Refresh Acknowledged At: {refresh_acknowledged_at}\n"
            f"Refresh Completed At: {refresh_completed_at}\n"
            f"Refresh Fulfilled At: {refresh_fulfilled_at}\n"
            f"Refresh Result: {refresh_result}\n"
            f"Refresh Completion Note: {refresh_completion_note}\n"
            f"Refresh Failed At: {refresh_failed_at}\n"
            f"Refresh Last Error: {refresh_last_error}\n"
            f"Refresh Retry Count: {refresh_retry_count}\n"
            f"Refresh Retriable: {refresh_retriable}\n"
            f"Drained: {drained}\n"
            f"Drain Status: {drain_status}\n"
            f"Drain Requested At: {drain_requested_at}\n"
            f"Drain At: {drain_at}\n"
            f"Drain Acknowledged At: {drain_acknowledged_at}\n"
            f"Drain Completed At: {drain_completed_at}\n"
            f"Drain Result: {drain_result}\n"
            f"Drain Completion Note: {drain_completion_note}\n"
            f"Drain Failed At: {drain_failed_at}\n"
            f"Drain Last Error: {drain_last_error}\n"
            f"Drain Retry Count: {drain_retry_count}\n"
            f"Drain Retriable: {drain_retriable}\n"
            f"Drained By: {drained_by}\n"
            f"Drain Reason: {drain_reason}\n"
            f"Drain Services: {drain_services}\n"
            f"\nStuck Actions:\n{chr(10).join(stuck_action_lines)}\n"
            f"\nAction History:\n{chr(10).join(action_history_lines)}\n"
            f"Service Health: {service_health.get('overall_status', 'unknown')}\n\n"
            f"Services:\n{chr(10).join(service_lines)}\n\n"
            f"Metadata:\n{chr(10).join(metadata_lines)}"
        )

    @staticmethod
    def _format_endpoint_timeline_cluster_detail(cluster_payload: dict[str, Any]) -> str:
        related_alerts, related_cases, open_cases = SocDashboard._format_investigation_counts(cluster_payload)
        event_types = cast(dict[str, Any], cluster_payload.get("event_types") or {})
        event_type_lines = [f"- {key}: {value}" for key, value in sorted(event_types.items())] or ["- none"]
        return (
            f"Endpoint Timeline Cluster: {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}\n"
            f"Cluster By: {cluster_payload.get('cluster_by', '-')}\n"
            f"Cluster Key: {cluster_payload.get('cluster_key', '-')}\n"
            f"Event Count: {cluster_payload.get('event_count', 0)}\n"
            f"First Seen: {cluster_payload.get('first_seen_at', '-')}\n"
            f"Last Seen: {cluster_payload.get('last_seen_at', '-')}\n"
            f"Devices: {', '.join(cast(list[str], cluster_payload.get('device_ids') or [])) or '-'}\n"
            f"Process Names: {', '.join(cast(list[str], cluster_payload.get('process_names') or [])) or '-'}\n"
            f"Process GUIDs: {', '.join(cast(list[str], cluster_payload.get('process_guids') or [])) or '-'}\n"
            f"Remote IPs: {', '.join(cast(list[str], cluster_payload.get('remote_ips') or [])) or '-'}\n"
            f"Filenames: {', '.join(cast(list[str], cluster_payload.get('filenames') or [])) or '-'}\n"
            f"{related_alerts}\n"
            f"{related_cases}\n"
            f"{open_cases}\n\n"
            f"Event Types:\n{chr(10).join(event_type_lines)}"
        )

    @staticmethod
    def _format_hunt_telemetry_cluster_detail(cluster_payload: dict[str, Any]) -> str:
        related_alerts, related_cases, open_cases = SocDashboard._format_investigation_counts(cluster_payload)
        event_types = cast(dict[str, Any], cluster_payload.get("event_types") or {})
        document_types = cast(dict[str, Any], cluster_payload.get("document_types") or {})
        telemetry_kinds = cast(dict[str, Any], cluster_payload.get("telemetry_kinds") or {})
        event_type_lines = [f"- {key}: {value}" for key, value in sorted(event_types.items())] or ["- none"]
        document_type_lines = [f"- {key}: {value}" for key, value in sorted(document_types.items())] or ["- none"]
        telemetry_kind_lines = [f"- {key}: {value}" for key, value in sorted(telemetry_kinds.items())] or ["- none"]
        return (
            f"Hunt Telemetry Cluster: {cluster_payload.get('label', cluster_payload.get('cluster_key', '-'))}\n"
            f"Cluster By: {cluster_payload.get('cluster_by', '-')}\n"
            f"Cluster Key: {cluster_payload.get('cluster_key', '-')}\n"
            f"Severity: {cluster_payload.get('severity', '-')}\n"
            f"Event Count: {cluster_payload.get('event_count', 0)}\n"
            f"First Seen: {cluster_payload.get('first_seen_at', '-')}\n"
            f"Last Seen: {cluster_payload.get('last_seen_at', '-')}\n"
            f"Devices: {', '.join(cast(list[str], cluster_payload.get('device_ids') or [])) or '-'}\n"
            f"Process Names: {', '.join(cast(list[str], cluster_payload.get('process_names') or [])) or '-'}\n"
            f"Process GUIDs: {', '.join(cast(list[str], cluster_payload.get('process_guids') or [])) or '-'}\n"
            f"Remote IPs: {', '.join(cast(list[str], cluster_payload.get('remote_ips') or [])) or '-'}\n"
            f"Filenames: {', '.join(cast(list[str], cluster_payload.get('filenames') or [])) or '-'}\n"
            f"Session Keys: {', '.join(cast(list[str], cluster_payload.get('session_keys') or [])) or '-'}\n"
            f"Signers: {', '.join(cast(list[str], cluster_payload.get('signers') or [])) or '-'}\n"
            f"{related_alerts}\n"
            f"{related_cases}\n"
            f"{open_cases}\n\n"
            f"Telemetry Kinds:\n{chr(10).join(telemetry_kind_lines)}\n\n"
            f"Document Types:\n{chr(10).join(document_type_lines)}\n\n"
            f"Event Types:\n{chr(10).join(event_type_lines)}"
        )

    @staticmethod
    def _normalize_endpoint_timeline_row(event_like: Any) -> dict[str, Any]:
        if isinstance(event_like, dict):
            payload = dict(event_like)
        elif hasattr(event_like, "model_dump"):
            payload = cast(dict[str, Any], event_like.model_dump(mode="json"))
        else:
            payload = {}
        recorded_at = (
            payload.get("recorded_at")
            or payload.get("created_at")
            or cast(dict[str, Any], payload.get("details") or {}).get("observed_at")
            or cast(dict[str, Any], payload.get("details") or {}).get("last_seen_at")
            or "-"
        )
        payload["recorded_at"] = recorded_at
        return payload

    @staticmethod
    def _coerce_detection_parameter(value: str) -> object:
        normalized = value.strip()
        if normalized.casefold() in {"true", "false"}:
            return normalized.casefold() == "true"
        try:
            return int(normalized)
        except ValueError:
            pass
        try:
            return float(normalized)
        except ValueError:
            pass
        return normalized

    @staticmethod
    def _build_alert_update_payload(*, field: str, value: str, acted_by: str | None = None) -> SocAlertUpdate:
        payload: dict[str, Any] = {}
        if field == "status":
            payload["status"] = value
        elif field == "assignee":
            payload["assignee"] = value
        elif field == "note":
            payload["note"] = value
        else:
            raise ValueError(f"Unsupported alert update field: {field}")
        if acted_by:
            payload["acted_by"] = acted_by
        return SocAlertUpdate.model_validate(payload)

    def _current_analyst_identity(self) -> str | None:
        value = self.analyst_identity_var.get().strip()
        return value or None

    def _selected_workload_assignee(self) -> str | None:
        value = self.workload_assignee_var.get().strip()
        if not value or value == "all":
            return None
        return value

    def _age_bucket_alert_rows(self, bucket: str) -> list[dict[str, Any]]:
        assignee = self._selected_workload_assignee()
        rows = list(self.all_alert_rows_by_id.values())
        rows = [row for row in rows if row.get("status") == SocAlertStatus.open.value]
        if assignee is not None:
            rows = [row for row in rows if str(row.get("assignee") or "") == assignee]
        if bucket == "all":
            return rows
        return [row for row in rows if self._record_matches_age_bucket(str(row.get("updated_at") or ""), bucket)]

    def _age_bucket_case_rows(self, bucket: str) -> list[dict[str, Any]]:
        assignee = self._selected_workload_assignee()
        rows = list(self.case_rows_by_id.values())
        rows = [row for row in rows if row.get("status") != SocCaseStatus.closed.value]
        if assignee is not None:
            rows = [row for row in rows if str(row.get("assignee") or "") == assignee]
        if bucket == "all":
            return rows
        return [row for row in rows if self._record_matches_age_bucket(str(row.get("updated_at") or ""), bucket)]

    def _select_age_bucket_rows(
        self,
        kind: str,
        bucket: str,
        rows: Sequence[dict[str, Any]],
        *,
        id_key: str,
    ) -> list[dict[str, Any]]:
        if not rows:
            return []
        if tk is None or not hasattr(self, "root"):
            return list(rows)
        if len(rows) == 1:
            return [dict(rows[0])]

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Select {kind.title()} Rows")
        dialog.configure(bg="#eef4ff")
        dialog.transient(self.root)
        dialog.grab_set()
        _center_window(dialog, 900, 560)
        dialog.minsize(780, 460)
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(1, weight=1)

        tk.Label(
            dialog,
            text=f"{kind.title()} rows in {bucket}",
            bg="#eef4ff",
            fg="#0f2f57",
            font=("Segoe UI", 14, "bold"),
            anchor="w",
            padx=16,
            pady=12,
        ).grid(row=0, column=0, sticky="ew")

        list_frame = tk.Frame(dialog, bg="#eef4ff", padx=16, pady=4)
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        listbox = tk.Listbox(
            list_frame,
            selectmode=tk.EXTENDED,
            activestyle="none",
            bg="#ffffff",
            fg="#24364a",
            font=("Consolas", 10),
            relief="flat",
            highlightthickness=1,
        )
        listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        listbox.configure(yscrollcommand=scrollbar.set)

        for index, row in enumerate(rows):
            listbox.insert("end", self._format_age_bucket_row_label(kind, row))
            listbox.selection_set(index)

        selected_indices: list[int] = list(range(len(rows)))

        def apply_selection() -> None:
            nonlocal selected_indices
            selected_indices = [int(index) for index in listbox.curselection()]
            dialog.destroy()

        def cancel_selection() -> None:
            nonlocal selected_indices
            selected_indices = []
            dialog.destroy()

        controls = tk.Frame(dialog, bg="#eef4ff", padx=16, pady=12)
        controls.grid(row=2, column=0, sticky="ew")
        tk.Button(controls, text="Select All", command=lambda: listbox.selection_set(0, "end"), width=12).pack(side="left")
        tk.Button(controls, text="Clear", command=lambda: listbox.selection_clear(0, "end"), width=12).pack(side="left", padx=(8, 0))
        tk.Button(controls, text="Cancel", command=cancel_selection, width=12).pack(side="right")
        tk.Button(controls, text="Use Selected", command=apply_selection, width=14).pack(side="right", padx=(0, 8))
        dialog.bind("<Escape>", lambda _event: cancel_selection())
        dialog.bind("<Return>", lambda _event: apply_selection())
        self.root.wait_window(dialog)
        return [
            dict(rows[index])
            for index in selected_indices
            if 0 <= index < len(rows) and str(rows[index].get(id_key) or "")
        ]

    def _stale_alert_ids(self) -> list[str]:
        triage = cast(dict[str, list[dict[str, Any]]], self._latest_dashboard.get("triage") or {})
        rows = cast(list[dict[str, Any]], triage.get("assigned_stale_alerts") or [])
        assignee = self._selected_workload_assignee()
        return [
            str(item["alert_id"])
            for item in rows
            if item.get("alert_id") and (assignee is None or str(item.get("assignee") or "") == assignee)
        ]

    def _stale_case_ids(self) -> list[str]:
        triage = cast(dict[str, list[dict[str, Any]]], self._latest_dashboard.get("triage") or {})
        rows = cast(list[dict[str, Any]], triage.get("stale_active_cases") or [])
        assignee = self._selected_workload_assignee()
        return [
            str(item["case_id"])
            for item in rows
            if item.get("case_id") and (assignee is None or str(item.get("assignee") or "") == assignee)
        ]

    def _refresh_workload_assignee_options(self, dashboard: dict[str, Any]) -> None:
        assignee_workload = cast(list[dict[str, Any]], dashboard.get("assignee_workload") or [])
        values = ["all"] + [str(item["assignee"]) for item in assignee_workload if item.get("assignee")]
        deduped: list[str] = []
        seen: set[str] = set()
        for value in values:
            key = value.casefold()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(value)
        current = self.workload_assignee_var.get().strip() or "all"
        self.workload_assignee_combo.configure(values=tuple(deduped))
        if current not in deduped:
            self.workload_assignee_var.set("all")

    @staticmethod
    def _record_matches_age_bucket(updated_at: str, bucket: str) -> bool:
        if not updated_at:
            return False
        try:
            timestamp = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        age = datetime.now(timestamp.tzinfo or UTC) - timestamp
        if bucket == "0-4h":
            return age < timedelta(hours=4)
        if bucket == "4-24h":
            return timedelta(hours=4) <= age < timedelta(hours=24)
        if bucket == "24-72h":
            return timedelta(hours=24) <= age < timedelta(hours=72)
        if bucket == "72h+":
            return age >= timedelta(hours=72)
        return True

    @staticmethod
    def _format_age_bucket_records(kind: str, bucket: str, rows: Sequence[dict[str, Any]]) -> str:
        if not rows:
            return f"No {kind}s matched the {bucket} bucket."
        lines = [f"{kind.title()}s in {bucket} ({len(rows)}):", ""]
        for row in rows[:20]:
            lines.append(
                f"- {row.get(f'{kind}_id', row.get('alert_id', row.get('case_id', '-')))}: "
                f"{row.get('severity', '-')} | {row.get('status', '-')} | {row.get('title', '-')}"
            )
        remaining = len(rows) - min(len(rows), 20)
        if remaining > 0:
            lines.append("")
            lines.append(f"...and {remaining} more")
        return "\n".join(lines)

    @staticmethod
    def _format_age_bucket_row_label(kind: str, row: dict[str, Any]) -> str:
        record_id = str((row.get("alert_id") if kind == "alert" else row.get("case_id")) or "-")
        severity = str(row.get("severity") or "-")
        status = str(row.get("status") or "-")
        assignee = str(row.get("assignee") or "unassigned")
        updated_at = str(row.get("updated_at") or "-")
        title = str(row.get("title") or "-")
        return f"{record_id} | {severity} | {status} | {assignee} | {updated_at} | {title}"

    @staticmethod
    def _format_summary_records(kind: str, rows: Sequence[dict[str, Any]], *, limit: int = 30) -> str:
        if not rows:
            return f"No {kind} records are available."
        if kind == "endpoint_timeline":
            lines = [f"{kind.title()} records ({len(rows)}):", ""]
            for row in rows[:limit]:
                lines.append(
                    f"- {row.get('event_id', '-')}: "
                    f"{row.get('event_type', '-')} | "
                    f"{row.get('recorded_at', row.get('created_at', '-'))} | "
                    f"{row.get('title', '-')}"
                )
            remaining = len(rows) - min(len(rows), limit)
            if remaining > 0:
                lines.append("")
                lines.append(f"...and {remaining} more")
            return "\n".join(lines)
        if kind == "endpoint_timeline_cluster":
            lines = [f"{kind.title()} records ({len(rows)}):", ""]
            for row in rows[:limit]:
                lines.append(
                    f"- {row.get('cluster_key', '-')}: "
                    f"{row.get('cluster_by', '-')} | "
                    f"events={row.get('event_count', 0)} | "
                    f"open_cases={row.get('open_case_count', 0)} | "
                    f"{row.get('title', row.get('label', '-'))}"
                )
            remaining = len(rows) - min(len(rows), limit)
            if remaining > 0:
                lines.append("")
                lines.append(f"...and {remaining} more")
            return "\n".join(lines)
        if kind == "hunt_telemetry_cluster":
            lines = [f"{kind.title()} records ({len(rows)}):", ""]
            for row in rows[:limit]:
                lines.append(
                    f"- {row.get('cluster_key', '-')}: "
                    f"{row.get('cluster_by', '-')} | "
                    f"events={row.get('event_count', 0)} | "
                    f"severity={row.get('severity', '-')} | "
                    f"open_cases={row.get('open_case_count', 0)} | "
                    f"{row.get('title', row.get('label', '-'))}"
                )
            remaining = len(rows) - min(len(rows), limit)
            if remaining > 0:
                lines.append("")
                lines.append(f"...and {remaining} more")
            return "\n".join(lines)
        if kind == "packet_session":
            lines = [f"{kind.title()} records ({len(rows)}):", ""]
            for row in rows[:limit]:
                lines.append(
                    f"- {row.get('session_key', '-')}: "
                    f"{row.get('remote_ip_display', row.get('remote_ip', '-'))} | "
                    f"{row.get('last_seen_at', '-')} | "
                    f"packets={row.get('total_packets', row.get('last_packet_count', 0))}"
                )
            remaining = len(rows) - min(len(rows), limit)
            if remaining > 0:
                lines.append("")
                lines.append(f"...and {remaining} more")
            return "\n".join(lines)
        if kind == "remote_node":
            lines = [f"{kind.title()} records ({len(rows)}):", ""]
            for row in rows[:limit]:
                lines.append(
                    f"- {row.get('node_name', '-')}: "
                    f"{row.get('node_role', '-')} | "
                    f"{row.get('status', 'unknown')} | "
                    f"open_cases={row.get('open_case_count', 0)} | "
                    f"{row.get('last_seen_at', '-')}"
                )
            remaining = len(rows) - min(len(rows), limit)
            if remaining > 0:
                lines.append("")
                lines.append(f"...and {remaining} more")
            return "\n".join(lines)
        if kind in {"alert_group", "evidence_group"}:
            count_key = "alert_count" if kind == "alert_group" else "event_count"
            lines = [f"{kind.title()} records ({len(rows)}):", ""]
            for row in rows[:limit]:
                lines.append(
                    f"- {row.get('group_key', '-')}: "
                    f"{count_key}={row.get(count_key, 0)} | "
                    f"severity={row.get('severity', '-')} | "
                    f"open_cases={row.get('open_case_count', 0)} | "
                    f"{row.get('title', '-')}"
                )
            remaining = len(rows) - min(len(rows), limit)
            if remaining > 0:
                lines.append("")
                lines.append(f"...and {remaining} more")
            return "\n".join(lines)
        labels: dict[str, tuple[str, str, str, str]] = {
            "event": ("event_id", "event_type", "severity", "title"),
            "alert": ("alert_id", "status", "severity", "title"),
            "case": ("case_id", "status", "severity", "title"),
            "host": ("key", "severity", "title", "summary"),
            "tracker_block": ("event_id", "event_type", "severity", "title"),
            "packet_session": ("session_key", "remote_ip", "last_seen_at", "total_packets"),
            "network_evidence": ("remote_ip", "severity", "last_seen_at", "title"),
            "detection_rule": ("rule_id", "enabled", "hit_count", "title"),
            "remote_node": ("node_name", "node_role", "status", "title"),
            "evidence_group": ("group_key", "event_count", "severity", "title"),
            "alert_group": ("group_key", "alert_count", "severity", "title"),
        }
        id_key, first_key, second_key, title_key = labels.get(kind, ("id", "type", "severity", "title"))
        lines = [f"{kind.title()} records ({len(rows)}):", ""]
        for row in rows[:limit]:
            lines.append(
                f"- {row.get(id_key, '-')}: "
                f"{row.get(first_key, '-')} | {row.get(second_key, '-')} | {row.get(title_key, '-')}"
            )
        remaining = len(rows) - min(len(rows), limit)
        if remaining > 0:
            lines.append("")
            lines.append(f"...and {remaining} more")
        return "\n".join(lines)

    @staticmethod
    def _format_summary_selection_label(kind: str, row: dict[str, Any]) -> str:
        if kind == "endpoint_timeline":
            return (
                f"{row.get('event_id', '-')} | "
                f"{row.get('event_type', '-')} | "
                f"{row.get('recorded_at', row.get('created_at', '-'))} | "
                f"{row.get('title', '-')}"
            )
        if kind == "endpoint_timeline_cluster":
            return (
                f"{row.get('cluster_key', '-')} | "
                f"{row.get('cluster_by', '-')} | "
                f"events={row.get('event_count', 0)} | "
                f"{row.get('title', row.get('label', '-'))}"
            )
        if kind == "hunt_telemetry_cluster":
            return (
                f"{row.get('cluster_key', '-')} | "
                f"{row.get('cluster_by', '-')} | "
                f"events={row.get('event_count', 0)} | "
                f"{row.get('severity', '-')} | "
                f"{row.get('title', row.get('label', '-'))}"
            )
        if kind == "packet_session":
            return (
                f"{row.get('session_key', '-')} | "
                f"{row.get('remote_ip_display', row.get('remote_ip', '-'))} | "
                f"{row.get('last_seen_at', '-')} | "
                f"{row.get('total_packets', row.get('last_packet_count', 0))}"
            )
        if kind == "remote_node":
            return (
                f"{row.get('node_name', '-')} | "
                f"{row.get('node_role', '-')} | "
                f"{row.get('status', 'unknown')} | "
                f"{row.get('open_case_count', 0)} open"
            )
        labels: dict[str, tuple[str, str, str, str]] = {
            "event": ("event_id", "event_type", "severity", "title"),
            "alert": ("alert_id", "status", "severity", "title"),
            "case": ("case_id", "status", "severity", "title"),
            "host": ("key", "severity", "title", "summary"),
            "tracker_block": ("event_id", "event_type", "severity", "title"),
            "endpoint_timeline": ("event_id", "event_type", "recorded_at", "title"),
            "endpoint_timeline_cluster": ("cluster_key", "cluster_by", "event_count", "title"),
            "hunt_telemetry_cluster": ("cluster_key", "cluster_by", "severity", "title"),
            "packet_session": ("session_key", "remote_ip", "last_seen_at", "total_packets"),
            "network_evidence": ("remote_ip", "severity", "last_seen_at", "title"),
            "detection_rule": ("rule_id", "enabled", "hit_count", "title"),
            "remote_node": ("node_name", "node_role", "status", "title"),
            "evidence_group": ("group_key", "event_count", "severity", "title"),
            "alert_group": ("group_key", "alert_count", "severity", "title"),
        }
        id_key, first_key, second_key, title_key = labels.get(kind, ("id", "type", "severity", "title"))
        return (
            f"{row.get(id_key, '-')} | "
            f"{row.get(first_key, '-')} | "
            f"{row.get(second_key, '-')} | "
            f"{row.get(title_key, '-')}"
        )

    @classmethod
    def _preset_values(cls, preset_name: str) -> dict[str, str]:
        return dict(cls.QUEUE_PRESETS.get((preset_name or "custom").strip().lower(), {}))

    def _selected_preset_name(self) -> str:
        return str(getattr(getattr(self, "queue_preset_var", None), "get", lambda: "tier1-triage")() or "tier1-triage")

    def _alert_rows_for_view(self, dashboard: dict[str, Any]) -> list[Any]:
        preset_name = self._selected_preset_name()
        if preset_name == "needs-attention":
            stale_rows = cast(list[dict[str, Any]], cast(dict[str, Any], dashboard["triage"]).get("stale_open_alerts") or [])
            return [self.manager.get_alert(str(item["alert_id"])) for item in stale_rows if item.get("alert_id")]
        if preset_name == "handoff":
            stale_rows = cast(list[dict[str, Any]], cast(dict[str, Any], dashboard["triage"]).get("assigned_stale_alerts") or [])
            return [self.manager.get_alert(str(item["alert_id"])) for item in stale_rows if item.get("alert_id")]
        if preset_name == "operational":
            return [
                self._annotate_operational_alert(item)
                for item in self.manager.list_alerts()
                if str(item.category or "").casefold() == "operational"
                and self._matches_operational_reason_filter(getattr(item, "correlation_key", None))
            ]
        return list(self.manager.query_alerts(**self._alert_query_kwargs()))

    def _case_rows_for_view(self, dashboard: dict[str, Any]) -> list[Any]:
        preset_name = self._selected_preset_name()
        if preset_name == "needs-attention":
            cases = [item for item in self.manager.list_cases() if item.status is not SocCaseStatus.closed]
            return sorted(cases, key=lambda item: item.updated_at)[:25]
        if preset_name == "handoff":
            stale_cases = cast(list[dict[str, Any]], cast(dict[str, Any], dashboard["triage"]).get("stale_active_cases") or [])
            return [self.manager.get_case(str(item["case_id"])) for item in stale_cases if item.get("case_id")]
        if preset_name == "operational":
            return self._operational_cases()
        return list(self.manager.query_cases(**self._case_query_kwargs()))

    def _operational_cases(self) -> list[Any]:
        operational_alerts = {
            item.alert_id: item
            for item in self.manager.list_alerts()
            if str(item.category or "").casefold() == "operational"
            and self._matches_operational_reason_filter(getattr(item, "correlation_key", None))
        }
        operational_alert_ids = set(operational_alerts)
        if not operational_alert_ids:
            return []
        return [
            self._annotate_operational_case(item, operational_alerts=operational_alerts)
            for item in self.manager.list_cases()
            if operational_alert_ids.intersection(cast(list[str], getattr(item, "linked_alert_ids", []) or []))
        ]

    def _choose_operational_summary_reason(self, focus_target: str) -> str:
        dashboard = cast(dict[str, Any], getattr(self, "_latest_dashboard", None) or {})
        operational_status = cast(dict[str, Any], dashboard.get("operational_status") or {})
        reason_counts = cast(dict[str, int], operational_status.get("reason_counts") or {})
        if not reason_counts:
            return "all"
        ordered_reasons = sorted(reason_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
        summary = (
            f"Operational {focus_target.title()}\n\n"
            f"Choose a reason filter for the operational {focus_target} queue."
        )
        summary_lines = [summary, "", "Current pressure:"]
        summary_lines.extend(f"- {reason}: {count}" for reason, count in ordered_reasons[:8])
        actions: list[tuple[str, str, int]] = [("All", "all", 12)]
        actions.extend((reason.title(), reason, max(14, len(reason) + 2)) for reason, _count in ordered_reasons[:5])
        return self._choose_action_dialog(
            title=f"Operational {focus_target.title()} Filter",
            summary="\n".join(summary_lines),
            actions=actions,
            default_choice="cancel",
            no_tk_choice="all",
            width=520,
            height=320,
            min_width=460,
            min_height=280,
            detail_label="Cancel",
            detail_width=12,
        )

    def _matches_operational_reason_filter(self, route_key: str | None) -> bool:
        reason_filter = str(getattr(self, "operational_reason_filter", "") or "").strip().casefold()
        if not reason_filter:
            return True
        return self._operational_route_reason(route_key).casefold() == reason_filter

    def _set_operational_reason_filter(self, value: str | None) -> None:
        normalized = str(value or "").strip() or None
        self.operational_reason_filter = normalized
        self.saved_operational_reason_filter = normalized
        latest = cast(dict[str, Any], getattr(self, "_latest_dashboard", None) or {})
        if latest:
            view_state = cast(dict[str, Any], latest.get("view_state") or {})
            latest["view_state"] = {
                **view_state,
                "operational_reason_filter": normalized,
            }
        self._persist_dashboard_view_state()

    def _persisted_operational_reason_filter(self) -> str | None:
        saved_filter = getattr(self, "saved_operational_reason_filter", None)
        if saved_filter is not None:
            return saved_filter
        latest = cast(dict[str, Any], getattr(self, "_latest_dashboard", None) or {})
        view_state = cast(dict[str, Any], latest.get("view_state") or {})
        persisted = str(view_state.get("operational_reason_filter") or "").strip() or None
        if persisted is not None:
            return persisted
        try:
            client = self._dashboard_view_state_client()
            payload = client.read()
        except Exception:
            return None
        return str(payload.get("operational_reason_filter") or "").strip() or None

    def _dashboard_view_state_client(self) -> DashboardViewStateClient:
        existing = getattr(self, "dashboard_view_state_client", None)
        if existing is not None:
            return cast(DashboardViewStateClient, existing)
        client = build_dashboard_view_state_client(
            manager=getattr(self, "manager", None),
            path=settings.soc_dashboard_view_state_path,
        )
        self.dashboard_view_state_client = client
        return client

    def _persist_dashboard_view_state(self) -> None:
        payload = {
            "operational_reason_filter": getattr(self, "saved_operational_reason_filter", None),
            "hunt_cluster_mode": getattr(self, "saved_hunt_cluster_mode", None) or "remote_ip",
            "hunt_cluster_value": getattr(self, "saved_hunt_cluster_value", None),
            "hunt_cluster_key": getattr(self, "saved_hunt_cluster_key", None),
            "hunt_cluster_action": getattr(self, "saved_hunt_cluster_action", None) or "events",
        }
        try:
            result = cast(
                dict[str, Any],
                self._dashboard_view_state_client().write(SocDashboardViewStateUpdate(**payload)),
            )
        except Exception:
            return
        latest = cast(dict[str, Any], getattr(self, "_latest_dashboard", None) or {})
        if latest:
            view_state = cast(dict[str, Any], latest.get("view_state") or {})
            latest["view_state"] = {
                **view_state,
                **result,
            }

    @staticmethod
    def _format_operational_summary_label(base_label: str, active_filter: str | None) -> str:
        normalized = str(active_filter or "").strip()
        if not normalized:
            return base_label
        return f"{base_label} [{normalized}]"

    @staticmethod
    def _operational_route_reason(route_key: str | None) -> str:
        route = (route_key or "").strip().casefold()
        if not route:
            return "operational"
        if route.startswith("remote-node:action-failed:"):
            return "action failed"
        if route.startswith("remote-node:action-failure-pattern:"):
            return "repeated failures"
        if route.startswith("remote-node:action-retry-pressure:"):
            return "retry pressure"
        if route.startswith("remote-node:action-stuck:"):
            return "stuck action"
        if route.startswith("remote-node:remote_node_degraded:") or route.startswith("remote-node:remote-node-degraded:"):
            return "node degraded"
        if route.startswith("remote-node:remote_node_stale:") or route.startswith("remote-node:remote-node-stale:"):
            return "node stale"
        if route == "handoff-stale-alerts":
            return "handoff required"
        if route == "stale-active-cases":
            return "case escalation"
        if route.startswith("assignee-pressure:"):
            return "assignee pressure"
        return "operational"

    @classmethod
    def _annotate_operational_alert(cls, alert: Any) -> Any:
        reason = cls._operational_route_reason(getattr(alert, "correlation_key", None))
        title = str(getattr(alert, "title", "") or "")
        prefix = f"[{reason}] "
        if title.startswith(prefix):
            return alert
        return cls._clone_record_with_updates(alert, {"title": f"{prefix}{title}"})

    @classmethod
    def _annotate_operational_case(cls, case: Any, *, operational_alerts: Mapping[str, Any]) -> Any:
        linked_alert_ids = cast(list[str], getattr(case, "linked_alert_ids", []) or [])
        reason = next(
            (
                cls._operational_route_reason(getattr(operational_alerts.get(alert_id), "correlation_key", None))
                for alert_id in linked_alert_ids
                if operational_alerts.get(alert_id) is not None
            ),
            "operational",
        )
        title = str(getattr(case, "title", "") or "")
        prefix = f"[{reason}] "
        if title.startswith(prefix):
            return case
        return cls._clone_record_with_updates(case, {"title": f"{prefix}{title}"})

    @staticmethod
    def _clone_record_with_updates(record: Any, updates: Mapping[str, Any]) -> Any:
        model_copy = getattr(record, "model_copy", None)
        if callable(model_copy):
            return model_copy(update=dict(updates))
        model_dump = getattr(record, "model_dump", None)
        if callable(model_dump):
            payload = dict(model_dump(mode="json"))
        else:
            payload = {
                name: getattr(record, name)
                for name in dir(record)
                if not name.startswith("_") and not callable(getattr(record, name, None))
            }
        payload.update(dict(updates))
        wrapper = SimpleNamespace(**payload)
        wrapper.model_dump = lambda mode="json", _payload=payload: dict(_payload)
        return wrapper

    @staticmethod
    def _parse_severity(value: str) -> SocSeverity | None:
        normalized = value.strip().lower()
        if normalized == "all" or not normalized:
            return None
        return SocSeverity(normalized)

    @staticmethod
    def _parse_case_status(value: str) -> SocCaseStatus | None:
        normalized = value.strip().lower()
        if normalized == "all" or not normalized:
            return None
        return SocCaseStatus(normalized)

    @staticmethod
    def _format_status_line(dashboard: dict[str, Any], *, host_findings_count: int = 0) -> str:
        summary = dashboard["summary"]
        workload = cast(dict[str, Any], dashboard.get("workload") or {})
        assignee_workload = cast(list[dict[str, Any]], dashboard.get("assignee_workload") or [])
        operational_status = cast(dict[str, Any], dashboard.get("operational_status") or {})
        hunt_cluster_status = cast(dict[str, Any], dashboard.get("hunt_cluster_status") or {})
        packet_session_status = cast(dict[str, Any], dashboard.get("packet_session_status") or {})
        network_evidence_status = cast(dict[str, Any], dashboard.get("network_evidence_status") or {})
        platform = cast(dict[str, Any], dashboard.get("platform") or {})
        service_health = cast(dict[str, Any], platform.get("service_health") or {})
        topology = cast(dict[str, Any], platform.get("topology") or {})
        top_event_types = dashboard.get("top_event_types") or {}
        operational_reason_counts = cast(dict[str, int], operational_status.get("reason_counts") or {})
        hunt_cluster_mode_counts = cast(dict[str, int], hunt_cluster_status.get("cluster_mode_counts") or {})
        active_hunt_cluster_mode = str(hunt_cluster_status.get("active_mode") or "remote_ip").strip() or "remote_ip"
        active_hunt_cluster_value = str(hunt_cluster_status.get("active_value") or "").strip()
        active_hunt_cluster_filter = (
            f"{active_hunt_cluster_mode}={active_hunt_cluster_value}" if active_hunt_cluster_value else "none"
        )
        active_operational_filter = str(operational_status.get("active_filter") or "").strip() or "none"
        most_common = ", ".join(f"{name}: {count}" for name, count in list(top_event_types.items())[:3]) or "none"
        operational_mix = ", ".join(
            f"{name}={count}" for name, count in list(operational_reason_counts.items())[:2]
        ) or "none"
        hunt_cluster_mix = ", ".join(
            f"{name}={count}" for name, count in (
                ("remote_ip", int(hunt_cluster_mode_counts.get("remote_ip", 0))),
                ("device_id", int(hunt_cluster_mode_counts.get("device_id", 0))),
                ("process_guid", int(hunt_cluster_mode_counts.get("process_guid", 0))),
            )
        ) or "none"
        loaded_assignees = sum(
            1
            for item in assignee_workload
            if int(item.get("open_alerts", 0)) > 0 or int(item.get("active_cases", 0)) > 0
        )
        return (
            f"Open alerts: {summary['open_alerts']} | "
            f"Open cases: {summary['open_cases']} | "
            f"Host findings: {host_findings_count} | "
            f"Hunt clusters: {hunt_cluster_status.get('count', 0)} | "
            f"Hunt cluster mix: {hunt_cluster_mix} | "
            f"Hunt filter: {active_hunt_cluster_filter} | "
            f"Operational alerts: {operational_status.get('alert_count', 0)} | "
            f"Operational cases: {operational_status.get('case_count', 0)} | "
            f"Operational mix: {operational_mix} | "
            f"Operational filter: {active_operational_filter} | "
            f"Platform services: {service_health.get('healthy_services', 0)}/{service_health.get('enabled_services', 0)} healthy | "
            f"Nodes: {topology.get('healthy_nodes', 0)}/{topology.get('total_nodes', 0)} healthy | "
            f"Node action pressure: {topology.get('repeated_failure_nodes', 0)} repeat-failure, "
            f"{topology.get('retry_pressure_nodes', 0)} retry, {topology.get('stuck_action_nodes', 0)} stuck | "
            f"Packet sessions: {packet_session_status.get('session_count', 0)} | "
            f"Network evidence: {network_evidence_status.get('observation_count', 0)} | "
            f"Stale assigned alerts: {workload.get('stale_assigned_alerts', 0)} | "
            f"Stale active cases: {workload.get('stale_active_cases', 0)} | "
            f"Loaded assignees: {loaded_assignees} | "
            f"Top event types: {most_common}"
        )

    @staticmethod
    def _format_workload_detail(dashboard: dict[str, Any]) -> str:
        assignee_workload = cast(list[dict[str, Any]], dashboard.get("assignee_workload") or [])
        aging = cast(dict[str, dict[str, int]], dashboard.get("aging_buckets") or {})
        tracker_status = cast(dict[str, Any], dashboard.get("tracker_feed_status") or {})
        operational_status = cast(dict[str, Any], dashboard.get("operational_status") or {})
        hunt_cluster_status = cast(dict[str, Any], dashboard.get("hunt_cluster_status") or {})
        packet_session_status = cast(dict[str, Any], dashboard.get("packet_session_status") or {})
        network_evidence_status = cast(dict[str, Any], dashboard.get("network_evidence_status") or {})
        platform = cast(dict[str, Any], dashboard.get("platform") or {})
        service_health = cast(dict[str, Any], platform.get("service_health") or {})
        topology = cast(dict[str, Any], platform.get("topology") or {})
        operational_reason_counts = cast(dict[str, int], operational_status.get("reason_counts") or {})
        hunt_cluster_mode_counts = cast(dict[str, int], hunt_cluster_status.get("cluster_mode_counts") or {})
        active_hunt_cluster_mode = str(hunt_cluster_status.get("active_mode") or "remote_ip").strip() or "remote_ip"
        active_hunt_cluster_value = str(hunt_cluster_status.get("active_value") or "").strip()
        active_hunt_cluster_filter = (
            f"{active_hunt_cluster_mode}={active_hunt_cluster_value}" if active_hunt_cluster_value else "none"
        )
        active_operational_filter = str(operational_status.get("active_filter") or "").strip() or "none"
        alert_aging = aging.get("alerts") or {}
        case_aging = aging.get("cases") or {}
        lines = ["Assignee Summary:"]
        if assignee_workload:
            for item in assignee_workload[:8]:
                lines.append(
                    "- "
                    f"{item.get('assignee', 'unassigned')}: "
                    f"alerts={item.get('open_alerts', 0)}, "
                    f"cases={item.get('active_cases', 0)}, "
                    f"stale alerts={item.get('stale_alerts', 0)}, "
                    f"stale cases={item.get('stale_cases', 0)}"
                )
        else:
            lines.append("- no active assignee workload")
        lines.extend(
            [
                "",
                "Alert Aging:",
                f"- 0-4h: {alert_aging.get('0-4h', 0)}",
                f"- 4-24h: {alert_aging.get('4-24h', 0)}",
                f"- 24-72h: {alert_aging.get('24-72h', 0)}",
                f"- 72h+: {alert_aging.get('72h+', 0)}",
                "",
                "Case Aging:",
                f"- 0-4h: {case_aging.get('0-4h', 0)}",
                f"- 4-24h: {case_aging.get('4-24h', 0)}",
                f"- 24-72h: {case_aging.get('24-72h', 0)}",
                f"- 72h+: {case_aging.get('72h+', 0)}",
                "",
                "Tracker Feed Status:",
                f"- domains: {tracker_status.get('domain_count', 0)}",
                f"- stale: {tracker_status.get('is_stale', False)}",
                f"- last result: {tracker_status.get('last_refresh_result') or 'unknown'}",
                f"- last error: {tracker_status.get('last_error') or 'none'}",
                "",
                "Operational Load:",
                f"- alerts: {operational_status.get('alert_count', 0)}",
                f"- cases: {operational_status.get('case_count', 0)}",
                f"- active filter: {active_operational_filter}",
            ]
        )
        if operational_reason_counts:
            for reason, count in operational_reason_counts.items():
                lines.append(f"- {reason}: {count}")
        else:
            lines.append("- breakdown: none")
        lines.extend(
            [
                "",
                "Hunt Clusters:",
                f"- count: {hunt_cluster_status.get('count', 0)}",
                f"- active filter: {active_hunt_cluster_filter}",
                f"- remote_ip: {hunt_cluster_mode_counts.get('remote_ip', 0)}",
                f"- device_id: {hunt_cluster_mode_counts.get('device_id', 0)}",
                f"- process_guid: {hunt_cluster_mode_counts.get('process_guid', 0)}",
            ]
        )
        recent_hunt_clusters = cast(list[dict[str, Any]], hunt_cluster_status.get("recent_clusters") or [])
        if recent_hunt_clusters:
            lines.extend(
                (
                    f"- {item.get('label', item.get('cluster_key', '-'))}: "
                    f"severity={item.get('severity', '-')}, "
                    f"events={item.get('event_count', 0)}, "
                    f"open_cases={item.get('open_case_count', 0)}"
                )
                for item in recent_hunt_clusters[:5]
            )
        else:
            lines.append("- recent: none")
        lines.extend(
            [
                "",
                "Packet Sessions:",
                f"- session count: {packet_session_status.get('session_count', 0)}",
            ]
        )
        recent_sessions = cast(list[dict[str, Any]], packet_session_status.get("recent_sessions") or [])
        if recent_sessions:
            lines.extend(
                f"- {item.get('remote_ip_display', item.get('remote_ip', '-'))}: packets={item.get('total_packets', item.get('last_packet_count', 0))}, last seen={item.get('last_seen_at', '-')}"
                for item in recent_sessions[:5]
            )
        else:
            lines.append("- none")
        lines.extend(
            [
                "",
                "Platform Services:",
                f"- node: {platform.get('node_name', '-')}",
                f"- role: {platform.get('node_role', '-')}",
                f"- deployment: {platform.get('deployment_mode', '-')}",
                f"- overall status: {service_health.get('overall_status', 'unknown')}",
                f"- healthy/enabled: {service_health.get('healthy_services', 0)}/{service_health.get('enabled_services', 0)}",
                (
                    f"- nodes: {topology.get('total_nodes', 0)} total, {topology.get('remote_node_count', 0)} remote, "
                    f"{topology.get('healthy_nodes', 0)} healthy, {topology.get('degraded_nodes', 0)} degraded, "
                    f"{topology.get('stale_nodes', 0)} stale, {topology.get('failed_action_nodes', 0)} action-failed, "
                    f"{topology.get('repeated_failure_nodes', 0)} repeat-failure, "
                    f"{topology.get('retry_pressure_nodes', 0)} retry-pressure, "
                    f"{topology.get('stuck_action_nodes', 0)} stuck"
                ),
            ]
        )
        service_rows = cast(dict[str, dict[str, Any]], service_health.get("services") or {})
        if service_rows:
            for name, item in list(service_rows.items())[:8]:
                lines.append(
                    f"- {name}: status={item.get('status', 'unknown')}, enabled={item.get('enabled', False)}"
                )
        else:
            lines.append("- no service health available")
        remote_nodes = cast(list[dict[str, Any]], topology.get("remote_nodes") or [])
        if remote_nodes:
            for item in remote_nodes[:5]:
                lines.append(
                    f"- {item.get('node_name', '-')}: role={item.get('node_role', '-')}, status={item.get('status', 'unknown')}, "
                    f"action_failures={', '.join(cast(list[str], item.get('action_failures') or [])) or '-'}, "
                    f"repeat_failures={bool(item.get('repeated_failure_active'))}, "
                    f"retry_pressure={bool(item.get('retry_pressure_active'))}, "
                    f"stuck_actions={bool(item.get('stuck_actions_active'))}"
                )
        lines.extend(
            [
                "",
                "Network Evidence:",
                f"- observation count: {network_evidence_status.get('observation_count', 0)}",
            ]
        )
        recent_evidence = cast(list[dict[str, Any]], network_evidence_status.get("combined_evidence") or [])
        if recent_evidence:
            lines.extend(
                f"- {item.get('remote_ip', '-')}: severity={item.get('severity', '-')}, last seen={item.get('last_seen_at', '-')}"
                for item in recent_evidence[:5]
            )
        else:
            lines.append("- none")
        return "\n".join(lines)

    @staticmethod
    def _format_bullet_list(items: Sequence[Any]) -> str:
        return "\n".join(f"- {item}" for item in items) if items else "- none"

    @staticmethod
    def _format_investigation_counts(payload: dict[str, Any]) -> tuple[str, str, str]:
        return (
            f"Related Alerts: {len(cast(list[str], payload.get('related_alert_ids') or []))}",
            f"Related Cases: {len(cast(list[str], payload.get('related_case_ids') or []))}",
            f"Open Cases: {int(payload.get('open_case_count') or 0)}",
        )

    @staticmethod
    def _format_endpoint_samples(samples: Sequence[dict[str, Any]], *, include_protocol: bool = False) -> str:
        if not samples:
            return "- none"
        lines: list[str] = []
        for item in samples[:10]:
            prefix = f"{item.get('protocol', '-')} " if include_protocol else ""
            lines.append(
                f"- {prefix}{item.get('remote_ip', '-')}:{item.get('remote_port', '-')} -> "
                f"{item.get('local_ip', '-')}:{item.get('local_port', '-')}"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_packet_session_detail(session_payload: dict[str, Any]) -> str:
        sample_endpoints = cast(list[dict[str, Any]], session_payload.get("sample_packet_endpoints") or [])
        sample_lines = SocDashboard._format_endpoint_samples(sample_endpoints)
        related_alerts, related_cases, open_cases = SocDashboard._format_investigation_counts(session_payload)
        return (
            f"Packet Session: {session_payload.get('session_key', '-')}\n"
            f"Remote IP: {session_payload.get('remote_ip', '-')}\n"
            f"Protocols: {session_payload.get('protocols', [])}\n"
            f"Local IPs: {session_payload.get('local_ips', [])}\n"
            f"Local Ports: {session_payload.get('local_ports', [])}\n"
            f"Remote Ports: {session_payload.get('remote_ports', [])}\n"
            f"Sensitive Ports: {session_payload.get('sensitive_ports', [])}\n"
            f"First Seen: {session_payload.get('first_seen_at', '-')}\n"
            f"Last Seen: {session_payload.get('last_seen_at', '-')}\n"
            f"{related_alerts}\n"
            f"{related_cases}\n"
            f"{open_cases}\n"
            f"Sightings: {session_payload.get('sightings', 0)}\n"
            f"Total Packets: {session_payload.get('total_packets', 0)}\n"
            f"Max Packet Count: {session_payload.get('max_packet_count', 0)}\n"
            f"Last Packet Count: {session_payload.get('last_packet_count', 0)}\n\n"
            f"Sample Endpoints:\n{sample_lines}"
        )

    @staticmethod
    def _format_network_evidence_detail(evidence_payload: dict[str, Any]) -> str:
        observation = cast(dict[str, Any], evidence_payload.get("observation") or {})
        packet_session = cast(dict[str, Any], evidence_payload.get("packet_session") or {})
        sample_connections = cast(list[dict[str, Any]], observation.get("sample_connections") or [])
        sample_sessions = cast(list[dict[str, Any]], packet_session.get("sample_packet_endpoints") or [])
        connection_lines = SocDashboard._format_endpoint_samples(sample_connections)
        session_lines = SocDashboard._format_endpoint_samples(sample_sessions, include_protocol=True)
        related_alerts, related_cases, open_cases = SocDashboard._format_investigation_counts(evidence_payload)
        return (
            f"Network Evidence: {evidence_payload.get('remote_ip', '-')}\n"
            f"Severity: {evidence_payload.get('severity', '-')}\n"
            f"Last Seen: {evidence_payload.get('last_seen_at', '-')}\n"
            f"{related_alerts}\n"
            f"{related_cases}\n"
            f"{open_cases}\n"
            f"Observation Sightings: {observation.get('sightings', 0)}\n"
            f"Observation Hits: {observation.get('total_hits', 0)}\n"
            f"Observation Ports: {', '.join(str(item) for item in cast(list[int], observation.get('local_ports') or [])) or '-'}\n"
            f"Session Packets: {packet_session.get('total_packets', packet_session.get('last_packet_count', 0))}\n"
            f"Session Protocols: {', '.join(str(item) for item in cast(list[str], packet_session.get('protocols') or [])) or '-'}\n\n"
            f"Sample Connections:\n{connection_lines}\n\n"
            f"Sample Session Endpoints:\n{session_lines}"
        )

    def _refresh_alert_detail(self) -> None:
        alert_id = self._selected_tree_item_id(self.alert_tree)
        if alert_id is None:
            self._set_alert_detail_text("Select an alert to view triage details and analyst actions.")
            return
        alert_payload = self.alert_rows_by_id.get(alert_id)
        if alert_payload is None:
            self._set_alert_detail_text("Selected alert is no longer available in the current filtered view.")
            return
        self._set_alert_detail_text(self._format_alert_detail(alert_payload))

    def _resolve_source_events(self, alert_payload: dict[str, Any]) -> list[dict[str, Any]]:
        source_event_ids = cast(list[str], alert_payload.get("source_event_ids") or [])
        return [
            event
            for event_id in source_event_ids
            for event in [self.event_rows_by_id.get(event_id)]
            if event is not None
        ]

    def _resolve_linked_alerts(self, case_payload: dict[str, Any]) -> list[dict[str, Any]]:
        linked_alert_ids = cast(list[str], case_payload.get("linked_alert_ids") or [])
        return [
            alert
            for alert_id in linked_alert_ids
            for alert in [self.all_alert_rows_by_id.get(alert_id)]
            if alert is not None
        ]

    def _resolve_case_source_events(self, case_payload: dict[str, Any]) -> list[dict[str, Any]]:
        source_event_ids = cast(list[str], case_payload.get("source_event_ids") or [])
        return [
            event
            for event_id in source_event_ids
            for event in [self.event_rows_by_id.get(event_id)]
            if event is not None
        ]

    def _resolve_host_events(self, finding_payload: dict[str, Any]) -> list[dict[str, Any]]:
        finding_key = str(finding_payload.get("key") or "")
        if not finding_key:
            return []
        related_events: list[dict[str, Any]] = []
        for event in self.event_rows_by_id.values():
            raw_details = event.get("details")
            event_details = cast(dict[str, Any], raw_details) if isinstance(raw_details, dict) else {}
            if str(event_details.get("key") or "") == finding_key:
                related_events.append(event)
        return related_events

    def _refresh_case_detail(self) -> None:
        case_id = self._selected_tree_item_id(self.case_tree)
        if case_id is None:
            self._set_case_detail_text("Select a case to view notes and observables.")
            return
        case_payload = self.case_rows_by_id.get(case_id)
        if case_payload is None:
            self._set_case_detail_text("Selected case is no longer available in the current filtered view.")
            return
        self._set_case_detail_text(self._format_case_detail(case_payload))

    def _set_alert_detail_text(self, text: str) -> None:
        self.alert_detail_text.configure(state="normal")
        self.alert_detail_text.delete("1.0", "end")
        self.alert_detail_text.insert("1.0", text)
        self.alert_detail_text.configure(state="disabled")

    def _set_case_detail_text(self, text: str) -> None:
        self.case_detail_text.configure(state="normal")
        self.case_detail_text.delete("1.0", "end")
        self.case_detail_text.insert("1.0", text)
        self.case_detail_text.configure(state="disabled")

    def _refresh_host_detail(self) -> None:
        finding_key = self._selected_tree_item_id(self.host_tree)
        if finding_key is None:
            self._set_host_detail_text("Select a host finding to view the current posture issue and snapshot context.")
            return
        finding_payload = self.host_rows_by_key.get(finding_key)
        if finding_payload is None:
            self._set_host_detail_text("Selected host finding is no longer available.")
            return
        self._set_host_detail_text(self._format_host_detail(finding_payload))

    def _set_host_detail_text(self, text: str) -> None:
        self.host_detail_text.configure(state="normal")
        self.host_detail_text.delete("1.0", "end")
        self.host_detail_text.insert("1.0", text)
        self.host_detail_text.configure(state="disabled")

    def _set_ops_detail_text(self, text: str) -> None:
        self.ops_detail_text.configure(state="normal")
        self.ops_detail_text.delete("1.0", "end")
        self.ops_detail_text.insert("1.0", text)
        self.ops_detail_text.configure(state="disabled")

    def _copy_text_to_clipboard(self, text: str, *, title: str, empty_message: str) -> None:
        if not text.strip():
            if messagebox is not None:
                messagebox.showwarning(title, empty_message)
            return
        if tk is None or not hasattr(self, "root"):
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update_idletasks()
        if messagebox is not None:
            messagebox.showinfo(title, "Copied to clipboard.")

    def _write_dashboard_export(self, *, prefix: str, content: str) -> Path:
        export_dir = Path(settings.report_output_dir)
        export_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        target = export_dir / f"{prefix}-{timestamp}.txt"
        target.write_text(content, encoding="utf-8")
        return target

    def _selected_record_detail(
        self,
        *,
        tree: Any,
        rows_by_id: dict[str, dict[str, Any]],
        formatter: Callable[[dict[str, Any]], str],
    ) -> tuple[str | None, str]:
        record_id = self._selected_tree_item_id(tree)
        if record_id is None:
            return None, ""
        payload = rows_by_id.get(record_id)
        if payload is None:
            return record_id, ""
        return record_id, formatter(payload)

    def _require_selected_record(
        self,
        *,
        tree: Any,
        rows_by_id: dict[str, dict[str, Any]],
        missing_selection_title: str,
        missing_selection_message: str,
        missing_record_title: str,
        missing_record_message: str,
    ) -> tuple[str, dict[str, Any]] | None:
        record_id = self._selected_tree_item_id(tree)
        if record_id is None:
            if messagebox is not None:
                messagebox.showwarning(missing_selection_title, missing_selection_message)
            return None
        payload = rows_by_id.get(record_id)
        if payload is None:
            if messagebox is not None:
                messagebox.showwarning(missing_record_title, missing_record_message)
            return None
        return record_id, payload

    def _open_linked_case_for_alert(
        self,
        *,
        alert_payload: dict[str, Any],
        dialog_title: str,
        missing_link_message: str,
        missing_case_message: str,
    ) -> bool:
        linked_case_id = str(alert_payload.get("linked_case_id") or "")
        if not linked_case_id:
            if messagebox is not None:
                messagebox.showinfo(dialog_title, missing_link_message)
            return False
        linked_case = self.case_rows_by_id.get(linked_case_id)
        if linked_case is None:
            if messagebox is not None:
                messagebox.showwarning(dialog_title, missing_case_message)
            return False
        self._pivot_from_case(linked_case)
        return True

    def _require_selected_operational_alert(self) -> tuple[str, dict[str, Any]] | None:
        selected = self._require_selected_record(
            tree=self.alert_tree,
            rows_by_id=self.alert_rows_by_id,
            missing_selection_title="Operational Alert",
            missing_selection_message="Select an operational alert before using this action.",
            missing_record_title="Operational Alert",
            missing_record_message="The selected alert is no longer available in the current view.",
        )
        if selected is None:
            return None
        alert_id, alert_payload = selected
        if str(alert_payload.get("category") or "").casefold() != "operational":
            if messagebox is not None:
                messagebox.showwarning(
                    "Operational Alert",
                    "The selected alert is not an operational alert.",
                )
            return None
        return alert_id, alert_payload

    def _require_selected_operational_case(self) -> tuple[str, dict[str, Any]] | None:
        selected = self._require_selected_record(
            tree=self.case_tree,
            rows_by_id=self.case_rows_by_id,
            missing_selection_title="Operational Case",
            missing_selection_message="Select an operational case before using this action.",
            missing_record_title="Operational Case",
            missing_record_message="The selected case is no longer available in the current view.",
        )
        if selected is None:
            return None
        case_id, case_payload = selected
        if not self._operational_alert_ids_for_case(case_payload):
            if messagebox is not None:
                messagebox.showwarning(
                    "Operational Case",
                    "The selected case is not an operational case.",
                )
            return None
        return case_id, case_payload

    def _operational_alert_ids_for_case(self, case_payload: dict[str, Any]) -> list[str]:
        return [
            str(alert_id)
            for alert_id in cast(list[Any], case_payload.get("linked_alert_ids") or [])
            if str(alert_id) and str(cast(dict[str, Any], self.all_alert_rows_by_id.get(str(alert_id)) or {}).get("category") or "").casefold() == "operational"
        ]

    def _copy_selected_detail(
        self,
        *,
        tree: Any,
        rows_by_id: dict[str, dict[str, Any]],
        formatter: Callable[[dict[str, Any]], str],
        title: str,
        missing_selection_message: str,
        missing_record_message: str,
    ) -> None:
        record_id, detail = self._selected_record_detail(tree=tree, rows_by_id=rows_by_id, formatter=formatter)
        self._copy_text_to_clipboard(
            detail,
            title=title,
            empty_message=missing_selection_message if record_id is None else missing_record_message,
        )

    def _save_selected_detail(
        self,
        *,
        tree: Any,
        rows_by_id: dict[str, dict[str, Any]],
        formatter: Callable[[dict[str, Any]], str],
        dialog_title: str,
        missing_selection_message: str,
        missing_record_message: str,
        prefix_template: str,
        success_message_template: str,
    ) -> None:
        record_id, detail = self._selected_record_detail(tree=tree, rows_by_id=rows_by_id, formatter=formatter)
        if record_id is None:
            if messagebox is not None:
                messagebox.showwarning(dialog_title, missing_selection_message)
            return
        if not detail:
            if messagebox is not None:
                messagebox.showwarning(dialog_title, missing_record_message)
            return
        target = self._write_dashboard_export(prefix=prefix_template.format(record_id=record_id), content=detail)
        if messagebox is not None:
            messagebox.showinfo(dialog_title, success_message_template.format(target=target))

    def _apply_selected_record_update(
        self,
        *,
        tree: Any,
        rows_by_id: dict[str, dict[str, Any]],
        missing_selection_title: str,
        missing_selection_message: str,
        missing_record_title: str,
        missing_record_message: str,
        update: Callable[[str, dict[str, Any]], Any],
        refresh_detail: Callable[[], None],
        success_title: str | None = None,
        success_message: str | Callable[[str], str] | None = None,
    ) -> None:
        selected = self._require_selected_record(
            tree=tree,
            rows_by_id=rows_by_id,
            missing_selection_title=missing_selection_title,
            missing_selection_message=missing_selection_message,
            missing_record_title=missing_record_title,
            missing_record_message=missing_record_message,
        )
        if selected is None:
            return
        record_id, payload = selected
        update(record_id, payload)
        if success_title is not None and success_message is not None and messagebox is not None:
            body = success_message(record_id) if callable(success_message) else success_message
            messagebox.showinfo(success_title, body)
        self.refresh()
        tree.selection_set(record_id)
        refresh_detail()

    def _prompt_selected_record_update(
        self,
        *,
        tree: Any,
        rows_by_id: dict[str, dict[str, Any]],
        missing_selection_title: str,
        missing_selection_message: str,
        missing_record_title: str,
        missing_record_message: str,
        prompt_title: str,
        prompt_message: str,
        apply_update: Callable[[str, str, dict[str, Any]], Any],
        refresh_detail: Callable[[], None],
    ) -> None:
        selected = self._require_selected_record(
            tree=tree,
            rows_by_id=rows_by_id,
            missing_selection_title=missing_selection_title,
            missing_selection_message=missing_selection_message,
            missing_record_title=missing_record_title,
            missing_record_message=missing_record_message,
        )
        if selected is None or simpledialog is None:
            return
        record_id, payload = selected
        value = simpledialog.askstring(prompt_title, prompt_message, parent=self.root)
        if value is None or not value.strip():
            return
        apply_update(record_id, value.strip(), payload)
        self.refresh()
        tree.selection_set(record_id)
        refresh_detail()

    def _apply_bulk_record_updates(
        self,
        *,
        record_ids: Sequence[str],
        empty_title: str,
        empty_message: str,
        apply_update: Callable[[str], Any],
        success_title: str,
        success_message: Callable[[int], str],
    ) -> int:
        valid_ids = [record_id for record_id in record_ids if record_id]
        if not valid_ids:
            if messagebox is not None:
                messagebox.showinfo(empty_title, empty_message)
            return 0
        for record_id in valid_ids:
            apply_update(record_id)
        if messagebox is not None:
            messagebox.showinfo(success_title, success_message(len(valid_ids)))
        self.refresh()
        return len(valid_ids)

    def _prompt_bulk_assignee_update(
        self,
        *,
        record_ids: Sequence[str],
        empty_title: str,
        empty_message: str,
        prompt_title: str,
        prompt_message: str,
        apply_update: Callable[[str, str], Any],
        success_title: str,
        success_message: Callable[[int], str],
    ) -> int:
        valid_ids = [record_id for record_id in record_ids if record_id]
        if not valid_ids:
            if messagebox is not None:
                messagebox.showinfo(empty_title, empty_message)
            return 0
        if simpledialog is None:
            return 0
        assignee = simpledialog.askstring(prompt_title, prompt_message, parent=self.root)
        if assignee is None or not assignee.strip():
            return 0
        assignee_value = assignee.strip()
        for record_id in valid_ids:
            apply_update(record_id, assignee_value)
        if messagebox is not None:
            messagebox.showinfo(success_title, success_message(len(valid_ids)))
        self.refresh()
        return len(valid_ids)

    def _promote_alert_rows_to_selected_case(
        self,
        *,
        rows: Sequence[dict[str, Any]],
        missing_case_title: str,
        missing_case_message: str,
        success_title: str,
        success_message: Callable[[int, str], str],
    ) -> int:
        case_id = self._selected_tree_item_id(self.case_tree)
        if case_id is None:
            if messagebox is not None:
                messagebox.showwarning(missing_case_title, missing_case_message)
            return 0
        actor = self._current_analyst_identity()
        promoted = 0
        for row in rows:
            alert_id = str(row.get("alert_id") or "")
            if not alert_id:
                continue
            alert = self.manager.get_alert(alert_id)
            self.manager.promote_alert_to_case(
                alert_id,
                payload=self._build_promote_payload(alert, acted_by=actor, existing_case_id=case_id),
            )
            promoted += 1
        if messagebox is not None:
            messagebox.showinfo(success_title, success_message(promoted, case_id))
        self.refresh()
        self.case_tree.selection_set(case_id)
        self._refresh_case_detail()
        return promoted

    def copy_selected_alert_detail(self) -> None:
        self._copy_selected_detail(
            tree=self.alert_tree,
            rows_by_id=self.alert_rows_by_id,
            formatter=self._format_alert_detail,
            title="Copy Alert Detail",
            missing_selection_message="Select an alert before copying its detail.",
            missing_record_message="The selected alert is no longer available.",
        )

    def save_selected_alert_detail(self) -> None:
        self._save_selected_detail(
            tree=self.alert_tree,
            rows_by_id=self.alert_rows_by_id,
            formatter=self._format_alert_detail,
            dialog_title="Save Alert Detail",
            missing_selection_message="Select an alert before saving its detail.",
            missing_record_message="The selected alert is no longer available.",
            prefix_template="alert-{record_id}",
            success_message_template="Saved alert detail to {target}.",
        )

    def copy_selected_case_detail(self) -> None:
        self._copy_selected_detail(
            tree=self.case_tree,
            rows_by_id=self.case_rows_by_id,
            formatter=self._format_case_detail,
            title="Copy Case Detail",
            missing_selection_message="Select a case before copying its detail.",
            missing_record_message="The selected case is no longer available.",
        )

    def save_selected_case_detail(self) -> None:
        self._save_selected_detail(
            tree=self.case_tree,
            rows_by_id=self.case_rows_by_id,
            formatter=self._format_case_detail,
            dialog_title="Save Case Detail",
            missing_selection_message="Select a case before saving its detail.",
            missing_record_message="The selected case is no longer available.",
            prefix_template="case-{record_id}",
            success_message_template="Saved case detail to {target}.",
        )

    def copy_selected_host_detail(self) -> None:
        self._copy_selected_detail(
            tree=self.host_tree,
            rows_by_id=self.host_rows_by_key,
            formatter=self._format_host_detail,
            title="Copy Host Detail",
            missing_selection_message="Select a host finding before copying its detail.",
            missing_record_message="The selected host finding is no longer available.",
        )

    def save_selected_host_detail(self) -> None:
        self._save_selected_detail(
            tree=self.host_tree,
            rows_by_id=self.host_rows_by_key,
            formatter=self._format_host_detail,
            dialog_title="Save Host Detail",
            missing_selection_message="Select a host finding before saving its detail.",
            missing_record_message="The selected host finding is no longer available.",
            prefix_template="host-{record_id}",
            success_message_template="Saved host detail to {target}.",
        )

    def open_linked_case_from_alert_detail(self) -> None:
        selected = self._require_selected_record(
            tree=self.alert_tree,
            rows_by_id=self.alert_rows_by_id,
            missing_selection_title="Open Linked Case",
            missing_selection_message="Select an alert before opening its linked case.",
            missing_record_title="Open Linked Case",
            missing_record_message="The selected alert is no longer available.",
        )
        if selected is None:
            return
        _alert_id, alert_payload = selected
        self._open_linked_case_for_alert(
            alert_payload=alert_payload,
            dialog_title="Open Linked Case",
            missing_link_message="The selected alert is not linked to a case.",
            missing_case_message="The linked case is not available in the current view.",
        )

    def export_current_dashboard_view(self) -> None:
        dashboard = getattr(self, "_latest_dashboard", {}) or {}
        alert_rows = [item.model_dump(mode="json") for item in self._alert_rows_for_view(dashboard)] if dashboard else []
        case_rows = [item.model_dump(mode="json") for item in self._case_rows_for_view(dashboard)] if dashboard else []
        preset = self._selected_preset_name()
        content = "\n\n".join(
            [
                f"Security Gateway Dashboard Export\nPreset: {preset}\nGenerated: {datetime.now().isoformat()}",
                self._format_view_state_summary(dashboard) if dashboard else "No dashboard view state loaded.",
                self._format_status_line(dashboard) if dashboard else "No dashboard state loaded.",
                self._format_workload_detail(dashboard) if dashboard else "No workload data loaded.",
                self._format_summary_records("alert", alert_rows, limit=50),
                self._format_summary_records("case", case_rows, limit=50),
                self._format_summary_records("event", cast(list[dict[str, Any]], cast(dict[str, Any], dashboard.get('summary') or {}).get('recent_events') or []), limit=25),
                self._format_summary_records("alert", cast(list[dict[str, Any]], cast(dict[str, Any], dashboard.get('triage') or {}).get('recent_correlations') or []), limit=25),
            ]
        )
        target = self._write_dashboard_export(prefix=f"dashboard-{preset}", content=content)
        if messagebox is not None:
            messagebox.showinfo("Export Current View", f"Saved dashboard export to {target}.")

    @staticmethod
    def _format_view_state_summary(dashboard: dict[str, Any]) -> str:
        view_state = cast(dict[str, Any], dashboard.get("view_state") or {})
        saved_operational_filter = str(view_state.get("operational_reason_filter") or "").strip() or "none"
        saved_hunt_mode = SocDashboard._normalize_hunt_cluster_mode(cast(str | None, view_state.get("hunt_cluster_mode")))
        saved_hunt_value = str(view_state.get("hunt_cluster_value") or "").strip() or "none"
        saved_hunt_key = str(view_state.get("hunt_cluster_key") or "").strip() or "none"
        saved_hunt_action = SocDashboard._normalize_hunt_cluster_action(cast(str | None, view_state.get("hunt_cluster_action")))
        return (
            "View State:\n"
            f"- saved operational filter: {saved_operational_filter}\n"
            f"- saved hunt filter: {saved_hunt_mode}={saved_hunt_value}\n"
            f"- saved hunt cluster: {saved_hunt_key}\n"
            f"- saved hunt action: {saved_hunt_action}"
        )

    @staticmethod
    def _format_correlation_detail(correlation_payload: dict[str, Any]) -> str:
        source_event_ids = correlation_payload.get("source_event_ids") or []
        return (
            f"Correlation Alert: {correlation_payload.get('alert_id', '-')}\n"
            f"Title: {correlation_payload.get('title', '-')}\n"
            f"Status: {correlation_payload.get('status', '-')}\n"
            f"Severity: {correlation_payload.get('severity', '-')}\n"
            f"Category: {correlation_payload.get('category', '-')}\n"
            f"Correlation Rule: {correlation_payload.get('correlation_rule') or '-'}\n"
            f"Linked Case: {correlation_payload.get('linked_case_id') or '-'}\n"
            f"Assignee: {correlation_payload.get('assignee') or '-'}\n"
            f"Source Events: {len(source_event_ids)}\n\n"
            f"Summary:\n{correlation_payload.get('summary', '-')}"
        )

    @staticmethod
    def _format_recent_event_detail(event_payload: dict[str, Any]) -> str:
        raw_details = event_payload.get("details")
        event_details = cast(dict[str, Any], raw_details) if isinstance(raw_details, dict) else {}
        evidence_block = SocDashboard._format_monitor_evidence_block(event_details)
        parts = [
            f"Event: {event_payload.get('event_id', '-')}",
            f"Type: {event_payload.get('event_type', '-')}",
            f"Severity: {event_payload.get('severity', '-')}",
            f"Created: {event_payload.get('created_at', '-')}",
            f"Title: {event_payload.get('title', '-')}",
            "",
            f"Summary:\n{event_payload.get('summary', '-')}",
        ]
        if evidence_block:
            parts.extend(["", evidence_block])
        return "\n".join(parts)

    @staticmethod
    def _format_alert_detail(alert_payload: dict[str, Any]) -> str:
        note_lines = SocDashboard._format_bullet_list(cast(list[Any], alert_payload.get("notes") or []))
        source_event_ids = alert_payload.get("source_event_ids") or []
        return (
            f"Alert: {alert_payload.get('alert_id', '-')}\n"
            f"Title: {alert_payload.get('title', '-')}\n"
            f"Status: {alert_payload.get('status', '-')}\n"
            f"Severity: {alert_payload.get('severity', '-')}\n"
            f"Category: {alert_payload.get('category', '-')}\n"
            f"Assignee: {alert_payload.get('assignee') or '-'}\n"
            f"Linked Case: {alert_payload.get('linked_case_id') or '-'}\n"
            f"Acknowledged By: {alert_payload.get('acknowledged_by') or '-'}\n"
            f"Escalated By: {alert_payload.get('escalated_by') or '-'}\n\n"
            f"Correlation Rule: {alert_payload.get('correlation_rule') or '-'}\n"
            f"Source Events: {len(source_event_ids)}\n\n"
            f"Summary:\n{alert_payload.get('summary', '-')}\n\n"
            f"Notes:\n{note_lines}"
        )

    @staticmethod
    def _format_source_events(alert_payload: dict[str, Any], source_events: Sequence[dict[str, Any]]) -> str:
        lines = [
            f"Alert: {alert_payload.get('alert_id', '-')}",
            f"Title: {alert_payload.get('title', '-')}",
            "",
        ]
        if not source_events:
            lines.append("No source events were found for this alert.")
            return "\n".join(lines)

        for event in source_events:
            raw_details = event.get("details")
            event_details = cast(dict[str, Any], raw_details) if isinstance(raw_details, dict) else {}
            evidence_block = SocDashboard._format_monitor_evidence_block(event_details)
            lines.extend(
                [
                    f"Event: {event.get('event_id', '-')}",
                    f"Type: {event.get('event_type', '-')}",
                    f"Severity: {event.get('severity', '-')}",
                    f"Created: {event.get('created_at', '-')}",
                    f"Title: {event.get('title', '-')}",
                    f"Summary: {event.get('summary', '-')}",
                    *(["", evidence_block] if evidence_block else []),
                    "",
                ]
            )
        return "\n".join(lines).rstrip()

    @staticmethod
    def _format_case_linked_activity(
        case_payload: dict[str, Any],
        linked_alerts: Sequence[dict[str, Any]],
        source_events: Sequence[dict[str, Any]],
        *,
        endpoint_timeline: Sequence[dict[str, Any]] | None = None,
    ) -> str:
        lines = [
            f"Case: {case_payload.get('case_id', '-')}",
            f"Title: {case_payload.get('title', '-')}",
            "",
            "Linked Alerts:",
        ]
        if linked_alerts:
            for alert in linked_alerts:
                lines.append(
                    f"- {alert.get('alert_id', '-')}: {alert.get('severity', '-')} | {alert.get('status', '-')} | {alert.get('title', '-')}"
                )
        else:
            lines.append("- none")

        lines.extend(["", "Source Events:"])
        if source_events:
            for event in source_events:
                lines.append(
                    f"- {event.get('event_id', '-')}: {event.get('event_type', '-')} | {event.get('severity', '-')} | {event.get('title', '-')}"
                )
        else:
            lines.append("- none")
        if endpoint_timeline is not None:
            lines.extend(["", "Endpoint Timeline:"])
            if endpoint_timeline:
                for event in endpoint_timeline[:20]:
                    lines.append(
                        f"- {event.get('event_id', '-')}: {event.get('event_type', '-')} | {event.get('recorded_at', '-')} | {event.get('title', '-')}"
                    )
                if len(endpoint_timeline) > 20:
                    lines.append(f"- ... {len(endpoint_timeline) - 20} more")
            else:
                lines.append("- none")
        return "\n".join(lines)

    @staticmethod
    def _format_case_detail(case_payload: dict[str, Any]) -> str:
        note_lines = SocDashboard._format_bullet_list(cast(list[Any], case_payload.get("notes") or []))
        observable_lines = SocDashboard._format_bullet_list(cast(list[Any], case_payload.get("observables") or []))
        return (
            f"Case: {case_payload.get('case_id', '-')}\n"
            f"Title: {case_payload.get('title', '-')}\n"
            f"Status: {case_payload.get('status', '-')}\n"
            f"Severity: {case_payload.get('severity', '-')}\n"
            f"Assignee: {case_payload.get('assignee') or '-'}\n\n"
            f"Summary:\n{case_payload.get('summary', '-')}\n\n"
            f"Observables:\n{observable_lines}\n\n"
            f"Notes:\n{note_lines}"
        )

    @staticmethod
    def _format_host_detail(finding_payload: dict[str, Any]) -> str:
        details = finding_payload.get("details") or {}
        snapshot = finding_payload.get("snapshot") or {}
        detail_lines = (
            "\n".join(f"- {key}: {value}" for key, value in details.items())
            if isinstance(details, dict) and details
            else "- none"
        )
        snapshot_pairs = [
            ("system_drive", snapshot.get("system_drive")),
            ("disk_free_percent", snapshot.get("disk_free_percent")),
            ("defender_running", snapshot.get("defender_running")),
            ("firewall_disabled_profiles", snapshot.get("firewall_disabled_profiles")),
            ("checked_at", finding_payload.get("last_checked_at")),
        ]
        snapshot_lines = "\n".join(f"- {key}: {value}" for key, value in snapshot_pairs if value is not None)
        return (
            f"Finding: {finding_payload.get('key', '-')}\n"
            f"Title: {finding_payload.get('title', '-')}\n"
            f"Severity: {finding_payload.get('severity', '-')}\n"
            f"Resolved: {finding_payload.get('resolved', False)}\n\n"
            f"Summary:\n{finding_payload.get('summary', '-')}\n\n"
            f"Details:\n{detail_lines}\n\n"
            f"Snapshot:\n{snapshot_lines or '- none'}"
        )

    @staticmethod
    def _format_monitor_evidence_block(event_details: dict[str, Any]) -> str:
        finding_details = event_details.get("details") if isinstance(event_details.get("details"), dict) else event_details
        if not isinstance(finding_details, dict):
            return ""

        evidence = finding_details.get("evidence")
        if not isinstance(evidence, dict):
            return ""

        sample_connections = evidence.get("sample_connections")
        sample_packet_endpoints = evidence.get("sample_packet_endpoints")
        lines = [
            "Compact Evidence:",
            f"- Reason: {finding_details.get('abnormal_reason') or finding_details.get('finding_type') or '-'}",
            f"- Retention: {evidence.get('retention_mode') or '-'}",
            f"- Sample Count: {evidence.get('sample_count') or 0}",
        ]
        if isinstance(finding_details.get("state_counts"), dict):
            lines.append(f"- State Counts: {finding_details.get('state_counts')}")
        if finding_details.get("local_ports") is not None:
            lines.append(f"- Local Ports: {finding_details.get('local_ports')}")
        if finding_details.get("remote_ports") is not None:
            lines.append(f"- Remote Ports: {finding_details.get('remote_ports')}")
        if finding_details.get("packet_count") is not None:
            lines.append(f"- Packet Count: {finding_details.get('packet_count')}")
        if finding_details.get("hit_count") is not None:
            lines.append(f"- Hit Count: {finding_details.get('hit_count')}")

        if isinstance(sample_connections, list) and sample_connections:
            lines.append("- Sample Connections:")
            for item in sample_connections:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    "  "
                    + f"{item.get('state', '-')} "
                    + f"{item.get('remote_ip', '-')}:{item.get('remote_port', '-')} "
                    + f"-> {item.get('local_ip', '-')}:{item.get('local_port', '-')}"
                )
        elif isinstance(sample_packet_endpoints, list) and sample_packet_endpoints:
            lines.append("- Sample Endpoints:")
            for item in sample_packet_endpoints:
                if not isinstance(item, dict):
                    continue
                lines.append(
                    "  "
                    + f"{item.get('protocol', '-')} "
                    + f"{item.get('remote_ip', '-')}:{item.get('remote_port', '-')} "
                    + f"-> {item.get('local_ip', '-')}:{item.get('local_port', '-')}"
                )
        return "\n".join(lines)

    @staticmethod
    def _load_host_monitor_state() -> dict[str, Any]:
        state_path = Path(settings.host_monitor_state_path)
        if not state_path.exists():
            return {}
        try:
            payload = json.loads(state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}


class RemoteSocDashboardConnector:
    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str | None = None,
        timeout_seconds: float = 5.0,
        transport: Any = None,
    ) -> None:
        self.manager = RemoteSecurityOperationsClient(
            base_url=base_url,
            bearer_token=bearer_token,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )
        self.tracker_intel = RemoteTrackerIntelClient(
            base_url=base_url,
            bearer_token=bearer_token,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )
        self.packet_monitor = RemotePacketMonitorClient(
            base_url=base_url,
            bearer_token=bearer_token,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )
        self.network_monitor = RemoteNetworkMonitorClient(
            base_url=base_url,
            bearer_token=bearer_token,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )
        self.platform_client = RemotePlatformClient(
            base_url=base_url,
            bearer_token=bearer_token,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )
        self.view_state_client = HttpDashboardViewStateClient(
            base_url=base_url,
            bearer_token=bearer_token,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )

    def create_dashboard(self, manager: SecurityOperationsManager | None = None) -> SocDashboard:
        return SocDashboard(
            manager=manager or self.manager,
            dashboard_view_state_client=self.view_state_client,
            tracker_intel=self.tracker_intel,
            packet_monitor=self.packet_monitor,
            network_monitor=self.network_monitor,
            platform_client=self.platform_client,
        )

    def run(self, manager: SecurityOperationsManager | None = None) -> None:
        self.create_dashboard(manager=manager).run()


def run_soc_dashboard(manager: SecurityOperationsManager | None = None) -> None:
    SocDashboard(manager=manager).run()


def run_remote_soc_dashboard(
    *,
    base_url: str,
    bearer_token: str | None = None,
    manager: SecurityOperationsManager | None = None,
    timeout_seconds: float = 5.0,
    transport: Any = None,
) -> None:
    RemoteSocDashboardConnector(
        base_url=base_url,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
        transport=transport,
    ).run(manager=manager)
