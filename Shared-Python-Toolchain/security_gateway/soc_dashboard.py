"""Tk dashboard for Security Gateway SOC operations."""
from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, cast

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
from .models import (
    SocAlertPromoteCaseRequest,
    SocAlertStatus,
    SocAlertUpdate,
    SocCaseCreate,
    SocCaseStatus,
    SocCaseUpdate,
    SocDetectionRuleUpdate,
    SocNetworkEvidenceCaseRequest,
    SocPacketSessionCaseRequest,
    SocSeverity,
)
from .network_monitor import NetworkMonitor
from .packet_monitor import PacketMonitor
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
        "my-queue": {
            "alert_severity": "all",
            "alert_link_state": "all",
            "alert_sort": "updated_desc",
            "case_status": "all",
            "case_sort": "updated_desc",
        },
    }

    def __init__(self, manager: SecurityOperationsManager | None = None):
        if tk is None or ttk is None:
            raise RuntimeError("Tk SOC dashboard is unavailable on this machine.")
        self.manager = manager or SecurityOperationsManager(
            event_log_path=settings.soc_event_log_path,
            alert_store_path=settings.soc_alert_store_path,
            case_store_path=settings.soc_case_store_path,
            audit_logger=AuditLogger(settings.audit_log_path),
            alert_manager=alert_manager,
        )
        self.tracker_intel = TrackerIntel(
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
        self.packet_monitor = PacketMonitor(
            state_path=settings.packet_monitor_state_path,
            sample_seconds=settings.packet_monitor_sample_seconds,
            min_packet_count=settings.packet_monitor_min_packet_count,
            anomaly_multiplier=settings.packet_monitor_anomaly_multiplier,
            learning_samples=settings.packet_monitor_learning_samples,
            pkt_size=settings.packet_monitor_capture_bytes,
            sensitive_ports=settings.packet_monitor_sensitive_ports,
        )
        self.network_monitor = NetworkMonitor(
            state_path=settings.network_monitor_state_path,
            suspicious_repeat_threshold=settings.network_monitor_repeat_threshold,
            dos_hit_threshold=settings.network_monitor_dos_hit_threshold,
            dos_syn_threshold=settings.network_monitor_dos_syn_threshold,
            dos_port_span_threshold=settings.network_monitor_dos_port_span_threshold,
            sensitive_ports=settings.network_monitor_sensitive_ports,
        )
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
            values=("tier1-triage", "tier2-investigation", "containment", "review-closed", "unassigned", "needs-attention", "handoff", "my-queue", "custom"),
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
        for index in range(8):
            summary.columnconfigure(index, weight=1)
        self.summary_vars = {
            "events_total": tk.StringVar(value="0"),
            "alerts_total": tk.StringVar(value="0"),
            "open_alerts": tk.StringVar(value="0"),
            "cases_total": tk.StringVar(value="0"),
            "open_cases": tk.StringVar(value="0"),
            "host_findings": tk.StringVar(value="0"),
            "stale_assigned_alerts": tk.StringVar(value="0"),
            "stale_active_cases": tk.StringVar(value="0"),
        }
        cards = [
            ("Events", "events_total", "#dbeafe"),
            ("Alerts", "alerts_total", "#fde68a"),
            ("Open Alerts", "open_alerts", "#fecaca"),
            ("Cases", "cases_total", "#d1fae5"),
            ("Open Cases", "open_cases", "#ddd6fe"),
            ("Host Findings", "host_findings", "#fee2e2"),
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
        ttk.Button(ops_controls, text="Toggle Detection Rule", command=self.toggle_detection_rule).grid(
            row=2, column=19, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="Update Detection Param", command=self.update_detection_rule_parameter).grid(
            row=2, column=20, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Rule Alerts", command=self.view_detection_rule_alerts).grid(
            row=2, column=21, sticky="w", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(ops_controls, text="View Rule Evidence", command=self.view_detection_rule_evidence).grid(
            row=2, column=22, sticky="w", padx=(8, 0), pady=(8, 0)
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
        title = tk.Label(card, text=label, font=("Segoe UI", 10, "bold"), bg=bg, fg="#1f2937", cursor="hand2")
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
        if preset:
            self.alert_severity_var.set(preset["alert_severity"])
            self.alert_link_state_var.set(preset["alert_link_state"])
            self.alert_sort_var.set(preset["alert_sort"])
            self.case_status_var.set(preset["case_status"])
            self.case_sort_var.set(preset["case_sort"])
        self.refresh()

    def refresh(self) -> None:
        dashboard = cast(dict[str, Any], self.manager.dashboard())
        self._latest_dashboard = dashboard
        summary = cast(dict[str, Any], dashboard["summary"])
        workload = cast(dict[str, Any], dashboard.get("workload") or {})
        triage = cast(dict[str, list[dict[str, Any]]], dashboard["triage"])
        dashboard["tracker_feed_status"] = self.tracker_intel.feed_status()
        packet_sessions = self._collect_packet_sessions()
        network_observations = self.network_monitor.list_recent_observations(limit=100)
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
        all_alerts = self.manager.list_alerts()
        for key, value in self.summary_vars.items():
            if key == "host_findings":
                value.set(str(len(host_findings)))
            elif key in workload:
                value.set(str(workload.get(key, 0)))
            else:
                value.set(str(summary.get(key, 0)))
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
        choice = self._choose_case_activity_pivot(case_payload, linked_alerts=linked_alerts, source_events=source_events)
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
        choice = self._choose_alert_pivot(alert_payload, source_events=source_events, linked_case=linked_case)
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
        if choice == "case" and linked_case is not None:
            self._pivot_from_case(linked_case)
            return
        self._show_info_dialog("Alert Details", self._format_alert_detail(alert_payload))

    def _pivot_from_case(self, case_payload: dict[str, Any]) -> None:
        linked_alerts = self._resolve_linked_alerts(case_payload)
        source_events = self._resolve_case_source_events(case_payload)
        choice = self._choose_case_activity_pivot(case_payload, linked_alerts=linked_alerts, source_events=source_events)
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

    def view_detection_rule_alerts(self) -> None:
        selected_rule = self._select_detection_rule()
        if selected_rule is None:
            return
        rule_id = str(selected_rule.get("rule_id") or "")
        alerts = [item.model_dump(mode="json") for item in self.manager.query_alerts(correlation_rule=rule_id, limit=50)]
        grouped_alerts = self._group_rule_alerts(alerts)
        selected_group = self._select_summary_record_or_show_info(
            "alert_group",
            grouped_alerts,
            title=f"Alert Groups for {rule_id}",
            info_title=f"Alerts for {rule_id}",
            limit=50,
        )
        if selected_group is None:
            return
        if self._handle_existing_case_guard(
            open_case_ids=[str(item) for item in cast(list[Any], selected_group.get("open_case_ids") or []) if str(item)],
            context_label=f"Alert group {selected_group.get('group_key', rule_id)}",
        ):
            return
        selected_alert = self._select_summary_record_or_show_info(
            "alert",
            cast(list[dict[str, Any]], selected_group.get("alerts") or []),
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
        alert_rows = [item.model_dump(mode="json") for item in self.manager.query_alerts(correlation_rule=rule_id, limit=50)]
        source_events = self._collect_rule_source_events(alert_rows)
        grouped_evidence = self._group_rule_evidence(source_events)
        selected_group = self._select_summary_record_or_show_info(
            "evidence_group",
            grouped_evidence,
            title=f"Evidence Groups for {rule_id}",
            info_title=f"Evidence for {rule_id}",
            limit=50,
        )
        if selected_group is None:
            return
        if self._handle_existing_case_guard(
            open_case_ids=[str(item) for item in cast(list[Any], selected_group.get("open_case_ids") or []) if str(item)],
            context_label=f"Evidence group {selected_group.get('group_key', rule_id)}",
        ):
            return
        selected_event = self._select_summary_record_or_show_info(
            "event",
            cast(list[dict[str, Any]], selected_group.get("events") or []),
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
    ) -> str:
        has_linked_case = linked_case is not None
        if not source_events and not has_linked_case:
            return "details"
        alert_id = str(alert_payload.get("alert_id") or "-")
        alert_title = str(alert_payload.get("title") or "-")
        summary = (
            f"Alert: {alert_id}\n"
            f"Title: {alert_title}\n\n"
            f"Source events: {len(source_events)}\n"
            f"Linked case: {'yes' if has_linked_case else 'no'}"
        )
        actions: list[tuple[str, str, int]] = []
        if source_events:
            actions.append(("Open Source Events", "events", 18))
        if has_linked_case:
            actions.append(("Open Linked Case", "case", 18))
        return self._choose_action_dialog(
            title="Alert Actions",
            summary=summary,
            actions=actions,
            default_choice="details",
            no_tk_choice="events" if source_events else "case",
            width=620,
            height=260,
            min_width=540,
            min_height=220,
            detail_label="Alert Details",
            detail_width=14,
        )

    def _choose_case_activity_pivot(
        self,
        case_payload: dict[str, Any],
        *,
        linked_alerts: Sequence[dict[str, Any]],
        source_events: Sequence[dict[str, Any]],
    ) -> str:
        if not linked_alerts and not source_events:
            return "details"
        case_id = str(case_payload.get("case_id") or "-")
        case_title = str(case_payload.get("title") or "-")
        summary = (
            f"Case: {case_id}\n"
            f"Title: {case_title}\n\n"
            f"Linked alerts: {len(linked_alerts)}\n"
            f"Source events: {len(source_events)}"
        )
        actions: list[tuple[str, str, int]] = []
        if linked_alerts:
            actions.append(("Open Linked Alerts", "alerts", 18))
        if source_events:
            actions.append(("Open Source Events", "events", 18))
        return self._choose_action_dialog(
            title="Case Activity",
            summary=summary,
            actions=actions,
            default_choice="details",
            no_tk_choice="alerts" if linked_alerts else "events",
            width=620,
            height=260,
            min_width=540,
            min_height=220,
            detail_label="Activity Details",
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
        if not event_id or not hasattr(self.manager, "list_cases"):
            return []
        all_cases = [item.model_dump(mode="json") for item in self.manager.list_cases()]
        return [
            case
            for case in all_cases
            if event_id in cast(list[str], case.get("source_event_ids") or [])
        ]

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
        if kind == "packet_session":
            return (
                f"{row.get('session_key', '-')} | "
                f"{row.get('remote_ip_display', row.get('remote_ip', '-'))} | "
                f"{row.get('last_seen_at', '-')} | "
                f"{row.get('total_packets', row.get('last_packet_count', 0))}"
            )
        labels: dict[str, tuple[str, str, str, str]] = {
            "event": ("event_id", "event_type", "severity", "title"),
            "alert": ("alert_id", "status", "severity", "title"),
            "case": ("case_id", "status", "severity", "title"),
            "host": ("key", "severity", "title", "summary"),
            "tracker_block": ("event_id", "event_type", "severity", "title"),
            "packet_session": ("session_key", "remote_ip", "last_seen_at", "total_packets"),
            "network_evidence": ("remote_ip", "severity", "last_seen_at", "title"),
            "detection_rule": ("rule_id", "enabled", "hit_count", "title"),
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
        return list(self.manager.query_alerts(**self._alert_query_kwargs()))

    def _case_rows_for_view(self, dashboard: dict[str, Any]) -> list[Any]:
        preset_name = self._selected_preset_name()
        if preset_name == "needs-attention":
            cases = [item for item in self.manager.list_cases() if item.status is not SocCaseStatus.closed]
            return sorted(cases, key=lambda item: item.updated_at)[:25]
        if preset_name == "handoff":
            stale_cases = cast(list[dict[str, Any]], cast(dict[str, Any], dashboard["triage"]).get("stale_active_cases") or [])
            return [self.manager.get_case(str(item["case_id"])) for item in stale_cases if item.get("case_id")]
        return list(self.manager.query_cases(**self._case_query_kwargs()))

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
        packet_session_status = cast(dict[str, Any], dashboard.get("packet_session_status") or {})
        network_evidence_status = cast(dict[str, Any], dashboard.get("network_evidence_status") or {})
        top_event_types = dashboard.get("top_event_types") or {}
        most_common = ", ".join(f"{name}: {count}" for name, count in list(top_event_types.items())[:3]) or "none"
        loaded_assignees = sum(
            1
            for item in assignee_workload
            if int(item.get("open_alerts", 0)) > 0 or int(item.get("active_cases", 0)) > 0
        )
        return (
            f"Open alerts: {summary['open_alerts']} | "
            f"Open cases: {summary['open_cases']} | "
            f"Host findings: {host_findings_count} | "
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
        packet_session_status = cast(dict[str, Any], dashboard.get("packet_session_status") or {})
        network_evidence_status = cast(dict[str, Any], dashboard.get("network_evidence_status") or {})
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


def run_soc_dashboard(manager: SecurityOperationsManager | None = None) -> None:
    SocDashboard(manager=manager).run()
