"""Tk dashboard for Security Gateway SOC operations."""
from __future__ import annotations

import json
from collections.abc import Sequence
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
    SocCaseStatus,
    SocCaseUpdate,
    SocSeverity,
)
from .soc import SecurityOperationsManager


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
        self.alert_rows_by_id: dict[str, dict[str, Any]] = {}
        self.case_rows_by_id: dict[str, dict[str, Any]] = {}
        self.event_rows_by_id: dict[str, dict[str, Any]] = {}
        self.all_alert_rows_by_id: dict[str, dict[str, Any]] = {}
        self.host_rows_by_key: dict[str, dict[str, Any]] = {}
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
            card = tk.Frame(summary, bg=bg, bd=0, highlightthickness=0, padx=14, pady=14)
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 8, 0))
            tk.Label(card, text=label, font=("Segoe UI", 10, "bold"), bg=bg, fg="#1f2937").pack(anchor="w")
            tk.Label(card, textvariable=self.summary_vars[key], font=("Segoe UI", 22, "bold"), bg=bg, fg="#0f2f57").pack(anchor="w", pady=(8, 0))

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
        self.host_tree = self._build_tree(
            body,
            row=0,
            column=2,
            title="Host Monitor Findings",
            columns=("severity", "title", "checked"),
            headings={"severity": "Severity", "title": "Title", "checked": "Checked"},
        )
        self.host_tree.bind("<<TreeviewSelect>>", lambda _event: self._refresh_host_detail())
        self.correlation_tree = self._build_tree(
            body,
            row=1,
            column=0,
            title="Recent Correlations",
            columns=("rule", "severity", "title", "events"),
            headings={"rule": "Rule", "severity": "Severity", "title": "Title", "events": "Events"},
        )
        self.event_tree = self._build_tree(
            body,
            row=1,
            column=1,
            title="Recent Events",
            columns=("type", "severity", "title", "created"),
            headings={"type": "Type", "severity": "Severity", "title": "Title", "created": "Created"},
        )
        ops_frame = ttk.LabelFrame(body, text="Ownership And Aging", padding=(10, 10), style="SOC.TLabelframe")
        ops_frame.grid(row=1, column=2, sticky="nsew", padx=(8, 0), pady=(8, 0))
        ops_frame.columnconfigure(0, weight=1)
        ops_frame.rowconfigure(0, weight=1)
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
        self.ops_detail_text.grid(row=0, column=0, sticky="nsew")
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
        alert_detail_frame.rowconfigure(0, weight=1)
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
        self.alert_detail_text.grid(row=0, column=0, sticky="nsew")
        self.alert_detail_text.configure(state="disabled")

        detail_frame = ttk.LabelFrame(detail_row, text="Case Details", padding=(10, 10), style="SOC.TLabelframe")
        detail_frame.grid(row=0, column=1, sticky="nsew")
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(0, weight=1)
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
        self.case_detail_text.grid(row=0, column=0, sticky="nsew")
        self.case_detail_text.configure(state="disabled")

        host_detail_frame = ttk.LabelFrame(detail_row, text="Host Monitor Details", padding=(10, 10), style="SOC.TLabelframe")
        host_detail_frame.grid(row=0, column=2, sticky="nsew")
        host_detail_frame.columnconfigure(0, weight=1)
        host_detail_frame.rowconfigure(0, weight=1)
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
        self.host_detail_text.grid(row=0, column=0, sticky="nsew")
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
        summary = cast(dict[str, Any], dashboard["summary"])
        workload = cast(dict[str, Any], dashboard.get("workload") or {})
        triage = cast(dict[str, list[dict[str, Any]]], dashboard["triage"])
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
        )
        self._populate_tree(
            self.event_tree,
            cast(list[dict[str, Any]], summary["recent_events"]),
            lambda item: (item["event_type"], item["severity"], item["title"], item["created_at"]),
        )
        self._set_ops_detail_text(self._format_workload_detail(dashboard))

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
        alert_id = self._selected_tree_item_id(self.alert_tree)
        if alert_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Alert Selected", "Select an alert before assigning it.")
            return
        if simpledialog is None:
            return
        assignee = simpledialog.askstring("Assign Alert", "Enter the analyst or queue for the selected alert:", parent=self.root)
        if assignee is None or not assignee.strip():
            return
        payload = self._build_alert_update_payload(field="assignee", value=assignee.strip(), acted_by=self._current_analyst_identity())
        self.manager.update_alert(alert_id, payload)
        self.refresh()
        self.alert_tree.selection_set(alert_id)
        self._refresh_alert_detail()

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
        alert_id = self._selected_tree_item_id(self.alert_tree)
        if alert_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Alert Selected", "Select an alert before viewing source events.")
            return
        alert_payload = self.alert_rows_by_id.get(alert_id)
        if alert_payload is None:
            if messagebox is not None:
                messagebox.showwarning("Alert Unavailable", "The selected alert is no longer available in the current view.")
            return
        source_events = self._resolve_source_events(alert_payload)
        if messagebox is not None:
            messagebox.showinfo(
                "Source Events",
                self._format_source_events(alert_payload, source_events),
            )

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

    def view_case_linked_activity(self) -> None:
        case_id = self._selected_tree_item_id(self.case_tree)
        if case_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Case Selected", "Select a case before viewing linked activity.")
            return
        case_payload = self.case_rows_by_id.get(case_id)
        if case_payload is None:
            if messagebox is not None:
                messagebox.showwarning("Case Unavailable", "The selected case is no longer available in the current view.")
            return
        linked_alerts = self._resolve_linked_alerts(case_payload)
        source_events = self._resolve_case_source_events(case_payload)
        if messagebox is not None:
            messagebox.showinfo(
                "Case Linked Activity",
                self._format_case_linked_activity(case_payload, linked_alerts, source_events),
            )

    def assign_selected_case(self) -> None:
        case_id = self._selected_tree_item_id(self.case_tree)
        if case_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Case Selected", "Select a case before assigning it.")
            return
        if simpledialog is None:
            return
        assignee = simpledialog.askstring("Assign Case", "Enter the analyst or queue for the selected case:", parent=self.root)
        if assignee is None or not assignee.strip():
            return
        payload = self._build_case_update_payload(field="assignee", value=assignee.strip())
        self.manager.update_case(case_id, payload)
        self.refresh()
        self.case_tree.selection_set(case_id)
        self._refresh_case_detail()

    def mark_case_investigating(self) -> None:
        self._apply_case_status("investigating", "Case Updated")

    def mark_case_contained(self) -> None:
        self._apply_case_status("contained", "Case Updated")

    def close_selected_case(self) -> None:
        self._apply_case_status("closed", "Case Updated")

    def _apply_alert_status(self, status_value: str, title: str) -> None:
        alert_id = self._selected_tree_item_id(self.alert_tree)
        if alert_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Alert Selected", "Select an alert before applying a status update.")
            return
        payload = self._build_alert_update_payload(
            field="status",
            value=status_value,
            acted_by=self._current_analyst_identity(),
        )
        self.manager.update_alert(alert_id, payload)
        if messagebox is not None:
            messagebox.showinfo(title, f"Updated alert {alert_id} to {status_value}.")
        self.refresh()
        self._refresh_alert_detail()

    def _prompt_alert_update(self, *, field: str, title: str, prompt: str) -> None:
        alert_id = self._selected_tree_item_id(self.alert_tree)
        if alert_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Alert Selected", "Select an alert before applying an update.")
            return
        if simpledialog is None:
            return
        value = simpledialog.askstring(title, prompt, parent=self.root)
        if value is None or not value.strip():
            return
        payload = self._build_alert_update_payload(
            field=field,
            value=value.strip(),
            acted_by=self._current_analyst_identity(),
        )
        self.manager.update_alert(alert_id, payload)
        self.refresh()
        self.alert_tree.selection_set(alert_id)
        self._refresh_alert_detail()

    def _apply_case_status(self, status_value: str, title: str) -> None:
        case_id = self._selected_tree_item_id(self.case_tree)
        if case_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Case Selected", "Select a case before applying a status update.")
            return
        payload = self._build_case_update_payload(field="status", value=status_value)
        self.manager.update_case(case_id, payload)
        if messagebox is not None:
            messagebox.showinfo(title, f"Updated case {case_id} to {status_value}.")
        self.refresh()
        self.case_tree.selection_set(case_id)
        self._refresh_case_detail()

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
        case_id = self._selected_tree_item_id(self.case_tree)
        if case_id is None:
            if messagebox is not None:
                messagebox.showwarning("No Case Selected", "Select a case before applying an update.")
            return
        if simpledialog is None:
            return
        value = simpledialog.askstring(title, prompt, parent=self.root)
        if value is None or not value.strip():
            return
        payload = self._build_case_update_payload(field=field, value=value.strip())
        self.manager.update_case(case_id, payload)
        self.refresh()
        self.case_tree.selection_set(case_id)
        self._refresh_case_detail()

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
            f"Stale assigned alerts: {workload.get('stale_assigned_alerts', 0)} | "
            f"Stale active cases: {workload.get('stale_active_cases', 0)} | "
            f"Loaded assignees: {loaded_assignees} | "
            f"Top event types: {most_common}"
        )

    @staticmethod
    def _format_workload_detail(dashboard: dict[str, Any]) -> str:
        assignee_workload = cast(list[dict[str, Any]], dashboard.get("assignee_workload") or [])
        aging = cast(dict[str, dict[str, int]], dashboard.get("aging_buckets") or {})
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
            ]
        )
        return "\n".join(lines)

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

    @staticmethod
    def _format_alert_detail(alert_payload: dict[str, Any]) -> str:
        notes = alert_payload.get("notes") or []
        note_lines = "\n".join(f"- {item}" for item in notes) if notes else "- none"
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
        notes = case_payload.get("notes") or []
        observables = case_payload.get("observables") or []
        note_lines = "\n".join(f"- {item}" for item in notes) if notes else "- none"
        observable_lines = "\n".join(f"- {item}" for item in observables) if observables else "- none"
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
