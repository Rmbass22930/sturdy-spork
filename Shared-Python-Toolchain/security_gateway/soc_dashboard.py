"""Tk dashboard for Security Gateway SOC operations."""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Callable, cast

try:
    import tkinter as tk
    from tkinter import ttk
except Exception:  # pragma: no cover
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]

from .alerts import alert_manager
from .audit import AuditLogger
from .config import settings
from .models import SocAlertStatus, SocCaseStatus, SocSeverity
from .soc import SecurityOperationsManager


def _center_window(root: Any, width: int, height: int) -> None:
    screen_width = int(root.winfo_screenwidth())
    screen_height = int(root.winfo_screenheight())
    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)
    root.geometry(f"{width}x{height}+{x}+{y}")


class SocDashboard:
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
        self.alert_severity_var = tk.StringVar(value="all")
        self.alert_link_state_var = tk.StringVar(value="unlinked")
        self.alert_sort_var = tk.StringVar(value="severity_desc")
        self.case_status_var = tk.StringVar(value="all")
        self.case_sort_var = tk.StringVar(value="updated_desc")
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
        ttk.Button(header, text="Refresh", command=self.refresh).grid(row=0, column=1, rowspan=2, sticky="e")

        summary = ttk.Frame(self.root, padding=(18, 0, 18, 12), style="SOC.TFrame")
        summary.grid(row=1, column=0, sticky="ew")
        for index in range(5):
            summary.columnconfigure(index, weight=1)
        self.summary_vars = {
            "events_total": tk.StringVar(value="0"),
            "alerts_total": tk.StringVar(value="0"),
            "open_alerts": tk.StringVar(value="0"),
            "cases_total": tk.StringVar(value="0"),
            "open_cases": tk.StringVar(value="0"),
        }
        cards = [
            ("Events", "events_total", "#dbeafe"),
            ("Alerts", "alerts_total", "#fde68a"),
            ("Open Alerts", "open_alerts", "#fecaca"),
            ("Cases", "cases_total", "#d1fae5"),
            ("Open Cases", "open_cases", "#ddd6fe"),
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
        body.rowconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)

        self.alert_tree = self._build_tree(
            body,
            row=0,
            column=0,
            title="Unassigned Alerts",
            columns=("severity", "title", "updated"),
            headings={"severity": "Severity", "title": "Title", "updated": "Updated"},
            controls=self._build_alert_controls,
        )
        self.case_tree = self._build_tree(
            body,
            row=0,
            column=1,
            title="Active Cases",
            columns=("status", "severity", "title", "assignee"),
            headings={"status": "Status", "severity": "Severity", "title": "Title", "assignee": "Assignee"},
            controls=self._build_case_controls,
        )
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

    def refresh(self) -> None:
        dashboard = cast(dict[str, Any], self.manager.dashboard())
        summary = cast(dict[str, Any], dashboard["summary"])
        triage = cast(dict[str, list[dict[str, Any]]], dashboard["triage"])
        alert_rows = self.manager.query_alerts(**self._alert_query_kwargs())
        case_rows = self.manager.query_cases(**self._case_query_kwargs())
        for key, value in self.summary_vars.items():
            value.set(str(summary.get(key, 0)))
        self.status_var.set(self._format_status_line(dashboard))
        self._populate_tree(
            self.alert_tree,
            [item.model_dump(mode="json") for item in alert_rows],
            lambda item: (item["severity"], item["title"], item["updated_at"]),
        )
        self._populate_tree(
            self.case_tree,
            [item.model_dump(mode="json") for item in case_rows],
            lambda item: (item["status"], item["severity"], item["title"], item.get("assignee") or "-"),
        )
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

    def _populate_tree(
        self,
        tree: Any,
        rows: Sequence[dict[str, Any]],
        row_builder: Callable[[dict[str, Any]], tuple[str, ...] | tuple[str, str, str] | tuple[str, str, str, str]],
    ) -> None:
        for item in tree.get_children():
            tree.delete(item)
        for index, row in enumerate(rows):
            tree.insert("", "end", iid=f"row-{index}", values=row_builder(row))

    def _alert_query_kwargs(self) -> dict[str, Any]:
        severity = self._parse_severity(self.alert_severity_var.get())
        linked_case_state = self.alert_link_state_var.get()
        return {
            "status": SocAlertStatus.open,
            "severity": severity,
            "assignee": "unassigned",
            "linked_case_state": None if linked_case_state == "all" else linked_case_state,
            "sort": self.alert_sort_var.get() or "severity_desc",
            "limit": 25,
        }

    def _case_query_kwargs(self) -> dict[str, Any]:
        status_value = self.case_status_var.get()
        return {
            "status": self._parse_case_status(status_value),
            "sort": self.case_sort_var.get() or "updated_desc",
            "limit": 25,
        }

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
    def _format_status_line(dashboard: dict[str, Any]) -> str:
        summary = dashboard["summary"]
        top_event_types = dashboard.get("top_event_types") or {}
        most_common = ", ".join(f"{name}: {count}" for name, count in list(top_event_types.items())[:3]) or "none"
        return (
            f"Open alerts: {summary['open_alerts']} | "
            f"Open cases: {summary['open_cases']} | "
            f"Top event types: {most_common}"
        )


def run_soc_dashboard(manager: SecurityOperationsManager | None = None) -> None:
    SocDashboard(manager=manager).run()
