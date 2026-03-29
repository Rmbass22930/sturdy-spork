"""Lightweight report browser for Security Gateway."""
from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except Exception:  # pragma: no cover
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]

from .reports import ReportFilters, SecurityReportBuilder
from .tracker_intel import TrackerIntel
from .config import settings


def _center_window(root: Any, width: int, height: int) -> None:
    screen_width = int(root.winfo_screenwidth())
    screen_height = int(root.winfo_screenheight())
    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)
    root.geometry(f"{width}x{height}+{x}+{y}")


class ReportBrowser:
    def __init__(self, builder: SecurityReportBuilder | None = None):
        if tk is None or ttk is None or messagebox is None:
            raise RuntimeError("Tk report browser is unavailable on this machine.")
        self.builder = builder or SecurityReportBuilder()
        self.tracker_intel = TrackerIntel(
            extra_domains_path=settings.tracker_domain_list_path,
            feed_cache_path=settings.tracker_feed_cache_path,
            feed_urls=settings.tracker_feed_urls,
            stale_after_hours=settings.tracker_feed_stale_hours,
        )
        self.root = tk.Tk()
        self.root.title("Security Gateway Reports")
        self.root.configure(bg="#f2f6fb")
        _center_window(self.root, 1320, 860)
        self.root.minsize(1100, 680)
        self._build_ui()
        self.refresh_reports()

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:  # pragma: no cover
            pass
        style.configure("SG.TFrame", background="#f2f6fb")
        style.configure("SG.TLabel", background="#f2f6fb", foreground="#233449", font=("Segoe UI", 10))
        style.configure("SG.Header.TLabel", background="#f2f6fb", foreground="#12335b", font=("Segoe UI", 18, "bold"))
        style.configure("SG.Subheader.TLabel", background="#f2f6fb", foreground="#3b4d63", font=("Segoe UI", 10, "bold"))
        style.configure("SG.TLabelframe", background="#f2f6fb")
        style.configure("SG.TLabelframe.Label", background="#f2f6fb", foreground="#12335b", font=("Segoe UI", 10, "bold"))
        style.configure("SG.TButton", font=("Segoe UI", 10, "bold"))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, padding=(18, 18, 18, 10), style="SG.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Security Gateway Reports", style="SG.Header.TLabel").grid(row=0, column=0, sticky="w")
        self.path_var = tk.StringVar(value=f"Reports directory: {self.builder.get_output_dir()}")
        ttk.Label(header, textvariable=self.path_var, style="SG.Subheader.TLabel").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.feed_status_var = tk.StringVar(value="Tracker feeds: status unavailable")
        ttk.Label(header, textvariable=self.feed_status_var, style="SG.TLabel").grid(row=2, column=0, sticky="w", pady=(6, 0))
        feed_panel = ttk.LabelFrame(header, text="Tracker Feed Management", padding=(14, 12), style="SG.TLabelframe")
        feed_panel.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        feed_panel.columnconfigure(0, weight=1)
        feed_panel.columnconfigure(1, weight=1)
        feed_panel.columnconfigure(2, weight=1)

        ttk.Button(feed_panel, text="Refresh Feeds", command=self.refresh_tracker_feeds, style="SG.TButton").grid(
            row=0, column=0, sticky="w", pady=(0, 8)
        )
        self.feed_detail_var = tk.StringVar(value="No feed refresh has been run in this session.")
        ttk.Label(feed_panel, textvariable=self.feed_detail_var, style="SG.TLabel").grid(
            row=0, column=1, columnspan=2, sticky="w", padx=(12, 0), pady=(0, 8)
        )

        ttk.Label(feed_panel, text="Active Sources", style="SG.Subheader.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Label(feed_panel, text="Disabled Sources", style="SG.Subheader.TLabel").grid(row=1, column=1, sticky="w")
        ttk.Label(feed_panel, text="Recent Failures", style="SG.Subheader.TLabel").grid(row=1, column=2, sticky="w")

        self.active_sources_text = tk.Text(feed_panel, width=44, height=7, wrap="word", bg="#fbfdff", fg="#24364a")
        self.active_sources_text.grid(row=2, column=0, sticky="nsew", padx=(0, 8))
        self.disabled_sources_text = tk.Text(feed_panel, width=34, height=7, wrap="word", bg="#fbfdff", fg="#24364a")
        self.disabled_sources_text.grid(row=2, column=1, sticky="nsew", padx=(0, 8))
        self.feed_failures_text = tk.Text(feed_panel, width=44, height=7, wrap="word", bg="#fbfdff", fg="#24364a")
        self.feed_failures_text.grid(row=2, column=2, sticky="nsew")
        for widget in (self.active_sources_text, self.disabled_sources_text, self.feed_failures_text):
            widget.configure(state="disabled")

        filters = ttk.Frame(header, style="SG.TFrame")
        filters.grid(row=4, column=0, sticky="w", pady=(10, 0))
        ttk.Label(filters, text="Window (hours)", style="SG.Subheader.TLabel").grid(row=0, column=0, sticky="w")
        self.window_var = tk.StringVar(value="24")
        ttk.Combobox(
            filters,
            textvariable=self.window_var,
            values=["1", "6", "24", "72", "168", "all"],
            width=8,
            state="normal",
        ).grid(row=0, column=1, padx=(6, 18), sticky="w")
        ttk.Label(filters, text="Min risk", style="SG.Subheader.TLabel").grid(row=0, column=2, sticky="w")
        self.min_risk_var = tk.StringVar(value="0")
        ttk.Entry(filters, textvariable=self.min_risk_var, width=8).grid(row=0, column=3, padx=(6, 18), sticky="w")
        self.include_blocked_var = tk.BooleanVar(value=True)
        self.include_potential_var = tk.BooleanVar(value=True)
        self.include_events_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(filters, text="Blocked IPs", variable=self.include_blocked_var).grid(row=0, column=4, padx=(0, 10))
        ttk.Checkbutton(filters, text="Potential Blocked", variable=self.include_potential_var).grid(row=0, column=5, padx=(0, 10))
        ttk.Checkbutton(filters, text="Recent Events", variable=self.include_events_var).grid(row=0, column=6, padx=(0, 10))

        body = ttk.Frame(self.root, padding=(18, 0, 18, 10), style="SG.TFrame")
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        columns = ("name", "generated_at", "blocked", "potential", "trackers", "size", "modified_at")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=18)
        headings = {
            "name": "Report",
            "generated_at": "Generated",
            "blocked": "Blocked IPs",
            "potential": "Potential Blocked",
            "trackers": "Tracker Blocks",
            "size": "Size",
            "modified_at": "Modified",
        }
        widths = {
            "name": 280,
            "generated_at": 220,
            "blocked": 110,
            "potential": 130,
            "trackers": 120,
            "size": 110,
            "modified_at": 220,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Double-1>", lambda _event: self.open_selected_report())

        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        footer = ttk.Frame(self.root, padding=(18, 10, 18, 18), style="SG.TFrame")
        footer.grid(row=2, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="No reports loaded.")
        ttk.Label(footer, textvariable=self.status_var, style="SG.Subheader.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Button(footer, text="Generate New", command=self.generate_report, style="SG.TButton").grid(row=0, column=1, padx=(0, 8))
        ttk.Button(footer, text="Refresh", command=self.refresh_reports, style="SG.TButton").grid(row=0, column=2, padx=(0, 8))
        ttk.Button(footer, text="Open", command=self.open_selected_report, style="SG.TButton").grid(row=0, column=3, padx=(0, 8))
        ttk.Button(footer, text="Print", command=self.print_selected_report, style="SG.TButton").grid(row=0, column=4)

    def run(self) -> None:
        self.root.mainloop()

    def refresh_reports(self) -> None:
        self.path_var.set(f"Reports directory: {self.builder.get_output_dir()}")
        feed_status = self.tracker_intel.feed_status()
        self.feed_status_var.set(self._format_feed_status(feed_status))
        self.feed_detail_var.set(self._format_feed_detail(feed_status))
        self._set_text_block(self.active_sources_text, self._format_feed_source_lines(feed_status.get("sources") or []))
        self._set_text_block(self.disabled_sources_text, self._format_disabled_sources(feed_status))
        self._set_text_block(self.feed_failures_text, self._format_feed_failures(feed_status))
        for item in self.tree.get_children():
            self.tree.delete(item)
        reports = self.builder.list_saved_reports()
        for report in reports:
            self.tree.insert(
                "",
                "end",
                iid=report["name"],
                values=(
                    report["name"],
                    report.get("generated_at") or "-",
                    report.get("blocked_ip_count") if report.get("blocked_ip_count") is not None else "-",
                    report.get("potential_blocked_ip_count") if report.get("potential_blocked_ip_count") is not None else "-",
                    report.get("tracker_block_count") if report.get("tracker_block_count") is not None else "-",
                    self._format_size(report["size"]),
                    report["modified_at"],
                ),
            )
        self.status_var.set(f"{len(reports)} report(s) available.")

    def generate_report(self) -> None:
        try:
            filters = self._current_filters()
        except ValueError as exc:
            if messagebox is not None:
                messagebox.showerror("Security Gateway Reports", str(exc))
            return
        target = self.builder.write_summary_pdf(
            max_events=filters.max_events,
            time_window_hours=filters.time_window_hours,
            min_risk_score=filters.min_risk_score,
            include_blocked_ips=filters.include_blocked_ips,
            include_potential_blocked_ips=filters.include_potential_blocked_ips,
            include_recent_events=filters.include_recent_events,
        )
        self.refresh_reports()
        self.status_var.set(f"Generated {target.name}")

    def open_selected_report(self) -> None:
        self._act_on_selected_report("open")

    def print_selected_report(self) -> None:
        self._act_on_selected_report("print")

    def refresh_tracker_feeds(self) -> None:
        try:
            result = self.tracker_intel.refresh_feed_cache()
        except Exception as exc:  # noqa: BLE001
            self.refresh_reports()
            if messagebox is not None:
                messagebox.showerror("Security Gateway Reports", f"Tracker feed refresh failed:\n{exc}")
            return
        self.refresh_reports()
        self.status_var.set(
            f"Tracker feeds refreshed: {result.get('domain_count', 0)} domains across {len(result.get('sources', []))} sources"
        )

    def _act_on_selected_report(self, action: str) -> None:
        selected = self.tree.selection()
        if not selected:
            if messagebox is not None:
                messagebox.showinfo("Security Gateway Reports", "Select a report first.")
            return
        name = selected[0]
        try:
            target = self.builder.open_saved_report(name, action=action)
        except Exception as exc:  # noqa: BLE001
            if messagebox is not None:
                messagebox.showerror("Security Gateway Reports", str(exc))
            return
        verb = "Printed" if action == "print" else "Opened"
        self.status_var.set(f"{verb} {Path(target).name}")

    def _format_size(self, size: int) -> str:
        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size / (1024 * 1024):.1f} MB"

    def _format_feed_status(self, status: dict | None = None) -> str:
        status = status or self.tracker_intel.feed_status()
        domain_count = status.get("domain_count", 0)
        updated_at = status.get("updated_at") or "never"
        last_result = status.get("last_refresh_result") or "unknown"
        parts = [
            f"Tracker feeds: {domain_count} domains",
            f"updated={updated_at}",
            f"last_result={last_result}",
        ]
        if status.get("is_stale"):
            age_hours = status.get("age_hours")
            if age_hours is None:
                parts.append("stale cache")
            else:
                parts.append(f"stale cache ({age_hours}h old)")
        failures = status.get("failures") or []
        if failures:
            parts.append(f"failures={len(failures)}")
        return " | ".join(parts)

    def _format_feed_detail(self, status: dict | None = None) -> str:
        status = status or self.tracker_intel.feed_status()
        last_attempt = status.get("last_refresh_attempted_at") or "never"
        sources = status.get("sources") or []
        return (
            f"Last attempt={last_attempt} | active_sources={len(status.get('active_feed_urls') or [])} | "
            f"loaded_sources={len(sources)}"
        )

    def _format_feed_source_lines(self, sources: list[dict]) -> str:
        if not sources:
            return "No active source data recorded."
        return "\n".join(
            f"{item.get('url', 'unknown')} ({item.get('domain_count', 0)} domains)"
            for item in sources
        )

    def _format_disabled_sources(self, status: dict | None = None) -> str:
        status = status or self.tracker_intel.feed_status()
        disabled = status.get("disabled_feed_urls") or []
        if not disabled:
            return "No disabled sources."
        return "\n".join(str(url) for url in disabled)

    def _format_feed_failures(self, status: dict | None = None) -> str:
        status = status or self.tracker_intel.feed_status()
        failures = status.get("failures") or []
        if not failures:
            return "No recent feed failures."
        return "\n\n".join(
            f"{item.get('url', 'unknown')}\n{item.get('error', 'unknown error')}"
            for item in failures
        )

    def _set_text_block(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _current_filters(self) -> ReportFilters:
        window_text = self.window_var.get().strip().lower()
        if window_text in {"", "all"}:
            time_window_hours = None
        else:
            time_window_hours = float(window_text)
            if time_window_hours <= 0:
                raise ValueError("Window hours must be greater than zero.")
        min_risk_score = float(self.min_risk_var.get().strip() or "0")
        if min_risk_score < 0:
            raise ValueError("Minimum risk must be zero or greater.")
        if not (self.include_blocked_var.get() or self.include_potential_var.get() or self.include_events_var.get()):
            raise ValueError("Enable at least one report section.")
        return ReportFilters(
            time_window_hours=time_window_hours,
            min_risk_score=min_risk_score,
            include_blocked_ips=self.include_blocked_var.get(),
            include_potential_blocked_ips=self.include_potential_var.get(),
            include_recent_events=self.include_events_var.get(),
        )


def run_report_browser(builder: SecurityReportBuilder | None = None) -> None:
    ReportBrowser(builder=builder).run()
