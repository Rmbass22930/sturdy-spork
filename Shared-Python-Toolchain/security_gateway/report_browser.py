"""Lightweight report browser for Security Gateway."""
from __future__ import annotations

from pathlib import Path

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except Exception:  # pragma: no cover
    tk = None
    ttk = None
    messagebox = None

from .reports import SecurityReportBuilder


class ReportBrowser:
    def __init__(self, builder: SecurityReportBuilder | None = None):
        if tk is None or ttk is None or messagebox is None:
            raise RuntimeError("Tk report browser is unavailable on this machine.")
        self.builder = builder or SecurityReportBuilder()
        self.root = tk.Tk()
        self.root.title("Security Gateway Reports")
        self.root.geometry("1180x720")
        self.root.minsize(980, 560)
        self._build_ui()
        self.refresh_reports()

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        header = ttk.Frame(self.root, padding=(16, 16, 16, 8))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Security Gateway Reports", font=("Segoe UI", 18, "bold")).grid(row=0, column=0, sticky="w")
        self.path_var = tk.StringVar(value=f"Reports directory: {self.builder.get_output_dir()}")
        ttk.Label(header, textvariable=self.path_var).grid(row=1, column=0, sticky="w", pady=(6, 0))

        body = ttk.Frame(self.root, padding=(16, 0, 16, 8))
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        columns = ("name", "generated_at", "blocked", "potential", "size", "modified_at")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=18)
        headings = {
            "name": "Report",
            "generated_at": "Generated",
            "blocked": "Blocked IPs",
            "potential": "Potential Blocked",
            "size": "Size",
            "modified_at": "Modified",
        }
        widths = {
            "name": 280,
            "generated_at": 220,
            "blocked": 110,
            "potential": 130,
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

        footer = ttk.Frame(self.root, padding=(16, 8, 16, 16))
        footer.grid(row=2, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="No reports loaded.")
        ttk.Label(footer, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        ttk.Button(footer, text="Generate New", command=self.generate_report).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(footer, text="Refresh", command=self.refresh_reports).grid(row=0, column=2, padx=(0, 8))
        ttk.Button(footer, text="Open", command=self.open_selected_report).grid(row=0, column=3, padx=(0, 8))
        ttk.Button(footer, text="Print", command=self.print_selected_report).grid(row=0, column=4)

    def run(self) -> None:
        self.root.mainloop()

    def refresh_reports(self) -> None:
        self.path_var.set(f"Reports directory: {self.builder.get_output_dir()}")
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
                    self._format_size(report["size"]),
                    report["modified_at"],
                ),
            )
        self.status_var.set(f"{len(reports)} report(s) available.")

    def generate_report(self) -> None:
        target = self.builder.write_summary_pdf()
        self.refresh_reports()
        self.status_var.set(f"Generated {target.name}")

    def open_selected_report(self) -> None:
        self._act_on_selected_report("open")

    def print_selected_report(self) -> None:
        self._act_on_selected_report("print")

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


def run_report_browser(builder: SecurityReportBuilder | None = None) -> None:
    ReportBrowser(builder=builder).run()
