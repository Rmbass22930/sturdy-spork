"""Windowed installer shell for SecurityGateway."""
from __future__ import annotations

import queue
import threading
import sys
from pathlib import Path
from typing import Any, Optional


project_root = Path(__file__).resolve().parents[1]
project_root_text = str(project_root)
if project_root_text not in sys.path:
    sys.path.insert(0, project_root_text)

from installer import installer as core  # noqa: E402
tk, ttk, _ = core.load_tk_modules()


def center_window(root, width: int, height: int) -> None:
    screen_width = int(root.winfo_screenwidth())
    screen_height = int(root.winfo_screenheight())
    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)
    root.geometry(f"{width}x{height}+{x}+{y}")


class InstallerUI(core.InstallReporter):
    STAGES = [
        "Opening install guide",
        "Resolving payload",
        "Installing prerequisites",
        "Copying application files",
        "Updating PATH",
        "Creating shortcuts",
        "Registering automation task",
        "Installing uninstaller",
        "Writing uninstall script",
        "Finishing",
    ]

    def __init__(self, args):
        if tk is None or ttk is None:
            raise RuntimeError("Tk installer UI is unavailable on this machine.")
        self.args = args
        self.root = tk.Tk()
        self.root.title("SecurityGateway Installer")
        self.root.configure(bg="#f2f6fb")
        center_window(self.root, 940, 700)
        self.root.minsize(840, 620)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._queue: "queue.Queue[tuple]" = queue.Queue()
        self._install_thread: Optional[threading.Thread] = None
        self._install_done = False
        self._build_ui()

    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:
            pass
        style.configure("Installer.TFrame", background="#f2f6fb")
        style.configure("Installer.TLabel", background="#f2f6fb", foreground="#233449", font=("Segoe UI", 10))
        style.configure("Installer.Header.TLabel", background="#f2f6fb", foreground="#12335b", font=("Segoe UI", 20, "bold"))
        style.configure("Installer.Subheader.TLabel", background="#f2f6fb", foreground="#3b4d63", font=("Segoe UI", 10, "bold"))
        style.configure("Installer.TButton", font=("Segoe UI", 10, "bold"))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)

        header = ttk.Frame(self.root, padding=(22, 20, 22, 10), style="Installer.TFrame")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="SecurityGateway Installer", style="Installer.Header.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Installs SecurityGateway, creates desktop shortcuts, registers automation startup, and includes the SOC Dashboard in the installed launcher.",
            wraplength=860,
            style="Installer.Subheader.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))

        progress_frame = ttk.Frame(self.root, padding=(22, 6, 22, 10), style="Installer.TFrame")
        progress_frame.grid(row=1, column=0, sticky="ew")
        progress_frame.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Ready to install.")
        ttk.Label(progress_frame, textvariable=self.status_var, style="Installer.Subheader.TLabel").grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(progress_frame, mode="determinate", maximum=len(self.STAGES), value=0)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(8, 0))

        body = ttk.Frame(self.root, padding=(22, 0, 22, 0), style="Installer.TFrame")
        body.grid(row=2, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)
        self.log = tk.Text(body, height=22, wrap="word", font=("Consolas", 10), bg="#fbfdff", fg="#24364a")
        self.log.grid(row=0, column=0, sticky="nsew")
        self.log.configure(state="disabled")
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.log.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scrollbar.set)

        footer = ttk.Frame(self.root, padding=(22, 12, 22, 20), style="Installer.TFrame")
        footer.grid(row=4, column=0, sticky="ew")
        footer.columnconfigure(0, weight=1)
        self.primary_button = ttk.Button(footer, text="Install", command=self._start_install, style="Installer.TButton")
        self.primary_button.grid(row=0, column=1, sticky="e")
        self.close_button = ttk.Button(footer, text="Close", command=self._on_close, style="Installer.TButton")
        self.close_button.grid(row=0, column=2, sticky="e", padx=(8, 0))

    def run(self) -> int:
        self.root.after(100, self._pump_queue)
        self.root.mainloop()
        return 0

    def _append_log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _on_close(self) -> None:
        if self._install_thread and self._install_thread.is_alive() and not self._install_done:
            return
        self.root.destroy()

    def _start_install(self) -> None:
        if self._install_thread and self._install_thread.is_alive():
            return
        self.primary_button.configure(state="disabled")
        self.status_var.set("Starting install...")
        self._install_thread = threading.Thread(target=self._run_install, daemon=True)
        self._install_thread.start()

    def _run_install(self) -> None:
        try:
            core.perform_install(self.args, reporter=self)
        except Exception as exc:  # noqa: BLE001
            self._queue.put(("error", str(exc)))
        else:
            self._queue.put(("done", None))

    def _pump_queue(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            kind = item[0]
            if kind == "stage":
                title = item[1]
                try:
                    stage_index = self.STAGES.index(title) + 1
                except ValueError:
                    stage_index = self.progress["value"]
                self.status_var.set(title)
                self.progress.configure(value=stage_index)
                self._append_log(f"[stage] {title}")
            elif kind == "info":
                self._append_log(item[1])
            elif kind == "summary":
                self.status_var.set("Install complete.")
                self.progress.configure(value=len(self.STAGES))
                self._append_log("")
                self._append_log("Install complete:")
                summary = item[1]
                self._append_log(f"- Application: {summary.installed_path}")
                self._append_log(f"- Reports directory: {summary.reports_dir}")
                self._append_log("- Installed launcher tools: SOC Dashboard, Reports, Install Folder, Uninstaller")
                self._append_log("- Shortcuts:")
                for shortcut_path in summary.shortcut_paths:
                    self._append_log(f"  - {shortcut_path}")
                if summary.dependency_results:
                    self._append_log("- Dependencies:")
                    for result in summary.dependency_results:
                        target_suffix = f" ({result.target})" if result.target else ""
                        detail_suffix = f" - {result.detail}" if result.detail else ""
                        self._append_log(f"  - {result.name}: {result.status} via {result.method}{target_suffix}{detail_suffix}")
                else:
                    self._append_log("- Dependencies: none")
                self._append_log(f"- Uninstall executable: {summary.uninstall_executable}")
                self._append_log(f"- Uninstall script: {summary.uninstall_script}")
                self._append_log(f"- Startup registration script: {summary.register_startup_script}")
                self._append_log("- PATH updated for current user. Sign out/in or restart terminal to use immediately.")
            elif kind == "error":
                self.status_var.set("Install failed.")
                self._append_log(f"[error] {item[1]}")
                self._install_done = True
                self.primary_button.configure(state="normal", text="Retry Install")
                self.close_button.configure(text="Close")
            elif kind == "done":
                self._install_done = True
                self.primary_button.configure(state="disabled")
                self.close_button.configure(text="Finish")
            elif kind == "dependency_prompt":
                dep, message, response, event = item[1], item[2], item[3], item[4]
                action = self._show_dependency_dialog(dep, message)
                response["action"] = action
                event.set()
        if self.root.winfo_exists():
            self.root.after(100, self._pump_queue)

    def _show_dependency_dialog(self, dep: Any, message: str) -> str:
        dialog = tk.Toplevel(self.root)
        dialog.title("Dependency issue")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(bg="#fdf4f0")
        center_window(dialog, 580, 270)
        dialog.columnconfigure(0, weight=1)
        ttk.Label(dialog, text=f"Dependency install failed: {dep.name}", font=("Segoe UI", 11, "bold"), padding=(20, 18, 20, 8)).grid(row=0, column=0, sticky="w")
        ttk.Label(dialog, text=message, wraplength=520, padding=(20, 0, 20, 0)).grid(row=1, column=0, sticky="w")
        ttk.Label(dialog, text="Choose how setup should continue.", padding=(20, 14, 20, 10)).grid(row=2, column=0, sticky="w")
        result = {"action": "abort"}

        buttons = ttk.Frame(dialog, padding=(20, 0, 20, 18))
        buttons.grid(row=3, column=0, sticky="e")

        def choose(action: str) -> None:
            result["action"] = action
            dialog.destroy()

        ttk.Button(buttons, text="Retry", command=lambda: choose("retry")).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(buttons, text="Continue Without", command=lambda: choose("skip")).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(buttons, text="Abort", command=lambda: choose("abort")).grid(row=0, column=2)
        dialog.wait_window()
        return result["action"]

    def stage(self, title: str) -> None:
        self._queue.put(("stage", title))

    def info(self, message: str) -> None:
        self._queue.put(("info", message))

    def dependency_failure(self, dep: Any, message: str) -> str:
        event = threading.Event()
        response: dict[str, str] = {}
        self._queue.put(("dependency_prompt", dep, message, response, event))
        event.wait()
        return response.get("action", "abort")

    def summary(self, summary: Any) -> None:
        self._queue.put(("summary", summary))

    def error(self, message: str) -> None:
        self._queue.put(("error", message))


def should_use_installer_ui(args) -> bool:
    return bool(getattr(core.sys, "frozen", False) and not args.console and tk is not None and ttk is not None)


def main(argv: Optional[list[str]] = None) -> int:
    core.ensure_frozen_installer_elevation(argv)
    args = core.parse_args(argv)
    if getattr(core.sys, "frozen", False):
        active_dir = Path(getattr(core.sys, "_MEIPASS")) if hasattr(core.sys, "_MEIPASS") else None
        core.cleanup_stale_mei_directories(active_dir=active_dir)
    if should_use_installer_ui(args):
        return InstallerUI(args).run()
    return core.perform_install(args, reporter=core.InstallReporter())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Installer failed: {exc}", file=core.sys.stderr)
        raise
