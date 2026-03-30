"""Lightweight desktop launcher for the installed Security Gateway app."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    from .config import get_runtime_data_dir
except ImportError:  # pragma: no cover - frozen entrypoint fallback
    from security_gateway.config import get_runtime_data_dir


def _alert_popup_state() -> bool:
    try:
        from .alerts import alert_manager
    except ImportError:  # pragma: no cover - frozen entrypoint fallback
        from security_gateway.alerts import alert_manager
    return bool(alert_manager.is_toast_enabled())


def _toggle_alert_popups() -> bool:
    try:
        from .alerts import alert_manager
    except ImportError:  # pragma: no cover - frozen entrypoint fallback
        from security_gateway.alerts import alert_manager
    next_state = not alert_manager.is_toast_enabled()
    alert_manager.set_toast_enabled(next_state)
    return next_state


def _center_window(root: Any, width: int, height: int) -> None:
    screen_width = int(root.winfo_screenwidth())
    screen_height = int(root.winfo_screenheight())
    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)
    root.geometry(f"{width}x{height}+{x}+{y}")


def _reports_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SecurityGateway" / "reports"


def _install_dir() -> Path:
    executable = Path(getattr(sys, "executable", "")).resolve()
    if executable.exists():
        return executable.parent
    return Path.cwd()


def _resolve_uninstaller_path() -> Path | None:
    install_dir = _install_dir()
    for candidate in (
        install_dir / "SecurityGateway-Uninstall.exe",
        install_dir / "Uninstall-SecurityGateway.ps1",
    ):
        if candidate.exists():
            return candidate
    return None


def _open_reports_folder() -> None:
    reports_dir = _reports_dir()
    reports_dir.mkdir(parents=True, exist_ok=True)
    os.startfile(str(reports_dir))  # type: ignore[attr-defined]


def _open_install_folder() -> None:
    os.startfile(str(_install_dir()))  # type: ignore[attr-defined]


def _launch_uninstaller() -> None:
    target = _resolve_uninstaller_path()
    if target is None:
        raise FileNotFoundError("Security Gateway uninstaller was not found.")
    if target.suffix.lower() == ".ps1":
        subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", str(target)])
        return
    os.startfile(str(target))  # type: ignore[attr-defined]


def _ensure_runtime_directories() -> None:
    runtime_root = get_runtime_data_dir()
    for directory in (runtime_root, runtime_root / "logs", runtime_root / "reports"):
        directory.mkdir(parents=True, exist_ok=True)


def _run_background_monitor() -> None:
    try:
        from .monitor_runtime import run_background_monitor
    except ImportError:  # pragma: no cover - frozen entrypoint fallback
        from security_gateway.monitor_runtime import run_background_monitor
    run_background_monitor()


def _run_soc_dashboard() -> None:
    try:
        from .soc_dashboard import run_soc_dashboard
    except ImportError:  # pragma: no cover - frozen entrypoint fallback
        from security_gateway.soc_dashboard import run_soc_dashboard
    run_soc_dashboard()


def main() -> int:
    import tkinter as tk
    from tkinter import messagebox

    _ensure_runtime_directories()
    if len(sys.argv) > 1 and sys.argv[1] == "automation-run":
        _run_background_monitor()
        return 0

    root = tk.Tk()
    root.title("Security Gateway")
    root.configure(bg="#eef4ff")
    root.resizable(False, False)
    _center_window(root, 620, 420)
    popup_status_var = tk.StringVar(value=f"Popup alerts: {'On' if _alert_popup_state() else 'Off'}")

    def run_action(action: str) -> None:
        try:
            if action == "reports":
                _open_reports_folder()
            elif action == "soc-dashboard":
                _run_soc_dashboard()
                return
            elif action == "install-folder":
                _open_install_folder()
            elif action == "uninstall":
                _launch_uninstaller()
            elif action == "toggle-alert-popups":
                popup_status_var.set(f"Popup alerts: {'On' if _toggle_alert_popups() else 'Off'}")
                return
            elif action == "exit":
                root.destroy()
                return
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Security Gateway", str(exc))
            return
        root.destroy()

    menu_bar = tk.Menu(root)
    tools_menu = tk.Menu(menu_bar, tearoff=False)
    tools_menu.add_command(label="SOC Dashboard", command=lambda: run_action("soc-dashboard"))
    tools_menu.add_separator()
    tools_menu.add_command(label="Toggle Popup Alerts", command=lambda: run_action("toggle-alert-popups"))
    tools_menu.add_separator()
    tools_menu.add_command(label="Open Reports Folder", command=lambda: run_action("reports"))
    tools_menu.add_command(label="Open Install Folder", command=lambda: run_action("install-folder"))
    tools_menu.add_command(label="Run Uninstaller", command=lambda: run_action("uninstall"))
    tools_menu.add_separator()
    tools_menu.add_command(label="Exit", command=lambda: run_action("exit"))
    menu_bar.add_cascade(label="Tools", menu=tools_menu)
    root.config(menu=menu_bar)

    frame = tk.Frame(root, padx=28, pady=28, bg="#eef4ff")
    frame.pack(fill="both", expand=True)

    tk.Label(
        frame,
        text="Security Gateway Tools",
        font=("Segoe UI", 18, "bold"),
        bg="#eef4ff",
        fg="#13315c",
    ).pack(fill="x", pady=(0, 10))
    tk.Label(
        frame,
        text="Use the Tools menu or the buttons below to open dashboards, reports, and maintenance actions.",
        font=("Segoe UI", 11, "bold"),
        justify="left",
        anchor="w",
        bg="#eef4ff",
        fg="#2f3e52",
    ).pack(fill="x", pady=(0, 20))
    tk.Label(
        frame,
        textvariable=popup_status_var,
        font=("Segoe UI", 10, "bold"),
        justify="left",
        anchor="w",
        bg="#eef4ff",
        fg="#8a1538",
    ).pack(fill="x", pady=(0, 14))

    button_specs = [
        ("SOC Dashboard", "#7c3aed", "white", "soc-dashboard"),
        ("Toggle Popup Alerts", "#b45309", "white", "toggle-alert-popups"),
        ("Open Reports Folder", "#1f6feb", "white", "reports"),
        ("Open Install Folder", "#2d6a4f", "white", "install-folder"),
        ("Run Uninstaller", "#b44c2f", "white", "uninstall"),
        ("Exit", "#d8e0ef", "#1f2a37", "exit"),
    ]
    def _make_action_callback(action_name: str):
        return lambda: run_action(action_name)

    for text, bg, fg, action in button_specs:
        tk.Button(
            frame,
            text=text,
            width=38,
            font=("Segoe UI", 11, "bold"),
            bg=bg,
            fg=fg,
            activebackground=bg,
            activeforeground=fg,
            relief="flat",
            padx=12,
            pady=10,
            command=_make_action_callback(action),
        ).pack(pady=7)

    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
