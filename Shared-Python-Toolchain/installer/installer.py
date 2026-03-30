"""Native installer bootstrap for SecurityGateway."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import subprocess as std_subprocess
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, List, Optional

tk: ModuleType | None
ttk: ModuleType | None
try:
    import tkinter as tk
    from tkinter import ttk
except Exception:  # pragma: no cover
    tk = None
    ttk = None

INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "SecurityGateway"
RESOURCE_RELATIVE = Path("payload") / "SecurityGateway.exe"
UNINSTALLER_RELATIVE = Path("payload") / "SecurityGateway-Uninstall.exe"
GUIDE_RELATIVE = Path("docs") / "INSTALL_GUIDE.pdf"
DEPENDENCY_MANIFEST_RELATIVE = Path("installer") / "dependencies.json"
UNINSTALL_SCRIPT_NAME = "Uninstall-SecurityGateway.ps1"
PATH_BACKUP_NAME = "user_path_backup.txt"
SYSTEM_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SecurityGateway"
USER_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SecurityGateway"
REPORTS_DIR = USER_DATA_DIR / "reports"
TASK_NAME = "SecurityGatewayAutomation"
PAYLOAD_URL_ENV = "SECURITY_GATEWAY_PAYLOAD_URL"
PAYLOAD_SHA_ENV = "SECURITY_GATEWAY_PAYLOAD_SHA256"
GUIDE_URL_ENV = "SECURITY_GATEWAY_GUIDE_URL"
MANIFEST_PATH_ENV = "SECURITY_GATEWAY_DEPENDENCY_MANIFEST"
MANIFEST_URL_ENV = "SECURITY_GATEWAY_DEPENDENCY_MANIFEST_URL"
DEFAULT_DEPENDENCY_TIMEOUT_SECONDS = 300
LOCKED_FILE_RETRY_ATTEMPTS = 3
LOCKED_FILE_RETRY_DELAY_SECONDS = 0.5


def center_window(root: Any, width: int, height: int) -> None:
    screen_width = int(root.winfo_screenwidth())
    screen_height = int(root.winfo_screenheight())
    x = max((screen_width - width) // 2, 0)
    y = max((screen_height - height) // 2, 0)
    root.geometry(f"{width}x{height}+{x}+{y}")


@dataclass
class ExternalDependency:
    name: str
    optional: bool = False
    download_url: Optional[str] = None
    sha256: Optional[str] = None
    installer_args: Optional[List[str]] = None
    run_installer: bool = False
    copy_to: Optional[str] = None
    winget_id: Optional[str] = None
    winget_args: Optional[List[str]] = None
    timeout_seconds: Optional[int] = None


@dataclass
class InstallTransaction:
    installed_path: Optional[Path] = None
    uninstall_executable: Optional[Path] = None
    previous_user_path: Optional[str] = None
    backup_file: Optional[Path] = None
    shortcut_paths: Optional[List[Path]] = None
    uninstall_script: Optional[Path] = None
    reports_dir: Optional[Path] = None
    automation_task_registered: bool = False


@dataclass
class DependencyInstallResult:
    name: str
    status: str
    method: str
    target: Optional[str] = None
    detail: Optional[str] = None


@dataclass
class InstallSummary:
    installed_path: Path
    reports_dir: Path
    shortcut_paths: List[Path]
    uninstall_executable: Path
    uninstall_script: Path
    dependency_results: List[DependencyInstallResult]


class InstallReporter:
    def stage(self, title: str) -> None:
        print(f"[stage] {title}")

    def info(self, message: str) -> None:
        print(message)

    def dependency_failure(self, dep: ExternalDependency, message: str) -> str:
        return prompt_dependency_failure(dep, message)

    def summary(self, summary: InstallSummary) -> None:
        print_install_summary(summary)

    def error(self, message: str) -> None:
        print(message, file=sys.stderr)


class InstallerUI(InstallReporter):
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

    def __init__(self, args: argparse.Namespace):
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
        self._decision_events: list[threading.Event] = []
        self._install_thread: Optional[threading.Thread] = None
        self._install_done = False
        self._build_ui()

    def _build_ui(self) -> None:
        assert tk is not None and ttk is not None
        style = ttk.Style()
        try:
            style.theme_use("vista")
        except Exception:  # pragma: no cover
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
        ttk.Label(header, text="SecurityGateway Installer", style="Installer.Header.TLabel").grid(
            row=0, column=0, sticky="w"
        )
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
        ttk.Label(progress_frame, textvariable=self.status_var, style="Installer.Subheader.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        self.progress = ttk.Progressbar(
            progress_frame,
            mode="determinate",
            maximum=len(self.STAGES),
            value=0,
        )
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
            perform_install(self.args, reporter=self)
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
                summary: InstallSummary = item[1]
                self._append_log(f"- Application: {summary.installed_path}")
                self._append_log(f"- Reports directory: {summary.reports_dir}")
                self._append_log("- Installed launcher tools: SOC Dashboard, Reports, Install Folder, Uninstaller")
                self._append_log("- Desktop shortcuts:")
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

    def _show_dependency_dialog(self, dep: ExternalDependency, message: str) -> str:
        assert tk is not None and ttk is not None
        dialog = tk.Toplevel(self.root)
        dialog.title("Dependency issue")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.configure(bg="#fdf4f0")
        center_window(dialog, 580, 270)
        dialog.columnconfigure(0, weight=1)
        ttk.Label(
            dialog,
            text=f"Dependency install failed: {dep.name}",
            font=("Segoe UI", 11, "bold"),
            padding=(20, 18, 20, 8),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            dialog,
            text=message,
            wraplength=520,
            padding=(20, 0, 20, 0),
        ).grid(row=1, column=0, sticky="w")
        ttk.Label(
            dialog,
            text="Choose how setup should continue.",
            padding=(20, 14, 20, 10),
        ).grid(row=2, column=0, sticky="w")
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

    def dependency_failure(self, dep: ExternalDependency, message: str) -> str:
        event = threading.Event()
        response: dict[str, str] = {}
        self._queue.put(("dependency_prompt", dep, message, response, event))
        event.wait()
        return response.get("action", "abort")

    def summary(self, summary: InstallSummary) -> None:
        self._queue.put(("summary", summary))

    def error(self, message: str) -> None:
        self._queue.put(("error", message))


def resolve_powershell_executable() -> str:
    return (
        shutil.which("pwsh")
        or shutil.which("powershell.exe")
        or shutil.which("powershell")
        or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )


def ensure_admin() -> None:
    if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        raise PermissionError("Please run this installer as Administrator.")


def ensure_frozen_installer_elevation(argv: Optional[list[str]] = None) -> None:
    if not getattr(sys, "frozen", False):
        return
    if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        return
    raw_args = list(sys.argv[1:] if argv is None else argv)
    executable = sys.executable
    parameters = std_subprocess.list2cmdline(raw_args) if raw_args else ""
    result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
        None,
        "runas",
        executable,
        parameters,
        None,
        1,
    )
    if int(result) <= 32:
        raise PermissionError("Please run this installer as Administrator.")
    raise SystemExit(0)


def resolve_resource(rel_path: Path) -> Path:
    if hasattr(sys, "_MEIPASS"):
        base = Path(getattr(sys, "_MEIPASS"))
        candidates = [base / rel_path]
    else:
        project_root = Path(__file__).resolve().parents[1]
        candidates = [project_root / rel_path]
        if rel_path == RESOURCE_RELATIVE:
            candidates.append(project_root / "dist" / "SecurityGateway.exe")
        if rel_path == UNINSTALLER_RELATIVE:
            candidates.append(project_root / "dist" / "SecurityGateway-Uninstall.exe")
    for resource in candidates:
        if resource.exists():
            return resource
    raise FileNotFoundError(f"Embedded resource missing: {candidates[0]}")


def resolve_optional_resource(rel_path: Path) -> Optional[Path]:
    try:
        resource = resolve_resource(rel_path)
    except FileNotFoundError:
        return None
    return resource


def materialize_external_resource(path: Path, *, target_dir: Optional[Path] = None) -> Path:
    destination_root = target_dir or (USER_DATA_DIR / "docs")
    destination_root.mkdir(parents=True, exist_ok=True)
    destination = destination_root / path.name
    shutil.copy2(path, destination)
    return destination


def cleanup_stale_mei_directories(
    *,
    temp_root: Optional[Path] = None,
    active_dir: Optional[Path] = None,
    stale_after_minutes: int = 10,
) -> list[Path]:
    root = temp_root or Path(tempfile.gettempdir())
    if not root.exists():
        return []
    active_resolved = active_dir.resolve() if active_dir is not None and active_dir.exists() else None
    cutoff = datetime.now(UTC) - timedelta(minutes=stale_after_minutes)
    removed: list[Path] = []
    for candidate in root.iterdir():
        if not candidate.is_dir() or not candidate.name.startswith("_MEI"):
            continue
        try:
            resolved = candidate.resolve()
        except OSError:
            resolved = candidate
        if active_resolved is not None and resolved == active_resolved:
            continue
        try:
            modified_at = datetime.fromtimestamp(candidate.stat().st_mtime, UTC)
        except OSError:
            continue
        if modified_at > cutoff:
            continue
        try:
            shutil.rmtree(candidate)
        except OSError:
            continue
        removed.append(candidate)
    return removed


def download_file(
    url: str,
    description: str,
    expected_sha256: Optional[str] = None,
    timeout_seconds: int = DEFAULT_DEPENDENCY_TIMEOUT_SECONDS,
) -> Path:
    parsed = urllib.parse.urlparse(url)
    filename = Path(parsed.path).name or f"{description.replace(' ', '_')}.bin"
    temp_dir = Path(tempfile.mkdtemp(prefix="sgw_dl_"))
    target = temp_dir / filename
    print(f"Downloading {description} from {url} ...")
    with urllib.request.urlopen(url, timeout=timeout_seconds) as response, open(target, "wb") as handle:
        shutil.copyfileobj(response, handle)
    if expected_sha256:
        verify_sha256(target, expected_sha256)
    return target


def verify_sha256(path: Path, expected: str) -> None:
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            sha.update(chunk)
    digest = sha.hexdigest()
    if digest.lower() != expected.lower():
        raise ValueError(f"SHA256 mismatch for {path.name}: expected {expected}, got {digest}")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SecurityGateway installer")
    parser.add_argument("--payload-url", help="Override payload download URL")
    parser.add_argument("--payload-sha256", help="Expected SHA256 for payload download")
    parser.add_argument("--guide-url", help="Override install guide download URL")
    parser.add_argument("--dependency-manifest", help="Path or URL to dependency manifest JSON")
    parser.add_argument("--skip-dependencies", action="store_true", help="Skip prerequisite dependency installation")
    parser.add_argument("--console", action="store_true", help="Use the console installer flow even when the GUI is available")
    return parser.parse_args(argv)


def copy_binary(src: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / src.name
    last_error: PermissionError | None = None
    for attempt in range(LOCKED_FILE_RETRY_ATTEMPTS):
        try:
            shutil.copy2(src, target)
            return target
        except PermissionError as exc:
            if not _is_locked_file_error(exc):
                raise
            last_error = exc
            _terminate_processes_for_binary(target)
            time.sleep(LOCKED_FILE_RETRY_DELAY_SECONDS * (attempt + 1))
    if last_error is not None:
        raise last_error
    raise RuntimeError(f"Failed to copy {src} to {target}")


def _is_locked_file_error(exc: PermissionError) -> bool:
    return getattr(exc, "winerror", None) == 32


def _terminate_processes_for_binary(target: Path) -> None:
    subprocess.run(
        ["taskkill", "/IM", target.name, "/F"],
        check=False,
        stdout=std_subprocess.DEVNULL,
        stderr=std_subprocess.DEVNULL,
    )


def update_user_path(dir_path: Path) -> str:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_ALL_ACCESS) as key:
        try:
            path_value, _ = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            path_value = ""
        previous = path_value or ""
        segments = path_value.split(";") if path_value else []
        if str(dir_path) in segments:
            return previous
        segments.append(str(dir_path))
        new_value = ";".join(filter(None, segments))
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_value)
        written, _ = winreg.QueryValueEx(key, "Path")
        if written != new_value:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, previous)
            raise RuntimeError("Failed to update user PATH; registry write verification failed.")
        return previous
    return ""


def restore_user_path(previous: str) -> None:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_ALL_ACCESS) as key:
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, previous)


def resolve_desktop_roots() -> List[Path]:
    roots: list[Path] = []
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        roots.append(Path(user_profile) / "Desktop")
        roots.append(Path(user_profile) / "OneDrive" / "Desktop")
    seen: set[str] = set()
    resolved: list[Path] = []
    for root in roots:
        key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        resolved.append(root)
    return resolved


def create_shortcut(exe_path: Path) -> List[Path]:
    shortcut_paths = [root / "SecurityGateway.lnk" for root in resolve_desktop_roots()]
    ps_targets = ", ".join(_ps_quote(str(path)) for path in shortcut_paths)
    ps_script = f"$targets=@({ps_targets}); foreach($shortcutPath in $targets) {{"
    ps_script += "New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($shortcutPath)) | Out-Null;"
    ps_script += "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath);"
    ps_script += f"$s.TargetPath={_ps_quote(str(exe_path))};"
    ps_script += f"$s.WorkingDirectory={_ps_quote(str(exe_path.parent))};"
    ps_script += "$s.Save() }"
    subprocess.run([resolve_powershell_executable(), "-NoProfile", "-Command", ps_script], check=True)
    return shortcut_paths


def create_reports_directory() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def register_automation_task(exe_path: Path) -> None:
    ps_script = f"""
$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute {_ps_quote(str(exe_path))} -Argument 'automation-run'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$existing = Get-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -ErrorAction SilentlyContinue
if ($existing) {{
    Unregister-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -Confirm:$false
}}
Register-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
"""
    subprocess.run(
        [resolve_powershell_executable(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        check=True,
    )


def unregister_automation_task() -> None:
    ps_script = f"""
$task = Get-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -ErrorAction SilentlyContinue
if ($task) {{
    Unregister-ScheduledTask -TaskName {_ps_quote(TASK_NAME)} -Confirm:$false
}}
"""
    subprocess.run(
        [resolve_powershell_executable(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
        check=True,
    )


def write_uninstall_script(installed_path: Path, path_backup_file: Path) -> Path:
    script_path = installed_path.parent / UNINSTALL_SCRIPT_NAME
    shortcut_paths = [path / "SecurityGateway.lnk" for path in resolve_desktop_roots()]
    shortcut_path_block = ", ".join(f'"{path}"' for path in shortcut_paths)
    system_data = SYSTEM_DATA_DIR
    user_data = USER_DATA_DIR
    script = f"""\
param(
    [string]$InstallDir = "{installed_path.parent}",
    [string]$SystemDataPath = "{system_data}",
    [string]$UserDataPath = "{user_data}",
    [string]$PathBackupFile = "{path_backup_file}",
    [string]$TaskName = "{TASK_NAME}"
)

function Assert-Admin {{
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
        throw "Please run this script in an elevated PowerShell session."
    }}
}}

function Remove-PathEntry {{
    param([string]$Dir)
    $path = [Environment]::GetEnvironmentVariable('Path','User')
    if (-not $path) {{ return }}
    $updated = ($path -split ';') | Where-Object {{ $_ -and ($_ -ne $Dir) }}
    [Environment]::SetEnvironmentVariable('Path', ($updated -join ';'), 'User')
}}

function Restore-PathFromBackup {{
    param([string]$File)
    if (-not (Test-Path $File)) {{ return $false }}
    $backupValue = Get-Content $File -Raw
    [Environment]::SetEnvironmentVariable('Path', $backupValue, 'User')
    Remove-Item $File -Force
    return $true
}}

function Remove-AutomationTask {{
    param([string]$Name)
    $task = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($task) {{
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    }}
}}

try {{
    Assert-Admin
    foreach ($ShortcutPath in @({shortcut_path_block})) {{
        if (Test-Path $ShortcutPath) {{ Remove-Item $ShortcutPath -Force }}
    }}
    $restored = Restore-PathFromBackup -File $PathBackupFile
    Remove-PathEntry -Dir $InstallDir
    Remove-AutomationTask -Name $TaskName
    foreach ($target in @($InstallDir, $SystemDataPath, $UserDataPath)) {{
        if (Test-Path $target) {{
            Remove-Item -Recurse -Force $target
        }}
    }}
    Write-Host "SecurityGateway uninstalled. Residual data directories removed."
    Write-Host "Restart your terminal to refresh PATH."
}} catch {{
    Write-Error $_
    exit 1
}}
"""
    script_path.write_text(script, encoding="utf-8")
    return script_path


def rollback_install(transaction: InstallTransaction) -> None:
    cleanup_errors: list[str] = []

    if transaction.automation_task_registered:
        try:
            unregister_automation_task()
        except Exception as exc:  # noqa: BLE001
            cleanup_errors.append(f"scheduled task rollback failed: {exc}")

    shortcut_paths = transaction.shortcut_paths or []
    for path in (
        transaction.uninstall_executable,
        transaction.uninstall_script,
        *shortcut_paths,
        transaction.backup_file,
        transaction.installed_path,
    ):
        if not path:
            continue
        try:
            if path.exists():
                path.unlink()
        except Exception as exc:  # noqa: BLE001
            cleanup_errors.append(f"cleanup failed for {path}: {exc}")

    if transaction.previous_user_path is not None:
        try:
            restore_user_path(transaction.previous_user_path)
        except Exception as exc:  # noqa: BLE001
            cleanup_errors.append(f"PATH rollback failed: {exc}")

    if transaction.installed_path:
        try:
            install_dir = transaction.installed_path.parent
            if install_dir.exists() and not any(install_dir.iterdir()):
                install_dir.rmdir()
        except Exception as exc:  # noqa: BLE001
            cleanup_errors.append(f"install directory cleanup failed: {exc}")

    if transaction.reports_dir:
        try:
            if transaction.reports_dir.exists() and not any(transaction.reports_dir.iterdir()):
                transaction.reports_dir.rmdir()
            if USER_DATA_DIR.exists() and not any(USER_DATA_DIR.iterdir()):
                USER_DATA_DIR.rmdir()
        except Exception as exc:  # noqa: BLE001
            cleanup_errors.append(f"reports directory cleanup failed: {exc}")

    if cleanup_errors:
        raise RuntimeError("Install rollback was incomplete: " + " | ".join(cleanup_errors))


def show_install_guide(override_url: Optional[str] = None, reporter: Optional[InstallReporter] = None) -> None:
    reporter = reporter or InstallReporter()
    if override_url:
        guide = download_file(override_url, "installation guide PDF")
    else:
        guide = resolve_resource(GUIDE_RELATIVE)
        if hasattr(sys, "_MEIPASS"):
            guide = materialize_external_resource(guide)
    reporter.info(f"Opening installation guide: {guide}")
    opened = False
    try:
        os.startfile(guide)  # type: ignore[attr-defined]
        opened = True
    except OSError as exc:
        reporter.info(f"Unable to open guide automatically (no default PDF app?): {exc}")
        try:
            subprocess.run(["explorer", "/select,", str(guide)], check=False)
            reporter.info("Opened File Explorer so you can launch the PDF manually.")
        except Exception as explorer_exc:  # pragma: no cover
            reporter.info(f"Also failed to open File Explorer: {explorer_exc}")
        reporter.info("If you do not have a PDF reader installed, install one (e.g., Edge, Acrobat) and open the guide manually.")
    if opened:
        reporter.info("Installation guide opened. Setup will continue immediately.")
    else:
        reporter.info(f"Guide path: {guide}")
        reporter.info("Setup will continue immediately.")


def resolve_manifest_reference(ref: Optional[str]) -> Optional[Path]:
    if not ref:
        return resolve_optional_resource(DEPENDENCY_MANIFEST_RELATIVE)
    if ref.startswith(("http://", "https://")):
        return download_file(ref, "dependency manifest")
    path = Path(ref)
    if not path.exists():
        raise FileNotFoundError(f"Dependency manifest not found: {path}")
    return path


def load_dependency_manifest(path: Optional[Path]) -> List[ExternalDependency]:
    if not path or not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    dependencies: List[ExternalDependency] = []
    for entry in data:
        dependencies.append(
            ExternalDependency(
                name=entry["name"],
                optional=entry.get("optional", False),
                download_url=entry.get("url"),
                sha256=entry.get("sha256"),
                installer_args=entry.get("installer_args"),
                run_installer=entry.get("run_installer", False),
                copy_to=entry.get("copy_to"),
                winget_id=entry.get("winget_id"),
                winget_args=entry.get("winget_args"),
                timeout_seconds=entry.get("timeout_seconds"),
            )
        )
    return dependencies


def install_external_dependencies(
    dependencies: List[ExternalDependency],
    reporter: Optional[InstallReporter] = None,
) -> List[DependencyInstallResult]:
    reporter = reporter or InstallReporter()
    if not dependencies:
        return []
    results: list[DependencyInstallResult] = []
    reporter.info(f"Installing {len(dependencies)} prerequisite program(s)...")
    for dep in dependencies:
        reporter.info(f"- Ensuring {dep.name}")
        while True:
            try:
                results.append(install_dependency(dep))
                break
            except Exception as exc:  # noqa: BLE001
                if dep.optional:
                    reporter.info(f"- Skipping optional dependency {dep.name}: {exc}")
                    results.append(
                        DependencyInstallResult(
                            name=dep.name,
                            status="skipped",
                            method="optional",
                            target=dep.winget_id or dep.download_url,
                            detail=str(exc),
                        )
                    )
                    break
                action = reporter.dependency_failure(dep, str(exc))
                if action == "retry":
                    continue
                if action == "skip":
                    results.append(
                        DependencyInstallResult(
                            name=dep.name,
                            status="skipped",
                            method="skipped",
                            target=dep.winget_id or dep.download_url,
                            detail=str(exc),
                        )
                    )
                    break
                raise RuntimeError(f"Dependency installation aborted for {dep.name}: {exc}") from exc
    return results


def install_dependency(dep: ExternalDependency) -> DependencyInstallResult:
    timeout_seconds = dep.timeout_seconds or DEFAULT_DEPENDENCY_TIMEOUT_SECONDS
    if dep.winget_id and shutil.which("winget"):
        cmd = [
            "winget",
            "install",
            "--id",
            dep.winget_id,
            "--source",
            "winget",
            "--accept-source-agreements",
            "--accept-package-agreements",
        ]
        if dep.winget_args:
            cmd.extend(dep.winget_args)
        subprocess.run(cmd, check=True, timeout=timeout_seconds)
        return DependencyInstallResult(name=dep.name, status="installed", method="winget", target=dep.winget_id)
    if dep.download_url:
        target = download_file(dep.download_url, dep.name, dep.sha256, timeout_seconds=timeout_seconds)
        if dep.copy_to:
            destination = Path(dep.copy_to)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, destination)
            target = destination
        if dep.run_installer:
            args = dep.installer_args or []
            subprocess.run([str(target), *args], check=True, timeout=timeout_seconds)
            return DependencyInstallResult(name=dep.name, status="installed", method="download+run", target=str(target))
        return DependencyInstallResult(name=dep.name, status="installed", method="download", target=str(target))
    raise RuntimeError(f"No installation method available for {dep.name}")


def print_install_summary(summary: InstallSummary) -> None:
    print("")
    print("Install complete:")
    print(f"- Application: {summary.installed_path}")
    print(f"- Reports directory: {summary.reports_dir}")
    print("- Installed launcher tools: SOC Dashboard, Reports, Install Folder, Uninstaller")
    print("- Desktop shortcuts:")
    for shortcut_path in summary.shortcut_paths:
        print(f"  - {shortcut_path}")
    if summary.dependency_results:
        print("- Dependencies:")
        for result in summary.dependency_results:
            target_suffix = f" ({result.target})" if result.target else ""
            detail_suffix = f" - {result.detail}" if result.detail else ""
            print(f"  - {result.name}: {result.status} via {result.method}{target_suffix}{detail_suffix}")
    else:
        print("- Dependencies: none")
    print(f"- Uninstall executable: {summary.uninstall_executable}")
    print(f"- Uninstall script: {summary.uninstall_script}")
    print("- PATH updated for current user. Sign out/in or restart terminal to use immediately.")


def prompt_dependency_failure(dep: ExternalDependency, message: str) -> str:
    text = (
        f"Dependency installation failed for {dep.name}.\n\n"
        f"{message}\n\n"
        "Retry the dependency install, continue without it, or abort setup?"
    )
    try:
        result = ctypes.windll.user32.MessageBoxW(  # type: ignore[attr-defined]
            None,
            text,
            "SecurityGateway Installer",
            0x00000002 | 0x00000030,
        )
    except Exception:  # noqa: BLE001
        return "abort"
    if result == 4:
        return "retry"
    if result == 5:
        return "skip"
    return "abort"


def perform_install(args: argparse.Namespace, reporter: Optional[InstallReporter] = None) -> int:
    reporter = reporter or InstallReporter()
    ensure_admin()

    guide_url = args.guide_url or os.environ.get(GUIDE_URL_ENV)
    reporter.stage("Opening install guide")
    show_install_guide(guide_url, reporter=reporter)

    payload_url = args.payload_url or os.environ.get(PAYLOAD_URL_ENV)
    payload_sha = args.payload_sha256 or os.environ.get(PAYLOAD_SHA_ENV)
    reporter.stage("Resolving payload")
    resource = (
        download_file(payload_url, "SecurityGateway payload", payload_sha)
        if payload_url
        else resolve_resource(RESOURCE_RELATIVE)
    )
    uninstall_resource = resolve_resource(UNINSTALLER_RELATIVE)

    dependency_results: List[DependencyInstallResult] = []
    if args.skip_dependencies:
        reporter.stage("Installing prerequisites")
        reporter.info("Skipping prerequisite dependency installation.")
    else:
        manifest_ref = (
            args.dependency_manifest
            or os.environ.get(MANIFEST_PATH_ENV)
            or os.environ.get(MANIFEST_URL_ENV)
        )
        manifest_path = resolve_manifest_reference(manifest_ref)
        dependencies = load_dependency_manifest(manifest_path)
        reporter.stage("Installing prerequisites")
        dependency_results = install_external_dependencies(dependencies, reporter=reporter)

    transaction = InstallTransaction()
    try:
        reporter.stage("Copying application files")
        installed_path = copy_binary(resource, INSTALL_DIR)
        transaction.installed_path = installed_path
        uninstall_executable = copy_binary(uninstall_resource, INSTALL_DIR)
        transaction.uninstall_executable = uninstall_executable
        transaction.reports_dir = create_reports_directory()
        reporter.info(f"Reports will be stored at {transaction.reports_dir}")
        reporter.stage("Updating PATH")
        previous_path = update_user_path(INSTALL_DIR)
        transaction.previous_user_path = previous_path
        backup_file = installed_path.parent / PATH_BACKUP_NAME
        backup_file.write_text(previous_path, encoding="utf-8")
        transaction.backup_file = backup_file
        reporter.stage("Creating shortcuts")
        transaction.shortcut_paths = create_shortcut(installed_path)
        reporter.stage("Registering automation task")
        register_automation_task(installed_path)
        transaction.automation_task_registered = True
        reporter.stage("Installing uninstaller")
        reporter.stage("Writing uninstall script")
        uninstall_script = write_uninstall_script(installed_path, backup_file)
        transaction.uninstall_script = uninstall_script
    except Exception as exc:
        try:
            rollback_install(transaction)
        except Exception as rollback_exc:
            message = f"Installer failed: {exc}. Rollback also failed: {rollback_exc}"
            reporter.error(message)
            raise RuntimeError(message) from exc
        message = f"Installer failed before completion: {exc}"
        reporter.error(message)
        raise RuntimeError(message) from exc
    reporter.stage("Finishing")
    reporter.summary(
        InstallSummary(
            installed_path=installed_path,
            reports_dir=transaction.reports_dir or REPORTS_DIR,
            shortcut_paths=transaction.shortcut_paths or [],
            uninstall_executable=uninstall_executable,
            uninstall_script=uninstall_script,
            dependency_results=dependency_results,
        )
    )
    return 0


def should_use_installer_ui(args: argparse.Namespace) -> bool:
    return bool(getattr(sys, "frozen", False) and not args.console and tk is not None and ttk is not None)


def run_installer_ui(args: argparse.Namespace) -> int:
    ui = InstallerUI(args)
    return ui.run()


def main(argv: Optional[list[str]] = None) -> int:
    ensure_frozen_installer_elevation(argv)
    args = parse_args(argv)
    if getattr(sys, "frozen", False):
        active_dir = Path(getattr(sys, "_MEIPASS")) if hasattr(sys, "_MEIPASS") else None
        cleanup_stale_mei_directories(active_dir=active_dir)
    if should_use_installer_ui(args):
        return run_installer_ui(args)
    return perform_install(args, reporter=InstallReporter())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Installer failed: {exc}", file=sys.stderr)
        raise
