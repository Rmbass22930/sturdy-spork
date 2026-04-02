"""Native installer bootstrap for SecurityGateway."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import subprocess as std_subprocess
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
from typing import List, Optional

INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "SecurityGateway"
PAYLOAD_BUNDLE_NAME = "SecurityGateway"
UNINSTALLER_BUNDLE_NAME = "SecurityGateway-Uninstall"
RESOURCE_RELATIVE = Path("payload") / PAYLOAD_BUNDLE_NAME / "SecurityGateway.exe"
UNINSTALLER_RELATIVE = Path("payload") / UNINSTALLER_BUNDLE_NAME / "SecurityGateway-Uninstall.exe"
GUIDE_RELATIVE = Path("docs") / "INSTALL_GUIDE.pdf"
DEPENDENCY_MANIFEST_RELATIVE = Path("installer") / "dependencies.json"
UNINSTALL_SCRIPT_NAME = "Uninstall-SecurityGateway.ps1"
REGISTER_STARTUP_SCRIPT_NAME = "Register-SecurityGatewayMonitor.ps1"
PATH_BACKUP_NAME = "user_path_backup.txt"
SYSTEM_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SecurityGateway"
USER_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SecurityGateway"
REPORTS_DIR = USER_DATA_DIR / "reports"
TASK_NAME = "SecurityGatewayMonitor"
LEGACY_TASK_NAMES = ("SecurityGatewayAutomation",)
PAYLOAD_URL_ENV = "SECURITY_GATEWAY_PAYLOAD_URL"
PAYLOAD_SHA_ENV = "SECURITY_GATEWAY_PAYLOAD_SHA256"
GUIDE_URL_ENV = "SECURITY_GATEWAY_GUIDE_URL"
MANIFEST_PATH_ENV = "SECURITY_GATEWAY_DEPENDENCY_MANIFEST"
MANIFEST_URL_ENV = "SECURITY_GATEWAY_DEPENDENCY_MANIFEST_URL"
DEFAULT_DEPENDENCY_TIMEOUT_SECONDS = 300
LOCKED_FILE_RETRY_ATTEMPTS = 3
LOCKED_FILE_RETRY_DELAY_SECONDS = 0.5
GUIDE_AUTO_CLOSE_SECONDS = 30
TASK_REGISTRATION_LOG = USER_DATA_DIR / "installer" / "task-registration.log"
SMOKE_TEST_DIR_NAME = "SecurityGatewaySmoke"
UNINSTALLER_INSTALL_SUBDIR = "uninstall"
SHORTCUT_SPECS: tuple[tuple[str, str, str], ...] = (
    ("SecurityGateway.lnk", "", "Security Gateway Tools"),
    ("SecurityGateway SOC Dashboard.lnk", "soc-dashboard", "Security Gateway SOC Dashboard"),
)


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
    register_startup_script: Optional[Path] = None
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
    register_startup_script: Path
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


def resolve_powershell_executable() -> str:
    return (
        shutil.which("pwsh")
        or shutil.which("powershell.exe")
        or shutil.which("powershell")
        or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )


def load_tk_modules():
    try:
        import tkinter as tk  # type: ignore[import-not-found]
        from tkinter import messagebox, ttk  # type: ignore[import-not-found]
    except Exception:  # pragma: no cover
        return None, None, None
    return tk, ttk, messagebox


def ensure_admin() -> None:
    if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        raise PermissionError("Please run this installer as Administrator.")


def ensure_frozen_installer_elevation(argv: Optional[list[str]] = None) -> None:
    if not getattr(sys, "frozen", False):
        return
    raw_args = list(sys.argv[1:] if argv is None else argv)
    try:
        parsed_args = parse_args(raw_args)
    except SystemExit:
        parsed_args = None
    if parsed_args is not None and parsed_args.smoke_test:
        return
    if ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        return
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
            payload_override = os.environ.get("SECURITY_GATEWAY_PAYLOAD_PATH")
            if payload_override:
                override_path = Path(payload_override)
                candidates.insert(0, override_path if override_path.is_file() else override_path / "SecurityGateway.exe")
            candidates.append(project_root / "dist" / PAYLOAD_BUNDLE_NAME / "SecurityGateway.exe")
            candidates.append(project_root / "dist" / "SecurityGateway.exe")
        if rel_path == UNINSTALLER_RELATIVE:
            uninstaller_override = os.environ.get("SECURITY_GATEWAY_UNINSTALLER_PATH")
            if uninstaller_override:
                override_path = Path(uninstaller_override)
                candidates.insert(
                    0,
                    override_path if override_path.is_file() else override_path / "SecurityGateway-Uninstall.exe",
                )
            candidates.append(project_root / "dist" / UNINSTALLER_BUNDLE_NAME / "SecurityGateway-Uninstall.exe")
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
    if destination.exists():
        try:
            source_stat = path.stat()
            destination_stat = destination.stat()
            if source_stat.st_size == destination_stat.st_size:
                return destination
        except OSError:
            pass
        destination = destination_root / f"{path.stem}-{int(time.time())}{path.suffix}"
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


def _foreground_window_pid() -> Optional[int]:
    try:
        hwnd = ctypes.windll.user32.GetForegroundWindow()  # type: ignore[attr-defined]
        if not hwnd:
            return None
        pid = ctypes.c_ulong()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))  # type: ignore[attr-defined]
        return int(pid.value) or None
    except Exception:
        return None


def _launch_guide_process(guide: Path) -> Optional[int]:
    command = (
        f"$p = Start-Process -FilePath {_ps_quote(str(guide))} -PassThru; "
        "if ($p) { $p.Id }"
    )
    result = subprocess.run(
        [resolve_powershell_executable(), "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    output = (result.stdout or "").strip()
    return int(output) if output.isdigit() else None


def _schedule_guide_auto_close(pid: Optional[int], *, timeout_seconds: int, reporter: InstallReporter) -> None:
    if pid is None:
        reporter.info(
            "Installation guide will stay open until you close it because the viewer did not expose a dedicated process."
        )
        return
    reporter.info(
        f"Installation guide will auto-close after {timeout_seconds} seconds unless you click into it to keep it open."
    )

    def _worker() -> None:
        interacted = False
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if _foreground_window_pid() == pid:
                interacted = True
                break
            time.sleep(0.5)
        if interacted:
            reporter.info("Installation guide was clicked. Leaving it open.")
            return
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            check=False,
            capture_output=True,
            text=True,
        )

    threading.Thread(target=_worker, name="guide-auto-close", daemon=True).start()


def _offer_to_print_install_guide(guide: Path, reporter: InstallReporter) -> None:
    reporter.info("You can print the installation guide now if you want a paper copy.")
    tk, _, messagebox = load_tk_modules()
    if messagebox is None or tk is None:
        reporter.info("Open the guide in your PDF viewer and use Print if you want a paper copy.")
        return
    try:
        prompt_root = tk.Tk()
        prompt_root.withdraw()
        should_print = bool(
            messagebox.askyesno(
                "Print Guide",
                "Do you want to print the installation guide now?",
                parent=prompt_root,
            )
        )
        prompt_root.destroy()
    except Exception:
        reporter.info("Open the guide in your PDF viewer and use Print if you want a paper copy.")
        return
    if not should_print:
        return
    try:
        os.startfile(str(guide), "print")  # type: ignore[attr-defined]
        reporter.info("Sent the installation guide to the default printer.")
    except Exception as exc:
        reporter.info(f"Unable to print the installation guide automatically: {exc}")
        reporter.info("Use your PDF viewer's Print command if you still want a paper copy.")


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
    parser.add_argument("--install-dir", help="Override installation directory")
    parser.add_argument("--skip-dependencies", action="store_true", help="Skip prerequisite dependency installation")
    parser.add_argument("--smoke-test", action="store_true", help="Install into a repo-local target without machine-wide integration")
    parser.add_argument("--console", action="store_true", help="Use the console installer flow even when the GUI is available")
    return parser.parse_args(argv)


def resolve_install_dir(args: argparse.Namespace) -> Path:
    install_dir = getattr(args, "install_dir", None)
    if install_dir:
        return Path(install_dir).expanduser().resolve()
    if getattr(args, "smoke_test", False):
        return (Path(tempfile.gettempdir()) / SMOKE_TEST_DIR_NAME).resolve()
    return INSTALL_DIR


def resolve_system_data_dir(args: argparse.Namespace) -> Path:
    if getattr(args, "smoke_test", False):
        return resolve_install_dir(args) / "system-data"
    return SYSTEM_DATA_DIR


def resolve_user_data_dir(args: argparse.Namespace) -> Path:
    if getattr(args, "smoke_test", False):
        return resolve_install_dir(args) / "user-data"
    return USER_DATA_DIR


def resolve_reports_dir(args: argparse.Namespace) -> Path:
    if getattr(args, "smoke_test", False):
        return resolve_user_data_dir(args) / "reports"
    return REPORTS_DIR


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


def copy_bundle(src_executable: Path, dest_dir: Path) -> Path:
    bundle_root = src_executable.parent
    if bundle_root.name != src_executable.stem:
        return copy_binary(src_executable, dest_dir)

    dest_dir.mkdir(parents=True, exist_ok=True)
    for source_path in bundle_root.rglob("*"):
        relative_path = source_path.relative_to(bundle_root)
        target_path = dest_dir / relative_path
        if source_path.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            continue
        copy_binary(source_path, target_path.parent)
    return dest_dir / src_executable.name


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


def resolve_start_menu_roots() -> List[Path]:
    roots: list[Path] = []
    appdata = os.environ.get("APPDATA")
    program_data = os.environ.get("ProgramData")
    if appdata:
        roots.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Security Gateway")
    if program_data:
        roots.append(Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Security Gateway")
    seen: set[str] = set()
    resolved: list[Path] = []
    for root in roots:
        key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        resolved.append(root)
    return resolved


def resolve_shortcut_paths() -> List[tuple[Path, str, str]]:
    shortcut_entries: list[tuple[Path, str, str]] = []
    for root in [*resolve_desktop_roots(), *resolve_start_menu_roots()]:
        for file_name, arguments, description in SHORTCUT_SPECS:
            shortcut_entries.append((root / file_name, arguments, description))
    return shortcut_entries


def create_shortcut(exe_path: Path) -> List[Path]:
    shortcut_entries = resolve_shortcut_paths()
    ps_script = ""
    for shortcut_path, arguments, description in shortcut_entries:
        ps_script += f"$shortcutPath={_ps_quote(str(shortcut_path))};"
        ps_script += "New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($shortcutPath)) | Out-Null;"
        ps_script += "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($shortcutPath);"
        ps_script += f"$s.TargetPath={_ps_quote(str(exe_path))};"
        ps_script += f"$s.Arguments={_ps_quote(arguments)};"
        ps_script += f"$s.WorkingDirectory={_ps_quote(str(exe_path.parent))};"
        ps_script += f"$s.Description={_ps_quote(description)};"
        ps_script += f"$s.IconLocation={_ps_quote(str(exe_path))};"
        ps_script += "$s.Save();"
    subprocess.run([resolve_powershell_executable(), "-NoProfile", "-Command", ps_script], check=True)
    return [path for path, _arguments, _description in shortcut_entries]


def create_reports_directory(args: argparse.Namespace) -> Path:
    reports_dir = resolve_reports_dir(args)
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _scheduled_task_registration_command(exe_path: Path) -> list[str]:
    exe_literal = _ps_quote(str(exe_path))
    task_name_literal = _ps_quote(TASK_NAME)
    script = (
        f"$action = New-ScheduledTaskAction -Execute {exe_literal} -Argument 'automation-run'; "
        "$trigger = New-ScheduledTaskTrigger -AtStartup; "
        "$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest; "
        f"Register-ScheduledTask -TaskName {task_name_literal} -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null"
    )
    return [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]


def _task_xml_contents(exe_path: Path) -> str:
    command = str(exe_path)
    arguments = "automation-run"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Security Gateway monitor startup task</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>SYSTEM</UserId>
      <LogonType>ServiceAccount</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
      <WorkingDirectory>{exe_path.parent}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _write_task_xml(exe_path: Path) -> Path:
    task_dir = USER_DATA_DIR / "installer"
    task_dir.mkdir(parents=True, exist_ok=True)
    xml_path = task_dir / "security_gateway_monitor_task.xml"
    xml_path.write_text(_task_xml_contents(exe_path), encoding="utf-16")
    return xml_path


def _append_task_registration_log(message: str) -> None:
    timestamp = datetime.now(UTC).isoformat()
    try:
        TASK_REGISTRATION_LOG.parent.mkdir(parents=True, exist_ok=True)
        with TASK_REGISTRATION_LOG.open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message.rstrip()}\n")
    except Exception:
        return


def _schtasks_xml_registration_command(xml_path: Path) -> list[str]:
    return [
        "schtasks",
        "/Create",
        "/TN",
        TASK_NAME,
        "/XML",
        str(xml_path),
        "/F",
    ]


def _schtasks_registration_command(exe_path: Path) -> list[str]:
    return [
        "schtasks",
        "/Create",
        "/TN",
        TASK_NAME,
        "/SC",
        "ONSTART",
        "/RU",
        "SYSTEM",
        "/RL",
        "HIGHEST",
        "/TR",
        f'"{exe_path}" automation-run',
        "/F",
    ]


def _query_scheduled_task_xml(task_name: str) -> str:
    result = subprocess.run(
        ["schtasks", "/Query", "/TN", task_name, "/XML"],
        check=False,
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        return ""
    lowered = output.lower()
    if "access is denied" in lowered or "error:" in lowered:
        return ""
    return output


def _scheduled_task_matches(task_name: str, exe_path: Path) -> bool:
    xml = _query_scheduled_task_xml(task_name)
    if not xml.strip():
        return False
    return str(exe_path) in xml and "automation-run" in xml


def register_automation_task(exe_path: Path) -> None:
    unregister_automation_task()
    xml_path = _write_task_xml(exe_path)
    _append_task_registration_log(f"Starting task registration for {exe_path}")
    _append_task_registration_log(f"Task XML written to {xml_path}")
    registration_errors: list[str] = []
    for label, command in (
        ("xml", _schtasks_xml_registration_command(xml_path)),
        ("powershell", _scheduled_task_registration_command(exe_path)),
        ("schtasks", _schtasks_registration_command(exe_path)),
    ):
        result = subprocess.run(command, check=False, capture_output=True, text=True)
        exists = _scheduled_task_matches(TASK_NAME, exe_path)
        output = (result.stderr or result.stdout or "").strip()
        _append_task_registration_log(
            f"{label} registration returned code {result.returncode}; task_matches={exists}; output={output or '<none>'}"
        )
        if result.returncode == 0 and exists:
            _append_task_registration_log(f"Task registration succeeded via {label}")
            return
        error_text = output or f"exit code {result.returncode}"
        registration_errors.append(error_text)
    _append_task_registration_log("Task registration failed: " + " | ".join(registration_errors))
    raise RuntimeError(
        f"Failed to register automation startup task. See {TASK_REGISTRATION_LOG}. "
        + " | ".join(registration_errors)
    )


def unregister_automation_task() -> None:
    for task_name in (TASK_NAME, *LEGACY_TASK_NAMES):
        subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            check=False,
            capture_output=True,
            text=True,
        )


def write_uninstall_script(
    installed_path: Path,
    path_backup_file: Path,
    *,
    system_data_path: Optional[Path] = None,
    user_data_path: Optional[Path] = None,
    shortcut_paths: Optional[List[Path]] = None,
    task_name: str = TASK_NAME,
) -> Path:
    script_path = installed_path.parent / UNINSTALL_SCRIPT_NAME
    shortcut_paths = shortcut_paths if shortcut_paths is not None else [
        path for path, _arguments, _description in resolve_shortcut_paths()
    ]
    shortcut_path_block = ", ".join(f'"{path}"' for path in shortcut_paths)
    system_data = system_data_path or SYSTEM_DATA_DIR
    user_data = user_data_path or USER_DATA_DIR
    script = f"""\
param(
    [string]$InstallDir = "{installed_path.parent}",
    [string]$SystemDataPath = "{system_data}",
    [string]$UserDataPath = "{user_data}",
    [string]$PathBackupFile = "{path_backup_file}",
    [string]$TaskName = "{task_name}"
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

function Remove-RegistryTreeIfPresent {{
    param([Microsoft.Win32.RegistryKey]$Root, [string]$SubKey)
    try {{
        $base = $Root.OpenSubKey($SubKey, $true)
        if ($null -eq $base) {{ return }}
        foreach ($child in $base.GetSubKeyNames()) {{
            Remove-RegistryTreeIfPresent -Root $Root -SubKey ($SubKey + "\\" + $child)
        }}
        $base.Close()
        $Root.DeleteSubKey($SubKey, $false)
    }} catch {{
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
    Remove-RegistryTreeIfPresent -Root ([Microsoft.Win32.Registry]::CurrentUser) -SubKey "Software\\SecurityGateway"
    Remove-RegistryTreeIfPresent -Root ([Microsoft.Win32.Registry]::LocalMachine) -SubKey "Software\\SecurityGateway"
    Remove-RegistryTreeIfPresent -Root ([Microsoft.Win32.Registry]::CurrentUser) -SubKey "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SecurityGateway"
    Remove-RegistryTreeIfPresent -Root ([Microsoft.Win32.Registry]::LocalMachine) -SubKey "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\SecurityGateway"
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


def write_register_startup_script(installed_path: Path) -> Path:
    script_path = installed_path.parent / REGISTER_STARTUP_SCRIPT_NAME
    script = f"""\
param(
    [string]$ExePath = "{installed_path}",
    [string]$TaskName = "{TASK_NAME}"
)

function Assert-Admin {{
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
        throw "Please run this script in an elevated PowerShell session."
    }}
}}

function Remove-TaskIfPresent {{
    param([string]$Name)
    schtasks /Delete /TN $Name /F | Out-Null
}}

Assert-Admin
Remove-TaskIfPresent -Name $TaskName
schtasks /Create /TN $TaskName /SC ONSTART /RU SYSTEM /RL HIGHEST /TR ('"' + $ExePath + '" automation-run') /F
Write-Host "Security Gateway startup task registered."
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
        transaction.register_startup_script,
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
            if (
                transaction.uninstall_executable
                and transaction.uninstall_executable.parent.exists()
                and not any(transaction.uninstall_executable.parent.iterdir())
            ):
                transaction.uninstall_executable.parent.rmdir()
            install_dir = transaction.installed_path.parent
            if install_dir.exists() and not any(install_dir.iterdir()):
                install_dir.rmdir()
        except Exception as exc:  # noqa: BLE001
            cleanup_errors.append(f"install directory cleanup failed: {exc}")

    if transaction.reports_dir:
        try:
            if transaction.reports_dir.exists() and not any(transaction.reports_dir.iterdir()):
                transaction.reports_dir.rmdir()
            user_data_dir = transaction.reports_dir.parent
            if user_data_dir.exists() and not any(user_data_dir.iterdir()):
                user_data_dir.rmdir()
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
    guide_pid: Optional[int] = None
    try:
        guide_pid = _launch_guide_process(guide)
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
        _schedule_guide_auto_close(guide_pid, reporter=reporter, timeout_seconds=GUIDE_AUTO_CLOSE_SECONDS)
        _offer_to_print_install_guide(guide, reporter)
        reporter.info("Installation guide opened. Setup will continue immediately.")
    else:
        reporter.info(f"Guide path: {guide}")
        reporter.info("If you want a paper copy, open the guide manually and print it from your PDF viewer.")
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
    print("- Shortcuts:")
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
    print(f"- Startup registration script: {summary.register_startup_script}")
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
    install_dir = resolve_install_dir(args)
    system_data_dir = resolve_system_data_dir(args)
    user_data_dir = resolve_user_data_dir(args)
    if not args.smoke_test:
        ensure_admin()

    reporter.stage("Opening install guide")
    if args.smoke_test:
        reporter.info("Smoke test mode: skipping installation guide launch.")
    else:
        guide_url = args.guide_url or os.environ.get(GUIDE_URL_ENV)
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
    if args.skip_dependencies or args.smoke_test:
        reporter.stage("Installing prerequisites")
        if args.smoke_test:
            reporter.info("Smoke test mode: skipping prerequisite dependency installation.")
        else:
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
        installed_path = copy_bundle(resource, install_dir)
        transaction.installed_path = installed_path
        uninstall_install_dir = install_dir / UNINSTALLER_INSTALL_SUBDIR
        uninstall_executable = copy_bundle(uninstall_resource, uninstall_install_dir)
        transaction.uninstall_executable = uninstall_executable
        transaction.reports_dir = create_reports_directory(args)
        reporter.info(f"Reports will be stored at {transaction.reports_dir}")
        reporter.stage("Updating PATH")
        if args.smoke_test:
            reporter.info("Smoke test mode: skipping PATH update.")
            previous_path = ""
        else:
            previous_path = update_user_path(install_dir)
        transaction.previous_user_path = previous_path
        backup_file = installed_path.parent / PATH_BACKUP_NAME
        backup_file.write_text(previous_path, encoding="utf-8")
        transaction.backup_file = backup_file
        reporter.stage("Creating shortcuts")
        if args.smoke_test:
            reporter.info("Smoke test mode: skipping desktop shortcuts.")
            transaction.shortcut_paths = []
        else:
            transaction.shortcut_paths = create_shortcut(installed_path)
        reporter.stage("Registering automation task")
        if args.smoke_test:
            reporter.info("Smoke test mode: skipping automation task registration.")
        else:
            register_automation_task(installed_path)
            transaction.automation_task_registered = True
        reporter.stage("Installing uninstaller")
        reporter.stage("Writing uninstall script")
        uninstall_script = write_uninstall_script(
            installed_path,
            backup_file,
            system_data_path=system_data_dir,
            user_data_path=user_data_dir,
            shortcut_paths=transaction.shortcut_paths,
        )
        transaction.uninstall_script = uninstall_script
        register_startup_script = write_register_startup_script(installed_path)
        transaction.register_startup_script = register_startup_script
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
            reports_dir=transaction.reports_dir or resolve_reports_dir(args),
            shortcut_paths=transaction.shortcut_paths or [],
            uninstall_executable=uninstall_executable,
            uninstall_script=uninstall_script,
            register_startup_script=register_startup_script,
            dependency_results=dependency_results,
        )
    )
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ensure_frozen_installer_elevation(argv)
    args = parse_args(argv)
    if getattr(sys, "frozen", False):
        active_dir = Path(getattr(sys, "_MEIPASS")) if hasattr(sys, "_MEIPASS") else None
        cleanup_stale_mei_directories(active_dir=active_dir)
    return perform_install(args, reporter=InstallReporter())


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Installer failed: {exc}", file=sys.stderr)
        raise
