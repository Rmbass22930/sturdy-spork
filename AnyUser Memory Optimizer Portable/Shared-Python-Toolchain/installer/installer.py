"""Native installer bootstrap for SecurityGateway."""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Tuple

INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "SecurityGateway"
RESOURCE_RELATIVE = Path("payload") / "SecurityGateway.exe"
GUIDE_RELATIVE = Path("docs") / "INSTALL_GUIDE.pdf"
UNINSTALL_SCRIPT_NAME = "Uninstall-SecurityGateway.ps1"
PATH_BACKUP_NAME = "user_path_backup.txt"
SYSTEM_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\\ProgramData")) / "SecurityGateway"
USER_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SecurityGateway"
TASK_NAME = "SecurityGatewayAutomation"


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


def resolve_resource(rel_path: Path) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    resource = base / rel_path
    if not resource.exists():
        raise FileNotFoundError(f"Embedded resource missing: {resource}")
    return resource


def copy_binary(src: Path, dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / src.name
    shutil.copy2(src, target)
    return target


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
        # Verify write succeeded; if not, revert to previous value.
        written, _ = winreg.QueryValueEx(key, "Path")
        if written != new_value:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, previous)
            raise RuntimeError("Failed to update user PATH; registry write verification failed.")
        return previous
    return ""


def create_shortcut(exe_path: Path) -> None:
    desktop = Path(os.path.join(os.environ["USERPROFILE"], "Desktop"))
    shortcut_path = desktop / "SecurityGateway.lnk"
    ps_script = f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut(\"{shortcut_path}\");"
    ps_script += f"$s.TargetPath=\"{exe_path}\";"
    ps_script += f"$s.Arguments=\"automation-run\";"
    ps_script += f"$s.WorkingDirectory=\"{exe_path.parent}\";"
    ps_script += "$s.Save()"
    subprocess.run([resolve_powershell_executable(), "-NoProfile", "-Command", ps_script], check=True)


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


def write_uninstall_script(installed_path: Path, path_backup_file: Path) -> Path:
    script_path = installed_path.parent / UNINSTALL_SCRIPT_NAME
    desktop_shortcut = Path(os.path.join(os.environ["USERPROFILE"], "Desktop")) / "SecurityGateway.lnk"
    system_data = SYSTEM_DATA_DIR
    user_data = USER_DATA_DIR
    script = f"""\
param(
    [string]$InstallDir = "{installed_path.parent}",
    [string]$ShortcutPath = "{desktop_shortcut}",
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
    if (Test-Path $ShortcutPath) {{ Remove-Item $ShortcutPath -Force }}
    if (-not (Restore-PathFromBackup -File $PathBackupFile)) {{
        Remove-PathEntry -Dir $InstallDir
    }}
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


def show_install_guide() -> None:
    guide = resolve_resource(GUIDE_RELATIVE)
    print(f"Opening installation guide: {guide}")
    opened = False
    try:
        os.startfile(guide)  # type: ignore[attr-defined]
        opened = True
    except OSError as exc:
        print(f"Unable to open guide automatically (no default PDF app?): {exc}")
        try:
            subprocess.run(["explorer", "/select,", str(guide)], check=False)
            print("Opened File Explorer so you can launch the PDF manually.")
        except Exception as explorer_exc:  # pragma: no cover
            print(f"Also failed to open File Explorer: {explorer_exc}")
        print("If you do not have a PDF reader installed, install one (e.g., Edge, Acrobat) and open the guide manually.")
    prompt = "Review the installation guide (opened automatically or manually), then press Enter to continue..."
    if not opened:
        prompt = f"{prompt}\nGuide path: {guide}"
    input(prompt)


def main() -> int:
    ensure_admin()
    show_install_guide()
    resource = resolve_resource(RESOURCE_RELATIVE)
    installed_path = copy_binary(resource, INSTALL_DIR)
    previous_path = update_user_path(INSTALL_DIR)
    backup_file = installed_path.parent / PATH_BACKUP_NAME
    backup_file.write_text(previous_path, encoding="utf-8")
    create_shortcut(installed_path)
    register_automation_task(installed_path)
    uninstall_script = write_uninstall_script(installed_path, backup_file)
    print(f"SecurityGateway installed to {installed_path}")
    print("PATH updated for current user. Sign out/in or restart terminal to use immediately.")
    print("Desktop shortcut created for automation mode.")
    print(f"To uninstall later, run {uninstall_script}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Installer failed: {exc}", file=sys.stderr)
        raise

