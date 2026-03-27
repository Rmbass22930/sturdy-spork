"""Native installer bootstrap for SecurityGateway."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "SecurityGateway"
RESOURCE_RELATIVE = Path("payload") / "SecurityGateway.exe"
GUIDE_RELATIVE = Path("docs") / "INSTALL_GUIDE.pdf"
DEPENDENCY_MANIFEST_RELATIVE = Path("installer") / "dependencies.json"
UNINSTALL_SCRIPT_NAME = "Uninstall-SecurityGateway.ps1"
PATH_BACKUP_NAME = "user_path_backup.txt"
SYSTEM_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SecurityGateway"
USER_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SecurityGateway"
TASK_NAME = "SecurityGatewayAutomation"
PAYLOAD_URL_ENV = "SECURITY_GATEWAY_PAYLOAD_URL"
PAYLOAD_SHA_ENV = "SECURITY_GATEWAY_PAYLOAD_SHA256"
GUIDE_URL_ENV = "SECURITY_GATEWAY_GUIDE_URL"
MANIFEST_PATH_ENV = "SECURITY_GATEWAY_DEPENDENCY_MANIFEST"
MANIFEST_URL_ENV = "SECURITY_GATEWAY_DEPENDENCY_MANIFEST_URL"


@dataclass
class ExternalDependency:
    name: str
    download_url: Optional[str] = None
    sha256: Optional[str] = None
    installer_args: Optional[List[str]] = None
    run_installer: bool = False
    copy_to: Optional[str] = None
    winget_id: Optional[str] = None
    winget_args: Optional[List[str]] = None


@dataclass
class InstallTransaction:
    installed_path: Optional[Path] = None
    previous_user_path: Optional[str] = None
    backup_file: Optional[Path] = None
    shortcut_paths: Optional[List[Path]] = None
    uninstall_script: Optional[Path] = None
    automation_task_registered: bool = False


@dataclass
class DependencyInstallResult:
    name: str
    method: str
    target: Optional[str] = None


@dataclass
class InstallSummary:
    installed_path: Path
    shortcut_paths: List[Path]
    uninstall_script: Path
    dependency_results: List[DependencyInstallResult]


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


def resolve_optional_resource(rel_path: Path) -> Optional[Path]:
    try:
        resource = resolve_resource(rel_path)
    except FileNotFoundError:
        return None
    return resource


def download_file(url: str, description: str, expected_sha256: Optional[str] = None) -> Path:
    parsed = urllib.parse.urlparse(url)
    filename = Path(parsed.path).name or f"{description.replace(' ', '_')}.bin"
    temp_dir = Path(tempfile.mkdtemp(prefix="sgw_dl_"))
    target = temp_dir / filename
    print(f"Downloading {description} from {url} ...")
    with urllib.request.urlopen(url) as response, open(target, "wb") as handle:
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
    return parser.parse_args(argv)


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
    ps_script += "$s.Arguments='automation-run';"
    ps_script += f"$s.WorkingDirectory={_ps_quote(str(exe_path.parent))};"
    ps_script += "$s.Save() }"
    subprocess.run([resolve_powershell_executable(), "-NoProfile", "-Command", ps_script], check=True)
    return shortcut_paths


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
    for path in (transaction.uninstall_script, *shortcut_paths, transaction.backup_file, transaction.installed_path):
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

    if cleanup_errors:
        raise RuntimeError("Install rollback was incomplete: " + " | ".join(cleanup_errors))


def show_install_guide(override_url: Optional[str] = None) -> None:
    if override_url:
        guide = download_file(override_url, "installation guide PDF")
    else:
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
    if opened:
        print("Installation guide opened. Setup will continue immediately.")
    else:
        print(f"Guide path: {guide}")
        print("Setup will continue immediately.")


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
                download_url=entry.get("url"),
                sha256=entry.get("sha256"),
                installer_args=entry.get("installer_args"),
                run_installer=entry.get("run_installer", False),
                copy_to=entry.get("copy_to"),
                winget_id=entry.get("winget_id"),
                winget_args=entry.get("winget_args"),
            )
        )
    return dependencies


def install_external_dependencies(dependencies: List[ExternalDependency]) -> List[DependencyInstallResult]:
    if not dependencies:
        return []
    results: list[DependencyInstallResult] = []
    print(f"Installing {len(dependencies)} prerequisite program(s)...")
    for dep in dependencies:
        print(f"- Ensuring {dep.name}")
        results.append(install_dependency(dep))
    return results


def install_dependency(dep: ExternalDependency) -> DependencyInstallResult:
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
        subprocess.run(cmd, check=True)
        return DependencyInstallResult(name=dep.name, method="winget", target=dep.winget_id)
    if dep.download_url:
        target = download_file(dep.download_url, dep.name, dep.sha256)
        if dep.copy_to:
            destination = Path(dep.copy_to)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, destination)
            target = destination
        if dep.run_installer:
            args = dep.installer_args or []
            subprocess.run([str(target), *args], check=True)
            return DependencyInstallResult(name=dep.name, method="download+run", target=str(target))
        return DependencyInstallResult(name=dep.name, method="download", target=str(target))
    raise RuntimeError(f"No installation method available for {dep.name}")


def print_install_summary(summary: InstallSummary) -> None:
    print("")
    print("Install complete:")
    print(f"- Application: {summary.installed_path}")
    print("- Desktop shortcuts:")
    for shortcut_path in summary.shortcut_paths:
        print(f"  - {shortcut_path}")
    if summary.dependency_results:
        print("- Dependencies:")
        for result in summary.dependency_results:
            target_suffix = f" ({result.target})" if result.target else ""
            print(f"  - {result.name}: {result.method}{target_suffix}")
    else:
        print("- Dependencies: none")
    print(f"- Uninstall script: {summary.uninstall_script}")
    print("- PATH updated for current user. Sign out/in or restart terminal to use immediately.")


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    ensure_admin()

    guide_url = args.guide_url or os.environ.get(GUIDE_URL_ENV)
    show_install_guide(guide_url)

    payload_url = args.payload_url or os.environ.get(PAYLOAD_URL_ENV)
    payload_sha = args.payload_sha256 or os.environ.get(PAYLOAD_SHA_ENV)
    resource = (
        download_file(payload_url, "SecurityGateway payload", payload_sha)
        if payload_url
        else resolve_resource(RESOURCE_RELATIVE)
    )

    dependency_results: List[DependencyInstallResult] = []
    if args.skip_dependencies:
        print("Skipping prerequisite dependency installation.")
    else:
        manifest_ref = (
            args.dependency_manifest
            or os.environ.get(MANIFEST_PATH_ENV)
            or os.environ.get(MANIFEST_URL_ENV)
        )
        manifest_path = resolve_manifest_reference(manifest_ref)
        dependencies = load_dependency_manifest(manifest_path)
        dependency_results = install_external_dependencies(dependencies)

    transaction = InstallTransaction()
    try:
        installed_path = copy_binary(resource, INSTALL_DIR)
        transaction.installed_path = installed_path
        previous_path = update_user_path(INSTALL_DIR)
        transaction.previous_user_path = previous_path
        backup_file = installed_path.parent / PATH_BACKUP_NAME
        backup_file.write_text(previous_path, encoding="utf-8")
        transaction.backup_file = backup_file
        transaction.shortcut_paths = create_shortcut(installed_path)
        register_automation_task(installed_path)
        transaction.automation_task_registered = True
        uninstall_script = write_uninstall_script(installed_path, backup_file)
        transaction.uninstall_script = uninstall_script
    except Exception as exc:
        try:
            rollback_install(transaction)
        except Exception as rollback_exc:
            raise RuntimeError(f"Installer failed: {exc}. Rollback also failed: {rollback_exc}") from exc
        raise RuntimeError(f"Installer failed before completion: {exc}") from exc
    print_install_summary(
        InstallSummary(
            installed_path=installed_path,
            shortcut_paths=transaction.shortcut_paths or [],
            uninstall_script=uninstall_script,
            dependency_results=dependency_results,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"Installer failed: {exc}", file=sys.stderr)
        raise
