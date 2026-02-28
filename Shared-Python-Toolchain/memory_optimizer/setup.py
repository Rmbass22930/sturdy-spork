"""End-to-end Hyper-V setup utilities."""
from __future__ import annotations

import argparse
import os
import sys
import textwrap
from pathlib import Path
from typing import List, Optional, Sequence

from . import hyperv

POWERSHELL = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]


def _run_powershell(script: str) -> None:
    import subprocess

    result = subprocess.run(
        POWERSHELL + [script],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell failure"
        raise RuntimeError(f"PowerShell failed: {details}")


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _startup_command(script_path: Path) -> str:
    return f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{script_path}"'


def register_startup_run_key(name: str, script_path: Path) -> None:
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, _startup_command(script_path))


def unregister_startup_run_key(name: str) -> bool:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
            return True
    except FileNotFoundError:
        return False


def build_optimizer_args(
    vm_name: str,
    *,
    min_free_mb: float,
    max_reserve_mb: Optional[float],
    block_size_mb: float,
    idle_seconds: float,
    sample_interval: float,
    vm_wait_free_mb: float,
    vm_wait_timeout: float,
    vm_start_delay: float,
    restart_vm: bool,
    control_panel_host: str,
    control_panel_port: int,
    disable_control_panel: bool,
    privacy_up_command: Optional[str],
    privacy_check_command: Optional[str],
    privacy_check_retries: int,
    privacy_check_interval: float,
    allow_unsafe_network_start: bool,
) -> List[str]:
    args: List[str] = [
        "-m",
        "memory_optimizer.cli",
        "autostart-run",
        "--hyperv-vm-name",
        vm_name,
        "--min-free-mb",
        str(min_free_mb),
        "--block-size-mb",
        str(block_size_mb),
        "--idle-seconds",
        str(idle_seconds),
        "--sample-interval",
        str(sample_interval),
        "--vm-wait-free-mb",
        str(vm_wait_free_mb),
        "--vm-wait-timeout",
        str(vm_wait_timeout),
        "--vm-start-delay",
        str(vm_start_delay),
        "--control-panel-host",
        control_panel_host,
        "--control-panel-port",
        str(control_panel_port),
        "--privacy-check-retries",
        str(privacy_check_retries),
        "--privacy-check-interval",
        str(privacy_check_interval),
    ]
    if max_reserve_mb is not None and max_reserve_mb > 0:
        args.extend(["--max-reserve-mb", str(max_reserve_mb)])
    if not restart_vm:
        args.append("--no-restart-vm")
    if disable_control_panel:
        args.append("--disable-control-panel")
    if privacy_up_command:
        args.extend(["--privacy-up-command", privacy_up_command])
    if privacy_check_command:
        args.extend(["--privacy-check-command", privacy_check_command])
    if allow_unsafe_network_start:
        args.append("--allow-unsafe-network-start")
    return args


def write_autostart_script(
    script_path: Path,
    *,
    python_path: Path,
    optimizer_args: Sequence[str],
    working_directory: Path,
) -> None:
    script_path.parent.mkdir(parents=True, exist_ok=True)
    quoted_args = "\n".join(f"    {_ps_quote(arg)}" for arg in optimizer_args)
    content = textwrap.dedent(
        f"""\
        $ErrorActionPreference = 'Stop'
        Set-Location -Path {_ps_quote(str(working_directory))}
        $args = @(
        {quoted_args}
        )
        & {_ps_quote(str(python_path))} @args
        """
    )
    script_path.write_text(content, encoding="utf-8")


def register_scheduled_task(task_name: str, script_path: Path) -> None:
    script = textwrap.dedent(
        f"""\
        $scriptFile = { _ps_quote(str(script_path)) }
        $psArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptFile`""
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArgs -WorkingDirectory { _ps_quote(str(script_path.parent)) }
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName { _ps_quote(task_name) } -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        """
    )
    _run_powershell(script)


def unregister_scheduled_task(task_name: str) -> None:
    script = textwrap.dedent(
        f"""\
        $task = Get-ScheduledTask -TaskName { _ps_quote(task_name) } -ErrorAction SilentlyContinue
        if ($task) {{
            Unregister-ScheduledTask -TaskName { _ps_quote(task_name) } -Confirm:$false
        }}
        """
    )
    _run_powershell(script)


def get_default_script_path() -> Path:
    data_dir = Path(os.environ.get("ProgramData", r"C:\\ProgramData")) / "MemoryOptimizer"
    return data_dir / "StartMemoryOptimizer.ps1"


def run_hyperv_setup(
    vm_name: str,
    *,
    python_path: Optional[Path] = None,
    task_name: str = "MemoryOptimizerHyperV",
    script_path: Optional[Path] = None,
    working_directory: Optional[Path] = None,
    min_free_mb: float = 1024.0,
    max_reserve_mb: Optional[float] = None,
    block_size_mb: float = 256.0,
    idle_seconds: float = 180.0,
    sample_interval: float = 5.0,
    vm_wait_free_mb: float = 2048.0,
    vm_wait_timeout: float = 600.0,
    vm_start_delay: float = 5.0,
    restart_vm: bool = True,
    control_panel_host: str = "0.0.0.0",
    control_panel_port: int = 8765,
    disable_control_panel: bool = False,
    skip_enable: bool = False,
    privacy_up_command: Optional[str] = None,
    privacy_check_command: Optional[str] = None,
    privacy_check_retries: int = 5,
    privacy_check_interval: float = 3.0,
    allow_unsafe_network_start: bool = False,
) -> dict:
    python_path = python_path or Path(sys.executable)
    working_directory = working_directory or Path.cwd()
    script_path = script_path or get_default_script_path()
    if not skip_enable:
        hyperv.enable_hyperv_features()
    optimizer_args = build_optimizer_args(
        vm_name,
        min_free_mb=min_free_mb,
        max_reserve_mb=max_reserve_mb,
        block_size_mb=block_size_mb,
        idle_seconds=idle_seconds,
        sample_interval=sample_interval,
        vm_wait_free_mb=vm_wait_free_mb,
        vm_wait_timeout=vm_wait_timeout,
        vm_start_delay=vm_start_delay,
        restart_vm=restart_vm,
        control_panel_host=control_panel_host,
        control_panel_port=control_panel_port,
        disable_control_panel=disable_control_panel,
        privacy_up_command=privacy_up_command,
        privacy_check_command=privacy_check_command,
        privacy_check_retries=privacy_check_retries,
        privacy_check_interval=privacy_check_interval,
        allow_unsafe_network_start=allow_unsafe_network_start,
    )
    write_autostart_script(
        script_path,
        python_path=python_path,
        optimizer_args=optimizer_args,
        working_directory=working_directory,
    )

    startup_mode = "scheduled_task"
    startup_warning = None
    try:
        register_scheduled_task(task_name, script_path)
    except RuntimeError as exc:
        message = str(exc)
        if "Access is denied" in message or "requires elevation" in message:
            register_startup_run_key(task_name, script_path)
            startup_mode = "run_key"
            startup_warning = "Scheduled task registration denied; configured HKCU Run fallback."
        else:
            raise

    return {
        "vm": vm_name,
        "task_name": task_name,
        "script_path": str(script_path),
        "python": str(python_path),
        "working_directory": str(working_directory),
        "startup_mode": startup_mode,
        "warning": startup_warning,
    }


def run_hyperv_uninstall(task_name: str = "MemoryOptimizerHyperV", script_path: Optional[Path] = None, remove_script: bool = True) -> dict:
    script_path = script_path or get_default_script_path()

    task_removed = False
    task_warning = None
    try:
        unregister_scheduled_task(task_name)
        task_removed = True
    except RuntimeError as exc:
        task_warning = str(exc)

    run_key_removed = unregister_startup_run_key(task_name)

    removed_script = False
    if remove_script and script_path.exists():
        script_path.unlink()
        removed_script = True
        parent = script_path.parent
        try:
            if not any(parent.iterdir()):
                parent.rmdir()
        except OSError:
            pass
    return {
        "task_name": task_name,
        "task_removed": task_removed,
        "run_key_removed": run_key_removed,
        "script_removed": removed_script,
        "script_path": str(script_path),
        "warning": task_warning,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Configure Hyper-V autostart with memory optimizer.")
    parser.add_argument("--vm-name", required=True, help="Hyper-V VM name to auto-start.")
    parser.add_argument("--task-name", default="MemoryOptimizerHyperV")
    parser.add_argument("--python-path", type=Path, default=None)
    parser.add_argument("--script-path", type=Path, default=None)
    parser.add_argument("--working-directory", type=Path, default=None)
    parser.add_argument("--min-free-mb", type=float, default=1024.0)
    parser.add_argument("--max-reserve-mb", type=float, default=None)
    parser.add_argument("--block-size-mb", type=float, default=256.0)
    parser.add_argument("--idle-seconds", type=float, default=180.0)
    parser.add_argument("--sample-interval", type=float, default=5.0)
    parser.add_argument("--vm-wait-free-mb", type=float, default=2048.0)
    parser.add_argument("--vm-wait-timeout", type=float, default=600.0)
    parser.add_argument("--vm-start-delay", type=float, default=5.0)
    parser.add_argument("--no-restart-vm", action="store_true")
    parser.add_argument("--control-panel-host", default="0.0.0.0")
    parser.add_argument("--control-panel-port", type=int, default=8765)
    parser.add_argument("--disable-control-panel", action="store_true")
    parser.add_argument("--skip-enable-hyperv", action="store_true")
    parser.add_argument("--privacy-up-command", default=None)
    parser.add_argument("--privacy-check-command", default=None)
    parser.add_argument("--privacy-check-retries", type=int, default=5)
    parser.add_argument("--privacy-check-interval", type=float, default=3.0)
    parser.add_argument("--allow-unsafe-network-start", action="store_true")
    parser.add_argument("--uninstall", action="store_true", help="Remove scheduled task and startup script instead of installing.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.uninstall:
        result = run_hyperv_uninstall(task_name=args.task_name, script_path=args.script_path)
        print("Hyper-V autostart removed:")
        for key, value in result.items():
            print(f"  {key}: {value}")
        return
    result = run_hyperv_setup(
        vm_name=args.vm_name,
        python_path=args.python_path,
        task_name=args.task_name,
        script_path=args.script_path,
        working_directory=args.working_directory,
        min_free_mb=args.min_free_mb,
        max_reserve_mb=args.max_reserve_mb,
        block_size_mb=args.block_size_mb,
        idle_seconds=args.idle_seconds,
        sample_interval=args.sample_interval,
        vm_wait_free_mb=args.vm_wait_free_mb,
        vm_wait_timeout=args.vm_wait_timeout,
        vm_start_delay=args.vm_start_delay,
        restart_vm=not args.no_restart_vm,
        control_panel_host=args.control_panel_host,
        control_panel_port=args.control_panel_port,
        disable_control_panel=args.disable_control_panel,
        skip_enable=args.skip_enable_hyperv,
        privacy_up_command=args.privacy_up_command,
        privacy_check_command=args.privacy_check_command,
        privacy_check_retries=args.privacy_check_retries,
        privacy_check_interval=args.privacy_check_interval,
        allow_unsafe_network_start=args.allow_unsafe_network_start,
    )
    print("Hyper-V autostart configured:")
    for key, value in result.items():
        print(f"  {key}: {value}")
