"""Typer CLI entry point for the memory optimizer."""
from __future__ import annotations

import json
import signal
import time
from pathlib import Path
from typing import List, Optional, Sequence

import typer

from common_crypto import AES256GCMCipher

from .autostart import AutoStartOrchestrator
from .manager import MemoryManager, get_memory_stats
from .vm_launcher import CommandVMLauncher, HyperVVMLauncher

app = typer.Typer(help="Efficient RAM utilization helper for Windows hosts.")

_stats_cipher = AES256GCMCipher()
_STATS_AAD = b"memory-optimizer:stats"


def _print(data: dict) -> None:
    typer.echo(json.dumps(data, indent=2))


def _write_stats(path: Path, snapshot: dict, stats_key: Optional[str]) -> None:
    serialized = json.dumps(snapshot, indent=2)
    if stats_key:
        payload = _stats_cipher.encrypt_text(stats_key, serialized, associated_data=_STATS_AAD)
        path.write_text(payload)
    else:
        path.write_text(serialized)


def _decrypt_stats_payload(stats_key: str, payload: str) -> str:
    return _stats_cipher.decrypt_text(stats_key, payload, associated_data=_STATS_AAD)


def _to_powershell_command(command: Optional[str]) -> Optional[Sequence[str]]:
    if not command:
        return None
    return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]


@app.command()
def status() -> None:
    """Print current system memory stats."""
    _print(get_memory_stats())


@app.command()
def reserve(
    mb: float = typer.Argument(..., help="Megabytes to reserve."),
    tag: Optional[str] = typer.Option(None, help="Optional identifier for the reservation."),
) -> None:
    """Reserve RAM immediately."""
    manager = MemoryManager(min_free_mb=0, block_size_mb=max(mb, 1))
    segments = manager.reserve(mb, tag=tag)
    total_mb = sum(seg.size_bytes for seg in segments) / (1024 * 1024)
    _print({"segments": [seg.id for seg in segments], "size_mb": total_mb})
    for seg in segments:
        manager.release(seg.id)


@app.command()
def run(
    min_free_mb: float = typer.Option(512.0, help="Keep at least this many MB free."),
    max_reserve_mb: Optional[float] = typer.Option(None, help="Cap the optimizer's total reserved MB."),
    block_size_mb: float = typer.Option(128.0, help="Chunk size for allocations."),
    idle_seconds: float = typer.Option(120.0, help="Release blocks idle for this many seconds."),
    sample_interval: float = typer.Option(5.0, help="How often to rebalance memory."),
    stats_path: Optional[Path] = typer.Option(None, help="Optional JSON file to write periodic stats."),
    stats_key: Optional[str] = typer.Option(
        None,
        help="Encrypt stats output with AES-256-GCM using this passphrase.",
    ),
) -> None:
    """Continuously balance RAM usage, releasing when pressure occurs."""
    if stats_key and not stats_path:
        raise typer.BadParameter("--stats-key requires --stats-path.")
    manager = MemoryManager(
        min_free_mb=min_free_mb,
        max_reserve_mb=max_reserve_mb,
        block_size_mb=block_size_mb,
        idle_seconds=idle_seconds,
        sample_interval=sample_interval,
    )

    def _shutdown(signum, frame):  # noqa: ARG001
        typer.echo(f"Stopping memory optimizer due to signal {signum}.")
        manager.stop()
        raise typer.Exit(code=0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    manager.start()
    typer.echo("Memory optimizer running. Press Ctrl+C to stop.")
    try:
        while True:
            snapshot = manager.status()
            if stats_path:
                _write_stats(stats_path, snapshot, stats_key)
            typer.echo(
                f"load={snapshot['load_percent']:.1f}% "
                f"free={snapshot['available_mb']:.0f}MB "
                f"reserved={snapshot['reserved_mb']:.0f}MB "
                f"segments={snapshot['segments']}"
            )
            time.sleep(sample_interval)
    finally:
        manager.stop()
        typer.echo("Memory optimizer stopped.")


@app.command("autostart-run")
def autostart_run(
    vm_command: List[str] = typer.Argument(
        [],
        help="Command used to start the VM (wrap the path in quotes if it contains spaces). Use `--` before the command to stop option parsing. Optional if --hyperv-vm-name is supplied.",
    ),
    min_free_mb: float = typer.Option(1024.0, help="Keep at least this many MB free before reclaiming RAM."),
    max_reserve_mb: Optional[float] = typer.Option(None, help="Cap the optimizer's total reserved MB."),
    block_size_mb: float = typer.Option(256.0, help="Chunk size for allocations."),
    idle_seconds: float = typer.Option(180.0, help="Release blocks idle for this many seconds."),
    sample_interval: float = typer.Option(5.0, help="How often to rebalance memory."),
    vm_wait_free_mb: float = typer.Option(2048.0, help="Wait until this many MB are free before launching the VM."),
    vm_wait_timeout: float = typer.Option(600.0, help="Maximum seconds to wait for free memory before launching anyway."),
    vm_start_delay: float = typer.Option(5.0, help="Seconds to sleep after memory target is met before starting the VM."),
    restart_vm: bool = typer.Option(True, "--restart-vm/--no-restart-vm", help="Restart the VM process if it exits."),
    hyperv_vm_name: Optional[str] = typer.Option(None, help="Name of the Hyper-V VM to start/stop."),
    control_panel_host: str = typer.Option("0.0.0.0", help="Host interface for the in-VM stop button."),
    control_panel_port: int = typer.Option(8765, help="Port for the stop button web UI."),
    disable_control_panel: bool = typer.Option(False, "--disable-control-panel", help="Disable the stop button server."),
    privacy_up_command: Optional[str] = typer.Option(
        None,
        help="PowerShell command to establish privacy route (e.g., VPN/Tor) before VM launch.",
    ),
    privacy_check_command: Optional[str] = typer.Option(
        None,
        help="PowerShell command that must return exit code 0 to confirm privacy route.",
    ),
    privacy_check_retries: int = typer.Option(5, min=1, help="Number of privacy check attempts before failure."),
    privacy_check_interval: float = typer.Option(3.0, min=0.1, help="Seconds between privacy verification attempts."),
    allow_unsafe_network_start: bool = typer.Option(
        False,
        "--allow-unsafe-network-start",
        help="Continue even if privacy setup/check fails (not recommended).",
    ),
) -> None:
    """Run the optimizer and launch a VM once enough free RAM is available."""
    if not vm_command and not hyperv_vm_name:
        raise typer.BadParameter("Provide either a VM command or --hyperv-vm-name.")
    if hyperv_vm_name:
        vm_launcher = HyperVVMLauncher(hyperv_vm_name, restart_on_exit=restart_vm)
    else:
        vm_launcher = CommandVMLauncher(vm_command, restart_on_exit=restart_vm)

    orchestrator = AutoStartOrchestrator(
        vm_launcher=vm_launcher,
        min_free_mb=min_free_mb,
        max_reserve_mb=max_reserve_mb,
        block_size_mb=block_size_mb,
        idle_seconds=idle_seconds,
        sample_interval=sample_interval,
        vm_wait_free_mb=vm_wait_free_mb,
        vm_wait_timeout=vm_wait_timeout,
        vm_start_delay=vm_start_delay,
        enable_control_panel=not disable_control_panel,
        control_panel_host=control_panel_host,
        control_panel_port=control_panel_port,
        privacy_up_command=_to_powershell_command(privacy_up_command),
        privacy_check_command=_to_powershell_command(privacy_check_command),
        privacy_check_retries=privacy_check_retries,
        privacy_check_interval=privacy_check_interval,
        fail_closed=not allow_unsafe_network_start,
    )

    def _status(snapshot: dict) -> None:
        if "message" in snapshot:
            typer.echo(snapshot["message"])
            return
        typer.echo(
            f"load={snapshot.get('load_percent', 0.0):.1f}% "
            f"free={snapshot.get('available_mb', 0.0):.0f}MB "
            f"reserved={snapshot.get('reserved_mb', 0.0):.0f}MB "
            f"segments={snapshot.get('segments', 0)}"
        )

    typer.echo("Waiting for memory headroom and launching VM once ready...")
    try:
        orchestrator.run(status_callback=_status)
    except KeyboardInterrupt:
        typer.echo("Stopping autostart orchestrator...")
    finally:
        orchestrator.stop()


@app.command("stats-decrypt")
def stats_decrypt(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Encrypted stats file created via --stats-key."),
    stats_key: str = typer.Option(..., "--stats-key", prompt=True, hide_input=True, help="Passphrase used for encryption."),
    output: Optional[Path] = typer.Option(None, help="Optional file to write decrypted JSON; stdout if omitted."),
) -> None:
    """Decrypt an AES-256-GCM stats file and print or persist the JSON."""
    payload = path.read_text()
    plaintext = _decrypt_stats_payload(stats_key, payload)
    if output:
        output.write_text(plaintext)
        typer.echo(f"Wrote decrypted stats to {output}")
    else:
        typer.echo(plaintext)


@app.command("hyperv-enable")
def hyperv_enable() -> None:
    """Enable Hyper-V features on Windows (requires admin)."""
    from . import hyperv

    typer.echo("Enabling Hyper-V features (requires restart to take effect)...")
    hyperv.enable_hyperv_features()
    typer.echo("Hyper-V features enabled. Reboot to finalize installation.")


@app.command("hyperv-setup")
def hyperv_setup(
    vm_name: str = typer.Argument(..., help="Hyper-V VM name to configure."),
    task_name: str = typer.Option("MemoryOptimizerHyperV", help="Scheduled task name."),
    python_path: Optional[Path] = typer.Option(None, help="Python interpreter path; defaults to current."),
    script_path: Optional[Path] = typer.Option(None, help="Path to generated startup PowerShell script."),
    working_directory: Optional[Path] = typer.Option(None, help="Working directory for the optimizer."),
    min_free_mb: float = typer.Option(1024.0),
    max_reserve_mb: Optional[float] = typer.Option(None),
    block_size_mb: float = typer.Option(256.0),
    idle_seconds: float = typer.Option(180.0),
    sample_interval: float = typer.Option(5.0),
    vm_wait_free_mb: float = typer.Option(2048.0),
    vm_wait_timeout: float = typer.Option(600.0),
    vm_start_delay: float = typer.Option(5.0),
    restart_vm: bool = typer.Option(True, "--restart-vm/--no-restart-vm"),
    control_panel_host: str = typer.Option("0.0.0.0"),
    control_panel_port: int = typer.Option(8765),
    disable_control_panel: bool = typer.Option(False),
    skip_enable_hyperv: bool = typer.Option(False, help="Skip enabling Hyper-V features."),
    privacy_up_command: Optional[str] = typer.Option(None, help="PowerShell command to establish privacy route before VM launch."),
    privacy_check_command: Optional[str] = typer.Option(None, help="PowerShell command that must return exit code 0 to confirm privacy route."),
    privacy_check_retries: int = typer.Option(5, min=1),
    privacy_check_interval: float = typer.Option(3.0, min=0.1),
    allow_unsafe_network_start: bool = typer.Option(False, help="Continue even if privacy setup/check fails."),
) -> None:
    """Enable Hyper-V (optional) and register a logon task that runs the optimizer + VM."""
    from .setup import run_hyperv_setup

    result = run_hyperv_setup(
        vm_name=vm_name,
        python_path=python_path,
        task_name=task_name,
        script_path=script_path,
        working_directory=working_directory,
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
        skip_enable=skip_enable_hyperv,
        privacy_up_command=privacy_up_command,
        privacy_check_command=privacy_check_command,
        privacy_check_retries=privacy_check_retries,
        privacy_check_interval=privacy_check_interval,
        allow_unsafe_network_start=allow_unsafe_network_start,
    )
    _print(result)


@app.command("hyperv-uninstall")
def hyperv_uninstall(
    task_name: str = typer.Option("MemoryOptimizerHyperV", help="Scheduled task name to remove."),
    script_path: Optional[Path] = typer.Option(None, help="Startup script path to delete."),
    keep_script: bool = typer.Option(False, help="Leave the startup script on disk."),
) -> None:
    """Remove the scheduled task and startup script created by hyperv-setup."""
    from .setup import run_hyperv_uninstall

    result = run_hyperv_uninstall(task_name=task_name, script_path=script_path, remove_script=not keep_script)
    _print(result)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
