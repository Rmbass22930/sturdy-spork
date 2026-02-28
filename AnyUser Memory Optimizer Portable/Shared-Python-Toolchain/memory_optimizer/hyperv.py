"""Hyper-V control helpers."""
from __future__ import annotations

import subprocess

POWERSHELL = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]


def _run_ps(script: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(POWERSHELL + [script], capture_output=True, text=True)
    if check and result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "unknown PowerShell failure"
        raise RuntimeError(f"Hyper-V PowerShell failed: {details}")
    return result


def enable_hyperv_features() -> None:
    script = (
        "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart;"
        "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Tools-All -NoRestart"
    )
    try:
        _run_ps(script)
    except RuntimeError as exc:
        raise RuntimeError(f"{exc} (run this command in an elevated Administrator PowerShell)") from exc


def get_vm_state(name: str) -> str:
    script = f"$vm = Get-VM -Name '{name}' -ErrorAction Stop; $vm.State.ToString()"
    result = _run_ps(script)
    return result.stdout.strip()


def start_vm(name: str) -> None:
    script = f"if ((Get-VM -Name '{name}').State -ne 'Running') {{ Start-VM -Name '{name}' | Out-Null }}"
    _run_ps(script)


def stop_vm(name: str, force: bool = False) -> None:
    cmd = f"Stop-VM -Name '{name}'"
    if force:
        cmd += " -Force"
    _run_ps(cmd)


def vm_exists(name: str) -> bool:
    script = f"if (Get-VM -Name '{name}' -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
    result = subprocess.run(POWERSHELL + [script])
    return result.returncode == 0
