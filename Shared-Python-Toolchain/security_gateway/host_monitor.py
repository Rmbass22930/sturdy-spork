"""Local host posture monitoring for Security Gateway."""
from __future__ import annotations

import ctypes
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class HostMonitorFinding:
    key: str
    severity: str
    title: str
    summary: str
    details: dict[str, Any]
    tags: list[str]
    resolved: bool = False


class HostMonitor:
    def __init__(
        self,
        *,
        state_path: str | Path,
        system_drive: str,
        disk_free_percent_threshold: float = 10.0,
        runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self._state_path = Path(state_path)
        self._system_drive = system_drive.rstrip("\\/") or "C:"
        self._disk_free_percent_threshold = disk_free_percent_threshold
        self._runner = runner or self._run_command
        self._state_path.parent.mkdir(parents=True, exist_ok=True)

    def run_check(self) -> dict[str, Any]:
        snapshot = self.collect_snapshot()
        active_findings = self.evaluate_snapshot(snapshot)
        previous_state = self._read_state()
        previous_findings = {
            str(item.get("key")): item
            for item in previous_state.get("active_findings", [])
            if isinstance(item, dict) and item.get("key")
        }

        emitted_findings = [finding for finding in active_findings if finding.key not in previous_findings]
        resolved_findings = [
            self._build_resolution_finding(previous_findings[key])
            for key in previous_findings.keys() - {finding.key for finding in active_findings}
        ]

        self._write_state(
            {
                "last_checked_at": _utc_now().isoformat(),
                "snapshot": snapshot,
                "active_findings": [asdict(finding) for finding in active_findings],
            }
        )
        return {
            "snapshot": snapshot,
            "active_findings": [asdict(finding) for finding in active_findings],
            "emitted_findings": [asdict(finding) for finding in emitted_findings],
            "resolved_findings": [asdict(finding) for finding in resolved_findings],
        }

    def collect_snapshot(self) -> dict[str, Any]:
        disk_total, disk_used, disk_free = shutil.disk_usage(f"{self._system_drive}\\")
        disk_free_percent = round((disk_free / disk_total) * 100, 2) if disk_total else 0.0
        firewall_state = self._read_firewall_state()
        defender_running = self._service_running("WinDefend")
        uptime_seconds = int(ctypes.windll.kernel32.GetTickCount64() // 1000)  # type: ignore[attr-defined]
        return {
            "checked_at": _utc_now().isoformat(),
            "system_drive": self._system_drive,
            "disk_total_bytes": disk_total,
            "disk_used_bytes": disk_used,
            "disk_free_bytes": disk_free,
            "disk_free_percent": disk_free_percent,
            "firewall_disabled_profiles": firewall_state["disabled_profiles"],
            "firewall_profiles": firewall_state["profiles"],
            "defender_running": defender_running,
            "uptime_seconds": uptime_seconds,
            "is_admin": bool(ctypes.windll.shell32.IsUserAnAdmin()),  # type: ignore[attr-defined]
        }

    def evaluate_snapshot(self, snapshot: dict[str, Any]) -> list[HostMonitorFinding]:
        findings: list[HostMonitorFinding] = []
        firewall_disabled_profiles = snapshot.get("firewall_disabled_profiles") or []
        if firewall_disabled_profiles:
            findings.append(
                HostMonitorFinding(
                    key="firewall-disabled",
                    severity="critical",
                    title="Windows firewall profile disabled",
                    summary="One or more Windows firewall profiles are disabled on the monitored host.",
                    details={
                        "disabled_profiles": firewall_disabled_profiles,
                        "profiles": snapshot.get("firewall_profiles") or {},
                    },
                    tags=["host", "firewall", "posture"],
                )
            )
        if snapshot.get("defender_running") is False:
            findings.append(
                HostMonitorFinding(
                    key="defender-stopped",
                    severity="high",
                    title="Microsoft Defender service is not running",
                    summary="The WinDefend service is not in the RUNNING state on the monitored host.",
                    details={"service": "WinDefend"},
                    tags=["host", "defender", "posture"],
                )
            )
        if float(snapshot.get("disk_free_percent") or 0.0) < self._disk_free_percent_threshold:
            findings.append(
                HostMonitorFinding(
                    key="system-drive-low-space",
                    severity="medium",
                    title="System drive is low on free space",
                    summary="The monitored host has dropped below the configured free-space threshold on the system drive.",
                    details={
                        "system_drive": snapshot.get("system_drive"),
                        "disk_free_percent": snapshot.get("disk_free_percent"),
                        "threshold_percent": self._disk_free_percent_threshold,
                    },
                    tags=["host", "disk", "capacity"],
                )
            )
        return findings

    def _read_firewall_state(self) -> dict[str, Any]:
        result = self._runner(["netsh", "advfirewall", "show", "allprofiles", "state"])
        profiles: dict[str, str] = {}
        current_profile = "unknown"
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lowered = line.casefold()
            if lowered.endswith("profile settings:"):
                current_profile = line.split()[0].casefold()
                continue
            if lowered.startswith("state"):
                value = line.split()[-1].casefold()
                profiles[current_profile] = value
        disabled_profiles = sorted(name for name, state in profiles.items() if state == "off")
        return {"profiles": profiles, "disabled_profiles": disabled_profiles}

    def _service_running(self, name: str) -> bool:
        result = self._runner(["sc", "query", name])
        return "RUNNING" in result.stdout.upper()

    @staticmethod
    def _run_command(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=True, text=True, check=False, timeout=15)

    def _read_state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {}
        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _write_state(self, payload: dict[str, Any]) -> None:
        self._state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def _build_resolution_finding(previous_finding: dict[str, Any]) -> HostMonitorFinding:
        return HostMonitorFinding(
            key=str(previous_finding.get("key", "resolved")),
            severity="low",
            title=f"Recovered: {previous_finding.get('title', 'Host monitor finding')}",
            summary="A previously active host posture issue is no longer present.",
            details={"previous_finding": previous_finding},
            tags=["host", "recovery"],
            resolved=True,
        )
