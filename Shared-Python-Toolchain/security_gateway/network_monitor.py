"""Live network monitoring for suspicious remote IP activity."""
from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class NetworkMonitorFinding:
    key: str
    severity: str
    title: str
    summary: str
    details: dict[str, Any]
    tags: list[str]
    resolved: bool = False


class NetworkMonitor:
    def __init__(
        self,
        *,
        state_path: str | Path,
        suspicious_repeat_threshold: int = 3,
        sensitive_ports: list[int] | None = None,
        runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self._state_path = Path(state_path)
        self._suspicious_repeat_threshold = max(1, suspicious_repeat_threshold)
        self._sensitive_ports = set(sensitive_ports or [22, 23, 135, 139, 445, 3389, 5900, 5985, 5986])
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
        result = self._runner(["netstat", "-nao", "-p", "tcp"])
        listening_ports: set[int] = set()
        inbound_candidates: list[dict[str, Any]] = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line.startswith("TCP"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[1]
            remote = parts[2]
            state = parts[3].upper()
            local_endpoint = self._parse_endpoint(local)
            remote_endpoint = self._parse_endpoint(remote)
            if local_endpoint is None or remote_endpoint is None:
                continue
            local_ip, local_port = local_endpoint
            remote_ip, remote_port = remote_endpoint
            if state == "LISTENING":
                listening_ports.add(local_port)
                continue
            if state not in {"ESTABLISHED", "SYN_RECEIVED"}:
                continue
            if local_port not in listening_ports:
                continue
            if not self._is_public_ip(remote_ip):
                continue
            inbound_candidates.append(
                {
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "state": state,
                    "sensitive_port": local_port in self._sensitive_ports,
                }
            )

        grouped: dict[str, dict[str, Any]] = {}
        for item in inbound_candidates:
            remote_ip = str(item["remote_ip"])
            record = grouped.setdefault(
                remote_ip,
                {
                    "remote_ip": remote_ip,
                    "states": set(),
                    "local_ports": set(),
                    "remote_ports": set(),
                    "hit_count": 0,
                    "sensitive_ports": set(),
                },
            )
            record["states"].add(str(item["state"]))
            record["local_ports"].add(int(item["local_port"]))
            record["remote_ports"].add(int(item["remote_port"]))
            record["hit_count"] += 1
            if bool(item["sensitive_port"]):
                record["sensitive_ports"].add(int(item["local_port"]))

        observations = []
        for value in grouped.values():
            observations.append(
                {
                    "remote_ip": value["remote_ip"],
                    "states": sorted(value["states"]),
                    "local_ports": sorted(value["local_ports"]),
                    "remote_ports": sorted(value["remote_ports"]),
                    "hit_count": value["hit_count"],
                    "sensitive_ports": sorted(value["sensitive_ports"]),
                }
            )
        observations.sort(key=lambda item: (-(int(item["hit_count"])), str(item["remote_ip"])))
        return {
            "checked_at": _utc_now().isoformat(),
            "listening_ports": sorted(listening_ports),
            "suspicious_observations": observations,
            "repeat_threshold": self._suspicious_repeat_threshold,
            "sensitive_ports": sorted(self._sensitive_ports),
        }

    def evaluate_snapshot(self, snapshot: dict[str, Any]) -> list[NetworkMonitorFinding]:
        findings: list[NetworkMonitorFinding] = []
        observations = snapshot.get("suspicious_observations") or []
        for item in observations:
            if not isinstance(item, dict):
                continue
            hit_count = int(item.get("hit_count") or 0)
            sensitive_ports = [int(value) for value in item.get("sensitive_ports") or []]
            if hit_count < self._suspicious_repeat_threshold and not sensitive_ports:
                continue
            remote_ip = str(item.get("remote_ip") or "unknown")
            key = f"suspicious-remote-ip:{remote_ip}"
            severity = "critical" if sensitive_ports else "high"
            title = f"Suspicious remote IP observed: {remote_ip}"
            if sensitive_ports:
                summary = (
                    "A public remote IP is actively connecting to sensitive local listening ports on the monitored host."
                )
            else:
                summary = (
                    "A public remote IP repeatedly appeared against local listening ports on the monitored host."
                )
            findings.append(
                NetworkMonitorFinding(
                    key=key,
                    severity=severity,
                    title=title,
                    summary=summary,
                    details={
                        "remote_ip": remote_ip,
                        "states": item.get("states") or [],
                        "local_ports": item.get("local_ports") or [],
                        "remote_ports": item.get("remote_ports") or [],
                        "hit_count": hit_count,
                        "sensitive_ports": sensitive_ports,
                        "repeat_threshold": self._suspicious_repeat_threshold,
                    },
                    tags=["network", "ip", "intrusion"],
                )
            )
        return findings

    @staticmethod
    def _parse_endpoint(value: str) -> tuple[str, int] | None:
        endpoint = value.strip()
        if not endpoint or endpoint == "*:*":
            return None
        if endpoint.startswith("["):
            if "]:" not in endpoint:
                return None
            ip_part, _, port_part = endpoint[1:].partition("]:")
            ip_text = ip_part
        else:
            ip_text, _, port_part = endpoint.rpartition(":")
        if not ip_text or not port_part or port_part == "*":
            return None
        try:
            return str(ip_address(ip_text)), int(port_part)
        except ValueError:
            return None

    @staticmethod
    def _is_public_ip(value: str) -> bool:
        try:
            candidate = ip_address(value)
        except ValueError:
            return False
        return not (
            candidate.is_private
            or candidate.is_loopback
            or candidate.is_link_local
            or candidate.is_multicast
            or candidate.is_unspecified
            or candidate.is_reserved
        )

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
    def _build_resolution_finding(previous_finding: dict[str, Any]) -> NetworkMonitorFinding:
        return NetworkMonitorFinding(
            key=str(previous_finding.get("key", "network-recovered")),
            severity="low",
            title=f"Recovered: {previous_finding.get('title', 'Suspicious remote IP')}",
            summary="A previously active suspicious remote IP is no longer present in the live connection view.",
            details={"previous_finding": previous_finding},
            tags=["network", "recovery"],
            resolved=True,
        )
