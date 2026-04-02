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
        dos_hit_threshold: int = 12,
        dos_syn_threshold: int = 6,
        dos_port_span_threshold: int = 3,
        evidence_sample_limit: int = 5,
        sensitive_ports: list[int] | None = None,
        runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self._state_path = Path(state_path)
        self._suspicious_repeat_threshold = max(1, suspicious_repeat_threshold)
        self._dos_hit_threshold = max(2, dos_hit_threshold)
        self._dos_syn_threshold = max(1, dos_syn_threshold)
        self._dos_port_span_threshold = max(1, dos_port_span_threshold)
        self._evidence_sample_limit = max(1, evidence_sample_limit)
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
                "connection_history": self._updated_connection_history(snapshot, previous_state=previous_state),
            }
        )
        return {
            "snapshot": snapshot,
            "active_findings": [asdict(finding) for finding in active_findings],
            "emitted_findings": [asdict(finding) for finding in emitted_findings],
            "resolved_findings": [asdict(finding) for finding in resolved_findings],
        }

    def list_recent_observations(self, *, limit: int = 50, remote_ip: str | None = None) -> list[dict[str, Any]]:
        state = self._read_state()
        connection_history = state.get("connection_history") or {}
        if not isinstance(connection_history, dict):
            return []
        observations = [payload for payload in connection_history.values() if isinstance(payload, dict)]
        if remote_ip is not None:
            observations = [item for item in observations if str(item.get("remote_ip") or "") == remote_ip]
        observations.sort(key=lambda item: self._sortable_timestamp(item.get("last_seen_at")), reverse=True)
        return observations[: max(1, limit)]

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
                    "state_counts": {},
                    "local_ports": set(),
                    "remote_ports": set(),
                    "hit_count": 0,
                    "sensitive_ports": set(),
                    "sample_connections": [],
                },
            )
            record["states"].add(str(item["state"]))
            state_name = str(item["state"])
            state_counts = record["state_counts"]
            if isinstance(state_counts, dict):
                state_counts[state_name] = int(state_counts.get(state_name, 0)) + 1
            record["local_ports"].add(int(item["local_port"]))
            record["remote_ports"].add(int(item["remote_port"]))
            record["hit_count"] += 1
            if bool(item["sensitive_port"]):
                record["sensitive_ports"].add(int(item["local_port"]))
            sample_connections = record["sample_connections"]
            if len(sample_connections) < self._evidence_sample_limit:
                sample_connections.append(
                    {
                        "state": state_name,
                        "local_ip": str(item["local_ip"]),
                        "local_port": int(item["local_port"]),
                        "remote_ip": remote_ip,
                        "remote_port": int(item["remote_port"]),
                    }
                )

        observations = []
        for value in grouped.values():
            observations.append(
                {
                    "remote_ip": value["remote_ip"],
                    "states": sorted(value["states"]),
                    "state_counts": {
                        str(key): int(count)
                        for key, count in sorted(value["state_counts"].items())
                    },
                    "local_ports": sorted(value["local_ports"]),
                    "remote_ports": sorted(value["remote_ports"]),
                    "hit_count": value["hit_count"],
                    "sensitive_ports": sorted(value["sensitive_ports"]),
                    "sample_connections": list(value["sample_connections"]),
                }
            )
        observations.sort(key=lambda item: (-(int(item["hit_count"])), str(item["remote_ip"])))
        return {
            "checked_at": _utc_now().isoformat(),
            "listening_ports": sorted(listening_ports),
            "suspicious_observations": observations,
            "repeat_threshold": self._suspicious_repeat_threshold,
            "dos_hit_threshold": self._dos_hit_threshold,
            "dos_syn_threshold": self._dos_syn_threshold,
            "dos_port_span_threshold": self._dos_port_span_threshold,
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
            raw_state_counts = item.get("state_counts")
            state_counts: dict[str, int]
            if isinstance(raw_state_counts, dict):
                state_counts = {str(key): int(value) for key, value in raw_state_counts.items()}
            else:
                state_counts = {}
            syn_received_count = int(state_counts.get("SYN_RECEIVED", 0))
            local_ports = [int(value) for value in item.get("local_ports") or []]
            remote_ports = [int(value) for value in item.get("remote_ports") or []]
            dos_candidate = (
                hit_count >= self._dos_hit_threshold
                and (
                    syn_received_count >= self._dos_syn_threshold
                    or len(local_ports) >= self._dos_port_span_threshold
                    or len(remote_ports) >= self._dos_port_span_threshold
                )
            )
            remote_ip = str(item.get("remote_ip") or "unknown")
            if dos_candidate:
                findings.append(
                    NetworkMonitorFinding(
                        key=f"dos-candidate:{remote_ip}",
                        severity="critical",
                        title=f"Potential denial-of-service source observed: {remote_ip}",
                        summary=(
                            "A public remote IP exceeded the abnormal inbound connection threshold and matched "
                            "denial-of-service indicators against local listening services."
                        ),
                        details={
                            "remote_ip": remote_ip,
                            "states": item.get("states") or [],
                            "state_counts": state_counts,
                            "local_ports": local_ports,
                            "remote_ports": remote_ports,
                            "hit_count": hit_count,
                            "sensitive_ports": sensitive_ports,
                            "syn_received_count": syn_received_count,
                            "finding_type": "dos_candidate",
                            "repeat_threshold": self._suspicious_repeat_threshold,
                            "dos_hit_threshold": self._dos_hit_threshold,
                            "dos_syn_threshold": self._dos_syn_threshold,
                            "dos_port_span_threshold": self._dos_port_span_threshold,
                            "evidence": {
                                "sample_connections": item.get("sample_connections") or [],
                                "sample_count": len(item.get("sample_connections") or []),
                                "retention_mode": "compact_evidence_only",
                            },
                        },
                        tags=["network", "ip", "intrusion", "dos"],
                    )
                )
                continue
            if hit_count < self._suspicious_repeat_threshold and not sensitive_ports:
                continue
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
                        "state_counts": state_counts,
                        "local_ports": local_ports,
                        "remote_ports": remote_ports,
                        "hit_count": hit_count,
                        "sensitive_ports": sensitive_ports,
                        "syn_received_count": syn_received_count,
                        "finding_type": "suspicious_remote_ip",
                        "repeat_threshold": self._suspicious_repeat_threshold,
                        "abnormal_reason": "sensitive_port" if sensitive_ports else "repeat_threshold_exceeded",
                        "evidence": {
                            "sample_connections": item.get("sample_connections") or [],
                            "sample_count": len(item.get("sample_connections") or []),
                            "retention_mode": "compact_evidence_only",
                        },
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

    def _updated_connection_history(self, snapshot: dict[str, Any], *, previous_state: dict[str, Any]) -> dict[str, Any]:
        history = previous_state.get("connection_history") or {}
        next_history: dict[str, Any] = {
            remote_ip: payload
            for remote_ip, payload in history.items()
            if isinstance(remote_ip, str) and isinstance(payload, dict)
        }
        checked_at = str(snapshot.get("checked_at") or _utc_now().isoformat())
        observations = snapshot.get("suspicious_observations") or []
        for item in observations:
            if not isinstance(item, dict):
                continue
            remote_ip = str(item.get("remote_ip") or "")
            if not remote_ip:
                continue
            previous = next_history.get(remote_ip)
            if not isinstance(previous, dict):
                previous = {}
            next_history[remote_ip] = {
                "remote_ip": remote_ip,
                "states": sorted({*self._as_string_list(previous.get("states")), *self._as_string_list(item.get("states"))}),
                "state_counts": self._merge_state_counts(previous.get("state_counts"), item.get("state_counts")),
                "local_ports": sorted({*self._as_int_list(previous.get("local_ports")), *self._as_int_list(item.get("local_ports"))}),
                "remote_ports": sorted({*self._as_int_list(previous.get("remote_ports")), *self._as_int_list(item.get("remote_ports"))})[-20:],
                "sensitive_ports": sorted({*self._as_int_list(previous.get("sensitive_ports")), *self._as_int_list(item.get("sensitive_ports"))}),
                "first_seen_at": str(previous.get("first_seen_at") or checked_at),
                "last_seen_at": checked_at,
                "sightings": int(previous.get("sightings") or 0) + 1,
                "total_hits": int(previous.get("total_hits") or 0) + int(item.get("hit_count") or 0),
                "max_hit_count": max(int(previous.get("max_hit_count") or 0), int(item.get("hit_count") or 0)),
                "last_hit_count": int(item.get("hit_count") or 0),
                "sample_connections": list(item.get("sample_connections") or [])[: self._evidence_sample_limit],
            }
        return next_history

    @staticmethod
    def _merge_state_counts(previous: Any, current: Any) -> dict[str, int]:
        merged: dict[str, int] = {}
        if isinstance(previous, dict):
            for key, value in previous.items():
                merged[str(key)] = int(value)
        if isinstance(current, dict):
            for key, value in current.items():
                merged[str(key)] = max(merged.get(str(key), 0), int(value))
        return merged

    @staticmethod
    def _as_string_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value]

    @staticmethod
    def _as_int_list(value: Any) -> list[int]:
        if not isinstance(value, list):
            return []
        return [int(item) for item in value]

    @staticmethod
    def _sortable_timestamp(value: Any) -> datetime:
        if not isinstance(value, str):
            return datetime.min.replace(tzinfo=UTC)
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return datetime.min.replace(tzinfo=UTC)
