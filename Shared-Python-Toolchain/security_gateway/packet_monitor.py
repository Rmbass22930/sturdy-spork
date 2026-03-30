"""Built-in packet metadata sampling using Windows pktmon."""
from __future__ import annotations

import json
import math
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class PacketMonitorFinding:
    key: str
    severity: str
    title: str
    summary: str
    details: dict[str, Any]
    tags: list[str]
    resolved: bool = False


class PacketMonitor:
    _ENDPOINT_PATTERNS = (
        re.compile(
            r"(?P<protocol>TCP|UDP|ICMPv4|ICMPv6|ICMP)?[^\n]*?"
            r"(?P<src>\[[0-9A-Fa-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d+)"
            r"\s*(?:->|>|to)\s*"
            r"(?P<dst>\[[0-9A-Fa-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}):(?P<dst_port>\d+)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?P<protocol>TCP|UDP|ICMPv4|ICMPv6|ICMP)?[^\n]*?"
            r"src=(?P<src>\[[0-9A-Fa-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}):(?P<src_port>\d+)[^\n]*?"
            r"dst=(?P<dst>\[[0-9A-Fa-f:]+\]|\d{1,3}(?:\.\d{1,3}){3}):(?P<dst_port>\d+)",
            re.IGNORECASE,
        ),
    )

    def __init__(
        self,
        *,
        state_path: str | Path,
        sample_seconds: float = 2.0,
        min_packet_count: int = 5,
        pkt_size: int = 128,
        anomaly_multiplier: float = 2.0,
        learning_samples: int = 3,
        evidence_sample_limit: int = 5,
        sensitive_ports: list[int] | None = None,
        runner: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        self._state_path = Path(state_path)
        self._sample_seconds = max(0.5, sample_seconds)
        self._min_packet_count = max(1, min_packet_count)
        self._pkt_size = max(0, pkt_size)
        self._anomaly_multiplier = max(1.1, anomaly_multiplier)
        self._learning_samples = max(1, learning_samples)
        self._evidence_sample_limit = max(1, evidence_sample_limit)
        self._sensitive_ports = set(sensitive_ports or [22, 23, 135, 139, 445, 3389, 5900, 5985, 5986])
        self._runner = runner or self._run_command
        self._sleeper = sleeper or time.sleep
        self._state_path.parent.mkdir(parents=True, exist_ok=True)

    def run_check(self) -> dict[str, Any]:
        snapshot = self.collect_snapshot()
        previous_state = self._read_state()
        if snapshot.get("capture_status") != "ok":
            self._write_state(
                {
                    "last_checked_at": _utc_now().isoformat(),
                    "snapshot": snapshot,
                    "active_findings": previous_state.get("active_findings", []),
                    "history": previous_state.get("history", {}),
                }
            )
            return {
                "snapshot": snapshot,
                "active_findings": previous_state.get("active_findings", []),
                "emitted_findings": [],
                "resolved_findings": [],
            }

        active_findings = self.evaluate_snapshot(snapshot, previous_state=previous_state)
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
                "history": self._updated_history(snapshot, previous_state=previous_state),
            }
        )
        return {
            "snapshot": snapshot,
            "active_findings": [asdict(finding) for finding in active_findings],
            "emitted_findings": [asdict(finding) for finding in emitted_findings],
            "resolved_findings": [asdict(finding) for finding in resolved_findings],
        }

    def collect_snapshot(self) -> dict[str, Any]:
        temp_root = self._state_path.parent / ".packet_capture_tmp"
        temp_dir = temp_root / f"sample-{uuid4().hex}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        try:
            etl_path = temp_dir / "capture.etl"
            txt_path = temp_dir / "capture.txt"
            start_result = self._runner(
                [
                    "pktmon",
                    "start",
                    "--capture",
                    "--pkt-size",
                    str(self._pkt_size),
                    "--file-name",
                    str(etl_path),
                    "--log-mode",
                    "memory",
                ]
            )
            start_error = (start_result.stderr or start_result.stdout or "").strip()
            if start_result.returncode != 0:
                return self._capture_failure_snapshot(start_error or "pktmon start failed")

            stop_result: subprocess.CompletedProcess[str] | None = None
            try:
                self._sleeper(self._sample_seconds)
            finally:
                stop_result = self._runner(["pktmon", "stop"])

            stop_error = (stop_result.stderr or stop_result.stdout or "").strip()
            if stop_result.returncode != 0:
                return self._capture_failure_snapshot(stop_error or "pktmon stop failed")

            convert_result = self._runner(
                [
                    "pktmon",
                    "etl2txt",
                    str(etl_path),
                    "--out",
                    str(txt_path),
                    "--brief",
                    "--timestamp",
                ]
            )
            convert_error = (convert_result.stderr or convert_result.stdout or "").strip()
            if convert_result.returncode != 0 or not txt_path.exists():
                return self._capture_failure_snapshot(convert_error or "pktmon conversion failed")

            text = txt_path.read_text(encoding="utf-8", errors="ignore")
            observations = self._parse_packet_text(text)
            return {
                "checked_at": _utc_now().isoformat(),
                "capture_status": "ok",
                "sample_seconds": self._sample_seconds,
                "packet_size": self._pkt_size,
                "packet_observations": observations,
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def evaluate_snapshot(self, snapshot: dict[str, Any], *, previous_state: dict[str, Any] | None = None) -> list[PacketMonitorFinding]:
        findings: list[PacketMonitorFinding] = []
        observations = snapshot.get("packet_observations") or []
        history = (previous_state or {}).get("history") or {}
        for item in observations:
            if not isinstance(item, dict):
                continue
            packet_count = int(item.get("packet_count") or 0)
            sensitive_ports = [int(value) for value in item.get("sensitive_ports") or []]
            remote_ip = str(item.get("remote_ip") or "unknown")
            previous_samples = self._history_samples(history, remote_ip)
            abnormal_result = self._abnormal_result(packet_count, previous_samples)
            if not sensitive_ports and not abnormal_result["abnormal"]:
                continue
            key = f"packet-remote-ip:{remote_ip}"
            severity = "critical" if sensitive_ports else "high"
            findings.append(
                PacketMonitorFinding(
                    key=key,
                    severity=severity,
                    title=f"Suspicious packet activity observed: {remote_ip}",
                    summary=(
                        "Packet metadata sampling observed a public remote IP against sensitive local ports."
                        if sensitive_ports
                        else "Packet metadata sampling observed packet volume materially above the learned baseline for this remote IP."
                    ),
                    details={
                        "remote_ip": remote_ip,
                        "protocols": item.get("protocols") or [],
                        "local_ports": item.get("local_ports") or [],
                        "remote_ports": item.get("remote_ports") or [],
                        "packet_count": packet_count,
                        "sensitive_ports": sensitive_ports,
                        "min_packet_count": self._min_packet_count,
                        "baseline_samples": previous_samples,
                        "baseline_average": abnormal_result["baseline_average"],
                        "abnormal_threshold": abnormal_result["threshold"],
                        "abnormal_reason": "sensitive_port" if sensitive_ports else "baseline_exceeded",
                        "evidence": {
                            "sample_packet_endpoints": item.get("sample_packet_endpoints") or [],
                            "sample_count": len(item.get("sample_packet_endpoints") or []),
                            "retention_mode": "compact_evidence_only",
                        },
                    },
                    tags=["packet", "network", "ip", "intrusion"],
                )
            )
        return findings

    def _updated_history(self, snapshot: dict[str, Any], *, previous_state: dict[str, Any]) -> dict[str, Any]:
        history = previous_state.get("history") or {}
        next_history: dict[str, Any] = {
            remote_ip: payload
            for remote_ip, payload in history.items()
            if isinstance(remote_ip, str) and isinstance(payload, dict)
        }
        observations = snapshot.get("packet_observations") or []
        for item in observations:
            if not isinstance(item, dict):
                continue
            remote_ip = str(item.get("remote_ip") or "")
            if not remote_ip:
                continue
            previous_samples = self._history_samples(history, remote_ip)
            next_history[remote_ip] = {
                "samples": (previous_samples + [int(item.get("packet_count") or 0)])[-10:],
                "last_seen_at": snapshot.get("checked_at"),
            }
        return next_history

    def _parse_packet_text(self, text: str) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parsed = self._parse_packet_line(line)
            if parsed is None:
                continue
            local_ip, local_port, remote_ip, remote_port, protocol = parsed
            record = grouped.setdefault(
                remote_ip,
                {
                    "remote_ip": remote_ip,
                    "protocols": set(),
                    "local_ports": set(),
                    "remote_ports": set(),
                    "packet_count": 0,
                    "sensitive_ports": set(),
                    "local_ips": set(),
                    "sample_packet_endpoints": [],
                },
            )
            record["protocols"].add(protocol)
            record["local_ports"].add(local_port)
            record["remote_ports"].add(remote_port)
            record["local_ips"].add(local_ip)
            record["packet_count"] += 1
            if local_port in self._sensitive_ports:
                record["sensitive_ports"].add(local_port)
            sample_packet_endpoints = record["sample_packet_endpoints"]
            if len(sample_packet_endpoints) < self._evidence_sample_limit:
                sample_packet_endpoints.append(
                    {
                        "protocol": protocol,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_ip": local_ip,
                        "local_port": local_port,
                    }
                )

        observations = []
        for value in grouped.values():
            observations.append(
                {
                    "remote_ip": value["remote_ip"],
                    "protocols": sorted(value["protocols"]),
                    "local_ips": sorted(value["local_ips"]),
                    "local_ports": sorted(value["local_ports"]),
                    "remote_ports": sorted(value["remote_ports"]),
                    "packet_count": value["packet_count"],
                    "sensitive_ports": sorted(value["sensitive_ports"]),
                    "sample_packet_endpoints": list(value["sample_packet_endpoints"]),
                }
            )
        observations.sort(key=lambda item: (-int(item["packet_count"]), str(item["remote_ip"])))
        return observations

    def _parse_packet_line(self, line: str) -> tuple[str, int, str, int, str] | None:
        protocol = next((token.upper() for token in ("TCP", "UDP", "ICMPV4", "ICMPV6", "ICMP") if token in line.upper()), "UNKNOWN")
        for pattern in self._ENDPOINT_PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            src = self._normalize_ip(match.group("src"))
            dst = self._normalize_ip(match.group("dst"))
            src_port = int(match.group("src_port"))
            dst_port = int(match.group("dst_port"))
            if self._is_public_ip(src) and not self._is_public_ip(dst):
                return dst, dst_port, src, src_port, protocol
            if self._is_public_ip(dst) and not self._is_public_ip(src):
                return src, src_port, dst, dst_port, protocol
        return None

    def _abnormal_result(self, packet_count: int, previous_samples: list[int]) -> dict[str, Any]:
        if packet_count < self._min_packet_count:
            return {"abnormal": False, "threshold": self._min_packet_count, "baseline_average": None}
        if len(previous_samples) < self._learning_samples:
            return {"abnormal": False, "threshold": None, "baseline_average": None}
        baseline_average = sum(previous_samples) / len(previous_samples)
        threshold = max(
            self._min_packet_count,
            math.ceil(baseline_average * self._anomaly_multiplier),
            max(previous_samples) + 1,
        )
        return {
            "abnormal": packet_count >= threshold,
            "threshold": threshold,
            "baseline_average": round(baseline_average, 2),
        }

    @staticmethod
    def _history_samples(history: Any, remote_ip: str) -> list[int]:
        if not isinstance(history, dict):
            return []
        payload = history.get(remote_ip) or {}
        if not isinstance(payload, dict):
            return []
        samples = payload.get("samples") or []
        if not isinstance(samples, list):
            return []
        return [int(value) for value in samples]

    @staticmethod
    def _normalize_ip(value: str) -> str:
        return value.strip("[]")

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

    def _capture_failure_snapshot(self, error: str) -> dict[str, Any]:
        normalized = error.casefold()
        if "access is denied" in normalized:
            status = "permission_denied"
        elif "not recognized" in normalized or "unknown command" in normalized:
            status = "unavailable"
        else:
            status = "failed"
        return {
            "checked_at": _utc_now().isoformat(),
            "capture_status": status,
            "sample_seconds": self._sample_seconds,
            "packet_size": self._pkt_size,
            "error": error,
            "packet_observations": [],
        }

    @staticmethod
    def _run_command(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, capture_output=True, text=True, check=False, timeout=30)

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
    def _build_resolution_finding(previous_finding: dict[str, Any]) -> PacketMonitorFinding:
        return PacketMonitorFinding(
            key=str(previous_finding.get("key", "packet-recovered")),
            severity="low",
            title=f"Recovered: {previous_finding.get('title', 'Suspicious packet activity')}",
            summary="A previously active packet-level remote IP finding is no longer present in the latest sample.",
            details={"previous_finding": previous_finding},
            tags=["packet", "network", "recovery"],
            resolved=True,
        )
