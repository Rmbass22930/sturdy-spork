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
from typing import Any, Callable, cast
from uuid import uuid4

from .network_monitor import NetworkMonitor


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
        capture_retention_enabled: bool = False,
        capture_retention_path: str | Path | None = None,
        capture_retention_limit: int = 20,
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
        self._capture_retention_enabled = capture_retention_enabled
        self._capture_retention_path = (
            Path(capture_retention_path)
            if capture_retention_path is not None
            else self._state_path.parent / "packet_captures"
        )
        self._capture_retention_limit = max(1, capture_retention_limit)
        self._runner = runner or self._run_command
        self._sleeper = sleeper or time.sleep
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        if self._capture_retention_enabled:
            self._capture_retention_path.mkdir(parents=True, exist_ok=True)

    def run_check(self) -> dict[str, Any]:
        snapshot = self.collect_snapshot()
        previous_state = self._read_state()
        if snapshot.get("capture_status") not in {"ok", "fallback_socket_table"}:
            self._write_state(
                {
                    "last_checked_at": _utc_now().isoformat(),
                    "snapshot": snapshot,
                    "active_findings": previous_state.get("active_findings", []),
                    "history": previous_state.get("history", {}),
                    "session_history": previous_state.get("session_history", {}),
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
                "session_history": self._updated_session_history(snapshot, previous_state=previous_state),
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
                    "--file-size",
                    "4",
                    "--log-mode",
                    "circular",
                ]
            )
            start_error = (start_result.stderr or start_result.stdout or "").strip()
            if start_result.returncode != 0:
                return self._snapshot_or_fallback(start_error or "pktmon start failed")

            stop_result: subprocess.CompletedProcess[str] | None = None
            try:
                self._sleeper(self._sample_seconds)
            finally:
                stop_result = self._runner(["pktmon", "stop"])

            stop_error = (stop_result.stderr or stop_result.stdout or "").strip()
            if stop_result.returncode != 0:
                return self._snapshot_or_fallback(stop_error or "pktmon stop failed")
            actual_etl_path = self._wait_for_capture_file(
                temp_dir,
                requested_path=etl_path,
                timeout_seconds=max(12.0, self._sample_seconds + 10.0),
            )
            if actual_etl_path is None:
                return self._snapshot_or_fallback(f"pktmon capture file missing: {etl_path}")

            convert_result = self._runner(
                [
                    "pktmon",
                    "etl2txt",
                    str(actual_etl_path),
                    "--out",
                    str(txt_path),
                    "--brief",
                    "--timestamp",
                ]
            )
            convert_error = (convert_result.stderr or convert_result.stdout or "").strip()
            if convert_result.returncode != 0:
                return self._snapshot_or_fallback(convert_error or "pktmon conversion failed")
            if not self._wait_for_file(txt_path, timeout_seconds=2.0):
                return self._snapshot_or_fallback(f"pktmon conversion output missing: {txt_path}")

            text = txt_path.read_text(encoding="utf-8", errors="ignore")
            observations = self._parse_packet_text(text)
            session_observations = self._build_session_observations(observations)
            for session in session_observations:
                session["protocol_evidence"] = self._merge_protocol_evidence(
                    session.get("protocol_evidence"),
                    self._extract_protocol_evidence(
                        text,
                        remote_ip=str(session.get("remote_ip") or ""),
                    ),
                )
            retained_capture = self._retain_capture_artifacts(
                actual_etl_path=actual_etl_path,
                txt_path=txt_path,
                observations=observations,
                session_observations=session_observations,
            )
            return {
                "checked_at": _utc_now().isoformat(),
                "capture_status": "ok",
                "evidence_mode": "pktmon",
                "sample_seconds": self._sample_seconds,
                "packet_size": self._pkt_size,
                "packet_observations": observations,
                "session_observations": session_observations,
                "retained_capture": retained_capture,
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
                        "session_key": item.get("session_key") or f"packet-session:{remote_ip}",
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
                            "sample_sessions": [self._session_summary(item)],
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

    def _updated_session_history(self, snapshot: dict[str, Any], *, previous_state: dict[str, Any]) -> dict[str, Any]:
        history = previous_state.get("session_history") or {}
        next_history: dict[str, Any] = {
            session_key: payload
            for session_key, payload in history.items()
            if isinstance(session_key, str) and isinstance(payload, dict)
        }
        checked_at = str(snapshot.get("checked_at") or _utc_now().isoformat())
        observations = snapshot.get("session_observations") or []
        for item in observations:
            if not isinstance(item, dict):
                continue
            session_key = str(item.get("session_key") or "")
            if not session_key:
                continue
            previous = next_history.get(session_key)
            if not isinstance(previous, dict):
                previous = {}
            enrichment = self._session_enrichment(item)
            next_history[session_key] = {
                "session_key": session_key,
                "remote_ip": item.get("remote_ip"),
                "protocols": sorted({*self._as_string_list(previous.get("protocols")), *self._as_string_list(item.get("protocols"))}),
                "local_ips": sorted({*self._as_string_list(previous.get("local_ips")), *self._as_string_list(item.get("local_ips"))}),
                "local_ports": sorted({*self._as_int_list(previous.get("local_ports")), *self._as_int_list(item.get("local_ports"))}),
                "remote_ports": sorted({*self._as_int_list(previous.get("remote_ports")), *self._as_int_list(item.get("remote_ports"))})[-20:],
                "sensitive_ports": sorted({*self._as_int_list(previous.get("sensitive_ports")), *self._as_int_list(item.get("sensitive_ports"))}),
                "transport_families": sorted(
                    {
                        *self._as_string_list(previous.get("transport_families")),
                        *cast(list[str], enrichment["transport_families"]),
                    }
                ),
                "service_names": sorted(
                    {
                        *self._as_string_list(previous.get("service_names")),
                        *cast(list[str], enrichment["service_names"]),
                    }
                ),
                "application_protocols": sorted(
                    {
                        *self._as_string_list(previous.get("application_protocols")),
                        *cast(list[str], enrichment["application_protocols"]),
                    }
                ),
                "flow_ids": sorted(
                    {
                        *self._as_string_list(previous.get("flow_ids")),
                        *cast(list[str], enrichment["flow_ids"]),
                    }
                )[-20:],
                "first_seen_at": str(previous.get("first_seen_at") or checked_at),
                "last_seen_at": checked_at,
                "sightings": int(previous.get("sightings") or 0) + 1,
                "total_packets": int(previous.get("total_packets") or 0) + int(item.get("packet_count") or 0),
                "max_packet_count": max(int(previous.get("max_packet_count") or 0), int(item.get("packet_count") or 0)),
                "last_packet_count": int(item.get("packet_count") or 0),
                "sample_packet_endpoints": list(item.get("sample_packet_endpoints") or [])[: self._evidence_sample_limit],
                "protocol_evidence": self._merge_protocol_evidence(
                    previous.get("protocol_evidence"),
                    item.get("protocol_evidence"),
                ),
            }
        return next_history

    def list_recent_sessions(self, *, limit: int = 50, remote_ip: str | None = None) -> list[dict[str, Any]]:
        state = self._read_state()
        session_history = state.get("session_history") or {}
        if not isinstance(session_history, dict):
            return []
        sessions = [payload for payload in session_history.values() if isinstance(payload, dict)]
        if remote_ip is not None:
            sessions = [item for item in sessions if str(item.get("remote_ip") or "") == remote_ip]
        sessions.sort(key=lambda item: self._sortable_timestamp(item.get("last_seen_at")), reverse=True)
        return sessions[: max(1, limit)]

    def list_retained_captures(
        self,
        *,
        limit: int = 50,
        remote_ip: str | None = None,
        session_key: str | None = None,
        protocol: str | None = None,
        local_port: int | None = None,
        remote_port: int | None = None,
    ) -> list[dict[str, Any]]:
        if not self._capture_retention_path.exists():
            return []
        captures: list[dict[str, Any]] = []
        for metadata_path in self._capture_retention_path.glob("*.json"):
            try:
                payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                payload = self._normalized_retained_capture_payload(payload)
                if not self._retained_capture_matches_filters(
                    payload,
                    remote_ip=remote_ip,
                    session_key=session_key,
                    protocol=protocol,
                    local_port=local_port,
                    remote_port=remote_port,
                ):
                    continue
                captures.append(payload)
        captures.sort(key=lambda item: str(item.get("captured_at") or ""), reverse=True)
        return captures[: max(1, limit)]

    def get_retained_capture(self, capture_id: str) -> dict[str, Any]:
        metadata_path = self._capture_retention_path / f"{capture_id}.json"
        if not metadata_path.exists():
            raise KeyError(f"Packet capture not found: {capture_id}")
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyError(f"Packet capture metadata is unavailable: {capture_id}") from exc
        if not isinstance(payload, dict):
            raise KeyError(f"Packet capture metadata is invalid: {capture_id}")
        return self._normalized_retained_capture_payload(payload)

    def get_retained_capture_text(self, capture_id: str) -> str:
        capture = self.get_retained_capture(capture_id)
        txt_path = Path(str(capture.get("txt_path") or ""))
        if not txt_path.exists():
            raise KeyError(f"Packet capture text not found: {capture_id}")
        return txt_path.read_text(encoding="utf-8", errors="ignore")

    def _normalized_retained_capture_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(payload)
        txt_path = Path(str(normalized.get("txt_path") or ""))
        text = txt_path.read_text(encoding="utf-8", errors="ignore") if txt_path.exists() else ""
        if not isinstance(normalized.get("protocol_evidence"), dict):
            normalized["protocol_evidence"] = self._extract_protocol_evidence(text)
        session_rows: list[dict[str, Any]] = []
        for row in cast(list[Any], normalized.get("session_observations") or []):
            if not isinstance(row, dict):
                continue
            updated_row = dict(row)
            if not isinstance(updated_row.get("protocol_evidence"), dict):
                updated_row["protocol_evidence"] = self._extract_protocol_evidence(
                    text,
                    remote_ip=str(updated_row.get("remote_ip") or ""),
                )
            session_rows.append(updated_row)
        normalized["session_observations"] = session_rows
        return normalized

    def _build_session_observations(self, observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        sessions: list[dict[str, Any]] = []
        for item in observations:
            remote_ip = str(item.get("remote_ip") or "")
            if not remote_ip:
                continue
            enrichment = self._session_enrichment(item)
            sessions.append(
                {
                    "session_key": f"packet-session:{remote_ip}",
                    "remote_ip": remote_ip,
                    "protocols": list(item.get("protocols") or []),
                    "local_ips": list(item.get("local_ips") or []),
                    "local_ports": list(item.get("local_ports") or []),
                    "remote_ports": list(item.get("remote_ports") or []),
                    "packet_count": int(item.get("packet_count") or 0),
                    "sensitive_ports": list(item.get("sensitive_ports") or []),
                    "sample_packet_endpoints": list(item.get("sample_packet_endpoints") or []),
                    "transport_families": enrichment["transport_families"],
                    "service_names": enrichment["service_names"],
                    "application_protocols": enrichment["application_protocols"],
                    "flow_ids": enrichment["flow_ids"],
                    "protocol_evidence": cast(dict[str, Any], item.get("protocol_evidence") or {}),
                }
            )
        return sessions

    @staticmethod
    def _session_summary(item: dict[str, Any]) -> dict[str, Any]:
        remote_ip = str(item.get("remote_ip") or "unknown")
        return {
            "session_key": item.get("session_key") or f"packet-session:{remote_ip}",
            "remote_ip": remote_ip,
            "protocols": list(item.get("protocols") or []),
            "local_ports": list(item.get("local_ports") or []),
            "packet_count": int(item.get("packet_count") or 0),
            "sensitive_ports": list(item.get("sensitive_ports") or []),
        }

    @staticmethod
    def _merge_protocol_evidence(previous: Any, current: Any) -> dict[str, Any]:
        def _string_values(payload: Any, key: str) -> set[str]:
            if not isinstance(payload, dict):
                return set()
            values = payload.get(key)
            if not isinstance(values, list):
                return set()
            return {str(item).strip() for item in values if str(item).strip()}

        return {
            "application_protocols": sorted(
                _string_values(previous, "application_protocols")
                | _string_values(current, "application_protocols")
            ),
            "hostnames": sorted(
                _string_values(previous, "hostnames")
                | _string_values(current, "hostnames")
            ),
            "indicators": sorted(
                _string_values(previous, "indicators")
                | _string_values(current, "indicators")
            ),
        }

    def _extract_protocol_evidence(self, text: str, *, remote_ip: str | None = None) -> dict[str, Any]:
        relevant_lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and (not remote_ip or remote_ip in line)
        ]
        haystack = "\n".join(relevant_lines or text.splitlines())
        application_protocols: set[str] = set()
        indicators: set[str] = set()
        hostnames = {
            match.lower()
            for match in re.findall(
                r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
                haystack,
                flags=re.IGNORECASE,
            )
            if not re.fullmatch(r"\d+(?:\.\d+){3}", match)
        }
        upper_haystack = haystack.upper()
        if re.search(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b|\bHTTP/\d\.\d\b", upper_haystack):
            application_protocols.add("http")
            indicators.add("http_request")
        if re.search(r"\bTLS(?:V?\d(?:\.\d)?)?\b|\bCLIENTHELLO\b|\bSERVERHELLO\b|\bSNI\b", upper_haystack):
            application_protocols.add("tls")
            indicators.add("tls_handshake")
        if re.search(r"\bDNS\b|\bAAAA?\?\b|\bPTR\?\b|\bCNAME\b", upper_haystack):
            application_protocols.add("dns")
            indicators.add("dns_query")
        if re.search(r"\bSSH-\d", upper_haystack):
            application_protocols.add("ssh")
            indicators.add("ssh_banner")
        if re.search(r"\bSMB2?\b", upper_haystack):
            application_protocols.add("smb")
            indicators.add("smb_negotiation")
        if re.search(r"\bRDP\b|\bTERMSRV\b", upper_haystack):
            application_protocols.add("rdp")
            indicators.add("rdp_session")
        if re.search(r"\bWINRM\b|\bWSMAN\b", upper_haystack):
            application_protocols.add("winrm")
            indicators.add("winrm_session")
        if re.search(r"\bLDAPS?\b", upper_haystack):
            application_protocols.add("ldap")
            indicators.add("ldap_query")
        return {
            "application_protocols": sorted(application_protocols),
            "hostnames": sorted(hostnames),
            "indicators": sorted(indicators),
        }

    def _extract_protocol_evidence_from_line(self, line: str) -> dict[str, set[str]]:
        application_protocols: set[str] = set()
        hostnames: set[str] = set()
        indicators: set[str] = set()
        upper_line = line.upper()

        def _capture_hostname(pattern: str) -> None:
            match = re.search(pattern, line, flags=re.IGNORECASE)
            if match is None:
                return
            hostname = str(match.group(1) or "").strip().strip(".,;")
            if hostname and not re.fullmatch(r"\d+(?:\.\d+){3}", hostname):
                hostnames.add(hostname.lower())

        if re.search(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b|\bHTTP/\d\.\d\b", upper_line):
            application_protocols.add("http")
            indicators.add("http_request")
            _capture_hostname(r"\bHost:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
        if re.search(r"\bTLS(?:V?\d(?:\.\d)?)?\b|\bCLIENTHELLO\b|\bSERVERHELLO\b|\bSNI\b", upper_line):
            application_protocols.add("tls")
            indicators.add("tls_handshake")
            _capture_hostname(r"\bSNI\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
            _capture_hostname(r"\bServer Name:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
        if re.search(r"\bDNS\b|\bAAAA?\?\b|\bPTR\?\b|\bCNAME\b", upper_line):
            application_protocols.add("dns")
            indicators.add("dns_query")
            _capture_hostname(r"\b(?:Query|QName|Question):\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
            _capture_hostname(r"\b(?:A|AAAA|PTR|CNAME)\?\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
        if re.search(r"\bSSH-\d", upper_line):
            application_protocols.add("ssh")
            indicators.add("ssh_banner")
        if re.search(r"\bSMB2?\b", upper_line):
            application_protocols.add("smb")
            indicators.add("smb_negotiation")
        if re.search(r"\bRDP\b|\bTERMSRV\b", upper_line):
            application_protocols.add("rdp")
            indicators.add("rdp_session")
        if re.search(r"\bWINRM\b|\bWSMAN\b", upper_line):
            application_protocols.add("winrm")
            indicators.add("winrm_session")
        if re.search(r"\bLDAPS?\b", upper_line):
            application_protocols.add("ldap")
            indicators.add("ldap_query")
        return {
            "application_protocols": application_protocols,
            "hostnames": hostnames,
            "indicators": indicators,
        }

    def _session_enrichment(self, item: dict[str, Any]) -> dict[str, list[str]]:
        transport_families: set[str] = set()
        service_names: set[str] = set()
        application_protocols: set[str] = set()
        flow_ids: set[str] = set()
        remote_ip = str(item.get("remote_ip") or "")
        sample_rows = [
            sample
            for sample in cast(list[Any], item.get("sample_packet_endpoints") or [])
            if isinstance(sample, dict)
        ]
        for protocol in self._as_string_list(item.get("protocols")):
            normalized_protocol = protocol.strip().lower()
            if normalized_protocol:
                transport_families.add(normalized_protocol)
        for port in self._as_int_list(item.get("local_ports")):
            service_name = NetworkMonitor._service_name_for_port(port)
            if service_name:
                service_names.add(service_name)
        for local_port in self._as_int_list(item.get("local_ports")):
            for remote_port in self._as_int_list(item.get("remote_ports")):
                application_protocol = NetworkMonitor._application_protocol_for_ports(local_port, remote_port)
                if application_protocol:
                    application_protocols.add(application_protocol)
        for sample in sample_rows:
            protocol = str(sample.get("protocol") or "").strip().lower()
            if protocol:
                transport_families.add(protocol)
            local_port = int(sample.get("local_port") or 0)
            remote_port = int(sample.get("remote_port") or 0)
            local_ip = str(sample.get("local_ip") or "")
            sample_remote_ip = str(sample.get("remote_ip") or remote_ip or "")
            service_name = NetworkMonitor._service_name_for_port(local_port)
            if service_name:
                service_names.add(service_name)
            application_protocol = NetworkMonitor._application_protocol_for_ports(local_port, remote_port)
            if application_protocol:
                application_protocols.add(application_protocol)
            if protocol and local_port and remote_port and local_ip and sample_remote_ip:
                process_id = sample.get("pid")
                flow_ids.add(
                    NetworkMonitor._build_flow_id(
                        remote_ip=sample_remote_ip,
                        remote_port=remote_port,
                        local_ip=local_ip,
                        local_port=local_port,
                        protocol=protocol,
                        process_id=process_id if isinstance(process_id, int) else None,
                    )
                )
        return {
            "transport_families": sorted(transport_families),
            "service_names": sorted(service_names),
            "application_protocols": sorted(application_protocols),
            "flow_ids": sorted(flow_ids),
        }

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
                    "protocol_evidence": {
                        "application_protocols": set(),
                        "hostnames": set(),
                        "indicators": set(),
                    },
                },
            )
            record["protocols"].add(protocol)
            record["local_ports"].add(local_port)
            record["remote_ports"].add(remote_port)
            record["local_ips"].add(local_ip)
            record["packet_count"] += 1
            line_protocol_evidence = self._extract_protocol_evidence_from_line(line)
            record["protocol_evidence"]["application_protocols"].update(
                cast(set[str], line_protocol_evidence["application_protocols"])
            )
            record["protocol_evidence"]["hostnames"].update(
                cast(set[str], line_protocol_evidence["hostnames"])
            )
            record["protocol_evidence"]["indicators"].update(
                cast(set[str], line_protocol_evidence["indicators"])
            )
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
                    "protocol_evidence": {
                        "application_protocols": sorted(value["protocol_evidence"]["application_protocols"]),
                        "hostnames": sorted(value["protocol_evidence"]["hostnames"]),
                        "indicators": sorted(value["protocol_evidence"]["indicators"]),
                    },
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

    def _snapshot_or_fallback(self, error: str) -> dict[str, Any]:
        failure_snapshot = self._capture_failure_snapshot(error)
        fallback_snapshot = self._collect_socket_table_snapshot(failure_snapshot)
        if fallback_snapshot is not None:
            return fallback_snapshot
        return failure_snapshot

    def _retain_capture_artifacts(
        self,
        *,
        actual_etl_path: Path,
        txt_path: Path,
        observations: list[dict[str, Any]],
        session_observations: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if not self._capture_retention_enabled:
            return None
        self._capture_retention_path.mkdir(parents=True, exist_ok=True)
        capture_id = f"packet-capture-{uuid4().hex[:12]}"
        retained_etl_path = self._capture_retention_path / f"{capture_id}.etl"
        retained_txt_path = self._capture_retention_path / f"{capture_id}.txt"
        shutil.copy2(actual_etl_path, retained_etl_path)
        shutil.copy2(txt_path, retained_txt_path)
        remote_ips = sorted(
            {
                str(item.get("remote_ip") or "")
                for item in session_observations
                if str(item.get("remote_ip") or "")
            }
        )
        protocols = sorted(
            {
                str(protocol).upper()
                for item in session_observations
                for protocol in cast(list[Any], item.get("protocols") or [])
                if str(protocol)
            }
        )
        local_ports = sorted(
            {
                int(port)
                for item in session_observations
                for port in cast(list[Any], item.get("local_ports") or [])
                if isinstance(port, int) or (isinstance(port, str) and port.isdigit())
            }
        )
        remote_ports = sorted(
            {
                int(port)
                for item in session_observations
                for port in cast(list[Any], item.get("remote_ports") or [])
                if isinstance(port, int) or (isinstance(port, str) and port.isdigit())
            }
        )
        primary_session = session_observations[0] if session_observations else None
        protocol_evidence = self._extract_protocol_evidence(txt_path.read_text(encoding="utf-8", errors="ignore"))
        for session in session_observations:
            protocol_evidence = self._merge_protocol_evidence(
                protocol_evidence,
                session.get("protocol_evidence"),
            )
        metadata = {
            "capture_id": capture_id,
            "captured_at": _utc_now().isoformat(),
            "etl_path": str(retained_etl_path),
            "txt_path": str(retained_txt_path),
            "etl_size_bytes": retained_etl_path.stat().st_size,
            "txt_size_bytes": retained_txt_path.stat().st_size,
            "observation_count": len(observations),
            "session_count": len(session_observations),
            "remote_ips": remote_ips,
            "protocols": protocols,
            "local_ports": local_ports,
            "remote_ports": remote_ports,
            "primary_remote_ip": str(primary_session.get("remote_ip") or "") if primary_session else None,
            "primary_session_key": str(primary_session.get("session_key") or "") if primary_session else None,
            "session_observations": session_observations,
            "protocol_evidence": protocol_evidence,
        }
        (self._capture_retention_path / f"{capture_id}.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        self._prune_retained_captures()
        return metadata

    @staticmethod
    def _retained_capture_matches_filters(
        payload: dict[str, Any],
        *,
        remote_ip: str | None,
        session_key: str | None,
        protocol: str | None,
        local_port: int | None,
        remote_port: int | None,
    ) -> bool:
        session_rows = [
            item
            for item in cast(list[Any], payload.get("session_observations") or [])
            if isinstance(item, dict)
        ]
        if remote_ip is not None:
            remote_ips = {
                str(payload.get("primary_remote_ip") or ""),
                *(str(item.get("remote_ip") or "") for item in session_rows),
                *(str(item) for item in cast(list[Any], payload.get("remote_ips") or [])),
            }
            if remote_ip not in remote_ips:
                return False
        if session_key is not None:
            session_keys = {
                str(payload.get("primary_session_key") or ""),
                *(str(item.get("session_key") or "") for item in session_rows),
            }
            if session_key not in session_keys:
                return False
        if protocol is not None:
            normalized_protocol = protocol.strip().upper()
            protocols = {
                *(str(item).upper() for item in cast(list[Any], payload.get("protocols") or [])),
                *(
                    str(item).upper()
                    for session in session_rows
                    for item in cast(list[Any], session.get("protocols") or [])
                ),
            }
            if normalized_protocol not in protocols:
                return False
        if local_port is not None:
            local_ports = {
                *(
                    int(item)
                    for item in cast(list[Any], payload.get("local_ports") or [])
                    if isinstance(item, int) or (isinstance(item, str) and item.isdigit())
                ),
                *(
                    int(item)
                    for session in session_rows
                    for item in cast(list[Any], session.get("local_ports") or [])
                    if isinstance(item, int) or (isinstance(item, str) and item.isdigit())
                ),
            }
            if local_port not in local_ports:
                return False
        if remote_port is not None:
            remote_ports = {
                *(
                    int(item)
                    for item in cast(list[Any], payload.get("remote_ports") or [])
                    if isinstance(item, int) or (isinstance(item, str) and item.isdigit())
                ),
                *(
                    int(item)
                    for session in session_rows
                    for item in cast(list[Any], session.get("remote_ports") or [])
                    if isinstance(item, int) or (isinstance(item, str) and item.isdigit())
                ),
            }
            if remote_port not in remote_ports:
                return False
        return True

    def _prune_retained_captures(self) -> None:
        metadata_paths = sorted(
            self._capture_retention_path.glob("*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for metadata_path in metadata_paths[self._capture_retention_limit :]:
            capture_id = metadata_path.stem
            for suffix in (".json", ".etl", ".txt"):
                try:
                    (self._capture_retention_path / f"{capture_id}{suffix}").unlink(missing_ok=True)
                except OSError:
                    continue

    def _collect_socket_table_snapshot(self, failure_snapshot: dict[str, Any]) -> dict[str, Any] | None:
        if str(failure_snapshot.get("capture_status") or "") != "permission_denied":
            return None
        try:
            observations, collected = self._collect_socket_table_observations()
        except Exception:  # noqa: BLE001
            return None
        if not collected:
            return None
        return {
            "checked_at": _utc_now().isoformat(),
            "capture_status": "fallback_socket_table",
            "evidence_mode": "socket_table",
            "sample_seconds": self._sample_seconds,
            "packet_size": self._pkt_size,
            "error": failure_snapshot.get("error"),
            "packet_observations": observations,
            "session_observations": self._build_session_observations(observations),
        }

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
            "evidence_mode": "pktmon",
            "sample_seconds": self._sample_seconds,
            "packet_size": self._pkt_size,
            "error": error,
            "packet_observations": [],
            "session_observations": [],
        }

    def _collect_socket_table_observations(self) -> tuple[list[dict[str, Any]], bool]:
        outputs: list[tuple[str, str]] = []
        for protocol in ("tcp", "udp"):
            result = self._runner(["netstat", "-ano", "-n", "-p", protocol])
            if result.returncode != 0:
                continue
            outputs.append((protocol.upper(), result.stdout or ""))
        if not outputs:
            return [], False
        grouped: dict[str, dict[str, Any]] = {}
        for protocol, text in outputs:
            self._merge_socket_table_observations(grouped, text=text, protocol=protocol)
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
                    "evidence_mode": "socket_table",
                }
            )
        observations.sort(key=lambda item: (-int(item["packet_count"]), str(item["remote_ip"])))
        return observations, True

    def _merge_socket_table_observations(self, grouped: dict[str, dict[str, Any]], *, text: str, protocol: str) -> None:
        for raw_line in text.splitlines():
            parsed = self._parse_socket_table_line(raw_line, protocol=protocol)
            if parsed is None:
                continue
            local_ip, local_port, remote_ip, remote_port, state, pid = parsed
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
                endpoint = {
                    "protocol": protocol,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "local_ip": local_ip,
                    "local_port": local_port,
                }
                if state:
                    endpoint["state"] = state
                if pid is not None:
                    endpoint["pid"] = pid
                sample_packet_endpoints.append(endpoint)

    def _parse_socket_table_line(
        self,
        line: str,
        *,
        protocol: str,
    ) -> tuple[str, int, str, int, str | None, int | None] | None:
        tokens = line.split()
        if not tokens or tokens[0].upper() != protocol.upper():
            return None
        if protocol == "TCP" and len(tokens) >= 5:
            local_token, remote_token, state_token, pid_token = tokens[1], tokens[2], tokens[3], tokens[4]
        elif protocol == "UDP" and len(tokens) >= 4:
            local_token, remote_token, state_token, pid_token = tokens[1], tokens[2], None, tokens[3]
        else:
            return None
        local_endpoint = self._parse_socket_endpoint(local_token)
        remote_endpoint = self._parse_socket_endpoint(remote_token)
        if local_endpoint is None or remote_endpoint is None:
            return None
        local_ip, local_port = local_endpoint
        remote_ip, remote_port = remote_endpoint
        if not self._is_public_ip(remote_ip):
            return None
        pid = None
        if pid_token is not None and pid_token.isdigit():
            pid = int(pid_token)
        return local_ip, local_port, remote_ip, remote_port, state_token, pid

    @staticmethod
    def _parse_socket_endpoint(value: str) -> tuple[str, int] | None:
        token = value.strip()
        if token in {"*", "*:*"}:
            return None
        if token.startswith("[") and "]:" in token:
            closing = token.rfind("]:")
            host = token[1:closing]
            port_text = token[closing + 2 :]
        else:
            if ":" not in token:
                return None
            host, port_text = token.rsplit(":", 1)
        if port_text in {"*", ""}:
            return None
        try:
            port = int(port_text)
        except ValueError:
            return None
        return host.strip("[]"), port

    @staticmethod
    def _run_command(args: list[str]) -> subprocess.CompletedProcess[str]:
        command = list(args)
        cwd: str | None = None
        if len(command) >= 2 and command[0].lower() == "pktmon":
            verb = command[1].lower()
            if verb == "start" and "--file-name" in command:
                index = command.index("--file-name") + 1
                target = Path(command[index])
                cwd = str(target.parent)
                command[index] = target.name
            elif verb == "etl2txt":
                input_path = Path(command[2])
                cwd = str(input_path.parent)
                if "--out" in command:
                    out_index = command.index("--out") + 1
                    output_path = Path(command[out_index])
                    if output_path.parent == input_path.parent:
                        command[out_index] = output_path.name
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=30, cwd=cwd)

    def _wait_for_file(self, path: Path, *, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        while time.monotonic() < deadline:
            if path.exists():
                return True
            self._sleeper(0.1)
        return path.exists()

    def _wait_for_capture_file(self, directory: Path, *, requested_path: Path, timeout_seconds: float) -> Path | None:
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        while time.monotonic() < deadline:
            located = self._find_capture_file(directory, requested_path=requested_path)
            if located is not None:
                return located
            self._sleeper(0.1)
        return self._find_capture_file(directory, requested_path=requested_path)

    @staticmethod
    def _find_capture_file(directory: Path, *, requested_path: Path) -> Path | None:
        candidates = [requested_path, directory / "PktMon.etl"]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        for candidate in sorted(directory.glob("*.etl"), key=lambda item: item.stat().st_mtime, reverse=True):
            if candidate.exists():
                return candidate
        return None

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
