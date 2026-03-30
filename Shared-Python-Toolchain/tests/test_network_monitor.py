from __future__ import annotations

import subprocess
from pathlib import Path

from security_gateway.network_monitor import NetworkMonitor


def test_parse_endpoint_handles_ipv4_and_ipv6() -> None:
    assert NetworkMonitor._parse_endpoint("203.0.113.10:443") == ("203.0.113.10", 443)
    assert NetworkMonitor._parse_endpoint("[2001:db8::1]:3389") == ("2001:db8::1", 3389)


def test_collect_snapshot_groups_public_remote_activity_against_listening_ports(tmp_path: Path) -> None:
    state_path = tmp_path / "network_state.json"

    def runner(_args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["netstat"],
            returncode=0,
            stdout="\n".join(
                    [
                        "  TCP    0.0.0.0:3389      0.0.0.0:0      LISTENING       100",
                        "  TCP    192.168.1.10:3389 8.8.8.8:51000 ESTABLISHED  101",
                        "  TCP    192.168.1.10:3389 8.8.8.8:51001 SYN_RECEIVED 101",
                        "  TCP    192.168.1.10:8443 1.1.1.1:53123 ESTABLISHED 102",
                        "  TCP    127.0.0.1:9000    127.0.0.1:60000 ESTABLISHED     103",
                    ]
                ),
            stderr="",
        )

    monitor = NetworkMonitor(
        state_path=state_path,
        suspicious_repeat_threshold=2,
        sensitive_ports=[3389],
        runner=runner,
    )

    snapshot = monitor.collect_snapshot()

    assert snapshot["listening_ports"] == [3389]
    observations = snapshot["suspicious_observations"]
    assert len(observations) == 1
    assert observations[0]["remote_ip"] == "8.8.8.8"
    assert observations[0]["hit_count"] == 2
    assert observations[0]["sensitive_ports"] == [3389]


def test_evaluate_snapshot_emits_critical_for_sensitive_ports(tmp_path: Path) -> None:
    monitor = NetworkMonitor(
        state_path=tmp_path / "network_state.json",
        suspicious_repeat_threshold=3,
        sensitive_ports=[3389],
    )

    findings = monitor.evaluate_snapshot(
        {
            "suspicious_observations": [
                {
                    "remote_ip": "203.0.113.45",
                    "states": ["ESTABLISHED"],
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "hit_count": 1,
                    "sensitive_ports": [3389],
                }
            ]
        }
    )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].details["remote_ip"] == "203.0.113.45"


def test_evaluate_snapshot_emits_high_for_repeated_non_sensitive_public_ip(tmp_path: Path) -> None:
    monitor = NetworkMonitor(
        state_path=tmp_path / "network_state.json",
        suspicious_repeat_threshold=3,
        sensitive_ports=[3389],
    )

    findings = monitor.evaluate_snapshot(
        {
            "suspicious_observations": [
                {
                    "remote_ip": "1.1.1.1",
                    "states": ["ESTABLISHED"],
                    "local_ports": [8443],
                    "remote_ports": [53123, 53124, 53125],
                    "hit_count": 3,
                    "sensitive_ports": [],
                }
            ]
        }
    )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].details["hit_count"] == 3


def test_run_check_tracks_resolution(tmp_path: Path) -> None:
    state_path = tmp_path / "network_state.json"
    outputs = [
        subprocess.CompletedProcess(
            args=["netstat"],
            returncode=0,
            stdout="\n".join(
                [
                        "  TCP    0.0.0.0:3389      0.0.0.0:0      LISTENING       100",
                        "  TCP    192.168.1.10:3389 8.8.8.8:51000 ESTABLISHED  101",
                ]
            ),
            stderr="",
        ),
        subprocess.CompletedProcess(
            args=["netstat"],
            returncode=0,
            stdout="  TCP    0.0.0.0:3389      0.0.0.0:0      LISTENING       100",
            stderr="",
        ),
    ]

    def runner(_args: list[str]) -> subprocess.CompletedProcess[str]:
        return outputs.pop(0)

    monitor = NetworkMonitor(
        state_path=state_path,
        suspicious_repeat_threshold=1,
        sensitive_ports=[3389],
        runner=runner,
    )

    first = monitor.run_check()
    second = monitor.run_check()

    assert len(first["emitted_findings"]) == 1
    assert len(second["resolved_findings"]) == 1
