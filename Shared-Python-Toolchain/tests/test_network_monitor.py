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
        if _args[:3] == ["tasklist", "/fo", "csv"]:
            return subprocess.CompletedProcess(
                args=_args,
                returncode=0,
                stdout='"svchost.exe","101","Console","1","10,000 K"\n',
                stderr="",
            )
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
    assert observations[0]["process_ids"] == [101]
    assert observations[0]["process_names"] == ["svchost.exe"]
    assert len(observations[0]["sample_connections"]) == 2
    assert observations[0]["sample_connections"][0]["process_name"] == "svchost.exe"
    assert observations[0]["sample_connections"][0]["protocol"] == "tcp"


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
    assert findings[0].details["finding_type"] == "suspicious_remote_ip"
    assert findings[0].details["abnormal_reason"] == "repeat_threshold_exceeded"
    assert findings[0].details["evidence"]["retention_mode"] == "compact_evidence_only"


def test_evaluate_snapshot_emits_critical_dos_candidate_for_abnormal_burst(tmp_path: Path) -> None:
    monitor = NetworkMonitor(
        state_path=tmp_path / "network_state.json",
        suspicious_repeat_threshold=3,
        dos_hit_threshold=12,
        dos_syn_threshold=6,
        dos_port_span_threshold=3,
        sensitive_ports=[3389],
    )

    findings = monitor.evaluate_snapshot(
        {
            "suspicious_observations": [
                {
                    "remote_ip": "198.51.100.80",
                    "states": ["ESTABLISHED", "SYN_RECEIVED"],
                    "state_counts": {"ESTABLISHED": 5, "SYN_RECEIVED": 7},
                    "local_ports": [80, 443, 3389],
                    "remote_ports": [50000, 50001, 50002, 50003],
                    "hit_count": 12,
                    "sensitive_ports": [3389],
                }
            ]
        }
    )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].details["finding_type"] == "dos_candidate"
    assert findings[0].details["remote_ip"] == "198.51.100.80"
    assert findings[0].details["syn_received_count"] == 7
    assert findings[0].details["evidence"]["retention_mode"] == "compact_evidence_only"


def test_evaluate_snapshot_carries_compact_network_evidence() -> None:
    monitor = NetworkMonitor(
        state_path=Path("network_state.json"),
        suspicious_repeat_threshold=1,
        sensitive_ports=[3389],
    )

    findings = monitor.evaluate_snapshot(
        {
            "suspicious_observations": [
                {
                    "remote_ip": "203.0.113.45",
                    "states": ["ESTABLISHED"],
                    "state_counts": {"ESTABLISHED": 1},
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "hit_count": 1,
                    "sensitive_ports": [3389],
                    "sample_connections": [
                        {
                            "state": "ESTABLISHED",
                            "local_ip": "192.168.1.10",
                            "local_port": 3389,
                            "remote_ip": "203.0.113.45",
                            "remote_port": 51000,
                        }
                    ],
                }
            ]
        }
    )

    assert findings[0].details["evidence"]["sample_count"] == 1
    assert findings[0].details["evidence"]["sample_connections"][0]["remote_ip"] == "203.0.113.45"


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
        if _args[:3] == ["tasklist", "/fo", "csv"]:
            return subprocess.CompletedProcess(args=_args, returncode=0, stdout="", stderr="")
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


def test_list_recent_observations_returns_latest_first(tmp_path: Path) -> None:
    state_path = tmp_path / "network_state.json"
    state_path.write_text(
        '{"connection_history":{'
        '"1.1.1.1":{"remote_ip":"1.1.1.1","last_seen_at":"2026-03-29T20:00:00+00:00"},'
        '"8.8.8.8":{"remote_ip":"8.8.8.8","last_seen_at":"2026-03-29T21:00:00+00:00"}'
        '}}',
        encoding="utf-8",
    )
    monitor = NetworkMonitor(state_path=state_path)

    observations = monitor.list_recent_observations()

    assert [item["remote_ip"] for item in observations] == ["8.8.8.8", "1.1.1.1"]


def test_updated_connection_history_accumulates_compact_network_state() -> None:
    monitor = NetworkMonitor(state_path=Path("network_state.json"))

    history = monitor._updated_connection_history(
        {
            "checked_at": "2026-03-29T20:30:00+00:00",
            "suspicious_observations": [
                {
                    "remote_ip": "8.8.8.8",
                    "states": ["ESTABLISHED"],
                    "state_counts": {"ESTABLISHED": 2},
                    "local_ports": [3389],
                    "remote_ports": [51000, 51001],
                    "hit_count": 2,
                    "sensitive_ports": [3389],
                    "sample_connections": [{"remote_ip": "8.8.8.8", "local_port": 3389}],
                }
            ],
        },
        previous_state={
            "connection_history": {
                "8.8.8.8": {
                    "remote_ip": "8.8.8.8",
                    "states": ["SYN_RECEIVED"],
                    "state_counts": {"SYN_RECEIVED": 1},
                    "local_ports": [8443],
                    "remote_ports": [50000],
                    "sensitive_ports": [],
                    "first_seen_at": "2026-03-29T20:00:00+00:00",
                    "last_seen_at": "2026-03-29T20:10:00+00:00",
                    "sightings": 1,
                    "total_hits": 1,
                    "max_hit_count": 1,
                }
            }
        },
    )

    observation = history["8.8.8.8"]
    assert observation["first_seen_at"] == "2026-03-29T20:00:00+00:00"
    assert observation["last_seen_at"] == "2026-03-29T20:30:00+00:00"
    assert observation["sightings"] == 2
    assert observation["total_hits"] == 3
    assert observation["max_hit_count"] == 2
    assert sorted(observation["states"]) == ["ESTABLISHED", "SYN_RECEIVED"]
