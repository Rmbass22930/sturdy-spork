from __future__ import annotations

import json
import subprocess
from pathlib import Path

from security_gateway.packet_monitor import PacketMonitor


def test_parse_packet_text_groups_public_remote_packet_activity() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"), min_packet_count=2, sensitive_ports=[3389])

    observations = monitor._parse_packet_text(
        "\n".join(
            [
                "2026-03-29T20:00:00 TCP 8.8.8.8:51000 -> 192.168.1.10:3389 TLS ClientHello SNI example.com",
                "2026-03-29T20:00:01 TCP 8.8.8.8:51001 -> 192.168.1.10:3389 GET / HTTP/1.1 Host: example.com",
                "2026-03-29T20:00:02 UDP 127.0.0.1:10000 -> 127.0.0.1:9000",
            ]
        )
    )

    assert len(observations) == 1
    assert observations[0]["remote_ip"] == "8.8.8.8"
    assert observations[0]["packet_count"] == 2
    assert observations[0]["sensitive_ports"] == [3389]
    assert len(observations[0]["sample_packet_endpoints"]) == 2
    assert observations[0]["protocol_evidence"]["application_protocols"] == ["http", "tls"]
    assert observations[0]["protocol_evidence"]["hostnames"] == ["example.com"]
    assert observations[0]["protocol_evidence"]["indicators"] == ["http_request", "tls_handshake"]


def test_parse_packet_text_handles_ipv6() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"), min_packet_count=1)

    observations = monitor._parse_packet_text(
        "2026-03-29T20:00:00 TCP [2606:4700:4700::1111]:443 -> [fe80::1]:51515"
    )

    assert len(observations) == 1
    assert observations[0]["remote_ip"] == "2606:4700:4700::1111"
    assert observations[0]["protocols"] == ["TCP"]


def test_parse_packet_text_handles_src_dst_style_lines() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"), min_packet_count=1)

    observations = monitor._parse_packet_text(
        "2026-03-29T20:00:00 UDP flow src=8.8.4.4:53 dst=192.168.1.10:53100"
    )

    assert len(observations) == 1
    assert observations[0]["remote_ip"] == "8.8.4.4"
    assert observations[0]["protocols"] == ["UDP"]


def test_collect_snapshot_reports_permission_denied(tmp_path: Path) -> None:
    state_path = tmp_path / "packet_state.json"

    def runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "pktmon":
            return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="Access is denied.")
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="netstat unavailable")

    monitor = PacketMonitor(state_path=state_path, runner=runner, sleeper=lambda _seconds: None)

    snapshot = monitor.collect_snapshot()

    assert snapshot["capture_status"] == "permission_denied"
    assert snapshot["packet_observations"] == []


def test_collect_snapshot_retains_capture_artifacts_when_enabled(tmp_path: Path) -> None:
    state_path = tmp_path / "packet_state.json"
    retention_path = tmp_path / "captures"
    current_etl: dict[str, Path] = {}

    def runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] != "pktmon":
            raise AssertionError(args)
        if args[1] == "start":
            current_etl["path"] = Path(args[6])
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
        if args[1] == "stop":
            current_etl["path"].write_text("etl", encoding="utf-8")
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
        if args[1] == "etl2txt":
            Path(args[4]).write_text(
                "2026-03-29T20:00:00 TCP 8.8.8.8:51000 -> 192.168.1.10:3389 TLS ClientHello SNI example.com\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
        raise AssertionError(args)

    monitor = PacketMonitor(
        state_path=state_path,
        min_packet_count=1,
        sensitive_ports=[3389],
        capture_retention_enabled=True,
        capture_retention_path=retention_path,
        runner=runner,
        sleeper=lambda _seconds: None,
    )

    snapshot = monitor.collect_snapshot()

    capture = snapshot["retained_capture"]
    assert capture["capture_id"].startswith("packet-capture-")
    assert Path(capture["etl_path"]).exists()
    assert Path(capture["txt_path"]).exists()
    assert capture["primary_remote_ip"] == "8.8.8.8"
    assert capture["primary_session_key"] == "packet-session:8.8.8.8"
    assert capture["protocols"] == ["TCP"]
    assert capture["local_ports"] == [3389]
    assert capture["remote_ports"] == [51000]
    assert capture["session_observations"][0]["session_key"] == "packet-session:8.8.8.8"
    assert capture["session_observations"][0]["protocol_evidence"]["application_protocols"] == ["tls"]
    assert capture["session_observations"][0]["protocol_evidence"]["hostnames"] == ["example.com"]
    assert capture["protocol_evidence"]["application_protocols"] == ["tls"]
    assert capture["protocol_evidence"]["hostnames"] == ["example.com"]
    assert monitor.list_retained_captures(limit=5)[0]["capture_id"] == capture["capture_id"]
    assert monitor.list_retained_captures(limit=5, remote_ip="8.8.8.8")[0]["capture_id"] == capture["capture_id"]
    assert monitor.list_retained_captures(limit=5, session_key="packet-session:8.8.8.8")[0]["capture_id"] == capture["capture_id"]
    assert monitor.list_retained_captures(limit=5, protocol="tcp")[0]["capture_id"] == capture["capture_id"]
    assert monitor.list_retained_captures(limit=5, local_port=3389)[0]["capture_id"] == capture["capture_id"]
    assert monitor.list_retained_captures(limit=5, remote_port=51000)[0]["capture_id"] == capture["capture_id"]
    assert "8.8.8.8" in monitor.get_retained_capture_text(capture["capture_id"])


def test_collect_snapshot_falls_back_to_socket_table_when_pktmon_is_denied(tmp_path: Path) -> None:
    state_path = tmp_path / "packet_state.json"

    def runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "pktmon":
            return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="Access is denied.")
        if args[:5] == ["netstat", "-ano", "-n", "-p", "tcp"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="  TCP    192.168.1.10:3389    8.8.8.8:51000    ESTABLISHED    4242\n",
                stderr="",
            )
        if args[:5] == ["netstat", "-ano", "-n", "-p", "udp"]:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
        raise AssertionError(args)

    monitor = PacketMonitor(state_path=state_path, runner=runner, sleeper=lambda _seconds: None)

    snapshot = monitor.collect_snapshot()

    assert snapshot["capture_status"] == "fallback_socket_table"
    assert snapshot["evidence_mode"] == "socket_table"
    assert snapshot["packet_observations"][0]["remote_ip"] == "8.8.8.8"
    assert snapshot["packet_observations"][0]["packet_count"] == 1
    assert snapshot["packet_observations"][0]["sensitive_ports"] == [3389]
    assert snapshot["session_observations"][0]["session_key"] == "packet-session:8.8.8.8"


def test_collect_socket_table_observations_groups_public_remote_connections(tmp_path: Path) -> None:
    state_path = tmp_path / "packet_state.json"

    def runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[:5] == ["netstat", "-ano", "-n", "-p", "tcp"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=(
                    "  TCP    192.168.1.10:3389    8.8.8.8:51000    ESTABLISHED    4242\n"
                    "  TCP    192.168.1.10:3389    8.8.8.8:51001    ESTABLISHED    4242\n"
                    "  TCP    127.0.0.1:5000       127.0.0.1:6000   ESTABLISHED    1111\n"
                ),
                stderr="",
            )
        if args[:5] == ["netstat", "-ano", "-n", "-p", "udp"]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="  UDP    192.168.1.10:5353    1.1.1.1:53                    5151\n",
                stderr="",
            )
        raise AssertionError(args)

    monitor = PacketMonitor(state_path=state_path, runner=runner)

    observations, collected = monitor._collect_socket_table_observations()

    assert collected is True
    assert len(observations) == 2
    assert observations[0]["remote_ip"] == "8.8.8.8"
    assert observations[0]["packet_count"] == 2
    assert observations[0]["protocols"] == ["TCP"]
    assert observations[0]["sensitive_ports"] == [3389]
    assert observations[1]["remote_ip"] == "1.1.1.1"
    assert observations[1]["protocols"] == ["UDP"]
    assert observations[1]["packet_count"] == 1


def test_collect_snapshot_reports_socket_table_fallback_without_public_observations(tmp_path: Path) -> None:
    state_path = tmp_path / "packet_state.json"

    def runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "pktmon":
            return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="Access is denied.")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="  TCP    127.0.0.1:5000    127.0.0.1:6000    ESTABLISHED    1111\n", stderr="")

    monitor = PacketMonitor(state_path=state_path, runner=runner, sleeper=lambda _seconds: None)

    snapshot = monitor.collect_snapshot()

    assert snapshot["capture_status"] == "fallback_socket_table"
    assert snapshot["evidence_mode"] == "socket_table"
    assert snapshot["packet_observations"] == []


def test_evaluate_snapshot_emits_finding_for_repeated_packets() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"), min_packet_count=3, sensitive_ports=[3389])

    findings = monitor.evaluate_snapshot(
        {
            "capture_status": "ok",
            "packet_observations": [
                {
                    "remote_ip": "1.1.1.1",
                    "protocols": ["TCP"],
                    "local_ports": [8443],
                    "remote_ports": [53000, 53001, 53002],
                    "packet_count": 3,
                    "sensitive_ports": [],
                }
            ],
        }
    )

    assert findings == []


def test_evaluate_snapshot_emits_finding_when_packet_count_exceeds_baseline() -> None:
    monitor = PacketMonitor(
        state_path=Path("packet_state.json"),
        min_packet_count=3,
        anomaly_multiplier=2.0,
        learning_samples=3,
        sensitive_ports=[3389],
    )

    findings = monitor.evaluate_snapshot(
        {
            "capture_status": "ok",
            "packet_observations": [
                {
                    "remote_ip": "1.1.1.1",
                    "protocols": ["TCP"],
                    "local_ports": [8443],
                    "remote_ports": [53000, 53001, 53002, 53003, 53004, 53005, 53006],
                    "packet_count": 7,
                    "sensitive_ports": [],
                }
            ],
        },
        previous_state={"history": {"1.1.1.1": {"samples": [2, 2, 3]}}},
    )

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].details["packet_count"] == 7
    assert findings[0].details["abnormal_threshold"] == 5
    assert findings[0].details["evidence"]["retention_mode"] == "compact_evidence_only"
    assert findings[0].details["evidence"]["sample_count"] == 0


def test_evaluate_snapshot_emits_sensitive_port_finding_without_baseline() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"), min_packet_count=5, sensitive_ports=[3389])

    findings = monitor.evaluate_snapshot(
        {
            "capture_status": "ok",
            "packet_observations": [
                {
                    "remote_ip": "8.8.8.8",
                    "protocols": ["TCP"],
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "packet_count": 1,
                    "sensitive_ports": [3389],
                }
            ],
        }
    )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].details["evidence"]["sample_count"] == 0


def test_evaluate_snapshot_carries_compact_packet_evidence() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"), min_packet_count=1, sensitive_ports=[3389])

    findings = monitor.evaluate_snapshot(
        {
            "capture_status": "ok",
            "packet_observations": [
                {
                    "remote_ip": "8.8.8.8",
                    "protocols": ["TCP"],
                    "local_ports": [3389],
                    "remote_ports": [51000],
                    "packet_count": 1,
                    "sensitive_ports": [3389],
                    "sample_packet_endpoints": [
                        {
                            "protocol": "TCP",
                            "remote_ip": "8.8.8.8",
                            "remote_port": 51000,
                            "local_ip": "192.168.1.10",
                            "local_port": 3389,
                        }
                    ],
                }
            ],
        }
    )

    assert findings[0].details["evidence"]["sample_count"] == 1
    assert findings[0].details["evidence"]["sample_packet_endpoints"][0]["remote_ip"] == "8.8.8.8"
    assert findings[0].details["evidence"]["sample_sessions"][0]["session_key"] == "packet-session:8.8.8.8"


def test_run_check_tracks_resolution(tmp_path: Path) -> None:
    state_path = tmp_path / "packet_state.json"
    current_etl: dict[str, Path] = {}
    outputs = [
        subprocess.CompletedProcess(args=["pktmon"], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(args=["pktmon"], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(args=["pktmon"], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(args=["pktmon"], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(args=["pktmon"], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(args=["pktmon"], returncode=0, stdout="", stderr=""),
    ]
    txt_payloads = [
        "2026-03-29T20:00:00 TCP 8.8.8.8:51000 -> 192.168.1.10:3389\n",
        "",
    ]

    def runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        result = outputs.pop(0)
        if args[1] == "start":
            current_etl["path"] = Path(args[6])
        if args[1] == "stop":
            current_etl["path"].write_text("etl", encoding="utf-8")
        if args[1] == "etl2txt":
            Path(args[4]).write_text(txt_payloads.pop(0), encoding="utf-8")
        return result

    monitor = PacketMonitor(
        state_path=state_path,
        min_packet_count=1,
        sensitive_ports=[3389],
        runner=runner,
        sleeper=lambda _seconds: None,
    )

    first = monitor.run_check()
    second = monitor.run_check()

    assert len(first["emitted_findings"]) == 1
    assert len(second["resolved_findings"]) == 1


def test_run_check_preserves_active_findings_when_capture_fails(tmp_path: Path) -> None:
    state_path = tmp_path / "packet_state.json"
    state_path.write_text(
        '{'
        '"active_findings":[{"key":"packet-remote-ip:8.8.8.8","severity":"high","title":"Suspicious packet activity observed: 8.8.8.8","summary":"Existing finding","details":{"remote_ip":"8.8.8.8"},"tags":["packet"]}],'
        '"history":{"8.8.8.8":{"samples":[4,5,6],"last_seen_at":"2026-03-29T20:00:00+00:00"}},'
        '"session_history":{"packet-session:8.8.8.8":{"session_key":"packet-session:8.8.8.8","remote_ip":"8.8.8.8","last_seen_at":"2026-03-29T20:00:00+00:00"}}'
        '}',
        encoding="utf-8",
    )

    def runner(_args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=["pktmon"], returncode=1, stdout="", stderr="Access is denied.")

    monitor = PacketMonitor(state_path=state_path, runner=runner, sleeper=lambda _seconds: None)

    result = monitor.run_check()

    assert result["emitted_findings"] == []
    assert result["resolved_findings"] == []
    assert len(result["active_findings"]) == 1
    persisted = state_path.read_text(encoding="utf-8")
    assert '"packet-remote-ip:8.8.8.8"' in persisted
    assert '"packet-session:8.8.8.8"' in persisted
    assert '"history"' in persisted
    assert '"last_seen_at": "2026-03-29T20:00:00+00:00"' in persisted


def test_list_recent_sessions_returns_latest_first(tmp_path: Path) -> None:
    state_path = tmp_path / "packet_state.json"
    state_path.write_text(
        json.dumps(
            {
                "session_history": {
                    "packet-session:1.1.1.1": {
                        "session_key": "packet-session:1.1.1.1",
                        "remote_ip": "1.1.1.1",
                        "last_seen_at": "2026-03-29T20:00:00+00:00",
                    },
                    "packet-session:8.8.8.8": {
                        "session_key": "packet-session:8.8.8.8",
                        "remote_ip": "8.8.8.8",
                        "last_seen_at": "2026-03-29T21:00:00+00:00",
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    monitor = PacketMonitor(state_path=state_path)

    sessions = monitor.list_recent_sessions()

    assert [item["remote_ip"] for item in sessions] == ["8.8.8.8", "1.1.1.1"]


def test_updated_session_history_accumulates_compact_session_state() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"))

    history = monitor._updated_session_history(
        {
            "checked_at": "2026-03-29T20:30:00+00:00",
            "session_observations": [
                {
                    "session_key": "packet-session:8.8.8.8",
                    "remote_ip": "8.8.8.8",
                    "protocols": ["TCP"],
                    "local_ips": ["192.168.1.10"],
                    "local_ports": [3389],
                    "remote_ports": [51000, 51001],
                    "packet_count": 7,
                    "sensitive_ports": [3389],
                    "sample_packet_endpoints": [{"remote_ip": "8.8.8.8", "local_port": 3389}],
                    "protocol_evidence": {
                        "application_protocols": ["tls"],
                        "hostnames": ["example.com"],
                        "indicators": ["tls_handshake"],
                    },
                }
            ],
        },
        previous_state={
            "session_history": {
                "packet-session:8.8.8.8": {
                    "session_key": "packet-session:8.8.8.8",
                    "remote_ip": "8.8.8.8",
                    "protocols": ["UDP"],
                    "local_ips": ["192.168.1.9"],
                    "local_ports": [8443],
                    "remote_ports": [50000],
                    "sensitive_ports": [],
                    "first_seen_at": "2026-03-29T20:00:00+00:00",
                    "last_seen_at": "2026-03-29T20:10:00+00:00",
                    "sightings": 1,
                    "total_packets": 3,
                    "max_packet_count": 3,
                    "protocol_evidence": {
                        "application_protocols": ["rdp"],
                        "hostnames": ["prior.example.com"],
                        "indicators": ["rdp_session"],
                    },
                }
            }
        },
    )

    session = history["packet-session:8.8.8.8"]
    assert session["first_seen_at"] == "2026-03-29T20:00:00+00:00"
    assert session["last_seen_at"] == "2026-03-29T20:30:00+00:00"
    assert session["sightings"] == 2
    assert session["total_packets"] == 10
    assert session["max_packet_count"] == 7
    assert session["local_ports"] == [3389, 8443]
    assert session["protocol_evidence"]["application_protocols"] == ["rdp", "tls"]
    assert session["protocol_evidence"]["hostnames"] == ["example.com", "prior.example.com"]
    assert session["protocol_evidence"]["indicators"] == ["rdp_session", "tls_handshake"]


def test_updated_history_keeps_prior_remote_ips() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"))

    history = monitor._updated_history(
        {
            "checked_at": "2026-03-29T20:30:00+00:00",
            "packet_observations": [
                {
                    "remote_ip": "1.1.1.1",
                    "packet_count": 7,
                }
            ],
        },
        previous_state={
            "history": {
                "8.8.8.8": {"samples": [2, 3], "last_seen_at": "2026-03-29T20:00:00+00:00"},
                "1.1.1.1": {"samples": [1, 2], "last_seen_at": "2026-03-29T20:10:00+00:00"},
            }
        },
    )

    assert history["8.8.8.8"]["samples"] == [2, 3]
    assert history["1.1.1.1"]["samples"] == [1, 2, 7]


def test_run_command_uses_capture_directory_as_cwd(monkeypatch, tmp_path: Path) -> None:
    etl_path = tmp_path / "nested" / "capture.etl"
    captured: dict[str, object] = {}

    def fake_run(args: list[str], capture_output: bool, text: bool, check: bool, timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured["cwd"] = cwd
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    PacketMonitor._run_command(["pktmon", "start", "--capture", "--file-name", str(etl_path)])

    assert captured["cwd"] == str(etl_path.parent)
    assert captured["args"] == ["pktmon", "start", "--capture", "--file-name", "capture.etl"]


def test_run_command_uses_etl_parent_for_conversion(monkeypatch, tmp_path: Path) -> None:
    etl_path = tmp_path / "capture.etl"
    txt_path = tmp_path / "capture.txt"
    captured: dict[str, object] = {}

    def fake_run(args: list[str], capture_output: bool, text: bool, check: bool, timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured["cwd"] = cwd
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    PacketMonitor._run_command(["pktmon", "etl2txt", str(etl_path), "--out", str(txt_path), "--brief"])

    assert captured["cwd"] == str(etl_path.parent)
    assert captured["args"] == ["pktmon", "etl2txt", str(etl_path), "--out", "capture.txt", "--brief"]


def test_find_capture_file_falls_back_to_pktmon_default_name(tmp_path: Path) -> None:
    requested = tmp_path / "capture.etl"
    fallback = tmp_path / "PktMon.etl"
    fallback.write_text("etl", encoding="utf-8")

    located = PacketMonitor._find_capture_file(tmp_path, requested_path=requested)

    assert located == fallback


def test_find_capture_file_falls_back_to_any_etl_in_directory(tmp_path: Path) -> None:
    requested = tmp_path / "capture.etl"
    fallback = tmp_path / "alternate.etl"
    fallback.write_text("etl", encoding="utf-8")

    located = PacketMonitor._find_capture_file(tmp_path, requested_path=requested)

    assert located == fallback
