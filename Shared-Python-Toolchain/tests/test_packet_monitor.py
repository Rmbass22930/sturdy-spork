from __future__ import annotations

import subprocess
from pathlib import Path

from security_gateway.packet_monitor import PacketMonitor


def test_parse_packet_text_groups_public_remote_packet_activity() -> None:
    monitor = PacketMonitor(state_path=Path("packet_state.json"), min_packet_count=2, sensitive_ports=[3389])

    observations = monitor._parse_packet_text(
        "\n".join(
            [
                "2026-03-29T20:00:00 TCP 8.8.8.8:51000 -> 192.168.1.10:3389",
                "2026-03-29T20:00:01 TCP 8.8.8.8:51001 -> 192.168.1.10:3389",
                "2026-03-29T20:00:02 UDP 127.0.0.1:10000 -> 127.0.0.1:9000",
            ]
        )
    )

    assert len(observations) == 1
    assert observations[0]["remote_ip"] == "8.8.8.8"
    assert observations[0]["packet_count"] == 2
    assert observations[0]["sensitive_ports"] == [3389]
    assert len(observations[0]["sample_packet_endpoints"]) == 2


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

    def runner(_args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=["pktmon"], returncode=1, stdout="", stderr="Access is denied.")

    monitor = PacketMonitor(state_path=state_path, runner=runner, sleeper=lambda _seconds: None)

    snapshot = monitor.collect_snapshot()

    assert snapshot["capture_status"] == "permission_denied"
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
        '"history":{"8.8.8.8":{"samples":[4,5,6],"last_seen_at":"2026-03-29T20:00:00+00:00"}}'
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
    assert '"history"' in persisted
    assert '"last_seen_at": "2026-03-29T20:00:00+00:00"' in persisted


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
