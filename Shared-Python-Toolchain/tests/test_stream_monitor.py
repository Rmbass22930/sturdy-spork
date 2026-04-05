from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_gateway.stream_monitor import StreamArtifactMonitor


def test_collect_snapshot_scans_recent_suspicious_artifacts(tmp_path: Path) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    artifact = downloads / "suspicious.exe"
    artifact.write_bytes(b"test")
    fixed_now = datetime(2026, 3, 29, 21, 0, tzinfo=UTC)
    modified_at = fixed_now.timestamp()
    artifact.touch()
    artifact.chmod(0o666)
    os.utime(artifact, (modified_at, modified_at))

    scanned_paths: list[Path] = []

    def runner(target: Path, timeout_seconds: float) -> dict[str, object]:
        scanned_paths.append(target)
        return {"scan_status": "clean", "detections": [], "timeout_seconds": timeout_seconds}

    monitor = StreamArtifactMonitor(
        state_path=tmp_path / "stream_state.json",
        artifact_roots=[downloads],
        suspicious_extensions=[".exe"],
        max_age_minutes=30,
        max_files_per_tick=5,
        runner=runner,
        now_provider=lambda: fixed_now,
    )

    snapshot = monitor.collect_snapshot()

    assert scanned_paths == [artifact]
    assert len(snapshot["scanned_artifacts"]) == 1
    assert snapshot["scanned_artifacts"][0]["path"] == str(artifact)
    assert snapshot["scanned_artifacts"][0]["scan_status"] == "clean"


def test_evaluate_snapshot_emits_finding_for_defender_detection(tmp_path: Path) -> None:
    monitor = StreamArtifactMonitor(
        state_path=tmp_path / "stream_state.json",
        artifact_roots=[tmp_path],
        suspicious_extensions=[".exe"],
    )

    findings = monitor.evaluate_snapshot(
        {
            "scanned_artifacts": [
                {
                    "path": str(tmp_path / "payload.exe"),
                    "name": "payload.exe",
                    "suffix": ".exe",
                    "scan_status": "infected",
                    "detections": [{"ThreatName": "Trojan:Test", "Resources": [str(tmp_path / "payload.exe")]}],
                }
            ]
        }
    )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].details["finding_type"] == "stream_artifact_malware"
    assert findings[0].details["artifact_name"] == "payload.exe"


def test_run_check_tracks_resolution(tmp_path: Path) -> None:
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    artifact = downloads / "payload.exe"
    artifact.write_bytes(b"test")
    fixed_now = datetime(2026, 3, 29, 21, 0, tzinfo=UTC)

    detections: list[dict[str, object]] = [
        {"scan_status": "infected", "detections": [{"ThreatName": "Trojan:Test", "Resources": [str(artifact)]}]},
        {"scan_status": "clean", "detections": []},
    ]

    def runner(_target: Path, _timeout_seconds: float) -> dict[str, object]:
        return detections.pop(0)

    monitor = StreamArtifactMonitor(
        state_path=tmp_path / "stream_state.json",
        artifact_roots=[downloads],
        suspicious_extensions=[".exe"],
        runner=runner,
        now_provider=lambda: fixed_now,
    )

    first = monitor.run_check()
    second = monitor.run_check()

    assert len(first["emitted_findings"]) == 1
    assert len(second["resolved_findings"]) == 1


def test_scan_with_defender_embeds_literal_scan_path(monkeypatch: Any, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args=args, returncode=0, stdout='{"scan_status":"clean","detections":[]}', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = StreamArtifactMonitor._scan_with_defender(tmp_path / "payload.exe", 15.0)

    assert result["scan_status"] == "clean"
    args = captured["args"]
    assert isinstance(args, list)
    assert "-ScanPath" not in args
    assert str(tmp_path / "payload.exe") in str(args[-1])
