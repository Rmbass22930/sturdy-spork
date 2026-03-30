from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

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
