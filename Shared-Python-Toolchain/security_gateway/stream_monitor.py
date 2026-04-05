"""Defender-backed monitoring for recent suspicious streaming artifacts."""
from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Sequence


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class StreamMonitorFinding:
    key: str
    severity: str
    title: str
    summary: str
    details: dict[str, Any]
    tags: list[str]
    resolved: bool = False


class StreamArtifactMonitor:
    def __init__(
        self,
        *,
        state_path: str | Path,
        artifact_roots: Sequence[str | Path],
        suspicious_extensions: list[str] | None = None,
        max_age_minutes: float = 30.0,
        max_files_per_tick: int = 8,
        scan_timeout_seconds: float = 90.0,
        runner: Callable[[Path, float], dict[str, Any]] | None = None,
        now_provider: Callable[[], datetime] | None = None,
    ) -> None:
        self._state_path = Path(state_path)
        self._artifact_roots = [Path(root) for root in artifact_roots]
        self._suspicious_extensions = {suffix.casefold() for suffix in (suspicious_extensions or [])}
        self._max_age_minutes = max(1.0, max_age_minutes)
        self._max_files_per_tick = max(1, max_files_per_tick)
        self._scan_timeout_seconds = max(10.0, scan_timeout_seconds)
        self._runner = runner or self._scan_with_defender
        self._now = now_provider or _utc_now
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
                "last_checked_at": self._now().isoformat(),
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
        cutoff = self._now() - timedelta(minutes=self._max_age_minutes)
        candidates = self._recent_suspicious_files(cutoff)
        scans: list[dict[str, Any]] = []
        for candidate in candidates[: self._max_files_per_tick]:
            scan_result = self._runner(candidate, self._scan_timeout_seconds)
            scans.append(
                {
                    "path": str(candidate),
                    "name": candidate.name,
                    "suffix": candidate.suffix.casefold(),
                    "size_bytes": candidate.stat().st_size if candidate.exists() else None,
                    "modified_at": datetime.fromtimestamp(candidate.stat().st_mtime, UTC).isoformat()
                    if candidate.exists()
                    else None,
                    **scan_result,
                }
            )
        return {
            "checked_at": self._now().isoformat(),
            "artifact_roots": [str(root) for root in self._artifact_roots],
            "max_age_minutes": self._max_age_minutes,
            "max_files_per_tick": self._max_files_per_tick,
            "scanned_artifacts": scans,
        }

    def evaluate_snapshot(self, snapshot: dict[str, Any]) -> list[StreamMonitorFinding]:
        findings: list[StreamMonitorFinding] = []
        scanned_artifacts = snapshot.get("scanned_artifacts") or []
        for artifact in scanned_artifacts:
            if not isinstance(artifact, dict):
                continue
            status = str(artifact.get("scan_status") or "unknown")
            detections = artifact.get("detections") if isinstance(artifact.get("detections"), list) else []
            if status != "infected" or not detections:
                continue
            artifact_path = str(artifact.get("path") or "unknown")
            artifact_name = str(artifact.get("name") or Path(artifact_path).name or "artifact")
            findings.append(
                StreamMonitorFinding(
                    key=f"stream-artifact:{artifact_path.casefold()}",
                    severity="critical",
                    title=f"Defender detected malware in stream artifact: {artifact_name}",
                    summary="Microsoft Defender reported a detection in a recent suspicious artifact associated with browser or stream activity.",
                    details={
                        "artifact_path": artifact_path,
                        "artifact_name": artifact_name,
                        "suffix": artifact.get("suffix"),
                        "size_bytes": artifact.get("size_bytes"),
                        "modified_at": artifact.get("modified_at"),
                        "finding_type": "stream_artifact_malware",
                        "detections": detections,
                    },
                    tags=["stream", "defender", "malware", "artifact"],
                )
            )
        return findings

    def _recent_suspicious_files(self, cutoff: datetime) -> list[Path]:
        candidates: list[Path] = []
        for root in self._artifact_roots:
            if not root.exists() or not root.is_dir():
                continue
            try:
                entries = list(root.iterdir())
            except OSError:
                continue
            for entry in entries:
                if not entry.is_file():
                    continue
                if entry.suffix.casefold() not in self._suspicious_extensions:
                    continue
                try:
                    modified_at = datetime.fromtimestamp(entry.stat().st_mtime, UTC)
                except OSError:
                    continue
                if modified_at < cutoff:
                    continue
                candidates.append(entry)
        candidates.sort(key=lambda item: item.stat().st_mtime if item.exists() else 0.0, reverse=True)
        return candidates

    @staticmethod
    def _scan_with_defender(target: Path, timeout_seconds: float) -> dict[str, Any]:
        escaped_target = str(target).replace("'", "''")
        command = (
            f"$ScanPath = '{escaped_target}'; "
            "$cmd = Get-Command Start-MpScan -ErrorAction SilentlyContinue; "
            "if (-not $cmd) { '{\"scan_status\":\"unavailable\",\"detections\":[]}' ; exit 0 } "
            "$before = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | "
            "Where-Object { ($_.Resources -join ' ') -like ('*' + $ScanPath + '*') } | "
            "Select-Object ThreatName,Resources,InitialDetectionTime); "
            "Start-MpScan -ScanType CustomScan -ScanPath $ScanPath -ErrorAction Stop | Out-Null; "
            "$after = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | "
            "Where-Object { ($_.Resources -join ' ') -like ('*' + $ScanPath + '*') } | "
            "Select-Object ThreatName,Resources,InitialDetectionTime); "
            "$newFindings = @($after | Where-Object { "
            "$signature = ($_.ThreatName + '|' + $_.InitialDetectionTime.ToString('o') + '|' + (($_.Resources -join ';'))); "
            "$signature -notin @($before | ForEach-Object { $_.ThreatName + '|' + $_.InitialDetectionTime.ToString('o') + '|' + (($_.Resources -join ';')) }) "
            "}); "
            "if ($newFindings.Count -gt 0) { "
            "(@{ scan_status='infected'; detections=$newFindings } | ConvertTo-Json -Compress -Depth 4) "
            "} else { "
            "'{\"scan_status\":\"clean\",\"detections\":[]}' "
            "}"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
        output = (result.stdout or "").strip()
        if result.returncode != 0:
            return {"scan_status": "failed", "detections": [], "error": (result.stderr or output).strip()}
        try:
            payload = json.loads(output) if output else {"scan_status": "clean", "detections": []}
        except json.JSONDecodeError:
            return {"scan_status": "failed", "detections": [], "error": output or "invalid defender output"}
        if not isinstance(payload, dict):
            return {"scan_status": "failed", "detections": [], "error": "invalid defender payload"}
        detections = payload.get("detections") if isinstance(payload.get("detections"), list) else []
        return {
            "scan_status": str(payload.get("scan_status") or "unknown"),
            "detections": detections,
        }

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
    def _build_resolution_finding(previous_finding: dict[str, Any]) -> StreamMonitorFinding:
        return StreamMonitorFinding(
            key=str(previous_finding.get("key", "stream-artifact-recovered")),
            severity="low",
            title=f"Recovered: {previous_finding.get('title', 'Stream artifact finding')}",
            summary="A previously detected suspicious stream artifact is no longer active in the current monitor window.",
            details={"previous_finding": previous_finding},
            tags=["stream", "recovery"],
            resolved=True,
        )
