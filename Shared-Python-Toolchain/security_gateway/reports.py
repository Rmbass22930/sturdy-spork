"""Printable PDF reports for Security Gateway operators."""
from __future__ import annotations

import io
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, List

from reportlab.lib.pagesizes import letter  # type: ignore[import-untyped]
from reportlab.pdfgen import canvas  # type: ignore[import-untyped]

from .config import settings
from .ip_controls import IPBlocklistManager

MIN_REPORT_MAX_EVENTS = 1
MAX_REPORT_MAX_EVENTS = 500
MAX_REPORT_TIME_WINDOW_HOURS = 24.0 * 90
MIN_REPORT_MIN_RISK_SCORE = 0.0
MAX_REPORT_MIN_RISK_SCORE = 100.0


@dataclass(frozen=True)
class ReportFilters:
    max_events: int = 25
    time_window_hours: float | None = None
    min_risk_score: float = 0.0
    include_blocked_ips: bool = True
    include_potential_blocked_ips: bool = True
    include_recent_events: bool = True

    def __post_init__(self) -> None:
        if self.max_events < MIN_REPORT_MAX_EVENTS or self.max_events > MAX_REPORT_MAX_EVENTS:
            raise ValueError(
                f"max_events must be between {MIN_REPORT_MAX_EVENTS} and {MAX_REPORT_MAX_EVENTS}."
            )
        if self.time_window_hours is not None:
            if self.time_window_hours <= 0 or self.time_window_hours > MAX_REPORT_TIME_WINDOW_HOURS:
                raise ValueError(
                    f"time_window_hours must be between 0 and {MAX_REPORT_TIME_WINDOW_HOURS} hours."
                )
        if self.min_risk_score < MIN_REPORT_MIN_RISK_SCORE or self.min_risk_score > MAX_REPORT_MIN_RISK_SCORE:
            raise ValueError(
                f"min_risk_score must be between {MIN_REPORT_MIN_RISK_SCORE} and {MAX_REPORT_MIN_RISK_SCORE}."
            )


class SecurityReportBuilder:
    def __init__(self, *, audit_log_path: str | Path | None = None, ip_blocklist_path: str | Path | None = None):
        self.audit_log_path = Path(audit_log_path or settings.audit_log_path)
        self.ip_blocklist = IPBlocklistManager(path=ip_blocklist_path or settings.ip_blocklist_path)

    def build_summary_pdf(
        self,
        *,
        title: str = "Security Gateway Summary Report",
        max_events: int = 25,
        time_window_hours: float | None = None,
        min_risk_score: float = 0.0,
        include_blocked_ips: bool = True,
        include_potential_blocked_ips: bool = True,
        include_recent_events: bool = True,
    ) -> bytes:
        summary = self.collect_summary(
            filters=ReportFilters(
                max_events=max_events,
                time_window_hours=time_window_hours,
                min_risk_score=min_risk_score,
                include_blocked_ips=include_blocked_ips,
                include_potential_blocked_ips=include_potential_blocked_ips,
                include_recent_events=include_recent_events,
            )
        )
        return self.build_summary_pdf_from_summary(summary, title=title)

    def collect_summary(self, *, filters: ReportFilters | None = None) -> dict[str, Any]:
        filters = filters or ReportFilters()
        blocked_ips = self.ip_blocklist.list_entries() if filters.include_blocked_ips else []
        recent_events = self._load_recent_events(
            max_events=filters.max_events,
            time_window_hours=filters.time_window_hours,
            min_risk_score=filters.min_risk_score,
        )
        return {
            "filters": {
                "max_events": filters.max_events,
                "time_window_hours": filters.time_window_hours,
                "min_risk_score": filters.min_risk_score,
                "include_blocked_ips": filters.include_blocked_ips,
                "include_potential_blocked_ips": filters.include_potential_blocked_ips,
                "include_recent_events": filters.include_recent_events,
            },
            "blocked_ips": [
                {
                    "ip": entry.ip,
                    "blocked_at": entry.blocked_at,
                    "blocked_by": entry.blocked_by,
                    "expires_at": entry.expires_at,
                    "reason": entry.reason,
                }
                for entry in blocked_ips
            ] if filters.include_blocked_ips else [],
            "potential_blocked_ips": self._collect_potential_blocks(recent_events, blocked_ips, min_risk_score=filters.min_risk_score)
            if filters.include_potential_blocked_ips else [],
            "tracker_block_events": self._collect_tracker_blocks(recent_events),
            "recent_events": recent_events if filters.include_recent_events else [],
        }

    def write_summary_pdf(
        self,
        output_path: str | Path | None = None,
        *,
        max_events: int = 25,
        time_window_hours: float | None = None,
        min_risk_score: float = 0.0,
        include_blocked_ips: bool = True,
        include_potential_blocked_ips: bool = True,
        include_recent_events: bool = True,
    ) -> Path:
        output_dir = self.get_output_dir()
        output_dir.mkdir(parents=True, exist_ok=True)
        target = Path(output_path) if output_path else output_dir / f"security-summary-{datetime.now():%Y%m%d-%H%M%S}.pdf"
        target.parent.mkdir(parents=True, exist_ok=True)
        summary = self.collect_summary(
            filters=ReportFilters(
                max_events=max_events,
                time_window_hours=time_window_hours,
                min_risk_score=min_risk_score,
                include_blocked_ips=include_blocked_ips,
                include_potential_blocked_ips=include_potential_blocked_ips,
                include_recent_events=include_recent_events,
            )
        )
        target.write_bytes(self.build_summary_pdf_from_summary(summary))
        self._write_report_metadata(target, summary)
        return target

    def build_summary_pdf_from_summary(
        self,
        summary: dict[str, Any],
        *,
        title: str = "Security Gateway Summary Report",
    ) -> bytes:
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=letter)
        _, height = letter
        y = height - 54

        def write_line(text: str, *, font: str = "Helvetica", size: int = 10, indent: int = 0, gap: int = 14):
            nonlocal y
            if y < 56:
                pdf.showPage()
                y = height - 54
            pdf.setFont(font, size)
            pdf.drawString(54 + indent, y, text[:118])
            y -= gap

        pdf.setTitle(title)
        write_line(title, font="Helvetica-Bold", size=16, gap=20)
        write_line(f"Generated: {datetime.now(UTC).isoformat()}", font="Helvetica", size=9, gap=18)
        filters = summary.get("filters", {})
        filter_text = (
            f"Filters: window_hours={filters.get('time_window_hours', 'all')} | "
            f"min_risk={filters.get('min_risk_score', 0)} | "
            f"blocked={filters.get('include_blocked_ips', True)} | "
            f"potential={filters.get('include_potential_blocked_ips', True)} | "
            f"events={filters.get('include_recent_events', True)}"
        )
        write_line(filter_text, font="Helvetica", size=8, gap=16)

        write_line("Blocked IPs", font="Helvetica-Bold", size=12, gap=16)
        if summary["blocked_ips"]:
            for entry in summary["blocked_ips"]:
                expiry = entry["expires_at"] or "permanent"
                write_line(
                    f"{entry['ip']} | by={entry['blocked_by']} | expires={expiry} | reason={entry['reason']}",
                    size=9,
                    gap=12,
                )
        else:
            write_line("No blocked IPs recorded.", size=9, gap=14)

        y -= 8
        write_line("Potential Blocked IPs", font="Helvetica-Bold", size=12, gap=16)
        if summary["potential_blocked_ips"]:
            for candidate in summary["potential_blocked_ips"]:
                write_line(
                    f"{candidate['ip']} | denies={candidate['count']} | max_risk={candidate['max_risk_score']} | last={candidate['last_seen']}",
                    size=9,
                    gap=12,
                )
                if candidate["resources"]:
                    write_line(
                        f"Resources: {', '.join(candidate['resources'])}",
                        size=8,
                        indent=12,
                        gap=11,
                    )
                if candidate["reasons"]:
                    for line in self._wrap_text(f"Reasons: {', '.join(candidate['reasons'])}", width=88):
                        write_line(line, size=8, indent=12, gap=11)
        else:
            write_line("No current candidates from recent deny events.", size=9, gap=14)

        y -= 8
        write_line("Tracker Activity", font="Helvetica-Bold", size=12, gap=16)
        if summary["tracker_block_events"]:
            for event in summary["tracker_block_events"]:
                write_line(
                    f"{event['ts']} | {event['target_type']} | host={event['hostname']} | confidence={event['confidence']}",
                    size=9,
                    gap=12,
                )
                for line in self._wrap_text(f"Reason: {event['reason']}", width=92):
                    write_line(line, size=8, indent=12, gap=11)
        else:
            write_line("No tracker activity recorded.", size=9, gap=14)

        y -= 8
        write_line("Recent Audit Events", font="Helvetica-Bold", size=12, gap=16)
        if summary["recent_events"]:
            for event in summary["recent_events"]:
                data_text = self._format_event_data(event.get("data", {}))
                write_line(
                    f"{event.get('ts', '')} | {event.get('type', '')}",
                    font="Helvetica-Bold",
                    size=9,
                    gap=12,
                )
                for line in self._wrap_text(data_text, width=92):
                    write_line(line, size=8, indent=12, gap=11)
        else:
            write_line("No audit events recorded.", size=9, gap=14)

        pdf.save()
        return buffer.getvalue()

    def get_output_dir(self) -> Path:
        return Path(settings.report_output_dir)

    def list_saved_reports(self) -> List[dict[str, Any]]:
        output_dir = self.get_output_dir()
        if not output_dir.exists():
            return []
        reports: list[dict[str, Any]] = []
        for path in sorted(output_dir.glob("*.pdf"), key=lambda item: item.stat().st_mtime, reverse=True):
            stat = path.stat()
            metadata = self._read_report_metadata(path)
            reports.append(
                {
                    "name": path.name,
                    "path": str(path),
                    "size": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
                    "blocked_ip_count": metadata.get("blocked_ip_count"),
                    "potential_blocked_ip_count": metadata.get("potential_blocked_ip_count"),
                    "tracker_block_count": metadata.get("tracker_block_count"),
                    "generated_at": metadata.get("generated_at"),
                }
            )
        return reports

    def resolve_saved_report(self, report_name: str | None = None) -> Path:
        reports = self.list_saved_reports()
        if not reports:
            raise FileNotFoundError("No saved reports found.")
        if report_name is None:
            return Path(reports[0]["path"])
        target = self.get_output_dir() / Path(report_name).name
        if not target.exists() or target.parent != self.get_output_dir():
            raise FileNotFoundError(f"Report not found: {report_name}")
        return target

    def open_saved_report(self, report_name: str | None = None, *, action: str = "open") -> Path:
        target = self.resolve_saved_report(report_name)
        os.startfile(target, action)  # type: ignore[attr-defined]
        return target

    def _metadata_path_for_report(self, report_path: Path) -> Path:
        return report_path.with_suffix(".json")

    def _write_report_metadata(self, report_path: Path, summary: dict[str, Any]) -> None:
        metadata = {
            "name": report_path.name,
            "generated_at": datetime.now(UTC).isoformat(),
            "blocked_ip_count": len(summary["blocked_ips"]),
            "potential_blocked_ip_count": len(summary["potential_blocked_ips"]),
            "tracker_block_count": len(summary["tracker_block_events"]),
            "filters": summary.get("filters", {}),
        }
        self._metadata_path_for_report(report_path).write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    def _read_report_metadata(self, report_path: Path) -> dict[str, Any]:
        metadata_path = self._metadata_path_for_report(report_path)
        if not metadata_path.exists():
            return {}
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _load_recent_events(
        self,
        *,
        max_events: int,
        time_window_hours: float | None = None,
        min_risk_score: float = 0.0,
    ) -> List[dict[str, Any]]:
        if not self.audit_log_path.exists():
            return []
        lines = self.audit_log_path.read_text(encoding="utf-8").splitlines()
        events: list[dict[str, Any]] = []
        now = datetime.now(UTC)
        for raw in lines[-max_events:]:
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            timestamp = self._parse_event_timestamp(event.get("ts"))
            if time_window_hours is not None and timestamp is not None:
                if (now - timestamp).total_seconds() > time_window_hours * 3600:
                    continue
            risk_score = float(event.get("data", {}).get("risk_score", 0) or 0)
            if risk_score < min_risk_score and event.get("type") == "access.evaluate":
                continue
            events.append(event)
        return events

    def _format_event_data(self, data: dict[str, Any]) -> str:
        parts: list[str] = []
        for key in sorted(data):
            value = data[key]
            if isinstance(value, (dict, list)):
                value = json.dumps(value, separators=(",", ":"), sort_keys=True)
            parts.append(f"{key}={value}")
        return "; ".join(parts)

    def _wrap_text(self, text: str, *, width: int) -> Iterable[str]:
        if not text:
            return [""]
        words = text.split()
        lines: list[str] = []
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if len(candidate) <= width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
        return lines

    def _collect_potential_blocks(
        self,
        events: List[dict[str, Any]],
        blocked_ips: List[Any],
        *,
        min_risk_score: float = 0.0,
    ) -> List[dict[str, Any]]:
        blocked_set = {entry.ip for entry in blocked_ips}
        candidates: dict[str, dict[str, Any]] = {}
        for event in events:
            if event.get("type") != "access.evaluate":
                continue
            data = event.get("data", {})
            ip = data.get("source_ip")
            if not ip or ip in blocked_set:
                continue
            if data.get("decision") != "deny":
                continue
            risk_score = float(data.get("risk_score", 0) or 0)
            if risk_score < min_risk_score:
                continue
            item = candidates.setdefault(
                ip,
                {
                    "ip": ip,
                    "count": 0,
                    "max_risk_score": 0.0,
                    "last_seen": event.get("ts", ""),
                    "reasons": set(),
                    "resources": set(),
                },
            )
            item["count"] += 1
            item["max_risk_score"] = max(item["max_risk_score"], risk_score)
            item["last_seen"] = event.get("ts", item["last_seen"])
            if data.get("resource"):
                item["resources"].add(str(data["resource"]))
            for reason in data.get("reasons", []):
                item["reasons"].add(str(reason))

        filtered_candidates: list[dict[str, Any]] = []
        for item in candidates.values():
            if item["count"] < 2 and item["max_risk_score"] < max(settings.max_risk_score, min_risk_score):
                continue
            filtered_candidates.append(
                {
                    "ip": item["ip"],
                    "count": item["count"],
                    "max_risk_score": item["max_risk_score"],
                    "last_seen": item["last_seen"],
                    "reasons": sorted(item["reasons"])[:4],
                    "resources": sorted(item["resources"]),
                }
            )
        return sorted(filtered_candidates, key=lambda item: (-item["count"], -item["max_risk_score"], item["ip"]))

    def _collect_tracker_blocks(self, events: List[dict[str, Any]]) -> List[dict[str, Any]]:
        tracker_events: list[dict[str, Any]] = []
        for event in events:
            if event.get("type") != "privacy.tracker_block":
                continue
            data = event.get("data", {})
            tracker_events.append(
                {
                    "ts": event.get("ts", ""),
                    "target_type": data.get("target_type", "unknown"),
                    "hostname": data.get("hostname", ""),
                    "matched_domain": data.get("matched_domain", ""),
                    "source": data.get("source", ""),
                    "confidence": data.get("confidence", ""),
                    "reason": data.get("reason", ""),
                }
            )
        return tracker_events

    def _parse_event_timestamp(self, value: Any) -> datetime | None:
        if not value or not isinstance(value, str):
            return None
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError:
            return None
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC)
