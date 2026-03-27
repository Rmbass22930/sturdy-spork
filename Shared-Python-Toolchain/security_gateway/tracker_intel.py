"""Tracker domain detection for privacy controls."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import parse_qs, urlparse


BUILTIN_TRACKER_DOMAINS = [
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "bat.bing.com",
    "ads-twitter.com",
    "analytics.yahoo.com",
    "analytics.tiktok.com",
    "connect.facebook.net",
    "analytics.pinterest.com",
    "pixel.wp.com",
    "stats.wp.com",
    "cdn.segment.com",
    "api.segment.io",
    "api.mixpanel.com",
    "js-agent.newrelic.com",
    "bam.nr-data.net",
]

TRACKER_HOST_LABELS = {
    "analytics",
    "api-analytics",
    "beacon",
    "capture",
    "collect",
    "events",
    "fingerprint",
    "ingest",
    "metric",
    "metrics",
    "pixel",
    "replay",
    "rum",
    "session-replay",
    "tagmanager",
    "telemetry",
    "track",
    "tracker",
    "trk",
}

STRONG_TRACKER_PATH_MARKERS = (
    "/analytics",
    "/beacon",
    "/collect",
    "/fingerprint",
    "/pixel",
    "/replay",
    "/rum",
    "/session-replay",
    "/telemetry",
    "/track",
)

WEAK_TRACKER_PATH_MARKERS = (
    "/capture",
    "/events",
    "/identify",
    "/ingest",
)

TRACKER_QUERY_KEYS = {
    "_fbc",
    "_fbp",
    "_ga",
    "_gid",
    "aid",
    "anonymous_id",
    "cid",
    "client_id",
    "clickid",
    "device_id",
    "dclid",
    "distinct_id",
    "fbclid",
    "fingerprint",
    "gclid",
    "mc_eid",
    "msclkid",
    "rb_clickid",
    "scid",
    "session_id",
    "ttclid",
    "twclid",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
    "visitor_id",
}

TRACKER_PATH_TOKENS = {
    "capture",
    "collect",
    "fingerprint",
    "identify",
    "ingest",
    "pixel",
    "replay",
    "rum",
    "session-replay",
    "telemetry",
    "track",
}


@dataclass(frozen=True)
class TrackerMatch:
    hostname: str
    matched_domain: str
    source: str
    confidence: str = "high"
    reason: str = ""


class TrackerIntel:
    def __init__(self, extra_domains_path: str | Path | None = None):
        self.extra_domains_path = Path(extra_domains_path) if extra_domains_path else None

    def is_tracker_hostname(self, hostname: str | None) -> Optional[TrackerMatch]:
        if not hostname:
            return None
        normalized = hostname.strip().lower().rstrip(".")
        for domain in self._domains():
            if normalized == domain or normalized.endswith(f".{domain}"):
                source = "custom" if self.extra_domains_path and domain in self._load_extra_domains() else "builtin"
                return TrackerMatch(
                    hostname=normalized,
                    matched_domain=domain,
                    source=source,
                    confidence="high",
                    reason=f"Known tracker domain match: {domain}",
                )
        score, reasons = self._heuristic_score(normalized, path="", query_keys=[])
        if score >= 3:
            return TrackerMatch(
                hostname=normalized,
                matched_domain=normalized,
                source="heuristic",
                confidence="medium",
                reason="; ".join(reasons),
            )
        return None

    def is_tracker_url(self, url: str) -> Optional[TrackerMatch]:
        parsed = urlparse(url)
        hostname_match = self.is_tracker_hostname(parsed.hostname)
        if hostname_match and hostname_match.source != "heuristic":
            return hostname_match
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        score, reasons = self._heuristic_score(
            hostname,
            path=parsed.path or "",
            query_keys=list(parse_qs(parsed.query, keep_blank_values=True).keys()),
        )
        if hostname_match is not None:
            score += 1
            reasons.append(hostname_match.reason)
        if score >= 3:
            return TrackerMatch(
                hostname=hostname,
                matched_domain=hostname_match.matched_domain if hostname_match else hostname,
                source="heuristic",
                confidence="high" if score >= 4 else "medium",
                reason="; ".join(dict.fromkeys(reasons)),
            )
        return None

    def _domains(self) -> List[str]:
        seen: set[str] = set()
        domains: list[str] = []
        for domain in [*BUILTIN_TRACKER_DOMAINS, *self._load_extra_domains()]:
            normalized = domain.strip().lower().rstrip(".")
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            domains.append(normalized)
        return domains

    def _load_extra_domains(self) -> Iterable[str]:
        if not self.extra_domains_path or not self.extra_domains_path.exists():
            return []
        try:
            payload = json.loads(self.extra_domains_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if isinstance(payload, list):
            return [str(item) for item in payload]
        return []

    def _heuristic_score(self, hostname: str, *, path: str, query_keys: list[str]) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []
        labels = [label for label in hostname.split(".") if label]
        matching_labels = sorted({label for label in labels if label in TRACKER_HOST_LABELS})
        if matching_labels:
            score += 2
            reasons.append(f"Tracker-style host labels: {', '.join(matching_labels)}")

        lowered_path = path.lower()
        strong_matching_paths = [marker for marker in STRONG_TRACKER_PATH_MARKERS if marker in lowered_path]
        if strong_matching_paths:
            score += 2
            reasons.append(f"Tracker-style URL path markers: {', '.join(strong_matching_paths)}")

        normalized_keys = sorted({key.lower() for key in query_keys if key.lower() in TRACKER_QUERY_KEYS})

        weak_matching_paths = [marker for marker in WEAK_TRACKER_PATH_MARKERS if marker in lowered_path]
        if weak_matching_paths and (matching_labels or normalized_keys):
            score += 1
            reasons.append(f"Weak tracker path markers with corroborating signals: {', '.join(weak_matching_paths)}")

        normalized_path_tokens = sorted(
            {
                token
                for token in lowered_path.replace("_", "-").split("/")
                if token in TRACKER_PATH_TOKENS
            }
        )
        if normalized_path_tokens and (matching_labels or normalized_keys or strong_matching_paths):
            score += 1
            reasons.append(f"Tracker-style path tokens: {', '.join(normalized_path_tokens)}")

        if normalized_keys:
            score += min(2, len(normalized_keys))
            reasons.append(f"Tracking query keys: {', '.join(normalized_keys)}")

        if self._looks_like_first_party_cloaked_tracker(hostname, matching_labels, lowered_path, normalized_keys):
            score += 1
            reasons.append("First-party tracker cloaking pattern")

        return score, reasons

    def _looks_like_first_party_cloaked_tracker(
        self,
        hostname: str,
        matching_labels: list[str],
        lowered_path: str,
        normalized_keys: list[str],
    ) -> bool:
        if not hostname or not matching_labels:
            return False
        host_parts = [part for part in hostname.split(".") if part]
        if len(host_parts) < 3:
            return False
        if not any(key in normalized_keys for key in {"_ga", "_gid", "_fbp", "_fbc", "distinct_id", "anonymous_id", "fingerprint"}):
            if not any(marker in lowered_path for marker in ("/collect", "/ingest", "/rum", "/replay", "/session-replay", "/fingerprint")):
                return False
        return True
