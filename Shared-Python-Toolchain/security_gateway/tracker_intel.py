"""Tracker domain detection for privacy controls."""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Optional
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen


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

DOMAIN_PATTERN = re.compile(r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])")


@dataclass(frozen=True)
class TrackerMatch:
    hostname: str
    matched_domain: str
    source: str
    confidence: str = "high"
    reason: str = ""


class TrackerIntel:
    def __init__(
        self,
        extra_domains_path: str | Path | None = None,
        *,
        feed_cache_path: str | Path | None = None,
        feed_urls: Iterable[str] | None = None,
        stale_after_hours: float = 168.0,
        disabled_feed_urls: Iterable[str] | None = None,
        min_domains_per_source: int = 10,
        min_total_domains: int = 500,
        replace_ratio_floor: float = 0.5,
    ):
        self.extra_domains_path = Path(extra_domains_path) if extra_domains_path else None
        self.feed_cache_path = Path(feed_cache_path) if feed_cache_path else None
        self.feed_urls = [str(url) for url in feed_urls] if feed_urls else []
        self.stale_after_hours = stale_after_hours
        self.disabled_feed_urls = {str(url) for url in (disabled_feed_urls or []) if str(url).strip()}
        self.min_domains_per_source = min_domains_per_source
        self.min_total_domains = min_total_domains
        self.replace_ratio_floor = replace_ratio_floor

    def is_tracker_hostname(self, hostname: str | None) -> Optional[TrackerMatch]:
        if not hostname:
            return None
        normalized = hostname.strip().lower().rstrip(".")
        for domain in self._domains():
            if normalized == domain or normalized.endswith(f".{domain}"):
                source = "builtin"
                if self.extra_domains_path and domain in self._load_extra_domains():
                    source = "custom"
                elif self.feed_cache_path and domain in self._load_feed_domains():
                    source = "feed"
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
        for domain in [*BUILTIN_TRACKER_DOMAINS, *self._load_extra_domains(), *self._load_feed_domains()]:
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

    def _load_feed_domains(self) -> Iterable[str]:
        payload = self._read_feed_cache_payload()
        if isinstance(payload, list):
            return [str(item) for item in payload]
        if isinstance(payload, dict) and isinstance(payload.get("domains"), list):
            return [str(item) for item in payload["domains"]]
        return []

    def feed_status(self) -> dict[str, Any]:
        payload = self._read_feed_cache_payload()
        if not payload:
            return {
                "cache_path": str(self.feed_cache_path) if self.feed_cache_path else None,
                "feed_urls": self.feed_urls,
                "active_feed_urls": self._active_feed_urls(),
                "disabled_feed_urls": sorted(self.disabled_feed_urls),
                "domain_count": 0,
                "updated_at": None,
                "last_refresh_attempted_at": None,
                "last_refresh_result": None,
                "last_error": None,
                "failures": [],
                "age_hours": None,
                "is_stale": True,
                "stale_after_hours": self.stale_after_hours,
                "min_domains_per_source": self.min_domains_per_source,
                "min_total_domains": self.min_total_domains,
                "replace_ratio_floor": self.replace_ratio_floor,
                "sources": [],
            }
        updated_at = payload.get("updated_at") if isinstance(payload, dict) else None
        updated_dt = self._parse_timestamp(updated_at)
        age_hours = None
        is_stale = True
        if updated_dt is not None:
            age_hours = round((datetime.now(UTC) - updated_dt).total_seconds() / 3600, 2)
            is_stale = age_hours > self.stale_after_hours
        return {
            "cache_path": str(self.feed_cache_path),
            "feed_urls": self.feed_urls,
            "active_feed_urls": self._active_feed_urls(),
            "disabled_feed_urls": sorted(self.disabled_feed_urls),
            "domain_count": len(list(self._load_feed_domains())),
            "updated_at": updated_at,
            "last_refresh_attempted_at": payload.get("last_refresh_attempted_at") if isinstance(payload, dict) else None,
            "last_refresh_result": payload.get("last_refresh_result") if isinstance(payload, dict) else None,
            "last_error": payload.get("last_error") if isinstance(payload, dict) else None,
            "failures": payload.get("failures", []) if isinstance(payload, dict) else [],
            "age_hours": age_hours,
            "is_stale": is_stale,
            "stale_after_hours": self.stale_after_hours,
            "min_domains_per_source": self.min_domains_per_source,
            "min_total_domains": self.min_total_domains,
            "replace_ratio_floor": self.replace_ratio_floor,
            "sources": payload.get("sources", []) if isinstance(payload, dict) else [],
        }

    def refresh_feed_cache(self, urls: Iterable[str] | None = None, *, timeout: float = 20.0) -> dict[str, Any]:
        active_urls = self._active_feed_urls(urls)
        if not active_urls:
            raise ValueError("No tracker feed URLs configured.")

        domains: set[str] = set()
        source_summaries: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        refresh_time = datetime.now(UTC).isoformat()
        for url in active_urls:
            try:
                with urlopen(url, timeout=timeout) as response:  # noqa: S310
                    payload = response.read().decode("utf-8", errors="replace")
                parsed = self._parse_feed_payload(payload, source_url=url)
                if len(parsed) < self.min_domains_per_source:
                    raise RuntimeError(
                        f"Source returned {len(parsed)} domains, below minimum {self.min_domains_per_source}"
                    )
                domains.update(parsed)
                source_summaries.append({"url": url, "domain_count": len(parsed)})
            except Exception as exc:  # noqa: BLE001
                failures.append({"url": url, "error": str(exc)})

        if not self.feed_cache_path:
            raise ValueError("Tracker feed cache path is not configured.")
        self.feed_cache_path.parent.mkdir(parents=True, exist_ok=True)
        existing_payload = self._read_feed_cache_payload()
        existing_count = len(existing_payload.get("domains", [])) if isinstance(existing_payload, dict) else 0
        suspiciously_small = False
        suspicious_reason = None
        if len(domains) < self.min_total_domains:
            suspiciously_small = True
            suspicious_reason = (
                f"Refresh produced {len(domains)} domains, below minimum total {self.min_total_domains}"
            )
        elif existing_count and len(domains) < int(existing_count * self.replace_ratio_floor):
            suspiciously_small = True
            suspicious_reason = (
                f"Refresh produced {len(domains)} domains, below replacement floor of "
                f"{int(existing_count * self.replace_ratio_floor)} from previous cache"
            )

        if not source_summaries or suspiciously_small:
            failed_payload = dict(existing_payload) if isinstance(existing_payload, dict) else {"domains": [], "sources": []}
            failure_messages = [f"{item['url']}: {item['error']}" for item in failures]
            if suspicious_reason:
                failure_messages.append(suspicious_reason)
            failed_payload.update(
                {
                    "last_refresh_attempted_at": refresh_time,
                    "last_refresh_result": "failed",
                    "last_error": "; ".join(failure_messages)[:2000] or "Feed refresh failed",
                    "failures": failures,
                }
            )
            self._write_feed_cache_payload(failed_payload)
            raise RuntimeError(failed_payload["last_error"])

        payload = {
            "updated_at": refresh_time,
            "last_refresh_attempted_at": refresh_time,
            "last_refresh_result": "success" if not failures else "partial",
            "last_error": "; ".join(f"{item['url']}: {item['error']}" for item in failures)[:2000] if failures else None,
            "failures": failures,
            "sources": source_summaries,
            "domains": sorted(domains),
        }
        self._write_feed_cache_payload(payload)
        result = {
            "cache_path": str(self.feed_cache_path),
            "domain_count": len(domains),
            "sources": source_summaries,
            "last_refresh_result": payload["last_refresh_result"],
            "last_error": payload["last_error"],
            "failures": failures,
        }
        return result

    def _active_feed_urls(self, urls: Iterable[str] | None = None) -> list[str]:
        return [
            str(url)
            for url in (urls or self.feed_urls)
            if str(url).strip() and str(url) not in self.disabled_feed_urls
        ]

    def _read_feed_cache_payload(self) -> dict[str, Any] | list[Any] | None:
        if not self.feed_cache_path or not self.feed_cache_path.exists():
            return None
        try:
            return json.loads(self.feed_cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    def _write_feed_cache_payload(self, payload: dict[str, Any]) -> None:
        if not self.feed_cache_path:
            raise ValueError("Tracker feed cache path is not configured.")
        self.feed_cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _parse_feed_payload(self, payload: str, *, source_url: str = "") -> set[str]:
        stripped = payload.lstrip()
        if stripped.startswith("{") or stripped.startswith("[") or source_url.endswith(".json"):
            try:
                parsed_json = json.loads(payload)
            except json.JSONDecodeError:
                parsed_json = None
            if parsed_json is not None:
                return self._extract_domains_from_json(parsed_json)
        domains: set[str] = set()
        for raw_line in payload.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("!", "#", "[", "@@")):
                continue
            if line.startswith(("127.0.0.1", "0.0.0.0")):
                parts = [part for part in line.split() if DOMAIN_PATTERN.fullmatch(part)]
                domains.update(part.lower() for part in parts)
                continue
            for match in DOMAIN_PATTERN.findall(line):
                candidate = match.lower().strip(".")
                if candidate.startswith("www."):
                    candidate = candidate[4:]
                domains.add(candidate)
        return domains

    def _extract_domains_from_json(self, payload: Any) -> set[str]:
        domains: set[str] = set()
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key == "properties" and isinstance(value, list):
                    for item in value:
                        domains.update(self._extract_domains_from_json(item))
                    continue
                domains.update(self._extract_domains_from_json(value))
        elif isinstance(payload, list):
            for item in payload:
                domains.update(self._extract_domains_from_json(item))
        elif isinstance(payload, str):
            for match in DOMAIN_PATTERN.findall(payload):
                candidate = match.lower().strip(".")
                if candidate.startswith("www."):
                    candidate = candidate[4:]
                domains.add(candidate)
        return domains

    def _parse_timestamp(self, value: Any) -> datetime | None:
        if not value or not isinstance(value, str):
            return None
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError:
            return None
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=UTC)
        return timestamp.astimezone(UTC)

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
