"""Endpoint telemetry and malware scanning."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple
from urllib.request import urlopen

from .models import DeviceContext
from .url_safety import validate_public_https_url


SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
BUILTIN_MALWARE_MARKERS = (
    (b"ransom", "Heuristic trigger: ransomware markers present"),
    (b"bitcoin", "Heuristic trigger: bitcoin payment marker present"),
    (b"double_extortion", "Heuristic trigger: double extortion marker present"),
)
RULE_VALUE_SPLIT_PATTERN = re.compile(r"\s*\|\|\s*|,")
RULE_NAME_KEYS = ("name", "rule", "id", "title")
RULE_PATTERN_KEYS = ("patterns", "strings", "contains", "literals", "keywords", "search", "pattern")
RULE_CONTAINER_KEYS = ("rules", "signatures", "yara", "sigma", "detections")


class EndpointTelemetryService:
    def __init__(
        self,
        signing_key: bytes | str | None = None,
        *,
        max_records: int = 10_000,
        retention_hours: float = 168.0,
    ):
        if isinstance(signing_key, str):
            signing_key = hashlib.sha256(signing_key.encode("utf-8")).digest()
        self._key = signing_key or secrets.token_bytes(32)
        self._max_records = max_records
        self._retention = timedelta(hours=retention_hours)
        self._records: Dict[str, dict] = {}

    def publish(self, device: DeviceContext) -> str:
        self._prune()
        body = device.model_dump()
        body["timestamp"] = datetime.now(UTC).isoformat()
        serialized = json.dumps(body, sort_keys=True).encode()
        signature = hmac.new(self._key, serialized, hashlib.sha256).hexdigest()
        self._records[device.device_id] = {"payload": body, "signature": signature}
        while len(self._records) > self._max_records:
            oldest_device_id = next(iter(self._records))
            del self._records[oldest_device_id]
        return signature

    def verify(self, device_id: str) -> bool:
        self._prune()
        record = self._records.get(device_id)
        if not record:
            return False
        serialized = json.dumps(record["payload"], sort_keys=True).encode()
        expected = hmac.new(self._key, serialized, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, record["signature"])

    def get_payload(self, device_id: str) -> dict | None:
        if self.verify(device_id):
            return self._records[device_id]["payload"]
        return None

    def _prune(self) -> None:
        if self._retention.total_seconds() <= 0:
            return
        cutoff = datetime.now(UTC) - self._retention
        expired_ids = [
            device_id
            for device_id, record in self._records.items()
            if self._parse_timestamp(record["payload"].get("timestamp")) < cutoff
        ]
        for device_id in expired_ids:
            del self._records[device_id]

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                return datetime.min.replace(tzinfo=UTC)
        return datetime.min.replace(tzinfo=UTC)


class MalwareScanner:
    def __init__(
        self,
        blocked_hashes: set[str] | None = None,
        *,
        feed_cache_path: str | Path | None = None,
        feed_urls: Iterable[str] | None = None,
        stale_after_hours: float = 168.0,
        disabled_feed_urls: Iterable[str] | None = None,
        min_hashes_per_source: int = 1,
        min_total_hashes: int = 1,
        replace_ratio_floor: float = 0.5,
        verify_tls: bool = True,
        ca_bundle_path: str | Path | None = None,
        rule_feed_cache_path: str | Path | None = None,
        rule_feed_urls: Iterable[str] | None = None,
        rule_feed_stale_after_hours: float = 168.0,
        disabled_rule_feed_urls: Iterable[str] | None = None,
        min_rules_per_source: int = 1,
        min_total_rules: int = 1,
        rule_replace_ratio_floor: float = 0.5,
        rule_feed_verify_tls: bool = True,
        rule_feed_ca_bundle_path: str | Path | None = None,
    ):
        self.blocked_hashes = {item.lower() for item in (blocked_hashes or set())}
        self.feed_cache_path = Path(feed_cache_path) if feed_cache_path else None
        self.feed_urls = [str(url) for url in feed_urls] if feed_urls else []
        self.stale_after_hours = stale_after_hours
        self.disabled_feed_urls = {str(url) for url in (disabled_feed_urls or []) if str(url).strip()}
        self.min_hashes_per_source = min_hashes_per_source
        self.min_total_hashes = min_total_hashes
        self.replace_ratio_floor = replace_ratio_floor
        self.verify_tls = verify_tls
        self.ca_bundle_path = Path(ca_bundle_path) if ca_bundle_path else None
        self.rule_feed_cache_path = Path(rule_feed_cache_path) if rule_feed_cache_path else None
        self.rule_feed_urls = [str(url) for url in rule_feed_urls] if rule_feed_urls else []
        self.rule_feed_stale_after_hours = rule_feed_stale_after_hours
        self.disabled_rule_feed_urls = {
            str(url) for url in (disabled_rule_feed_urls or []) if str(url).strip()
        }
        self.min_rules_per_source = min_rules_per_source
        self.min_total_rules = min_total_rules
        self.rule_replace_ratio_floor = rule_replace_ratio_floor
        self.rule_feed_verify_tls = rule_feed_verify_tls
        self.rule_feed_ca_bundle_path = Path(rule_feed_ca_bundle_path) if rule_feed_ca_bundle_path else None

    def scan_bytes(self, data: bytes) -> Tuple[bool, str]:
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.blocked_hashes:
            return True, f"Hash {digest} flagged as malicious"
        if digest in self._load_feed_hashes():
            return True, f"Hash {digest} flagged as malicious (feed)"
        matched_rule = self._match_feed_rule(data)
        if matched_rule:
            return True, f"Rule {matched_rule} matched (feed)"
        for marker, reason in BUILTIN_MALWARE_MARKERS:
            if marker in data:
                return True, reason
        return False, "clean"

    def scan_path(self, path: str | Path) -> Tuple[bool, str]:
        with open(path, "rb") as handle:
            data = handle.read()
        return self.scan_bytes(data)

    def feed_status(self) -> dict[str, Any]:
        payload = self._read_feed_cache_payload()
        if not payload:
            return {
                "cache_path": str(self.feed_cache_path) if self.feed_cache_path else None,
                "feed_urls": self.feed_urls,
                "active_feed_urls": self._active_feed_urls(),
                "disabled_feed_urls": sorted(self.disabled_feed_urls),
                "verify_tls": self.verify_tls,
                "ca_bundle_path": str(self.ca_bundle_path) if self.ca_bundle_path else None,
                "hash_count": 0,
                "updated_at": None,
                "last_refresh_attempted_at": None,
                "last_refresh_result": None,
                "last_error": None,
                "failures": [],
                "age_hours": None,
                "is_stale": True,
                "stale_after_hours": self.stale_after_hours,
                "min_hashes_per_source": self.min_hashes_per_source,
                "min_total_hashes": self.min_total_hashes,
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
            "cache_path": str(self.feed_cache_path) if self.feed_cache_path else None,
            "feed_urls": self.feed_urls,
            "active_feed_urls": self._active_feed_urls(),
            "disabled_feed_urls": sorted(self.disabled_feed_urls),
            "verify_tls": self.verify_tls,
            "ca_bundle_path": str(self.ca_bundle_path) if self.ca_bundle_path else None,
            "hash_count": len(list(self._load_feed_hashes())),
            "updated_at": updated_at,
            "last_refresh_attempted_at": payload.get("last_refresh_attempted_at") if isinstance(payload, dict) else None,
            "last_refresh_result": payload.get("last_refresh_result") if isinstance(payload, dict) else None,
            "last_error": payload.get("last_error") if isinstance(payload, dict) else None,
            "failures": payload.get("failures", []) if isinstance(payload, dict) else [],
            "age_hours": age_hours,
            "is_stale": is_stale,
            "stale_after_hours": self.stale_after_hours,
            "min_hashes_per_source": self.min_hashes_per_source,
            "min_total_hashes": self.min_total_hashes,
            "replace_ratio_floor": self.replace_ratio_floor,
            "sources": payload.get("sources", []) if isinstance(payload, dict) else [],
        }

    def rule_feed_status(self) -> dict[str, Any]:
        payload = self._read_rule_feed_cache_payload()
        if not payload:
            return {
                "cache_path": str(self.rule_feed_cache_path) if self.rule_feed_cache_path else None,
                "feed_urls": self.rule_feed_urls,
                "active_feed_urls": self._active_rule_feed_urls(),
                "disabled_feed_urls": sorted(self.disabled_rule_feed_urls),
                "verify_tls": self.rule_feed_verify_tls,
                "ca_bundle_path": str(self.rule_feed_ca_bundle_path) if self.rule_feed_ca_bundle_path else None,
                "rule_count": 0,
                "updated_at": None,
                "last_refresh_attempted_at": None,
                "last_refresh_result": None,
                "last_error": None,
                "failures": [],
                "age_hours": None,
                "is_stale": True,
                "stale_after_hours": self.rule_feed_stale_after_hours,
                "min_rules_per_source": self.min_rules_per_source,
                "min_total_rules": self.min_total_rules,
                "replace_ratio_floor": self.rule_replace_ratio_floor,
                "sources": [],
            }
        updated_at = payload.get("updated_at") if isinstance(payload, dict) else None
        updated_dt = self._parse_timestamp(updated_at)
        age_hours = None
        is_stale = True
        if updated_dt is not None:
            age_hours = round((datetime.now(UTC) - updated_dt).total_seconds() / 3600, 2)
            is_stale = age_hours > self.rule_feed_stale_after_hours
        return {
            "cache_path": str(self.rule_feed_cache_path) if self.rule_feed_cache_path else None,
            "feed_urls": self.rule_feed_urls,
            "active_feed_urls": self._active_rule_feed_urls(),
            "disabled_feed_urls": sorted(self.disabled_rule_feed_urls),
            "verify_tls": self.rule_feed_verify_tls,
            "ca_bundle_path": str(self.rule_feed_ca_bundle_path) if self.rule_feed_ca_bundle_path else None,
            "rule_count": len(self._load_feed_rules()),
            "updated_at": updated_at,
            "last_refresh_attempted_at": payload.get("last_refresh_attempted_at") if isinstance(payload, dict) else None,
            "last_refresh_result": payload.get("last_refresh_result") if isinstance(payload, dict) else None,
            "last_error": payload.get("last_error") if isinstance(payload, dict) else None,
            "failures": payload.get("failures", []) if isinstance(payload, dict) else [],
            "age_hours": age_hours,
            "is_stale": is_stale,
            "stale_after_hours": self.rule_feed_stale_after_hours,
            "min_rules_per_source": self.min_rules_per_source,
            "min_total_rules": self.min_total_rules,
            "replace_ratio_floor": self.rule_replace_ratio_floor,
            "sources": payload.get("sources", []) if isinstance(payload, dict) else [],
        }

    def health_status(self) -> dict[str, Any]:
        hash_status = self.feed_status()
        rule_status = self.rule_feed_status()
        warnings: list[str] = []
        if hash_status["active_feed_urls"] and hash_status["is_stale"]:
            warnings.append("malware hash feed cache is stale")
        if hash_status["last_refresh_result"] == "failed":
            warnings.append("last malware hash feed refresh failed")
        if not self.verify_tls:
            warnings.append("malware hash feed TLS verification is disabled")
        if rule_status["active_feed_urls"] and rule_status["is_stale"]:
            warnings.append("malware rule feed cache is stale")
        if rule_status["last_refresh_result"] == "failed":
            warnings.append("last malware rule feed refresh failed")
        if not self.rule_feed_verify_tls:
            warnings.append("malware rule feed TLS verification is disabled")
        return {
            "healthy": not warnings,
            "warnings": warnings,
            "hash_feed_status": hash_status,
            "rule_feed_status": rule_status,
        }

    def refresh_feed_cache(self, urls: Iterable[str] | None = None, *, timeout: float = 20.0) -> dict[str, Any]:
        active_urls = self._active_feed_urls(urls)
        if not active_urls:
            raise ValueError("No malware feed URLs configured.")

        hashes: set[str] = set()
        source_summaries: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        refresh_time = datetime.now(UTC).isoformat()
        for url in active_urls:
            try:
                payload = self._fetch_payload(
                    url,
                    timeout=timeout,
                    verify_tls=self.verify_tls,
                    ca_bundle_path=self.ca_bundle_path,
                )
                parsed = self._parse_hash_feed_payload(payload, source_url=url)
                if len(parsed) < self.min_hashes_per_source:
                    raise RuntimeError(
                        f"Source returned {len(parsed)} hashes, below minimum {self.min_hashes_per_source}"
                    )
                hashes.update(parsed)
                source_summaries.append({"url": url, "hash_count": len(parsed)})
            except Exception as exc:  # noqa: BLE001
                failures.append({"url": url, "error": str(exc)})

        if not self.feed_cache_path:
            raise ValueError("Malware feed cache path is not configured.")
        self.feed_cache_path.parent.mkdir(parents=True, exist_ok=True)
        existing_payload = self._read_feed_cache_payload()
        existing_count = len(existing_payload.get("hashes", [])) if isinstance(existing_payload, dict) else 0
        suspiciously_small = False
        suspicious_reason = None
        if len(hashes) < self.min_total_hashes:
            suspiciously_small = True
            suspicious_reason = (
                f"Refresh produced {len(hashes)} hashes, below minimum total {self.min_total_hashes}"
            )
        elif existing_count and len(hashes) < int(existing_count * self.replace_ratio_floor):
            suspiciously_small = True
            suspicious_reason = (
                f"Refresh produced {len(hashes)} hashes, below replacement floor of "
                f"{int(existing_count * self.replace_ratio_floor)} from previous cache"
            )

        if not source_summaries or suspiciously_small:
            failed_payload = dict(existing_payload) if isinstance(existing_payload, dict) else {"hashes": [], "sources": []}
            failure_messages = [f"{item['url']}: {item['error']}" for item in failures]
            if suspicious_reason:
                failure_messages.append(suspicious_reason)
            failed_payload.update(
                {
                    "last_refresh_attempted_at": refresh_time,
                    "last_refresh_result": "failed",
                    "last_error": "; ".join(failure_messages)[:2000] or "Malware feed refresh failed",
                    "failures": failures,
                }
            )
            self._write_feed_cache_payload(failed_payload)
            if suspicious_reason and source_summaries:
                raise ValueError(f"Refusing to replace malware feed cache: {suspicious_reason}")
            raise RuntimeError(failed_payload["last_error"])

        payload = {
            "updated_at": refresh_time,
            "last_refresh_attempted_at": refresh_time,
            "last_refresh_result": "success" if not failures else "partial",
            "last_error": "; ".join(f"{item['url']}: {item['error']}" for item in failures)[:2000] if failures else None,
            "failures": failures,
            "sources": source_summaries,
            "hashes": sorted(hashes),
        }
        self._write_feed_cache_payload(payload)
        return {
            "cache_path": str(self.feed_cache_path),
            "hash_count": len(hashes),
            "sources": source_summaries,
            "last_refresh_result": payload["last_refresh_result"],
            "last_error": payload["last_error"],
            "failures": failures,
        }

    def refresh_rule_feed_cache(
        self,
        urls: Iterable[str] | None = None,
        *,
        timeout: float = 20.0,
    ) -> dict[str, Any]:
        active_urls = self._active_rule_feed_urls(urls)
        if not active_urls:
            raise ValueError("No malware rule feed URLs configured.")

        rules: list[dict[str, Any]] = []
        source_summaries: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        refresh_time = datetime.now(UTC).isoformat()
        for url in active_urls:
            try:
                payload = self._fetch_payload(
                    url,
                    timeout=timeout,
                    verify_tls=self.rule_feed_verify_tls,
                    ca_bundle_path=self.rule_feed_ca_bundle_path,
                )
                parsed = self._parse_rule_feed_payload(payload, source_url=url)
                if len(parsed) < self.min_rules_per_source:
                    raise RuntimeError(
                        f"Source returned {len(parsed)} rules, below minimum {self.min_rules_per_source}"
                    )
                rules.extend(parsed)
                source_summaries.append({"url": url, "rule_count": len(parsed)})
            except Exception as exc:  # noqa: BLE001
                failures.append({"url": url, "error": str(exc)})

        deduped_rules = self._dedupe_rules(rules)
        if not self.rule_feed_cache_path:
            raise ValueError("Malware rule feed cache path is not configured.")
        self.rule_feed_cache_path.parent.mkdir(parents=True, exist_ok=True)
        existing_payload = self._read_rule_feed_cache_payload()
        existing_count = len(existing_payload.get("rules", [])) if isinstance(existing_payload, dict) else 0
        suspiciously_small = False
        suspicious_reason = None
        if len(deduped_rules) < self.min_total_rules:
            suspiciously_small = True
            suspicious_reason = (
                f"Refresh produced {len(deduped_rules)} rules, below minimum total {self.min_total_rules}"
            )
        elif existing_count and len(deduped_rules) < int(existing_count * self.rule_replace_ratio_floor):
            suspiciously_small = True
            suspicious_reason = (
                f"Refresh produced {len(deduped_rules)} rules, below replacement floor of "
                f"{int(existing_count * self.rule_replace_ratio_floor)} from previous cache"
            )

        if not source_summaries or suspiciously_small:
            failed_payload = dict(existing_payload) if isinstance(existing_payload, dict) else {"rules": [], "sources": []}
            failure_messages = [f"{item['url']}: {item['error']}" for item in failures]
            if suspicious_reason:
                failure_messages.append(suspicious_reason)
            failed_payload.update(
                {
                    "last_refresh_attempted_at": refresh_time,
                    "last_refresh_result": "failed",
                    "last_error": "; ".join(failure_messages)[:2000] or "Malware rule feed refresh failed",
                    "failures": failures,
                }
            )
            self._write_rule_feed_cache_payload(failed_payload)
            if suspicious_reason and source_summaries:
                raise ValueError(f"Refusing to replace malware rule feed cache: {suspicious_reason}")
            raise RuntimeError(failed_payload["last_error"])

        payload = {
            "updated_at": refresh_time,
            "last_refresh_attempted_at": refresh_time,
            "last_refresh_result": "success" if not failures else "partial",
            "last_error": "; ".join(f"{item['url']}: {item['error']}" for item in failures)[:2000] if failures else None,
            "failures": failures,
            "sources": source_summaries,
            "rules": deduped_rules,
        }
        self._write_rule_feed_cache_payload(payload)
        return {
            "cache_path": str(self.rule_feed_cache_path),
            "rule_count": len(deduped_rules),
            "sources": source_summaries,
            "last_refresh_result": payload["last_refresh_result"],
            "last_error": payload["last_error"],
            "failures": failures,
        }

    def import_feed_cache(self, source_path: str | Path) -> dict[str, Any]:
        source = Path(source_path)
        if not source.exists():
            raise ValueError(f"Malware feed import source not found: {source}")
        parsed = self._parse_hash_feed_payload(source.read_text(encoding="utf-8"), source_url=source.name)
        if len(parsed) < self.min_total_hashes:
            raise ValueError(
                f"Malware feed import produced {len(parsed)} hashes, below minimum total {self.min_total_hashes}"
            )
        if not self.feed_cache_path:
            raise ValueError("Malware feed cache path is not configured.")
        self.feed_cache_path.parent.mkdir(parents=True, exist_ok=True)
        refresh_time = datetime.now(UTC).isoformat()
        payload = {
            "updated_at": refresh_time,
            "last_refresh_attempted_at": refresh_time,
            "last_refresh_result": "imported",
            "last_error": None,
            "failures": [],
            "sources": [{"url": str(source), "hash_count": len(parsed), "imported": True}],
            "hashes": sorted(parsed),
        }
        self._write_feed_cache_payload(payload)
        return {
            "cache_path": str(self.feed_cache_path),
            "hash_count": len(parsed),
            "sources": payload["sources"],
            "last_refresh_result": "imported",
            "failures": [],
        }

    def import_rule_feed_cache(self, source_path: str | Path) -> dict[str, Any]:
        source = Path(source_path)
        if not source.exists():
            raise ValueError(f"Malware rule feed import source not found: {source}")
        parsed = self._parse_rule_feed_payload(source.read_text(encoding="utf-8"), source_url=source.name)
        if len(parsed) < self.min_total_rules:
            raise ValueError(
                f"Malware rule feed import produced {len(parsed)} rules, below minimum total {self.min_total_rules}"
            )
        if not self.rule_feed_cache_path:
            raise ValueError("Malware rule feed cache path is not configured.")
        self.rule_feed_cache_path.parent.mkdir(parents=True, exist_ok=True)
        refresh_time = datetime.now(UTC).isoformat()
        payload = {
            "updated_at": refresh_time,
            "last_refresh_attempted_at": refresh_time,
            "last_refresh_result": "imported",
            "last_error": None,
            "failures": [],
            "sources": [{"url": str(source), "rule_count": len(parsed), "imported": True}],
            "rules": self._dedupe_rules(parsed),
        }
        self._write_rule_feed_cache_payload(payload)
        return {
            "cache_path": str(self.rule_feed_cache_path),
            "rule_count": len(payload["rules"]),
            "sources": payload["sources"],
            "last_refresh_result": "imported",
            "failures": [],
        }

    def _load_feed_hashes(self) -> set[str]:
        payload = self._read_feed_cache_payload()
        if isinstance(payload, list):
            return {str(item).lower() for item in payload if SHA256_PATTERN.fullmatch(str(item))}
        if isinstance(payload, dict) and isinstance(payload.get("hashes"), list):
            return {
                str(item).lower()
                for item in payload["hashes"]
                if SHA256_PATTERN.fullmatch(str(item))
            }
        return set()

    def _load_feed_rules(self) -> list[dict[str, Any]]:
        payload = self._read_rule_feed_cache_payload()
        if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
            return self._dedupe_rules(payload["rules"])
        return []

    def _match_feed_rule(self, data: bytes) -> str | None:
        sample = data.decode("utf-8", errors="ignore").lower()
        for rule in self._load_feed_rules():
            name = str(rule.get("name") or "unnamed-rule")
            for pattern in rule.get("patterns", []):
                candidate = str(pattern).strip().lower()
                if candidate and candidate in sample:
                    return name
        return None

    def _active_feed_urls(self, urls: Iterable[str] | None = None) -> list[str]:
        return [
            str(url)
            for url in (urls or self.feed_urls)
            if str(url).strip() and str(url) not in self.disabled_feed_urls
        ]

    def _active_rule_feed_urls(self, urls: Iterable[str] | None = None) -> list[str]:
        return [
            str(url)
            for url in (urls or self.rule_feed_urls)
            if str(url).strip() and str(url) not in self.disabled_rule_feed_urls
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
            raise ValueError("Malware feed cache path is not configured.")
        self.feed_cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _read_rule_feed_cache_payload(self) -> dict[str, Any] | None:
        if not self.rule_feed_cache_path or not self.rule_feed_cache_path.exists():
            return None
        try:
            payload = json.loads(self.rule_feed_cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None

    def _write_rule_feed_cache_payload(self, payload: dict[str, Any]) -> None:
        if not self.rule_feed_cache_path:
            raise ValueError("Malware rule feed cache path is not configured.")
        self.rule_feed_cache_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _parse_hash_feed_payload(self, payload: str, *, source_url: str = "") -> set[str]:
        stripped = payload.lstrip()
        if stripped.startswith("{") or stripped.startswith("[") or source_url.endswith(".json"):
            try:
                parsed_json = json.loads(payload)
            except json.JSONDecodeError:
                parsed_json = None
            if parsed_json is not None:
                hashes = self._extract_hashes_from_json(parsed_json)
                if hashes:
                    return hashes
        return {match.group(0).lower() for match in SHA256_PATTERN.finditer(payload)}

    def _extract_hashes_from_json(self, payload: Any) -> set[str]:
        hashes: set[str] = set()
        if isinstance(payload, dict):
            for value in payload.values():
                hashes.update(self._extract_hashes_from_json(value))
        elif isinstance(payload, list):
            for item in payload:
                hashes.update(self._extract_hashes_from_json(item))
        elif isinstance(payload, str):
            hashes.update(match.group(0).lower() for match in SHA256_PATTERN.finditer(payload))
        return hashes

    def _parse_rule_feed_payload(self, payload: str, *, source_url: str = "") -> list[dict[str, Any]]:
        stripped = payload.lstrip()
        if stripped.startswith("{") or stripped.startswith("[") or source_url.endswith(".json"):
            try:
                parsed_json = json.loads(payload)
            except json.JSONDecodeError:
                parsed_json = None
            if parsed_json is not None:
                rules = self._extract_rule_definitions(parsed_json)
                if rules:
                    return self._dedupe_rules(rules)
        return self._parse_text_rule_lines(payload)

    def _extract_rule_definitions(self, payload: Any) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            normalized = None
            if not any(key in payload for key in RULE_CONTAINER_KEYS):
                normalized = self._normalize_rule(payload)
            if normalized:
                rules.append(normalized)
            for key, value in payload.items():
                if key in RULE_CONTAINER_KEYS and isinstance(value, list):
                    for item in value:
                        rules.extend(self._extract_rule_definitions(item))
                elif isinstance(value, (dict, list)):
                    rules.extend(self._extract_rule_definitions(value))
        elif isinstance(payload, list):
            for item in payload:
                rules.extend(self._extract_rule_definitions(item))
        return rules

    def _normalize_rule(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        patterns = self._extract_rule_patterns(payload)
        if not patterns:
            return None
        name = None
        for key in RULE_NAME_KEYS:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                name = value.strip()
                break
        if not name:
            name = f"rule-{hashlib.sha1('|'.join(patterns).encode()).hexdigest()[:12]}"
        return {"name": name, "patterns": patterns}

    def _extract_rule_patterns(self, payload: Any) -> list[str]:
        patterns: list[str] = []
        if isinstance(payload, dict):
            for key in RULE_PATTERN_KEYS:
                patterns.extend(self._extract_rule_patterns(payload.get(key)))
            detection = payload.get("detection")
            if isinstance(detection, (dict, list)):
                patterns.extend(self._extract_rule_patterns(detection))
            for key, value in payload.items():
                if key not in RULE_PATTERN_KEYS and key not in RULE_NAME_KEYS and key != "detection":
                    if isinstance(value, (dict, list)):
                        patterns.extend(self._extract_rule_patterns(value))
        elif isinstance(payload, list):
            for item in payload:
                patterns.extend(self._extract_rule_patterns(item))
        elif isinstance(payload, str):
            for item in RULE_VALUE_SPLIT_PATTERN.split(payload.strip()):
                candidate = item.strip().strip("^\"'")
                if len(candidate) >= 4:
                    patterns.append(candidate)
        return list(dict.fromkeys(patterns))

    def _parse_text_rule_lines(self, payload: str) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        for raw_line in payload.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "!", ";", "//", "---")):
                continue
            if ":" in line:
                name, raw_patterns = line.split(":", 1)
                patterns = self._extract_rule_patterns(raw_patterns)
                if name.strip() and patterns:
                    rules.append({"name": name.strip(), "patterns": patterns})
                continue
            patterns = self._extract_rule_patterns(line)
            if patterns:
                rules.append({"name": f"literal-{len(rules) + 1}", "patterns": patterns})
        return self._dedupe_rules(rules)

    def _dedupe_rules(self, rules: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            name = str(rule.get("name") or "").strip()
            patterns = [
                str(item).strip()
                for item in rule.get("patterns", [])
                if isinstance(item, str) and str(item).strip()
            ]
            if not name or not patterns:
                continue
            key = (name.lower(), tuple(pattern.lower() for pattern in patterns))
            if key in seen:
                continue
            seen.add(key)
            deduped.append({"name": name, "patterns": patterns})
        return deduped

    def _fetch_payload(
        self,
        url: str,
        *,
        timeout: float,
        verify_tls: bool,
        ca_bundle_path: str | Path | None,
    ) -> str:
        validate_public_https_url(url, label="Malware feed URL")
        context = self._build_ssl_context(verify_tls, ca_bundle_path)
        with urlopen(url, timeout=timeout, context=context) as response:  # noqa: S310
            return response.read().decode("utf-8", errors="replace")

    def _build_ssl_context(
        self,
        verify_tls: bool,
        ca_bundle_path: str | Path | None,
    ) -> ssl.SSLContext:
        if not verify_tls:
            return ssl._create_unverified_context()  # noqa: SLF001
        cafile = str(ca_bundle_path) if ca_bundle_path else None
        return ssl.create_default_context(cafile=cafile)

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
