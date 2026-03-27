"""Persistent IP blocklist controls for the security gateway."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional

from .audit import AuditLogger
from .config import settings


@dataclass
class BlockedIPEntry:
    ip: str
    blocked_at: str
    reason: str
    blocked_by: str = "operator"
    expires_at: Optional[str] = None


class IPBlocklistManager:
    def __init__(self, path: str | Path | None = None, audit_logger: Optional[AuditLogger] = None):
        self._path = Path(path or settings.ip_blocklist_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._audit = audit_logger or AuditLogger(settings.audit_log_path)
        self._lock = Lock()

    def list_entries(self) -> List[BlockedIPEntry]:
        with self._lock:
            data = self._load_data()
            data, expired = self._prune_expired_locked(data)
            if expired:
                self._save_data(data)
                self._log_expired(expired)
            return [BlockedIPEntry(**item) for item in data.values()]

    def is_blocked(self, ip: str | None) -> bool:
        if not ip:
            return False
        normalized = self._normalize_ip(ip)
        with self._lock:
            data = self._load_data()
            data, expired = self._prune_expired_locked(data)
            if expired:
                self._save_data(data)
                self._log_expired(expired)
            return normalized in data

    def block(
        self,
        ip: str,
        *,
        reason: str,
        blocked_by: str = "operator",
        duration_minutes: Optional[int] = None,
    ) -> BlockedIPEntry:
        normalized = self._normalize_ip(ip)
        now = datetime.now(UTC)
        entry = BlockedIPEntry(
            ip=normalized,
            blocked_at=now.isoformat(),
            reason=reason,
            blocked_by=blocked_by,
            expires_at=(now + timedelta(minutes=duration_minutes)).isoformat() if duration_minutes else None,
        )
        with self._lock:
            data = self._load_data()
            data, expired = self._prune_expired_locked(data)
            data[normalized] = asdict(entry)
            self._save_data(data)
        self._log_expired(expired)
        self._audit.log(
            "network.ip_block",
            {
                "source_ip": normalized,
                "reason": reason,
                "blocked_by": blocked_by,
                "duration_minutes": duration_minutes,
                "expires_at": entry.expires_at,
            },
        )
        return entry

    def unblock(self, ip: str, *, reason: Optional[str] = None, unblocked_by: str = "operator") -> bool:
        normalized = self._normalize_ip(ip)
        removed = False
        with self._lock:
            data = self._load_data()
            data, expired = self._prune_expired_locked(data)
            if normalized in data:
                removed = True
                data.pop(normalized, None)
                self._save_data(data)
            elif expired:
                self._save_data(data)
        self._log_expired(expired)
        if removed:
            self._audit.log(
                "network.ip_unblock",
                {"source_ip": normalized, "reason": reason or "", "unblocked_by": unblocked_by},
            )
        return removed

    def promote_to_permanent(
        self,
        ip: str,
        *,
        reason: Optional[str] = None,
        promoted_by: str = "operator",
    ) -> Optional[BlockedIPEntry]:
        normalized = self._normalize_ip(ip)
        with self._lock:
            data = self._load_data()
            data, expired = self._prune_expired_locked(data)
            item = data.get(normalized)
            if expired:
                self._save_data(data)
            if not item:
                self._log_expired(expired)
                return None
            item["expires_at"] = None
            if reason:
                item["reason"] = reason
            item["blocked_by"] = promoted_by
            data[normalized] = item
            self._save_data(data)
        self._log_expired(expired)
        self._audit.log(
            "network.ip_block_promote_permanent",
            {"source_ip": normalized, "reason": reason or "", "promoted_by": promoted_by},
        )
        return BlockedIPEntry(**item)

    def _normalize_ip(self, ip: str) -> str:
        return str(ipaddress.ip_address(ip.strip()))

    def _load_data(self) -> Dict[str, Dict[str, str]]:
        if not self._path.exists():
            return {}
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        return payload

    def _save_data(self, data: Dict[str, Dict[str, str]]) -> None:
        self._path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    def _log_expired(self, expired: list[str]) -> None:
        for expired_ip in expired:
            self._audit.log("network.ip_unblock_expired", {"source_ip": expired_ip})

    def _prune_expired_locked(self, data: Dict[str, Dict[str, str]]) -> tuple[Dict[str, Dict[str, str]], list[str]]:
        now = datetime.now(UTC)
        expired: list[str] = []
        active: Dict[str, Dict[str, str]] = {}
        for ip, item in data.items():
            expires_at = item.get("expires_at")
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(expires_at)
                except ValueError:
                    expiry = None
                if expiry and expiry <= now:
                    expired.append(ip)
                    continue
            active[ip] = item
        return active, expired
