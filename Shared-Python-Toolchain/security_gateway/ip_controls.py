"""Persistent IP blocklist controls for the security gateway."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, asdict
from datetime import UTC, datetime
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


class IPBlocklistManager:
    def __init__(self, path: str | Path | None = None, audit_logger: Optional[AuditLogger] = None):
        self._path = Path(path or settings.ip_blocklist_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._audit = audit_logger or AuditLogger(settings.audit_log_path)
        self._lock = Lock()

    def list_entries(self) -> List[BlockedIPEntry]:
        with self._lock:
            return [BlockedIPEntry(**item) for item in self._load_data().values()]

    def is_blocked(self, ip: str | None) -> bool:
        if not ip:
            return False
        normalized = self._normalize_ip(ip)
        with self._lock:
            return normalized in self._load_data()

    def block(self, ip: str, *, reason: str, blocked_by: str = "operator") -> BlockedIPEntry:
        normalized = self._normalize_ip(ip)
        entry = BlockedIPEntry(
            ip=normalized,
            blocked_at=datetime.now(UTC).isoformat(),
            reason=reason,
            blocked_by=blocked_by,
        )
        with self._lock:
            data = self._load_data()
            data[normalized] = asdict(entry)
            self._save_data(data)
        self._audit.log(
            "network.ip_block",
            {"source_ip": normalized, "reason": reason, "blocked_by": blocked_by},
        )
        return entry

    def unblock(self, ip: str, *, reason: Optional[str] = None, unblocked_by: str = "operator") -> bool:
        normalized = self._normalize_ip(ip)
        removed = False
        with self._lock:
            data = self._load_data()
            if normalized in data:
                removed = True
                data.pop(normalized, None)
                self._save_data(data)
        if removed:
            self._audit.log(
                "network.ip_unblock",
                {"source_ip": normalized, "reason": reason or "", "unblocked_by": unblocked_by},
            )
        return removed

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
