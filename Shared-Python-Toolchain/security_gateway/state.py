"""Shared state containers."""
from __future__ import annotations

from datetime import UTC, datetime
from threading import Lock
from typing import Optional


class DNSSecurityCache:
    def __init__(self) -> None:
        self._lock = Lock()
        self._records: dict[str, dict[str, object]] = {}

    def record(self, hostname: str, secure: bool) -> None:
        key = hostname.lower()
        with self._lock:
            self._records[key] = {"secure": secure, "ts": datetime.now(UTC)}

    def get(self, hostname: str) -> Optional[bool]:
        key = hostname.lower()
        with self._lock:
            record = self._records.get(key)
            if not record:
                return None
            return bool(record["secure"])


dns_security_cache = DNSSecurityCache()
