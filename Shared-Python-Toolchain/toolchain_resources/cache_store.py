"""Shared cache metadata store for toolchain resources."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_gateway.models import ToolchainCacheEntryRecord


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _CacheEntry:
    namespace: str
    cache_key: str
    source: str
    summary: str
    updated_at: datetime
    expires_at: datetime | None
    payload: Any
    metadata: dict[str, Any]

    def to_record(self) -> ToolchainCacheEntryRecord:
        now = _utc_now()
        if self.expires_at is None:
            status = "fresh"
        elif self.expires_at <= now:
            status = "expired"
        elif self.expires_at <= now + timedelta(minutes=15):
            status = "stale"
        else:
            status = "fresh"
        return ToolchainCacheEntryRecord(
            namespace=self.namespace,
            cache_key=self.cache_key,
            status=status,
            source=self.source,
            summary=self.summary,
            updated_at=self.updated_at,
            expires_at=self.expires_at,
            payload=self.payload,
            metadata=dict(self.metadata),
        )

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "_CacheEntry":
        expires_at = payload.get("expires_at")
        return cls(
            namespace=str(payload["namespace"]),
            cache_key=str(payload["cache_key"]),
            source=str(payload["source"]),
            summary=str(payload["summary"]),
            updated_at=datetime.fromisoformat(str(payload["updated_at"])),
            expires_at=datetime.fromisoformat(str(expires_at)) if expires_at else None,
            payload=payload.get("payload"),
            metadata=dict(payload.get("metadata") or {}),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace,
            "cache_key": self.cache_key,
            "source": self.source,
            "summary": self.summary,
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "payload": self.payload,
            "metadata": dict(self.metadata),
        }


class ToolchainCacheStore:
    def __init__(self, state_path: str | Path) -> None:
        self._state_path = Path(state_path)

    def _load(self) -> list[_CacheEntry]:
        if not self._state_path.exists():
            return []
        payload = json.loads(self._state_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            return []
        return [_CacheEntry.from_json(item) for item in payload if isinstance(item, dict)]

    def _save(self, entries: list[_CacheEntry]) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [entry.to_json() for entry in entries]
        self._state_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def list_entries(self, namespace: str | None = None, status: str | None = None) -> list[ToolchainCacheEntryRecord]:
        records = [entry.to_record() for entry in self._load()]
        if namespace:
            records = [record for record in records if record.namespace == namespace]
        if status:
            records = [record for record in records if record.status == status]
        return sorted(records, key=lambda item: (item.namespace, item.cache_key))

    def get_entry(self, namespace: str, cache_key: str) -> ToolchainCacheEntryRecord | None:
        for record in self.list_entries(namespace=namespace):
            if record.cache_key == cache_key:
                return record
        return None

    def set_entry(
        self,
        namespace: str,
        cache_key: str,
        *,
        source: str,
        summary: str,
        ttl_seconds: float | None = 3600.0,
        payload: Any = None,
        metadata: dict[str, Any] | None = None,
    ) -> ToolchainCacheEntryRecord:
        now = _utc_now()
        expires_at = now + timedelta(seconds=ttl_seconds) if ttl_seconds and ttl_seconds > 0 else None
        entries = [entry for entry in self._load() if not (entry.namespace == namespace and entry.cache_key == cache_key)]
        entries.append(
            _CacheEntry(
                namespace=namespace,
                cache_key=cache_key,
                source=source,
                summary=summary,
                updated_at=now,
                expires_at=expires_at,
                payload=payload,
                metadata=dict(metadata or {}),
            )
        )
        self._save(entries)
        record = self.get_entry(namespace, cache_key)
        assert record is not None
        return record

    def delete_entry(self, namespace: str, cache_key: str) -> bool:
        entries = self._load()
        updated = [entry for entry in entries if not (entry.namespace == namespace and entry.cache_key == cache_key)]
        if len(updated) == len(entries):
            return False
        self._save(updated)
        return True

    def summary(self) -> dict[str, Any]:
        records = self.list_entries()
        return {
            "count": len(records),
            "fresh_count": sum(1 for item in records if item.status == "fresh"),
            "stale_count": sum(1 for item in records if item.status == "stale"),
            "expired_count": sum(1 for item in records if item.status == "expired"),
            "namespaces": {namespace: len([item for item in records if item.namespace == namespace]) for namespace in {item.namespace for item in records}},
            "recent_entries": [item.model_dump(mode="json") for item in records[:5]],
        }
