"""Shared update registry with controlled sync/apply semantics."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_gateway.models import ToolchainUpdateRecord
from toolchain_resources.docker_resources import list_docker_resources
from toolchain_resources.linear_forms import LinearAsksFormRegistry


def _serialize_update(record: ToolchainUpdateRecord) -> dict[str, Any]:
    return record.model_dump(mode="json")


class ToolchainUpdateRegistry:
    def __init__(self, path: str | Path, *, linear_forms_path: str | Path) -> None:
        self.path = Path(path)
        self.linear_forms = LinearAsksFormRegistry(linear_forms_path)

    def _read_all(self) -> dict[str, ToolchainUpdateRecord]:
        if not self.path.exists():
            return {}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        updates: dict[str, ToolchainUpdateRecord] = {}
        for update_id, value in payload.items():
            if not isinstance(update_id, str) or not isinstance(value, dict):
                continue
            try:
                updates[update_id] = ToolchainUpdateRecord.model_validate(value)
            except Exception:
                continue
        return updates

    def _write_all(self, updates: dict[str, ToolchainUpdateRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        serialized = {
            key: _serialize_update(value)
            for key, value in sorted(updates.items(), key=lambda item: item[0])
        }
        self.path.write_text(json.dumps(serialized, indent=2, sort_keys=True), encoding="utf-8")

    def _provider_records(self) -> list[ToolchainUpdateRecord]:
        now = datetime.now(UTC)
        records: list[ToolchainUpdateRecord] = []
        for resource in list_docker_resources():
            records.append(
                ToolchainUpdateRecord(
                    update_id=f"docker:{resource.resource_key}",
                    provider="docker",
                    resource_type="catalog_resource",
                    title=resource.title,
                    url=resource.url,
                    summary=resource.summary,
                    announced_at=resource.announced_at,
                    first_seen_at=now,
                    last_seen_at=now,
                    status="new",
                    load_policy="safe_catalog",
                    loaded=True,
                    metadata={
                        "category": resource.category,
                        "toolchain_relevance": resource.toolchain_relevance,
                    },
                )
            )
        for form in self.linear_forms.list_forms(include_disabled=True):
            records.append(
                ToolchainUpdateRecord(
                    update_id=f"linear_form:{form.form_key}",
                    provider="linear",
                    resource_type="configured_form",
                    title=form.title,
                    url=form.url,
                    summary=form.description or "Configured Linear Asks form.",
                    announced_at=form.updated_at,
                    first_seen_at=now,
                    last_seen_at=now,
                    status="new",
                    load_policy="safe_catalog",
                    loaded=form.enabled,
                    metadata={
                        "category": form.category,
                        "team": form.team,
                        "enabled": form.enabled,
                    },
                )
            )
        return records

    def sync(self, *, apply_safe_only: bool = True) -> dict[str, object]:
        existing = self._read_all()
        current_records = self._provider_records()
        now = datetime.now(UTC)
        discovered = 0
        updated = 0
        applied = 0

        for record in current_records:
            previous = existing.get(record.update_id)
            if previous is None:
                discovered += 1
                if apply_safe_only and record.load_policy == "safe_catalog":
                    record.status = "applied"
                    record.loaded = True
                    applied += 1
                existing[record.update_id] = record
                continue
            merged = record.model_copy(
                update={
                    "first_seen_at": previous.first_seen_at,
                    "status": previous.status,
                    "loaded": previous.loaded or record.loaded,
                    "last_seen_at": now,
                }
            )
            if apply_safe_only and merged.load_policy == "safe_catalog" and merged.status in {"new", "seen"}:
                merged = merged.model_copy(update={"status": "applied", "loaded": True})
                applied += 1
            existing[record.update_id] = merged
            updated += 1

        self._write_all(existing)
        return {
            "updates": [record.model_dump(mode="json") for record in self.list_updates()],
            "discovered": discovered,
            "updated": updated,
            "applied": applied,
        }

    def list_updates(
        self,
        *,
        provider: str | None = None,
        status: str | None = None,
    ) -> list[ToolchainUpdateRecord]:
        updates = list(self._read_all().values())
        if provider:
            updates = [item for item in updates if item.provider == provider]
        if status:
            updates = [item for item in updates if item.status == status]
        return sorted(
            updates,
            key=lambda item: (
                item.last_seen_at,
                item.announced_at or datetime.fromtimestamp(0, UTC),
                item.update_id,
            ),
            reverse=True,
        )

    def get_update(self, update_id: str) -> ToolchainUpdateRecord | None:
        return self._read_all().get(update_id)

    def mark_seen(self, update_id: str) -> ToolchainUpdateRecord | None:
        updates = self._read_all()
        record = updates.get(update_id)
        if record is None:
            return None
        if record.status == "new":
            record = record.model_copy(update={"status": "seen", "last_seen_at": datetime.now(UTC)})
            updates[update_id] = record
            self._write_all(updates)
        return record

