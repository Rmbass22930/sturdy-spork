"""Shared Linear form registry for all toolchain programs."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from security_gateway.models import LinearAsksFormRecord, LinearAsksFormUpsert


class LinearAsksFormRegistry:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _read_all(self) -> dict[str, LinearAsksFormRecord]:
        if not self.path.exists():
            return {}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        forms: dict[str, LinearAsksFormRecord] = {}
        for form_key, value in payload.items():
            if not isinstance(form_key, str) or not isinstance(value, dict):
                continue
            try:
                forms[form_key] = LinearAsksFormRecord.model_validate(value)
            except Exception:
                continue
        return forms

    def _write_all(self, forms: dict[str, LinearAsksFormRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        serialized = {
            key: value.model_dump(mode="json")
            for key, value in sorted(forms.items(), key=lambda item: item[0])
        }
        self.path.write_text(json.dumps(serialized, indent=2, sort_keys=True), encoding="utf-8")

    def list_forms(self, *, include_disabled: bool = False) -> list[LinearAsksFormRecord]:
        forms = list(self._read_all().values())
        if not include_disabled:
            forms = [form for form in forms if form.enabled]
        return sorted(forms, key=lambda form: (form.category or "", form.title.casefold(), form.form_key))

    def get_form(self, form_key: str) -> LinearAsksFormRecord | None:
        return self._read_all().get(form_key)

    def upsert_form(self, payload: LinearAsksFormUpsert) -> LinearAsksFormRecord:
        forms = self._read_all()
        existing = forms.get(payload.form_key)
        created_at = existing.created_at if existing is not None else datetime.now(UTC)
        record = LinearAsksFormRecord(
            **payload.model_dump(mode="python"),
            created_at=created_at,
            updated_at=datetime.now(UTC),
        )
        forms[payload.form_key] = record
        self._write_all(forms)
        return record

    def delete_form(self, form_key: str) -> bool:
        forms = self._read_all()
        if form_key not in forms:
            return False
        del forms[form_key]
        self._write_all(forms)
        return True


__all__ = ["LinearAsksFormRecord", "LinearAsksFormRegistry", "LinearAsksFormUpsert"]
