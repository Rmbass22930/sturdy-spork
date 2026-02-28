"""Audit logging utilities."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, Dict


class AuditLogger:
    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def log(self, event_type: str, data: Dict[str, Any]) -> None:
        entry = {
            "ts": datetime.now(UTC).isoformat(),
            "type": event_type,
            "data": data,
        }
        line = json.dumps(entry, separators=(",", ":"))
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
