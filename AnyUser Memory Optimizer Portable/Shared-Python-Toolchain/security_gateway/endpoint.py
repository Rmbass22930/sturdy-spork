"""Endpoint telemetry and malware scanning."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, Tuple

from .models import DeviceContext


class EndpointTelemetryService:
    def __init__(self, signing_key: bytes | None = None):
        self._key = signing_key or secrets.token_bytes(32)
        self._records: Dict[str, dict] = {}

    def publish(self, device: DeviceContext) -> str:
        body = device.model_dump()
        body["timestamp"] = datetime.now(UTC).isoformat()
        serialized = json.dumps(body, sort_keys=True).encode()
        signature = hmac.new(self._key, serialized, hashlib.sha256).hexdigest()
        self._records[device.device_id] = {"payload": body, "signature": signature}
        return signature

    def verify(self, device_id: str) -> bool:
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


class MalwareScanner:
    def __init__(self, blocked_hashes: set[str] | None = None):
        self.blocked_hashes = blocked_hashes or set()

    def scan_bytes(self, data: bytes) -> Tuple[bool, str]:
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.blocked_hashes:
            return True, f"Hash {digest} flagged as malicious"
        if any(marker in data for marker in [b"ransom", b"bitcoin", b"double_extortion"]):
            return True, "Heuristic trigger: ransomware markers present"
        return False, "clean"

    def scan_path(self, path: str | Path) -> Tuple[bool, str]:
        with open(path, "rb") as handle:
            data = handle.read()
        return self.scan_bytes(data)
