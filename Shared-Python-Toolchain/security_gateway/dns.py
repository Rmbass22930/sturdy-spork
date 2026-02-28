"""Encrypted DNS resolution (DoH)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import httpx

from .config import settings


@dataclass
class DNSRecord:
    name: str
    type: str
    ttl: int
    data: str


@dataclass
class DNSResponse:
    secure: bool
    records: List[DNSRecord]


class SecureDNSResolver:
    def __init__(
        self,
        providers: Optional[List[str]] = None,
        timeout: float = 3.0,
        client: httpx.Client | None = None,
    ):
        self.providers = providers or list(settings.doh_providers)
        self._external_client = client is not None
        self._client = client or httpx.Client(timeout=timeout, headers={"accept": "application/dns-json"})

    def resolve(self, hostname: str, record_type: str = "A") -> DNSResponse:
        last_error: Exception | None = None
        for endpoint in self.providers:
            try:
                response = self._client.get(endpoint, params={"name": hostname, "type": record_type})
                response.raise_for_status()
                body = response.json()
                answers = body.get("Answer", [])
                records = [
                    DNSRecord(
                        name=answer.get("name", hostname),
                        type=str(answer.get("type", record_type)),
                        ttl=int(answer.get("TTL", 0)),
                        data=answer.get("data", ""),
                    )
                    for answer in answers
                ]
                return DNSResponse(secure=body.get("AD", False), records=records)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                continue
        raise RuntimeError(f"All DoH providers failed: {last_error}")

    def close(self) -> None:
        if not self._external_client:
            self._client.close()

    def __del__(self) -> None:  # pragma: no cover - best effort cleanup
        try:
            self.close()
        except Exception:
            pass
