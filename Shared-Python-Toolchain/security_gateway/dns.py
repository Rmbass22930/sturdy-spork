"""Encrypted DNS resolution (DoH)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

import httpx

from .config import settings
from .url_safety import validate_public_https_url

ALLOWED_RECORD_TYPES = {"A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT"}
HOSTNAME_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


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
        self.providers = self._normalize_providers(providers or list(settings.doh_providers))
        self._external_client = client is not None
        self._client = client or httpx.Client(timeout=timeout, headers={"accept": "application/dns-json"})

    def resolve(self, hostname: str, record_type: str = "A") -> DNSResponse:
        hostname, record_type = self.normalize_query(hostname, record_type)
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

    def normalize_query(self, hostname: str, record_type: str = "A") -> tuple[str, str]:
        return self._normalize_hostname(hostname), self._normalize_record_type(record_type)

    def _normalize_hostname(self, hostname: str) -> str:
        candidate = hostname.strip().rstrip(".")
        if not candidate or len(candidate) > 253:
            raise ValueError("hostname must be between 1 and 253 characters.")
        labels = candidate.split(".")
        if any(len(label) == 0 or len(label) > 63 for label in labels):
            raise ValueError("hostname contains an invalid DNS label length.")
        if any(not HOSTNAME_LABEL_PATTERN.fullmatch(label) for label in labels):
            raise ValueError("hostname contains invalid characters.")
        return candidate

    def _normalize_record_type(self, record_type: str) -> str:
        candidate = record_type.strip().upper()
        if candidate not in ALLOWED_RECORD_TYPES:
            raise ValueError(f"record_type must be one of: {', '.join(sorted(ALLOWED_RECORD_TYPES))}")
        return candidate

    def _normalize_providers(self, providers: List[str]) -> List[str]:
        normalized: list[str] = []
        for provider in providers:
            candidate = str(provider).strip()
            if not candidate:
                continue
            validate_public_https_url(candidate, label="DoH provider URL")
            normalized.append(candidate)
        if not normalized:
            raise ValueError("At least one DoH provider URL must be configured.")
        return normalized

    def close(self) -> None:
        if not self._external_client:
            self._client.close()

    def __del__(self) -> None:  # pragma: no cover - best effort cleanup
        try:
            self.close()
        except Exception:
            pass
