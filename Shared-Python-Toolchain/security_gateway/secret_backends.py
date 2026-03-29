"""Secret storage backends."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Optional
from urllib.parse import urlparse

import requests


class SecretBackend(ABC):
    @abstractmethod
    def write(self, name: str, version: str, ciphertext: str) -> None:
        """Persist ciphertext for the given secret version."""

    @abstractmethod
    def read(self, name: str, version: str) -> Optional[str]:
        """Retrieve ciphertext for the version if available."""


class LocalMemoryBackend(SecretBackend):
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, str]] = {}

    def write(self, name: str, version: str, ciphertext: str) -> None:
        self._store.setdefault(name, {})[version] = ciphertext

    def read(self, name: str, version: str) -> Optional[str]:
        return self._store.get(name, {}).get(version)


class HashicorpVaultBackend(SecretBackend):
    def __init__(
        self,
        url: str,
        token: str,
        mount: str = "secret",
        namespace: Optional[str] = None,
        *,
        timeout_seconds: float = 5.0,
        verify_tls: bool = True,
        session: requests.Session | None = None,
    ) -> None:
        self._validate_url(url)
        self._url = url.rstrip("/")
        self._token = token
        self._mount = mount.strip("/")
        self._namespace = namespace
        self._timeout_seconds = timeout_seconds
        self._session = session or requests.Session()
        self._session.verify = verify_tls

    def _headers(self) -> Dict[str, str]:
        headers = {"X-Vault-Token": self._token}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        return headers

    def _path(self, name: str, version: str) -> str:
        path = f"security-gateway/{name}/{version}"
        return f"{self._url}/v1/{self._mount}/data/{path}"

    def write(self, name: str, version: str, ciphertext: str) -> None:
        response = self._session.post(
            self._path(name, version),
            headers=self._headers(),
            json={"data": {"ciphertext": ciphertext}},
            timeout=self._timeout_seconds,
            allow_redirects=False,
        )
        response.raise_for_status()

    def read(self, name: str, version: str) -> Optional[str]:
        response = self._session.get(
            self._path(name, version),
            headers=self._headers(),
            timeout=self._timeout_seconds,
            allow_redirects=False,
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        body = response.json()
        data = body.get("data", {}).get("data", {})
        return data.get("ciphertext")

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            raise ValueError("HashiCorp Vault URL must use HTTPS.")
        if parsed.username or parsed.password:
            raise ValueError("HashiCorp Vault URL must not contain embedded credentials.")
        if not parsed.hostname:
            raise ValueError("HashiCorp Vault URL must include a hostname.")
