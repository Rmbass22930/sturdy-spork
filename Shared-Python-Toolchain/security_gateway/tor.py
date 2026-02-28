"""Outbound privacy-preserving HTTP utilities."""
from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

from .config import settings


@dataclass
class ProxyResponse:
    status_code: int
    headers: dict[str, str]
    body: str


class OutboundProxy:
    def __init__(self, tor_proxy: Optional[str] = None, warp_endpoint: Optional[str] = None, timeout: float = 10.0):
        self.tor_proxy = tor_proxy or settings.tor_socks_proxy
        self.warp_endpoint = warp_endpoint or settings.warp_endpoint
        self.timeout = timeout

    def request(self, method: str, url: str, via: str = "tor", **kwargs) -> ProxyResponse:
        if via not in {"tor", "warp", "direct"}:
            raise ValueError("via must be 'tor', 'warp', or 'direct'")
        proxies = None
        headers = kwargs.pop("headers", {}) or {}
        if via == "tor":
            proxies = {
                "http": self.tor_proxy,
                "https": self.tor_proxy,
            }
        elif via == "warp" and self.warp_endpoint:
            headers.setdefault("CF-Access-Client-Id", "demo")
            headers.setdefault("CF-Access-Client-Secret", "demo")
        with httpx.Client(timeout=self.timeout, proxies=proxies) as client:
            response = client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()
            return ProxyResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
            )

    def health(self) -> dict:
        return {
            "tor": self._check_tor(),
            "warp": self._check_warp(),
        }

    def _check_tor(self) -> dict:
        if not self.tor_proxy:
            return {"status": "disabled"}
        parsed = urlparse(self.tor_proxy)
        host, port = parsed.hostname, parsed.port
        if not host or not port:
            return {"status": "misconfigured"}
        try:
            with socket.create_connection((host, port), timeout=2):
                return {"status": "ok", "endpoint": f"{host}:{port}"}
        except OSError as exc:
            return {"status": "error", "error": str(exc)}

    def _check_warp(self) -> dict:
        if not self.warp_endpoint:
            return {"status": "disabled"}
        try:
            result = subprocess.run(
                ["warp-cli", "status"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except FileNotFoundError:
            return {"status": "unknown", "error": "warp-cli not installed"}
        except subprocess.SubprocessError as exc:
            return {"status": "error", "error": str(exc)}
        output = result.stdout.strip() or result.stderr.strip()
        status = "ok" if "Connected" in output else "degraded"
        return {"status": status, "details": output}
