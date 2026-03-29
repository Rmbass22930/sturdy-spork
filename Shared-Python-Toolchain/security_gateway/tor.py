"""Outbound privacy-preserving HTTP utilities."""
from __future__ import annotations

import ipaddress
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

from .config import settings

ALLOWED_PROXY_METHODS = frozenset({"GET", "HEAD"})
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass
class ProxyResponse:
    status_code: int
    headers: dict[str, str]
    body: str


class ProxyRequestTimeoutError(RuntimeError):
    """Raised when the upstream proxy request times out."""


class ProxyResponseTooLargeError(RuntimeError):
    """Raised when the upstream response body exceeds the configured limit."""


class OutboundProxy:
    def __init__(
        self,
        tor_proxy: Optional[str] = None,
        warp_endpoint: Optional[str] = None,
        timeout: float | None = None,
        max_response_bytes: int | None = None,
    ):
        self.tor_proxy = tor_proxy or settings.tor_socks_proxy
        self.warp_endpoint = warp_endpoint or settings.warp_endpoint
        self.timeout = settings.proxy_timeout_seconds if timeout is None else timeout
        self.max_response_bytes = settings.proxy_max_response_bytes if max_response_bytes is None else max_response_bytes
        self.allowed_schemes = {scheme.lower() for scheme in settings.proxy_allowed_url_schemes}
        self.allowed_hosts = {host.lower().rstrip(".") for host in settings.proxy_allowed_hosts}
        self.block_private_destinations = settings.proxy_block_private_destinations
        self.blocked_hosts = {host.lower().rstrip(".") for host in settings.proxy_blocked_hosts}

    def request(self, method: str, url: str, via: str = "tor", **kwargs) -> ProxyResponse:
        normalized_method = str(method).strip().upper()
        if normalized_method not in ALLOWED_PROXY_METHODS:
            raise ValueError(f"Proxy request method must be one of: {', '.join(sorted(ALLOWED_PROXY_METHODS))}")
        if via not in {"tor", "warp", "direct"}:
            raise ValueError("via must be 'tor', 'warp', or 'direct'")
        self._validate_target(url)
        proxy = None
        headers = kwargs.pop("headers", {}) or {}
        if via == "tor":
            proxy = self.tor_proxy
        elif via == "warp" and self.warp_endpoint:
            headers.setdefault("CF-Access-Client-Id", "demo")
            headers.setdefault("CF-Access-Client-Secret", "demo")
        return self._send_request(normalized_method, url, proxy=proxy, headers=headers, **kwargs)

    def _send_request(
        self,
        method: str,
        url: str,
        *,
        proxy: str | None = None,
        headers: dict[str, str] | None = None,
        **kwargs,
    ) -> ProxyResponse:
        try:
            with httpx.Client(timeout=self.timeout, proxy=proxy) as client:
                with client.stream(method, url, headers=headers or {}, **kwargs) as response:
                    response.raise_for_status()
                    content_length = response.headers.get("content-length")
                    if content_length and int(content_length) > self.max_response_bytes:
                        raise ProxyResponseTooLargeError(
                            f"Proxy response exceeds the configured limit of {self.max_response_bytes} bytes."
                        )
                    body_bytes = bytearray()
                    for chunk in response.iter_bytes():
                        body_bytes.extend(chunk)
                        if len(body_bytes) > self.max_response_bytes:
                            raise ProxyResponseTooLargeError(
                                f"Proxy response exceeds the configured limit of {self.max_response_bytes} bytes."
                            )
                    encoding = response.encoding or "utf-8"
                    return ProxyResponse(
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        body=body_bytes.decode(encoding, errors="replace"),
                    )
        except httpx.TimeoutException as exc:
            raise ProxyRequestTimeoutError(f"Proxy request timed out after {self.timeout} seconds.") from exc

    def _validate_target(self, url: str) -> None:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in self.allowed_schemes:
            raise ValueError(f"Proxy target scheme must be one of: {', '.join(sorted(self.allowed_schemes))}")
        if parsed.username or parsed.password:
            raise ValueError("Proxy target credentials are not allowed.")
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        if not hostname:
            raise ValueError("Proxy target must include a hostname.")
        if self.allowed_hosts and not any(hostname == host or hostname.endswith(f".{host}") for host in self.allowed_hosts):
            raise ValueError("Proxy target host is not in the configured allowlist.")
        if hostname in {"localhost", "localhost.localdomain"} or hostname in self.blocked_hosts:
            raise ValueError(f"Proxy target host is blocked: {hostname}")
        ip_literal = self._parse_ip_literal(hostname)
        if ip_literal is not None:
            if self.block_private_destinations and self._is_disallowed_ip(ip_literal):
                raise ValueError(f"Proxy target IP is not allowed: {ip_literal}")
            return
        if not self.block_private_destinations:
            return
        port = parsed.port or (443 if scheme == "https" else 80)
        try:
            resolved = {
                ipaddress.ip_address(sockaddr[0])
                for *_ignored, sockaddr in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            }
        except socket.gaierror:
            return
        for resolved_ip in resolved:
            if self._is_disallowed_ip(resolved_ip):
                raise ValueError(f"Proxy target resolves to a blocked address: {resolved_ip}")

    def _parse_ip_literal(self, hostname: str) -> IPAddress | None:
        try:
            return ipaddress.ip_address(hostname)
        except ValueError:
            return None

    def _is_disallowed_ip(self, address: IPAddress) -> bool:
        return (
            address.is_loopback
            or address.is_private
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
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
