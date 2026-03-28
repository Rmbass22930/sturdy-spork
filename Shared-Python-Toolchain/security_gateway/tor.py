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
        self.allowed_schemes = {scheme.lower() for scheme in settings.proxy_allowed_url_schemes}
        self.allowed_hosts = {host.lower().rstrip(".") for host in settings.proxy_allowed_hosts}
        self.block_private_destinations = settings.proxy_block_private_destinations
        self.blocked_hosts = {host.lower().rstrip(".") for host in settings.proxy_blocked_hosts}

    def request(self, method: str, url: str, via: str = "tor", **kwargs) -> ProxyResponse:
        if via not in {"tor", "warp", "direct"}:
            raise ValueError("via must be 'tor', 'warp', or 'direct'")
        self._validate_target(url)
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
        return self._send_request(method, url, proxies=proxies, headers=headers, **kwargs)

    def _send_request(self, method: str, url: str, *, proxies=None, headers=None, **kwargs) -> ProxyResponse:
        with httpx.Client(timeout=self.timeout, proxies=proxies) as client:
            response = client.request(method, url, headers=headers or {}, **kwargs)
            response.raise_for_status()
            return ProxyResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text,
            )

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

    def _parse_ip_literal(self, hostname: str) -> ipaddress._BaseAddress | None:
        try:
            return ipaddress.ip_address(hostname)
        except ValueError:
            return None

    def _is_disallowed_ip(self, address: ipaddress._BaseAddress) -> bool:
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
