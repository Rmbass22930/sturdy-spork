"""Helpers for validating outbound URLs before network access."""
from __future__ import annotations

import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlparse


DEFAULT_BLOCKED_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "100.100.100.200",
    }
)


def validate_public_https_url(
    url: str,
    *,
    label: str,
    blocked_hosts: Iterable[str] | None = None,
) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"{label} must use HTTPS.")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not contain embedded credentials.")

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if not hostname:
        raise ValueError(f"{label} must include a hostname.")

    normalized_blocked_hosts = {
        str(host).strip().lower().rstrip(".")
        for host in (blocked_hosts or DEFAULT_BLOCKED_HOSTS)
        if str(host).strip()
    }
    if hostname in {"localhost", "localhost.localdomain"} or any(
        hostname == host or hostname.endswith(f".{host}") for host in normalized_blocked_hosts
    ):
        raise ValueError(f"{label} host is blocked: {hostname}")

    literal_ip = _parse_ip_literal(hostname)
    if literal_ip is not None:
        _raise_if_disallowed_ip(literal_ip, label)
        return

    port = parsed.port or 443
    try:
        resolved = {
            ipaddress.ip_address(sockaddr[0])
            for *_ignored, sockaddr in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror:
        return

    for resolved_ip in resolved:
        _raise_if_disallowed_ip(resolved_ip, label)


def _parse_ip_literal(hostname: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _raise_if_disallowed_ip(address: ipaddress._BaseAddress, label: str) -> None:
    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError(f"{label} resolves to a blocked address: {address}")
