"""Helpers for validating outbound URLs before network access."""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Iterable
from urllib.parse import urlparse

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

DEFAULT_BLOCKED_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "100.100.100.200",
    }
)
HOSTNAME_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


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
    validate_public_host_or_ip(hostname, label=label, blocked_hosts=normalized_blocked_hosts, port=parsed.port or 443)


def validate_public_host_or_ip(
    value: str,
    *,
    label: str,
    blocked_hosts: Iterable[str] | None = None,
    port: int = 443,
) -> str:
    candidate = str(value).strip()
    if not candidate:
        raise ValueError(f"{label} must include a hostname or IP address.")
    if "://" in candidate:
        raise ValueError(f"{label} must be a hostname or IP address, not a URL.")
    if any(character.isspace() for character in candidate):
        raise ValueError(f"{label} must not contain whitespace.")
    if candidate.startswith("-"):
        raise ValueError(f"{label} must not start with '-'.")

    normalized_host = candidate.rstrip(".").lower()
    normalized_blocked_hosts = {
        str(host).strip().lower().rstrip(".")
        for host in (blocked_hosts or DEFAULT_BLOCKED_HOSTS)
        if str(host).strip()
    }
    if normalized_host in {"localhost", "localhost.localdomain"} or any(
        normalized_host == host or normalized_host.endswith(f".{host}") for host in normalized_blocked_hosts
    ):
        raise ValueError(f"{label} host is blocked: {normalized_host}")

    literal_ip = _parse_ip_literal(normalized_host)
    if literal_ip is not None:
        _raise_if_disallowed_ip(literal_ip, label)
        return normalized_host

    if len(normalized_host) > 253:
        raise ValueError(f"{label} must be between 1 and 253 characters.")
    labels = normalized_host.split(".")
    if any(len(label_value) == 0 or len(label_value) > 63 for label_value in labels):
        raise ValueError(f"{label} contains an invalid DNS label length.")
    if any(not HOSTNAME_LABEL_PATTERN.fullmatch(label_value) for label_value in labels):
        raise ValueError(f"{label} contains invalid characters.")

    try:
        resolved = {
            ipaddress.ip_address(sockaddr[0])
            for *_ignored, sockaddr in socket.getaddrinfo(normalized_host, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror:
        return normalized_host

    for resolved_ip in resolved:
        _raise_if_disallowed_ip(resolved_ip, label)
    return normalized_host


def _parse_ip_literal(hostname: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _raise_if_disallowed_ip(address: IPAddress, label: str) -> None:
    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError(f"{label} resolves to a blocked address: {address}")
