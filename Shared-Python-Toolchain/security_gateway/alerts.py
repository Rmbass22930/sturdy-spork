"""Alerting subsystem."""
from __future__ import annotations

import ipaddress
import json
import socket
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from enum import Enum
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx

from .config import get_runtime_data_dir, settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class AlertLevel(str, Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


@dataclass
class AlertEvent:
    level: AlertLevel
    title: str
    message: str
    context: Dict[str, Any]


def _resolve_powershell_executable() -> str:
    return (
        shutil.which("pwsh")
        or shutil.which("powershell.exe")
        or shutil.which("powershell")
        or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )


class AlertManager:
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        enable_toast: Optional[bool] = None,
        preference_path: Path | None = None,
    ):
        self.webhook_url = webhook_url or settings.alert_webhook_url
        self.enable_toast = settings.alert_enable_toast if enable_toast is None else enable_toast
        self._preference_path = preference_path or (get_runtime_data_dir() / "alert_preferences.json")
        self._http_client = None
        self._webhook_error: str | None = None
        if self.webhook_url:
            try:
                self._validate_webhook_url(self.webhook_url)
            except ValueError as exc:
                self._webhook_error = str(exc)
                self.webhook_url = None
            else:
                self._http_client = httpx.Client(
                    timeout=settings.alert_webhook_timeout_seconds,
                    verify=settings.alert_webhook_verify_tls,
                    follow_redirects=False,
                )

    def emit(self, event: AlertEvent) -> None:
        payload = {
            "level": event.level.value,
            "title": event.title,
            "message": event.message,
            "context": event.context,
        }
        print(f"[ALERT] {payload}")
        if self._http_client:
            try:
                if self.webhook_url is None:
                    raise RuntimeError("Webhook client configured without a URL.")
                self._http_client.post(self.webhook_url, json=payload).raise_for_status()
            except Exception as exc:  # noqa: BLE001
                print(f"Failed to send webhook alert: {exc}", file=sys.stderr)
        elif self._webhook_error:
            print(f"Webhook alert delivery disabled: {self._webhook_error}", file=sys.stderr)
        if self.is_toast_enabled():
            self._toast(payload)

    def is_toast_enabled(self) -> bool:
        preferences = self._load_preferences()
        if "enable_toast" in preferences:
            return bool(preferences["enable_toast"])
        return bool(self.enable_toast)

    def set_toast_enabled(self, enabled: bool) -> None:
        self.enable_toast = enabled
        preferences = self._load_preferences()
        preferences["enable_toast"] = enabled
        self._save_preferences(preferences)

    def _toast(self, payload: Dict[str, Any]) -> None:
        title = self._escape_powershell_single_quoted(f"SecurityGateway: {payload['title']}")
        message = self._escape_powershell_single_quoted(str(payload["message"]))
        ps_script = (
            "Add-Type -AssemblyName System.Windows.Forms;"
            "$toast = New-Object System.Windows.Forms.NotifyIcon;"
            "$toast.Icon = [System.Drawing.SystemIcons]::Warning;"
            "$toast.Visible = $true;"
            f"$toast.BalloonTipTitle = '{title}';"
            f"$toast.BalloonTipText = '{message}';"
            "$toast.ShowBalloonTip(10000);"
            "Start-Sleep -Seconds 5;"
            "$toast.Dispose();"
        )
        try:
            subprocess.Popen(
                [_resolve_powershell_executable(), "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            pass

    @staticmethod
    def _escape_powershell_single_quoted(value: str) -> str:
        return value.replace("'", "''")

    def close(self) -> None:
        if self._http_client:
            self._http_client.close()

    def _load_preferences(self) -> Dict[str, Any]:
        if not self._preference_path.exists():
            return {}
        try:
            payload = json.loads(self._preference_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _save_preferences(self, payload: Dict[str, Any]) -> None:
        self._preference_path.parent.mkdir(parents=True, exist_ok=True)
        self._preference_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def _validate_webhook_url(url: str) -> None:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme != "https":
            raise ValueError("Alert webhook URL must use HTTPS.")
        if parsed.username or parsed.password:
            raise ValueError("Alert webhook URL must not contain embedded credentials.")
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        if not hostname:
            raise ValueError("Alert webhook URL must include a hostname.")
        if hostname in {"localhost", "localhost.localdomain"}:
            raise ValueError("Alert webhook URL must not target localhost.")

        try:
            literal_ip = ipaddress.ip_address(hostname)
        except ValueError:
            literal_ip = None

        if literal_ip is not None:
            AlertManager._raise_if_disallowed_ip(literal_ip)
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
            AlertManager._raise_if_disallowed_ip(resolved_ip)

    @staticmethod
    def _raise_if_disallowed_ip(address: IPAddress) -> None:
        if (
            address.is_loopback
            or address.is_private
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        ):
            raise ValueError(f"Alert webhook URL resolves to a blocked address: {address}")


alert_manager = AlertManager()
