"""Alerting subsystem."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

import httpx

from .config import settings


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
    def __init__(self, webhook_url: Optional[str] = None, enable_toast: Optional[bool] = None):
        self.webhook_url = webhook_url or settings.alert_webhook_url
        self.enable_toast = settings.alert_enable_toast if enable_toast is None else enable_toast
        self._http_client = None
        if self.webhook_url:
            self._http_client = httpx.Client(timeout=4.0)

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
                self._http_client.post(self.webhook_url, json=payload).raise_for_status()
            except Exception as exc:  # noqa: BLE001
                print(f"Failed to send webhook alert: {exc}", file=sys.stderr)
        if self.enable_toast:
            self._toast(payload)

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


alert_manager = AlertManager()


