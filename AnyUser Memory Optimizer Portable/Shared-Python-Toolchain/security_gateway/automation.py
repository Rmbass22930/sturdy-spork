"""Automation supervisor for background tasks."""
from __future__ import annotations

import signal
import threading
import time
from datetime import UTC, datetime
from typing import Optional

from .alerts import AlertEvent, AlertLevel, AlertManager
from .audit import AuditLogger
from .pam import VaultClient
from .tor import OutboundProxy


class AutomationSupervisor:
    def __init__(
        self,
        vault: VaultClient,
        proxy: OutboundProxy,
        audit_logger: AuditLogger,
        alert_manager: AlertManager,
        interval_seconds: float = 300.0,
    ):
        self._vault = vault
        self._proxy = proxy
        self._audit = audit_logger
        self._alerts = alert_manager
        self._interval = interval_seconds
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_run: Optional[datetime] = None
        self._errors: int = 0

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="automation-supervisor", daemon=True)
        self._thread.start()
        self._audit.log("automation.start", {"interval_seconds": self._interval})

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval)
        self._audit.log("automation.stop", {})

    def _run(self) -> None:
        while not self._stop.is_set():
            self.perform_tasks()
            self._stop.wait(self._interval)

    def perform_tasks(self) -> None:
        try:
            self._vault.rotate_if_needed()
            metrics = self._vault.get_metrics()
            health = self._proxy.health()
            self._audit.log(
                "automation.tick",
                {
                    "vault": metrics,
                    "proxy": health,
                },
            )
            self._last_run = datetime.now(UTC)
        except Exception as exc:  # noqa: BLE001
            self._errors += 1
            self._audit.log("automation.error", {"error": str(exc)})
            self._alerts.emit(
                AlertEvent(
                    level=AlertLevel.warning,
                    title="Automation failure",
                    message=str(exc),
                    context={"errors": self._errors},
                )
            )

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict:
        return {
            "running": self.running,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "error_count": self._errors,
            "interval_seconds": self._interval,
        }


def run_forever(supervisor: AutomationSupervisor) -> None:
    supervisor.start()

    def _handle(sig, frame):  # noqa: ARG001
        supervisor.stop()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    while supervisor.running:
        time.sleep(1)
