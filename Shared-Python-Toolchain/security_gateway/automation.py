"""Automation supervisor for background tasks."""
from __future__ import annotations

import signal
import threading
import time
from datetime import UTC, datetime
from typing import Any, Optional

from .alerts import AlertEvent, AlertLevel, AlertManager
from .audit import AuditLogger
from .endpoint import MalwareScanner
from .pam import VaultClient
from .tracker_intel import TrackerIntel
from .tor import OutboundProxy


class AutomationSupervisor:
    def __init__(
        self,
        vault: VaultClient,
        proxy: OutboundProxy,
        audit_logger: AuditLogger,
        alert_manager: AlertManager,
        tracker_intel: TrackerIntel | None = None,
        malware_scanner: MalwareScanner | None = None,
        interval_seconds: float = 300.0,
        tracker_feed_refresh_enabled: bool = False,
        tracker_feed_refresh_every_ticks: int = 12,
        malware_feed_refresh_enabled: bool = False,
        malware_feed_refresh_every_ticks: int = 12,
        malware_rule_feed_refresh_enabled: bool = False,
        malware_rule_feed_refresh_every_ticks: int = 12,
    ):
        self._vault = vault
        self._proxy = proxy
        self._audit = audit_logger
        self._alerts = alert_manager
        self._tracker_intel = tracker_intel
        self._malware_scanner = malware_scanner
        self._interval = interval_seconds
        self._tracker_feed_refresh_enabled = tracker_feed_refresh_enabled
        self._tracker_feed_refresh_every_ticks = max(1, tracker_feed_refresh_every_ticks)
        self._malware_feed_refresh_enabled = malware_feed_refresh_enabled
        self._malware_feed_refresh_every_ticks = max(1, malware_feed_refresh_every_ticks)
        self._malware_rule_feed_refresh_enabled = malware_rule_feed_refresh_enabled
        self._malware_rule_feed_refresh_every_ticks = max(1, malware_rule_feed_refresh_every_ticks)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_run: Optional[datetime] = None
        self._errors: int = 0
        self._tick_count: int = 0
        self._tracker_feed_last_run: Optional[datetime] = None
        self._tracker_feed_last_result: Optional[str] = None
        self._tracker_feed_last_error: Optional[str] = None
        self._malware_feed_last_run: Optional[datetime] = None
        self._malware_feed_last_result: Optional[str] = None
        self._malware_feed_last_error: Optional[str] = None
        self._malware_rule_feed_last_run: Optional[datetime] = None
        self._malware_rule_feed_last_result: Optional[str] = None
        self._malware_rule_feed_last_error: Optional[str] = None

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
            self._tick_count += 1
            self._vault.rotate_if_needed()
            metrics = self._vault.get_metrics()
            health = self._proxy.health()
            tracker_feed = self._maybe_refresh_tracker_feeds()
            malware_feed = self._maybe_refresh_malware_feeds()
            malware_rule_feed = self._maybe_refresh_malware_rule_feeds()
            self._audit.log(
                "automation.tick",
                {
                    "vault": metrics,
                    "proxy": health,
                    "tracker_feeds": tracker_feed,
                    "malware_feeds": malware_feed,
                    "malware_rule_feeds": malware_rule_feed,
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

    def _maybe_refresh_tracker_feeds(self) -> dict[str, Any]:
        if not self._tracker_feed_refresh_enabled:
            return {"enabled": False}
        if self._tracker_intel is None:
            return {"enabled": True, "result": "unavailable"}
        if self._tick_count % self._tracker_feed_refresh_every_ticks != 0:
            return {
                "enabled": True,
                "result": "skipped",
                "reason": "waiting_for_refresh_tick",
                "every_ticks": self._tracker_feed_refresh_every_ticks,
                "tick_count": self._tick_count,
            }
        try:
            result = self._tracker_intel.refresh_feed_cache()
            self._tracker_feed_last_run = datetime.now(UTC)
            self._tracker_feed_last_result = result.get("last_refresh_result", "success")
            self._tracker_feed_last_error = result.get("last_error")
            self._audit.log("automation.tracker_feed_refresh", result)
            return {"enabled": True, **result}
        except Exception as exc:  # noqa: BLE001
            self._tracker_feed_last_run = datetime.now(UTC)
            self._tracker_feed_last_result = "failed"
            self._tracker_feed_last_error = str(exc)
            self._audit.log("automation.tracker_feed_refresh_error", {"error": str(exc)})
            return {"enabled": True, "result": "failed", "error": str(exc)}

    def _maybe_refresh_malware_feeds(self) -> dict[str, Any]:
        if not self._malware_feed_refresh_enabled:
            return {"enabled": False}
        if self._malware_scanner is None:
            return {"enabled": True, "result": "unavailable"}
        if self._tick_count % self._malware_feed_refresh_every_ticks != 0:
            return {
                "enabled": True,
                "result": "skipped",
                "reason": "waiting_for_refresh_tick",
                "every_ticks": self._malware_feed_refresh_every_ticks,
                "tick_count": self._tick_count,
            }
        try:
            result = self._malware_scanner.refresh_feed_cache()
            self._malware_feed_last_run = datetime.now(UTC)
            self._malware_feed_last_result = result.get("last_refresh_result", "success")
            self._malware_feed_last_error = result.get("last_error")
            self._audit.log("automation.malware_feed_refresh", result)
            return {"enabled": True, **result}
        except Exception as exc:  # noqa: BLE001
            self._malware_feed_last_run = datetime.now(UTC)
            self._malware_feed_last_result = "failed"
            self._malware_feed_last_error = str(exc)
            self._audit.log("automation.malware_feed_refresh_error", {"error": str(exc)})
            return {"enabled": True, "result": "failed", "error": str(exc)}

    def _maybe_refresh_malware_rule_feeds(self) -> dict[str, Any]:
        if not self._malware_rule_feed_refresh_enabled:
            return {"enabled": False}
        if self._malware_scanner is None:
            return {"enabled": True, "result": "unavailable"}
        if self._tick_count % self._malware_rule_feed_refresh_every_ticks != 0:
            return {
                "enabled": True,
                "result": "skipped",
                "reason": "waiting_for_refresh_tick",
                "every_ticks": self._malware_rule_feed_refresh_every_ticks,
                "tick_count": self._tick_count,
            }
        try:
            result = self._malware_scanner.refresh_rule_feed_cache()
            self._malware_rule_feed_last_run = datetime.now(UTC)
            self._malware_rule_feed_last_result = result.get("last_refresh_result", "success")
            self._malware_rule_feed_last_error = result.get("last_error")
            self._audit.log("automation.malware_rule_feed_refresh", result)
            return {"enabled": True, **result}
        except Exception as exc:  # noqa: BLE001
            self._malware_rule_feed_last_run = datetime.now(UTC)
            self._malware_rule_feed_last_result = "failed"
            self._malware_rule_feed_last_error = str(exc)
            self._audit.log("automation.malware_rule_feed_refresh_error", {"error": str(exc)})
            return {"enabled": True, "result": "failed", "error": str(exc)}

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict:
        return {
            "running": self.running,
            "last_run": self._last_run.isoformat() if self._last_run else None,
            "error_count": self._errors,
            "interval_seconds": self._interval,
            "tick_count": self._tick_count,
            "tracker_feed_refresh": {
                "enabled": self._tracker_feed_refresh_enabled,
                "every_ticks": self._tracker_feed_refresh_every_ticks,
                "last_run": self._tracker_feed_last_run.isoformat() if self._tracker_feed_last_run else None,
                "last_result": self._tracker_feed_last_result,
                "last_error": self._tracker_feed_last_error,
            },
            "malware_feed_refresh": {
                "enabled": self._malware_feed_refresh_enabled,
                "every_ticks": self._malware_feed_refresh_every_ticks,
                "last_run": self._malware_feed_last_run.isoformat() if self._malware_feed_last_run else None,
                "last_result": self._malware_feed_last_result,
                "last_error": self._malware_feed_last_error,
            },
            "malware_rule_feed_refresh": {
                "enabled": self._malware_rule_feed_refresh_enabled,
                "every_ticks": self._malware_rule_feed_refresh_every_ticks,
                "last_run": self._malware_rule_feed_last_run.isoformat() if self._malware_rule_feed_last_run else None,
                "last_result": self._malware_rule_feed_last_result,
                "last_error": self._malware_rule_feed_last_error,
            },
        }


def run_forever(supervisor: AutomationSupervisor) -> None:
    supervisor.start()

    def _handle(sig, frame):  # noqa: ARG001
        supervisor.stop()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    while supervisor.running:
        time.sleep(1)
