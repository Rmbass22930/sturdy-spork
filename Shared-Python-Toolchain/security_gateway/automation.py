"""Automation supervisor for background tasks."""
from __future__ import annotations

import signal
import threading
import time
from datetime import UTC, datetime
from typing import Any, Callable, Optional

from .alerts import AlertEvent, AlertLevel, AlertManager
from .audit import AuditLogger
from .endpoint import MalwareScanner
from .host_monitor import HostMonitor
from .ip_controls import IPBlocklistManager
from .network_monitor import NetworkMonitor
from .packet_monitor import PacketMonitor
from .pam import VaultClient
from .stream_monitor import StreamArtifactMonitor
from .tracker_intel import TrackerIntel
from .tor import OutboundProxy
from .config import settings


class AutomationSupervisor:
    def __init__(
        self,
        vault: VaultClient,
        proxy: OutboundProxy,
        audit_logger: AuditLogger,
        alert_manager: AlertManager,
        ip_blocklist: IPBlocklistManager | None = None,
        tracker_intel: TrackerIntel | None = None,
        malware_scanner: MalwareScanner | None = None,
        interval_seconds: float = 300.0,
        tracker_feed_refresh_enabled: bool = False,
        tracker_feed_refresh_every_ticks: int = 12,
        malware_feed_refresh_enabled: bool = False,
        malware_feed_refresh_every_ticks: int = 12,
        malware_rule_feed_refresh_enabled: bool = False,
        malware_rule_feed_refresh_every_ticks: int = 12,
        host_monitor: HostMonitor | None = None,
        host_monitor_enabled: bool = False,
        host_monitor_every_ticks: int = 1,
        host_monitor_callback: Callable[[dict[str, Any]], None] | None = None,
        network_monitor: NetworkMonitor | None = None,
        network_monitor_enabled: bool = False,
        network_monitor_every_ticks: int = 1,
        network_monitor_callback: Callable[[dict[str, Any]], None] | None = None,
        packet_monitor: PacketMonitor | None = None,
        packet_monitor_enabled: bool = False,
        packet_monitor_every_ticks: int = 1,
        packet_monitor_callback: Callable[[dict[str, Any]], None] | None = None,
        stream_monitor: StreamArtifactMonitor | None = None,
        stream_monitor_enabled: bool = False,
        stream_monitor_every_ticks: int = 1,
        stream_monitor_callback: Callable[[dict[str, Any]], None] | None = None,
        operational_callback: Callable[[], dict[str, Any]] | None = None,
    ):
        self._vault = vault
        self._proxy = proxy
        self._audit = audit_logger
        self._alerts = alert_manager
        self._ip_blocklist = ip_blocklist
        self._tracker_intel = tracker_intel
        self._malware_scanner = malware_scanner
        self._interval = interval_seconds
        self._tracker_feed_refresh_enabled = tracker_feed_refresh_enabled
        self._tracker_feed_refresh_every_ticks = max(1, tracker_feed_refresh_every_ticks)
        self._malware_feed_refresh_enabled = malware_feed_refresh_enabled
        self._malware_feed_refresh_every_ticks = max(1, malware_feed_refresh_every_ticks)
        self._malware_rule_feed_refresh_enabled = malware_rule_feed_refresh_enabled
        self._malware_rule_feed_refresh_every_ticks = max(1, malware_rule_feed_refresh_every_ticks)
        self._host_monitor = host_monitor
        self._host_monitor_enabled = host_monitor_enabled
        self._host_monitor_every_ticks = max(1, host_monitor_every_ticks)
        self._host_monitor_callback = host_monitor_callback
        self._network_monitor = network_monitor
        self._network_monitor_enabled = network_monitor_enabled
        self._network_monitor_every_ticks = max(1, network_monitor_every_ticks)
        self._network_monitor_callback = network_monitor_callback
        self._packet_monitor = packet_monitor
        self._packet_monitor_enabled = packet_monitor_enabled
        self._packet_monitor_every_ticks = max(1, packet_monitor_every_ticks)
        self._packet_monitor_callback = packet_monitor_callback
        self._stream_monitor = stream_monitor
        self._stream_monitor_enabled = stream_monitor_enabled
        self._stream_monitor_every_ticks = max(1, stream_monitor_every_ticks)
        self._stream_monitor_callback = stream_monitor_callback
        self._operational_callback = operational_callback
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
        self._host_monitor_last_run: Optional[datetime] = None
        self._host_monitor_last_result: Optional[str] = None
        self._host_monitor_last_error: Optional[str] = None
        self._network_monitor_last_run: Optional[datetime] = None
        self._network_monitor_last_result: Optional[str] = None
        self._network_monitor_last_error: Optional[str] = None
        self._packet_monitor_last_run: Optional[datetime] = None
        self._packet_monitor_last_result: Optional[str] = None
        self._packet_monitor_last_error: Optional[str] = None
        self._stream_monitor_last_run: Optional[datetime] = None
        self._stream_monitor_last_result: Optional[str] = None
        self._stream_monitor_last_error: Optional[str] = None

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
            host_monitor = self._maybe_run_host_monitor()
            network_monitor = self._maybe_run_network_monitor()
            stream_monitor = self._maybe_run_stream_monitor()
            packet_monitor = self._maybe_run_packet_monitor(
                force_run=self._stream_activity_detected(stream_monitor)
            )
            operational = self._maybe_emit_operational_notifications()
            self._audit.log(
                "automation.tick",
                {
                    "vault": metrics,
                    "proxy": health,
                    "tracker_feeds": tracker_feed,
                    "malware_feeds": malware_feed,
                    "malware_rule_feeds": malware_rule_feed,
                    "host_monitor": host_monitor,
                    "network_monitor": network_monitor,
                    "packet_monitor": packet_monitor,
                    "stream_monitor": stream_monitor,
                    "operational": operational,
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

    def _maybe_run_host_monitor(self) -> dict[str, Any]:
        if not self._host_monitor_enabled:
            return {"enabled": False}
        if self._host_monitor is None:
            return {"enabled": True, "result": "unavailable"}
        if self._tick_count % self._host_monitor_every_ticks != 0:
            return {
                "enabled": True,
                "result": "skipped",
                "reason": "waiting_for_refresh_tick",
                "every_ticks": self._host_monitor_every_ticks,
                "tick_count": self._tick_count,
            }
        try:
            result = self._host_monitor.run_check()
            self._host_monitor_last_run = datetime.now(UTC)
            self._host_monitor_last_result = "success"
            self._host_monitor_last_error = None
            for finding in result.get("emitted_findings", []):
                self._emit_host_monitor_finding(finding)
            for finding in result.get("resolved_findings", []):
                self._emit_host_monitor_finding(finding)
            self._audit.log("automation.host_monitor", result)
            return {
                "enabled": True,
                "result": "success",
                "active_findings": len(result.get("active_findings", [])),
                "new_findings": len(result.get("emitted_findings", [])),
                "resolved_findings": len(result.get("resolved_findings", [])),
            }
        except Exception as exc:  # noqa: BLE001
            self._host_monitor_last_run = datetime.now(UTC)
            self._host_monitor_last_result = "failed"
            self._host_monitor_last_error = str(exc)
            self._audit.log("automation.host_monitor_error", {"error": str(exc)})
            return {"enabled": True, "result": "failed", "error": str(exc)}

    def _emit_host_monitor_finding(self, finding: dict[str, Any]) -> None:
        severity = str(finding.get("severity", "medium")).casefold()
        resolved = bool(finding.get("resolved"))
        if resolved:
            level = AlertLevel.info
        elif severity == "critical":
            level = AlertLevel.critical
        elif severity in {"high", "medium"}:
            level = AlertLevel.warning
        else:
            level = AlertLevel.info
        self._alerts.emit(
            AlertEvent(
                level=level,
                title=str(finding.get("title", "Host monitor finding")),
                message=str(finding.get("summary", "")),
                context={"source": "host_monitor", "details": finding.get("details", {})},
            )
        )
        if self._host_monitor_callback is not None:
            self._host_monitor_callback(finding)

    def _maybe_run_network_monitor(self) -> dict[str, Any]:
        if not self._network_monitor_enabled:
            return {"enabled": False}
        if self._network_monitor is None:
            return {"enabled": True, "result": "unavailable"}
        if self._tick_count % self._network_monitor_every_ticks != 0:
            return {
                "enabled": True,
                "result": "skipped",
                "reason": "waiting_for_refresh_tick",
                "every_ticks": self._network_monitor_every_ticks,
                "tick_count": self._tick_count,
            }
        try:
            result = self._network_monitor.run_check()
            self._network_monitor_last_run = datetime.now(UTC)
            self._network_monitor_last_result = "success"
            self._network_monitor_last_error = None
            for finding in result.get("emitted_findings", []):
                self._emit_network_monitor_finding(finding)
            for finding in result.get("resolved_findings", []):
                self._emit_network_monitor_finding(finding)
            self._audit.log("automation.network_monitor", result)
            return {
                "enabled": True,
                "result": "success",
                "active_findings": len(result.get("active_findings", [])),
                "new_findings": len(result.get("emitted_findings", [])),
                "resolved_findings": len(result.get("resolved_findings", [])),
            }
        except Exception as exc:  # noqa: BLE001
            self._network_monitor_last_run = datetime.now(UTC)
            self._network_monitor_last_result = "failed"
            self._network_monitor_last_error = str(exc)
            self._audit.log("automation.network_monitor_error", {"error": str(exc)})
            return {"enabled": True, "result": "failed", "error": str(exc)}

    def _emit_network_monitor_finding(self, finding: dict[str, Any]) -> None:
        self._maybe_auto_block_network_finding(finding)
        severity = str(finding.get("severity", "medium")).casefold()
        resolved = bool(finding.get("resolved"))
        if resolved:
            level = AlertLevel.info
        elif severity == "critical":
            level = AlertLevel.critical
        elif severity in {"high", "medium"}:
            level = AlertLevel.warning
        else:
            level = AlertLevel.info
        self._alerts.emit(
            AlertEvent(
                level=level,
                title=str(finding.get("title", "Network monitor finding")),
                message=str(finding.get("summary", "")),
                context={"source": "network_monitor", "details": finding.get("details", {})},
            )
        )
        if self._network_monitor_callback is not None:
            self._network_monitor_callback(finding)

    def _maybe_auto_block_network_finding(self, finding: dict[str, Any]) -> None:
        if self._ip_blocklist is None or not settings.auto_block_enabled or bool(finding.get("resolved")):
            return
        details = finding.get("details")
        if not isinstance(details, dict):
            return
        if str(details.get("finding_type")) != "dos_candidate":
            return
        remote_ip = details.get("remote_ip")
        if not isinstance(remote_ip, str) or not remote_ip:
            return
        if self._ip_blocklist.is_blocked(remote_ip):
            details["block_status"] = "already_blocked"
            return
        hit_count = int(details.get("hit_count") or 0)
        local_ports = details.get("local_ports")
        blocked_entry = self._ip_blocklist.block(
            remote_ip,
            reason=(
                "Automatic block after abnormal inbound connection burst "
                f"({hit_count} hits against local ports {local_ports or []})."
            ),
            blocked_by="network_monitor",
            duration_minutes=settings.auto_block_duration_minutes,
        )
        details["block_status"] = "blocked"
        details["block_reason"] = blocked_entry.reason
        details["block_expires_at"] = blocked_entry.expires_at

    def _maybe_run_packet_monitor(self, *, force_run: bool = False) -> dict[str, Any]:
        if not self._packet_monitor_enabled:
            return {"enabled": False}
        if self._packet_monitor is None:
            return {"enabled": True, "result": "unavailable"}
        if not force_run and self._should_wait_for_tick(
            tick_count=self._tick_count,
            every_ticks=self._packet_monitor_every_ticks,
            last_run=self._packet_monitor_last_run,
        ):
            return {
                "enabled": True,
                "result": "skipped",
                "reason": "waiting_for_refresh_tick",
                "every_ticks": self._packet_monitor_every_ticks,
                "tick_count": self._tick_count,
            }
        try:
            result = self._packet_monitor.run_check()
            self._packet_monitor_last_run = datetime.now(UTC)
            self._packet_monitor_last_result = str(result["snapshot"].get("capture_status", "success"))
            packet_error = result["snapshot"].get("error")
            self._packet_monitor_last_error = str(packet_error) if packet_error else None
            for finding in result.get("emitted_findings", []):
                self._emit_packet_monitor_finding(finding)
            for finding in result.get("resolved_findings", []):
                self._emit_packet_monitor_finding(finding)
            self._audit.log("automation.packet_monitor", result)
            return {
                "enabled": True,
                "result": self._packet_monitor_last_result,
                "active_findings": len(result.get("active_findings", [])),
                "new_findings": len(result.get("emitted_findings", [])),
                "resolved_findings": len(result.get("resolved_findings", [])),
                "error": self._packet_monitor_last_error,
            }
        except Exception as exc:  # noqa: BLE001
            self._packet_monitor_last_run = datetime.now(UTC)
            self._packet_monitor_last_result = "failed"
            self._packet_monitor_last_error = str(exc)
            self._audit.log("automation.packet_monitor_error", {"error": str(exc)})
            return {"enabled": True, "result": "failed", "error": str(exc)}

    def _emit_packet_monitor_finding(self, finding: dict[str, Any]) -> None:
        severity = str(finding.get("severity", "medium")).casefold()
        resolved = bool(finding.get("resolved"))
        if resolved:
            level = AlertLevel.info
        elif severity == "critical":
            level = AlertLevel.critical
        elif severity in {"high", "medium"}:
            level = AlertLevel.warning
        else:
            level = AlertLevel.info
        self._alerts.emit(
            AlertEvent(
                level=level,
                title=str(finding.get("title", "Packet monitor finding")),
                message=str(finding.get("summary", "")),
                context={"source": "packet_monitor", "details": finding.get("details", {})},
            )
        )
        if self._packet_monitor_callback is not None:
            self._packet_monitor_callback(finding)

    def _maybe_run_stream_monitor(self) -> dict[str, Any]:
        if not self._stream_monitor_enabled:
            return {"enabled": False}
        if self._stream_monitor is None:
            return {"enabled": True, "result": "unavailable"}
        if self._should_wait_for_tick(
            tick_count=self._tick_count,
            every_ticks=self._stream_monitor_every_ticks,
            last_run=self._stream_monitor_last_run,
        ):
            return {
                "enabled": True,
                "result": "skipped",
                "reason": "waiting_for_refresh_tick",
                "every_ticks": self._stream_monitor_every_ticks,
                "tick_count": self._tick_count,
            }
        try:
            result = self._stream_monitor.run_check()
            self._stream_monitor_last_run = datetime.now(UTC)
            self._stream_monitor_last_result = "success"
            self._stream_monitor_last_error = None
            for finding in result.get("emitted_findings", []):
                self._emit_stream_monitor_finding(finding)
            for finding in result.get("resolved_findings", []):
                self._emit_stream_monitor_finding(finding)
            self._audit.log("automation.stream_monitor", result)
            return {
                "enabled": True,
                "result": "success",
                "active_findings": len(result.get("active_findings", [])),
                "new_findings": len(result.get("emitted_findings", [])),
                "resolved_findings": len(result.get("resolved_findings", [])),
            }
        except Exception as exc:  # noqa: BLE001
            self._stream_monitor_last_run = datetime.now(UTC)
            self._stream_monitor_last_result = "failed"
            self._stream_monitor_last_error = str(exc)
            self._audit.log("automation.stream_monitor_error", {"error": str(exc)})
            return {"enabled": True, "result": "failed", "error": str(exc)}

    def _maybe_emit_operational_notifications(self) -> dict[str, Any]:
        if self._operational_callback is None or not settings.soc_operational_notifications_enabled:
            return {"enabled": False}
        try:
            return self._operational_callback()
        except Exception as exc:  # noqa: BLE001
            self._audit.log("automation.operational_notification_error", {"error": str(exc)})
            return {"enabled": True, "result": "failed", "error": str(exc)}

    def _emit_stream_monitor_finding(self, finding: dict[str, Any]) -> None:
        severity = str(finding.get("severity", "medium")).casefold()
        resolved = bool(finding.get("resolved"))
        if resolved:
            level = AlertLevel.info
        elif severity == "critical":
            level = AlertLevel.critical
        elif severity in {"high", "medium"}:
            level = AlertLevel.warning
        else:
            level = AlertLevel.info
        self._alerts.emit(
            AlertEvent(
                level=level,
                title=str(finding.get("title", "Stream monitor finding")),
                message=str(finding.get("summary", "")),
                context={"source": "stream_monitor", "details": finding.get("details", {})},
            )
        )
        if self._stream_monitor_callback is not None:
            self._stream_monitor_callback(finding)

    @staticmethod
    def _should_wait_for_tick(*, tick_count: int, every_ticks: int, last_run: Optional[datetime]) -> bool:
        if last_run is None:
            return False
        return tick_count % every_ticks != 0

    @staticmethod
    def _stream_activity_detected(stream_result: dict[str, Any]) -> bool:
        snapshot = stream_result.get("snapshot")
        if not isinstance(snapshot, dict):
            return False
        scanned_artifacts = snapshot.get("scanned_artifacts")
        return isinstance(scanned_artifacts, list) and len(scanned_artifacts) > 0

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
            "host_monitor": {
                "enabled": self._host_monitor_enabled,
                "every_ticks": self._host_monitor_every_ticks,
                "last_run": self._host_monitor_last_run.isoformat() if self._host_monitor_last_run else None,
                "last_result": self._host_monitor_last_result,
                "last_error": self._host_monitor_last_error,
            },
            "network_monitor": {
                "enabled": self._network_monitor_enabled,
                "every_ticks": self._network_monitor_every_ticks,
                "last_run": self._network_monitor_last_run.isoformat() if self._network_monitor_last_run else None,
                "last_result": self._network_monitor_last_result,
                "last_error": self._network_monitor_last_error,
            },
            "packet_monitor": {
                "enabled": self._packet_monitor_enabled,
                "every_ticks": self._packet_monitor_every_ticks,
                "last_run": self._packet_monitor_last_run.isoformat() if self._packet_monitor_last_run else None,
                "last_result": self._packet_monitor_last_result,
                "last_error": self._packet_monitor_last_error,
            },
            "stream_monitor": {
                "enabled": self._stream_monitor_enabled,
                "every_ticks": self._stream_monitor_every_ticks,
                "last_run": self._stream_monitor_last_run.isoformat() if self._stream_monitor_last_run else None,
                "last_result": self._stream_monitor_last_result,
                "last_error": self._stream_monitor_last_error,
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
