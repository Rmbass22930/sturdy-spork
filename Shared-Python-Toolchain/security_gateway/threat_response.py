"""Adaptive threat response helpers that rotate secrets without downtime."""
from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Dict, Optional

from .alerts import AlertEvent, AlertLevel, AlertManager
from .audit import AuditLogger
from .config import settings
from .pam import VaultClient


class ThreatResponseCoordinator:
    """Coordinates emergency key rotations when high-risk events are detected."""

    def __init__(
        self,
        vault: VaultClient,
        audit_logger: AuditLogger,
        alert_manager: AlertManager,
        *,
        cooldown_seconds: Optional[float] = None,
        enabled: Optional[bool] = None,
        background: bool = True,
    ) -> None:
        self._vault = vault
        self._audit = audit_logger
        self._alerts = alert_manager
        self._cooldown = cooldown_seconds if cooldown_seconds is not None else settings.threat_rotation_cooldown_seconds
        self._enabled = settings.threat_rotation_enabled if enabled is None else enabled
        self._background = background
        self._lock = threading.Lock()
        self._last_trigger: Optional[datetime] = None

    def trigger_rotation(self, source: str, severity: float, metadata: Optional[Dict[str, float]] = None) -> bool:
        """Request an out-of-band rotation. Returns True if a rotation was started."""
        if not self._enabled:
            return False

        now = datetime.now(UTC)
        with self._lock:
            if self._last_trigger and (now - self._last_trigger).total_seconds() < self._cooldown:
                self._audit.log(
                    "threat.rotation.skip",
                    {
                        "source": source,
                        "severity": severity,
                        "cooldown_seconds": self._cooldown,
                        "metadata": metadata or {},
                    },
                )
                return False
            self._last_trigger = now

        payload = {"source": source, "severity": severity, "metadata": metadata or {}}
        if self._background:
            thread = threading.Thread(target=self._rotate, args=(payload,), name="threat-rotation", daemon=True)
            thread.start()
        else:
            self._rotate(payload)
        return True

    def _rotate(self, payload: Dict[str, object]) -> None:
        self._audit.log("threat.rotation.start", payload)
        try:
            self._vault.force_rotate()
            metrics = self._vault.get_metrics()
        except Exception as exc:  # noqa: BLE001
            failure = {**payload, "error": str(exc)}
            self._audit.log("threat.rotation.failed", failure)
            self._alerts.emit(
                AlertEvent(
                    level=AlertLevel.critical,
                    title="Emergency key rotation failed",
                    message=str(exc),
                    context=failure,
                )
            )
            return

        result = {**payload, "current_key": metrics.get("current_key"), "rotation_count": metrics.get("rotation_count")}
        self._audit.log("threat.rotation.success", result)
        self._alerts.emit(
            AlertEvent(
                level=AlertLevel.warning,
                title="Keys rotated due to threat signal",
                message=f"Rotated to {metrics.get('current_key')}",
                context=result,
            )
        )

