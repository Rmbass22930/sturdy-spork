"""Dashboard view-state client abstractions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Protocol, cast

import httpx

from .config import settings
from .models import SocDashboardViewStateUpdate


class DashboardViewStateClient(Protocol):
    def read(self) -> dict[str, object]: ...

    def write(self, payload: SocDashboardViewStateUpdate) -> dict[str, object]: ...


def _normalize_view_state(payload: Mapping[str, Any]) -> dict[str, object]:
    hunt_cluster_mode = str(payload.get("hunt_cluster_mode") or "").strip()
    if hunt_cluster_mode not in {"remote_ip", "device_id", "process_guid"}:
        hunt_cluster_mode = "remote_ip"
    hunt_cluster_action = str(payload.get("hunt_cluster_action") or "").strip()
    if hunt_cluster_action not in {"events", "existing_case", "case", "details"}:
        hunt_cluster_action = "events"
    return {
        "operational_reason_filter": str(payload.get("operational_reason_filter") or "").strip() or None,
        "hunt_cluster_mode": hunt_cluster_mode,
        "hunt_cluster_value": str(payload.get("hunt_cluster_value") or "").strip() or None,
        "hunt_cluster_key": str(payload.get("hunt_cluster_key") or "").strip() or None,
        "hunt_cluster_action": hunt_cluster_action,
    }


class ManagerDashboardViewStateClient:
    def __init__(self, manager: Any) -> None:
        self._manager = manager

    def read(self) -> dict[str, object]:
        dashboard = cast(dict[str, Any], self._manager.dashboard())
        return _normalize_view_state(cast(dict[str, Any], dashboard.get("view_state") or {}))

    def write(self, payload: SocDashboardViewStateUpdate) -> dict[str, object]:
        return cast(dict[str, object], self._manager.update_dashboard_view_state(payload))


class FileDashboardViewStateClient:
    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path or settings.soc_dashboard_view_state_path)

    def read(self) -> dict[str, object]:
        if not self._path.exists():
            return {}
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict):
            return {}
        return _normalize_view_state(cast(dict[str, Any], payload))

    def write(self, payload: SocDashboardViewStateUpdate) -> dict[str, object]:
        normalized = _normalize_view_state(payload.model_dump(mode="json"))
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(normalized, indent=2, sort_keys=True), encoding="utf-8")
        return normalized


class HttpDashboardViewStateClient:
    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str | None = None,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._bearer_token = bearer_token
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        if not self._bearer_token:
            return {}
        return {"Authorization": f"Bearer {self._bearer_token}"}

    def read(self) -> dict[str, object]:
        with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
            response = client.get(f"{self._base_url}/soc/dashboard", headers=self._headers())
            response.raise_for_status()
            payload = cast(dict[str, Any], response.json())
        return _normalize_view_state(cast(dict[str, Any], payload.get("view_state") or {}))

    def write(self, payload: SocDashboardViewStateUpdate) -> dict[str, object]:
        with httpx.Client(timeout=self._timeout_seconds, transport=self._transport) as client:
            response = client.post(
                f"{self._base_url}/soc/dashboard/view-state",
                json=payload.model_dump(mode="json"),
                headers=self._headers(),
            )
            response.raise_for_status()
            result = cast(dict[str, Any], response.json())
        return _normalize_view_state(cast(dict[str, Any], result.get("view_state") or {}))


def build_dashboard_view_state_client(
    *,
    manager: Any | None = None,
    base_url: str | None = None,
    bearer_token: str | None = None,
    path: str | Path | None = None,
    timeout_seconds: float = 5.0,
    transport: httpx.BaseTransport | None = None,
) -> DashboardViewStateClient:
    if manager is not None and callable(getattr(manager, "dashboard", None)) and callable(
        getattr(manager, "update_dashboard_view_state", None)
    ):
        return ManagerDashboardViewStateClient(manager)
    if base_url:
        return HttpDashboardViewStateClient(
            base_url=base_url,
            bearer_token=bearer_token,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )
    return FileDashboardViewStateClient(path=path)
