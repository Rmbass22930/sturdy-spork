"""Platform profile primitives for Security Gateway."""
from __future__ import annotations

import json
import socket
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, cast
from urllib.parse import urljoin

import httpx

from .config import settings


_AUTOMATION_SERVICE_LABELS: dict[str, tuple[str, str]] = {
    "tracker_feed_refresh": ("tracker_feed_refresh", "automation_tracker_feed_refresh_enabled"),
    "malware_feed_refresh": ("malware_feed_refresh", "automation_malware_feed_refresh_enabled"),
    "malware_rule_feed_refresh": ("malware_rule_feed_refresh", "automation_malware_rule_feed_refresh_enabled"),
    "host_monitor": ("host_monitor", "host_monitor_enabled"),
    "network_monitor": ("network_monitor", "network_monitor_enabled"),
    "packet_monitor": ("packet_monitor", "packet_monitor_enabled"),
    "stream_monitor": ("stream_monitor", "stream_monitor_enabled"),
}

_ROLE_SERVICE_DEFAULTS: dict[str, dict[str, bool]] = {
    "standalone": {
        "automation": True,
        "tracker_intel": True,
        "malware_scanner": True,
        "tracker_feed_refresh": True,
        "malware_feed_refresh": True,
        "malware_rule_feed_refresh": True,
        "host_monitor": True,
        "network_monitor": True,
        "packet_monitor": True,
        "stream_monitor": True,
    },
    "manager": {
        "automation": True,
        "tracker_intel": True,
        "malware_scanner": True,
        "tracker_feed_refresh": True,
        "malware_feed_refresh": True,
        "malware_rule_feed_refresh": True,
        "host_monitor": True,
        "network_monitor": False,
        "packet_monitor": False,
        "stream_monitor": True,
    },
    "sensor": {
        "automation": True,
        "tracker_intel": False,
        "malware_scanner": False,
        "tracker_feed_refresh": False,
        "malware_feed_refresh": False,
        "malware_rule_feed_refresh": False,
        "host_monitor": False,
        "network_monitor": True,
        "packet_monitor": True,
        "stream_monitor": True,
    },
    "search": {
        "automation": True,
        "tracker_intel": True,
        "malware_scanner": True,
        "tracker_feed_refresh": True,
        "malware_feed_refresh": True,
        "malware_rule_feed_refresh": True,
        "host_monitor": False,
        "network_monitor": False,
        "packet_monitor": False,
        "stream_monitor": False,
    },
}


def _coerce_mapping(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(payload) if payload is not None else {}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def normalize_platform_node_role(node_role: str | None = None) -> str:
    candidate = (node_role or settings.platform_node_role or "standalone").strip().casefold()
    return candidate if candidate in _ROLE_SERVICE_DEFAULTS else "standalone"


def build_platform_role_profile(*, node_role: str | None = None) -> dict[str, Any]:
    normalized_role = normalize_platform_node_role(node_role)
    services = dict(_ROLE_SERVICE_DEFAULTS[normalized_role])
    return {
        "node_role": normalized_role,
        "enabled_services": [name for name, enabled in services.items() if enabled],
        "disabled_services": [name for name, enabled in services.items() if not enabled],
        "services": services,
    }


def role_managed_service_enabled(service_name: str, *, configured: bool, node_role: str | None = None) -> bool:
    role_profile = build_platform_role_profile(node_role=node_role)
    services = cast(dict[str, bool], role_profile["services"])
    return configured and bool(services.get(service_name, False))


def _service_entry(
    *,
    name: str,
    enabled: bool,
    status: str,
    healthy: bool,
    last_run: str | None = None,
    last_result: str | None = None,
    last_error: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": name,
        "enabled": enabled,
        "status": status,
        "healthy": healthy,
    }
    if last_run is not None:
        entry["last_run"] = last_run
    if last_result is not None:
        entry["last_result"] = last_result
    if last_error is not None:
        entry["last_error"] = last_error
    if details:
        entry["details"] = dict(details)
    return entry


def _automation_service_entry(name: str, section: Mapping[str, Any] | None, *, enabled_by_default: bool) -> dict[str, Any]:
    payload = _coerce_mapping(section)
    enabled = bool(payload.get("enabled", enabled_by_default))
    if not enabled:
        return _service_entry(name=name, enabled=False, status="disabled", healthy=True)

    last_result = payload.get("last_result")
    last_error = payload.get("last_error")
    if isinstance(last_error, str) and not last_error.strip():
        last_error = None
    last_result_text = str(last_result) if last_result is not None else None
    status = "pending"
    healthy = True
    if last_error or last_result_text in {"failed", "permission_denied", "unavailable"}:
        status = "degraded"
        healthy = False
    elif last_result_text in {"success", "skipped"}:
        status = "healthy"
    elif last_result_text:
        status = last_result_text

    details: dict[str, Any] = {}
    every_ticks = payload.get("every_ticks")
    if every_ticks is not None:
        details["every_ticks"] = every_ticks
    return _service_entry(
        name=name,
        enabled=True,
        status=status,
        healthy=healthy,
        last_run=payload.get("last_run"),
        last_result=last_result_text,
        last_error=str(last_error) if last_error is not None else None,
        details=details,
    )


def _component_health_entry(
    *,
    name: str,
    enabled: bool,
    payload: Mapping[str, Any] | None,
    warning_key: str = "warnings",
) -> dict[str, Any]:
    if not enabled:
        return _service_entry(name=name, enabled=False, status="disabled", healthy=True)
    status_payload = _coerce_mapping(payload)
    warnings = status_payload.get(warning_key)
    warning_count = len(warnings) if isinstance(warnings, list) else 0
    healthy = bool(status_payload.get("healthy", warning_count == 0))
    status = "healthy" if healthy else "degraded"
    details = {}
    if warning_count:
        details["warning_count"] = warning_count
    if "status" in status_payload:
        details["component_status"] = status_payload["status"]
    return _service_entry(name=name, enabled=True, status=status, healthy=healthy, details=details)


def read_platform_node_registry(path: str | Path | None = None) -> list[dict[str, Any]]:
    target = Path(path or settings.platform_node_registry_path)
    if not target.exists():
        return []
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    records: list[dict[str, Any]] = []
    for item in payload:
        if isinstance(item, dict) and item.get("node_name"):
            records.append(dict(item))
    return records


def write_platform_node_registry(records: Sequence[Mapping[str, Any]], path: str | Path | None = None) -> None:
    target = Path(path or settings.platform_node_registry_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = [dict(item) for item in records]
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def read_local_platform_action_state(path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path or settings.platform_local_action_state_path)
    if not target.exists():
        return {}
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return dict(payload) if isinstance(payload, dict) else {}


def write_local_platform_action_state(payload: Mapping[str, Any], path: str | Path | None = None) -> None:
    target = Path(path or settings.platform_local_action_state_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dict(payload), indent=2, sort_keys=True), encoding="utf-8")


def apply_local_platform_action(
    action_payload: Mapping[str, Any],
    *,
    path: str | Path | None = None,
    available_services: Sequence[str] | None = None,
) -> dict[str, Any]:
    state = read_local_platform_action_state(path)
    action = str(action_payload.get("action") or "").strip().casefold()
    available = {str(item).strip() for item in (available_services or []) if str(item).strip()}
    now = _utc_now().isoformat()
    if action == "refresh":
        state["last_refresh_local_at"] = now
        write_local_platform_action_state(state, path)
        return {
            "action": "refresh",
            "result": "success",
            "note": "local refresh cycle completed",
        }
    if action == "drain":
        requested = {
            str(item).strip()
            for item in cast(list[Any], action_payload.get("drain_services") or [])
            if str(item).strip()
        }
        effective = sorted((requested or available) & available)
        if not effective:
            state["drain_active"] = False
            state["drained_services"] = []
            state["last_drain_local_at"] = now
            write_local_platform_action_state(state, path)
            return {
                "action": "drain",
                "result": "failed",
                "note": "no local services matched drain request",
                "effective_services": [],
            }
        state["drain_active"] = True
        state["drained_services"] = effective
        state["last_drain_local_at"] = now
        write_local_platform_action_state(state, path)
        return {
            "action": "drain",
            "result": "success",
            "note": "drained services: " + ", ".join(effective),
            "effective_services": effective,
        }
    if action == "maintenance":
        requested = {
            str(item).strip()
            for item in cast(list[Any], action_payload.get("maintenance_services") or [])
            if str(item).strip()
        }
        effective = sorted((requested or available) & available)
        if requested and not effective:
            state["maintenance_active"] = False
            state["maintenance_services"] = []
            state["last_maintenance_local_at"] = now
            write_local_platform_action_state(state, path)
            return {
                "action": "maintenance",
                "result": "failed",
                "note": "no local services matched maintenance request",
                "effective_services": [],
            }
        state["maintenance_active"] = True
        state["maintenance_services"] = effective
        state["maintenance_until"] = action_payload.get("maintenance_until")
        state["maintenance_reason"] = action_payload.get("maintenance_reason")
        state["last_maintenance_local_at"] = now
        write_local_platform_action_state(state, path)
        return {
            "action": "maintenance",
            "result": "success",
            "note": (
                "maintenance applied to services: " + ", ".join(effective)
                if effective
                else "maintenance applied with no service-specific restrictions"
            ),
            "effective_services": effective,
        }
    return {
        "action": action,
        "result": "unsupported",
        "note": f"unsupported local platform action: {action}",
    }


def sync_local_platform_action_state(
    *,
    node_payload: Mapping[str, Any] | None,
    path: str | Path | None = None,
    available_services: Sequence[str] | None = None,
) -> dict[str, Any]:
    state = read_local_platform_action_state(path)
    drain_payload = cast(Mapping[str, Any] | None, cast(dict[str, Any], node_payload or {}).get("drain"))
    maintenance_payload = cast(Mapping[str, Any] | None, cast(dict[str, Any], node_payload or {}).get("maintenance"))
    available = {str(item).strip() for item in (available_services or []) if str(item).strip()}
    drain_active = bool(cast(dict[str, Any], drain_payload or {}).get("active"))
    requested = {
        str(item).strip()
        for item in cast(list[Any], cast(dict[str, Any], drain_payload or {}).get("drain_services") or [])
        if str(item).strip()
    }
    if drain_active:
        effective = sorted((requested or available) & available)
        state["drain_active"] = True
        state["drained_services"] = effective
    else:
        state["drain_active"] = False
        state["drained_services"] = []
    maintenance_active = bool(cast(dict[str, Any], maintenance_payload or {}).get("active"))
    maintenance_requested = {
        str(item).strip()
        for item in cast(list[Any], cast(dict[str, Any], maintenance_payload or {}).get("maintenance_services") or [])
        if str(item).strip()
    }
    if maintenance_active:
        effective_maintenance = sorted((maintenance_requested or available) & available)
        state["maintenance_active"] = True
        state["maintenance_services"] = effective_maintenance
        state["maintenance_until"] = cast(dict[str, Any], maintenance_payload or {}).get("maintenance_until")
        state["maintenance_reason"] = cast(dict[str, Any], maintenance_payload or {}).get("maintenance_reason")
    else:
        state["maintenance_active"] = False
        state["maintenance_services"] = []
        state["maintenance_until"] = None
        state["maintenance_reason"] = None
    write_local_platform_action_state(state, path)
    return state


def upsert_platform_node(
    node_payload: Mapping[str, Any],
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    node_name = str(node_payload.get("node_name") or "").strip()
    if not node_name:
        raise ValueError("node_name is required")
    deployment_mode = str(node_payload.get("deployment_mode") or settings.platform_deployment_mode)
    node_role = normalize_platform_node_role(str(node_payload.get("node_role") or None))
    service_health = _coerce_mapping(cast(Mapping[str, Any] | None, node_payload.get("service_health")))
    incoming_metadata = _coerce_mapping(cast(Mapping[str, Any] | None, node_payload.get("metadata")))
    records = read_platform_node_registry(path)
    existing_entry = next((item for item in records if str(item.get("node_name") or "") == node_name), None)
    metadata = _coerce_mapping(cast(Mapping[str, Any] | None, existing_entry.get("metadata") if existing_entry else None))
    metadata.update(incoming_metadata)
    last_seen_at = str(node_payload.get("last_seen_at") or _utc_now().isoformat())
    entry = {
        "node_name": node_name,
        "node_role": node_role,
        "deployment_mode": deployment_mode,
        "service_health": service_health,
        "metadata": metadata,
        "last_seen_at": last_seen_at,
    }
    updated_records = [item for item in records if str(item.get("node_name") or "") != node_name]
    updated_records.append(entry)
    updated_records.sort(key=lambda item: str(item.get("node_name") or "").casefold())
    write_platform_node_registry(updated_records, path)
    return entry


def update_platform_node_metadata(
    node_name: str,
    metadata_updates: Mapping[str, Any],
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    records = read_platform_node_registry(path)
    for index, item in enumerate(records):
        if str(item.get("node_name") or "") != node_name:
            continue
        metadata = _coerce_mapping(cast(Mapping[str, Any] | None, item.get("metadata")))
        metadata.update(dict(metadata_updates))
        updated = dict(item)
        updated["metadata"] = metadata
        updated["last_seen_at"] = str(item.get("last_seen_at") or _utc_now().isoformat())
        records[index] = updated
        write_platform_node_registry(records, path)
        return updated
    raise KeyError(f"Platform node not found: {node_name}")


def _read_platform_node_metadata(
    node_name: str,
    *,
    path: str | Path | None = None,
) -> dict[str, Any]:
    for item in read_platform_node_registry(path):
        if str(item.get("node_name") or "") == node_name:
            return _coerce_mapping(cast(Mapping[str, Any] | None, item.get("metadata")))
    raise KeyError(f"Platform node not found: {node_name}")


def _append_platform_node_action_history(
    node_name: str,
    *,
    action: str,
    transition: str,
    actor: str | None = None,
    note: str | None = None,
    result: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    metadata = _read_platform_node_metadata(node_name, path=path)
    history = [
        dict(item)
        for item in cast(list[Any], metadata.get("action_history") or [])
        if isinstance(item, Mapping)
    ]
    entry: dict[str, Any] = {
        "action": action,
        "transition": transition,
        "at": _utc_now().isoformat(),
    }
    if actor:
        entry["actor"] = actor
    if note:
        entry["note"] = note
    if result:
        entry["result"] = result
    history.append(entry)
    return update_platform_node_metadata(
        node_name,
        {"action_history": history[-50:]},
        path=path,
    )


def _recent_platform_node_action_history(
    metadata: Mapping[str, Any] | None,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    payload = _coerce_mapping(metadata)
    current = now or _utc_now()
    window_start = current - timedelta(hours=max(settings.soc_remote_node_action_history_window_hours, 0.0))
    recent_history: list[dict[str, Any]] = []
    for item in cast(list[Any], payload.get("action_history") or []):
        if not isinstance(item, Mapping):
            continue
        entry = dict(item)
        parsed_at = _parse_datetime(entry.get("at"))
        if parsed_at is None or parsed_at < window_start:
            continue
        recent_history.append(entry)
    return recent_history


def _platform_node_action_pressure(
    metadata: Mapping[str, Any] | None,
    *,
    refresh: Mapping[str, Any] | None = None,
    maintenance: Mapping[str, Any] | None = None,
    drain: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or _utc_now()
    recent_history = _recent_platform_node_action_history(metadata, now=current)
    failure_threshold = max(settings.soc_remote_node_action_failure_repeat_threshold, 1)
    retry_threshold = max(settings.soc_remote_node_action_retry_threshold, 1)
    stuck_threshold = max(settings.soc_remote_node_action_stuck_minutes, 0.0)

    failed_counts = {
        action: count
        for action, count in Counter(
            str(entry.get("action") or "").strip()
            for entry in recent_history
            if str(entry.get("transition") or "").strip().casefold() == "failed"
            and str(entry.get("action") or "").strip()
        ).items()
        if count >= failure_threshold
    }
    retry_counts = {
        action: count
        for action, count in Counter(
            str(entry.get("action") or "").strip()
            for entry in recent_history
            if str(entry.get("transition") or "").strip().casefold() == "retried"
            and str(entry.get("action") or "").strip()
        ).items()
        if count >= retry_threshold
    }

    stuck_actions: list[dict[str, Any]] = []
    for action_name, state in (
        ("refresh", _coerce_mapping(refresh)),
        ("maintenance", _coerce_mapping(maintenance)),
        ("drain", _coerce_mapping(drain)),
    ):
        status = str(state.get("status") or "").strip().casefold()
        if status not in {"requested", "acknowledged"}:
            continue
        started_at = _parse_datetime(state.get(f"{action_name}_acknowledged_at")) or _parse_datetime(
            state.get(f"{action_name}_requested_at")
        )
        if started_at is None:
            continue
        age_minutes = round((current - started_at).total_seconds() / 60.0, 1)
        if age_minutes < stuck_threshold:
            continue
        stuck_actions.append(
            {
                "action": action_name,
                "status": status,
                "age_minutes": age_minutes,
                "requested_at": state.get(f"{action_name}_requested_at"),
                "acknowledged_at": state.get(f"{action_name}_acknowledged_at"),
            }
        )
    stuck_actions.sort(key=lambda item: (-cast(float, item["age_minutes"]), str(item["action"])))
    return {
        "recent_history_count": len(recent_history),
        "history_window_hours": settings.soc_remote_node_action_history_window_hours,
        "repeated_failures": dict(sorted(failed_counts.items())),
        "retry_pressure": dict(sorted(retry_counts.items())),
        "stuck_actions": stuck_actions,
        "repeated_failure_active": bool(failed_counts),
        "retry_pressure_active": bool(retry_counts),
        "stuck_actions_active": bool(stuck_actions),
    }


def platform_node_suppression_state(
    metadata: Mapping[str, Any] | None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    payload = _coerce_mapping(metadata)
    suppressed_until = str(payload.get("suppressed_until") or "")
    parsed_until = _parse_datetime(suppressed_until)
    current = now or _utc_now()
    active = parsed_until is not None and parsed_until > current
    scoped_entries: list[dict[str, Any]] = []
    for item in cast(list[Any], payload.get("pressure_suppressions") or []):
        if not isinstance(item, Mapping):
            continue
        scope_until = str(item.get("suppressed_until") or "")
        parsed_scope_until = _parse_datetime(scope_until)
        scope_active = parsed_scope_until is not None and parsed_scope_until > current
        scopes = [str(scope) for scope in cast(list[Any], item.get("scopes") or []) if str(scope)]
        scoped_entries.append(
            {
                "active": scope_active,
                "scopes": scopes,
                "suppressed_until": scope_until or None,
                "suppressed_by": item.get("suppressed_by"),
                "suppression_reason": item.get("suppression_reason"),
            }
        )
    active_scopes = sorted(
        {
            scope
            for item in scoped_entries
            if bool(item.get("active"))
            for scope in cast(list[str], item.get("scopes") or [])
        }
    )
    return {
        "active": active or bool(active_scopes),
        "suppressed_until": suppressed_until or None,
        "suppressed_by": payload.get("suppressed_by"),
        "suppression_reason": payload.get("suppression_reason"),
        "scoped_entries": scoped_entries,
        "active_scopes": active_scopes,
    }


def suppress_platform_node(
    node_name: str,
    *,
    minutes: int,
    suppressed_by: str,
    reason: str | None = None,
    scopes: Sequence[str] | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    normalized_scopes = [str(scope).strip() for scope in (scopes or ["remote_node_health"]) if str(scope).strip()]
    until = (_utc_now() + timedelta(minutes=minutes)).isoformat()
    if normalized_scopes == ["remote_node_health"]:
        updates: dict[str, Any] = {
            "suppressed_at": _utc_now().isoformat(),
            "suppressed_until": until,
            "suppressed_by": suppressed_by,
        }
        if reason:
            updates["suppression_reason"] = reason
        return update_platform_node_metadata(node_name, updates, path=path)
    records = read_platform_node_registry(path)
    for index, item in enumerate(records):
        if str(item.get("node_name") or "") != node_name:
            continue
        metadata = _coerce_mapping(cast(Mapping[str, Any] | None, item.get("metadata")))
        scoped = [
            dict(candidate)
            for candidate in cast(list[Any], metadata.get("pressure_suppressions") or [])
            if isinstance(candidate, Mapping)
        ]
        scoped.append(
            {
                "suppressed_at": _utc_now().isoformat(),
                "suppressed_until": until,
                "suppressed_by": suppressed_by,
                "suppression_reason": reason,
                "scopes": normalized_scopes,
            }
        )
        metadata["pressure_suppressions"] = scoped
        updated = dict(item)
        updated["metadata"] = metadata
        records[index] = updated
        write_platform_node_registry(records, path)
        return updated
    raise KeyError(f"Platform node not found: {node_name}")


def clear_platform_node_suppression(
    node_name: str,
    *,
    cleared_by: str | None = None,
    scopes: Sequence[str] | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    normalized_scopes = {str(scope).strip() for scope in (scopes or []) if str(scope).strip()}
    if not normalized_scopes:
        updates: dict[str, Any] = {
            "suppressed_until": None,
            "suppressed_by": None,
            "suppression_reason": None,
            "pressure_suppressions": [],
            "suppression_cleared_at": _utc_now().isoformat(),
        }
        if cleared_by:
            updates["suppression_cleared_by"] = cleared_by
        return update_platform_node_metadata(node_name, updates, path=path)
    records = read_platform_node_registry(path)
    for index, item in enumerate(records):
        if str(item.get("node_name") or "") != node_name:
            continue
        metadata = _coerce_mapping(cast(Mapping[str, Any] | None, item.get("metadata")))
        scoped = []
        for candidate in cast(list[Any], metadata.get("pressure_suppressions") or []):
            if not isinstance(candidate, Mapping):
                continue
            candidate_scopes = {str(scope).strip() for scope in cast(list[Any], candidate.get("scopes") or []) if str(scope).strip()}
            if candidate_scopes and candidate_scopes.intersection(normalized_scopes):
                continue
            scoped.append(dict(candidate))
        metadata["pressure_suppressions"] = scoped
        metadata["suppression_cleared_at"] = _utc_now().isoformat()
        if cleared_by:
            metadata["suppression_cleared_by"] = cleared_by
        updated = dict(item)
        updated["metadata"] = metadata
        records[index] = updated
        write_platform_node_registry(records, path)
        return updated
    raise KeyError(f"Platform node not found: {node_name}")


def platform_node_maintenance_state(
    metadata: Mapping[str, Any] | None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    payload = _coerce_mapping(metadata)
    maintenance_until = str(payload.get("maintenance_until") or "")
    parsed_until = _parse_datetime(maintenance_until)
    current = now or _utc_now()
    acknowledged_at = payload.get("maintenance_acknowledged_at")
    completed_at = payload.get("maintenance_completed_at")
    failed_at = payload.get("maintenance_failed_at")
    cancelled_at = payload.get("maintenance_cancelled_at")
    parsed_completed = _parse_datetime(completed_at)
    parsed_failed = _parse_datetime(failed_at)
    parsed_cancelled = _parse_datetime(cancelled_at)
    failed = parsed_failed is not None and (parsed_completed is None or parsed_failed >= parsed_completed)
    active = parsed_until is not None and parsed_until > current and not failed
    cancelled = (
        parsed_cancelled is not None
        and not active
        and (parsed_completed is None or parsed_cancelled >= parsed_completed)
        and (parsed_failed is None or parsed_cancelled >= parsed_failed)
    )
    services = [str(service) for service in cast(list[Any], payload.get("maintenance_services") or []) if str(service)]
    status = "inactive"
    if failed:
        status = "failed"
    elif cancelled:
        status = "cancelled"
    elif completed_at and active:
        status = "completed"
    elif active and acknowledged_at:
        status = "acknowledged"
    elif active:
        status = "requested"
    return {
        "active": active,
        "status": status,
        "maintenance_until": maintenance_until or None,
        "maintenance_by": payload.get("maintenance_by"),
        "maintenance_reason": payload.get("maintenance_reason"),
        "maintenance_services": services,
        "maintenance_acknowledged_at": acknowledged_at,
        "maintenance_completed_at": completed_at,
        "maintenance_result": payload.get("maintenance_result"),
        "maintenance_completion_note": payload.get("maintenance_completion_note"),
        "maintenance_failed_at": failed_at,
        "maintenance_cancelled_at": cancelled_at,
        "maintenance_cancelled_by": payload.get("maintenance_cancelled_by"),
        "maintenance_last_error": payload.get("maintenance_last_error"),
        "maintenance_retry_count": int(payload.get("maintenance_retry_count") or 0),
        "maintenance_retriable": bool(payload.get("maintenance_retriable")),
    }


def platform_node_refresh_state(
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    payload = _coerce_mapping(metadata)
    pending = bool(payload.get("refresh_pending"))
    acknowledged_at = payload.get("refresh_acknowledged_at")
    completed_at = payload.get("refresh_completed_at") or payload.get("refresh_fulfilled_at")
    failed_at = payload.get("refresh_failed_at")
    cancelled_at = payload.get("refresh_cancelled_at")
    parsed_completed = _parse_datetime(completed_at)
    parsed_failed = _parse_datetime(failed_at)
    parsed_cancelled = _parse_datetime(cancelled_at)
    failed = parsed_failed is not None and (parsed_completed is None or parsed_failed >= parsed_completed)
    cancelled = (
        parsed_cancelled is not None
        and not pending
        and (parsed_completed is None or parsed_cancelled >= parsed_completed)
        and (parsed_failed is None or parsed_cancelled >= parsed_failed)
    )
    status = "inactive"
    if failed:
        status = "failed"
    elif cancelled:
        status = "cancelled"
    elif pending and acknowledged_at:
        status = "acknowledged"
    elif pending:
        status = "requested"
    elif completed_at:
        status = "completed"
    return {
        "status": status,
        "pending": pending,
        "refresh_requested_at": payload.get("refresh_requested_at"),
        "refresh_requested_by": payload.get("refresh_requested_by"),
        "refresh_request_reason": payload.get("refresh_request_reason"),
        "refresh_acknowledged_at": acknowledged_at,
        "refresh_completed_at": payload.get("refresh_completed_at"),
        "refresh_fulfilled_at": payload.get("refresh_fulfilled_at"),
        "refresh_result": payload.get("refresh_result"),
        "refresh_completion_note": payload.get("refresh_completion_note"),
        "refresh_failed_at": failed_at,
        "refresh_cancelled_at": cancelled_at,
        "refresh_cancelled_by": payload.get("refresh_cancelled_by"),
        "refresh_last_error": payload.get("refresh_last_error"),
        "refresh_retry_count": int(payload.get("refresh_retry_count") or 0),
        "refresh_retriable": bool(payload.get("refresh_retriable")),
    }


def request_platform_node_refresh(
    node_name: str,
    *,
    requested_by: str,
    reason: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    updates: dict[str, Any] = {
        "refresh_requested_at": _utc_now().isoformat(),
        "refresh_requested_by": requested_by,
        "refresh_pending": True,
        "refresh_acknowledged_at": None,
        "refresh_completed_at": None,
        "refresh_fulfilled_at": None,
        "refresh_result": None,
        "refresh_completion_note": None,
        "refresh_failed_at": None,
        "refresh_cancelled_at": None,
        "refresh_cancelled_by": None,
        "refresh_last_error": None,
        "refresh_retriable": False,
    }
    if reason:
        updates["refresh_request_reason"] = reason
    update_platform_node_metadata(node_name, updates, path=path)
    return _append_platform_node_action_history(
        node_name,
        action="refresh",
        transition="requested",
        actor=requested_by,
        note=reason,
        path=path,
    )


def platform_node_drain_state(
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    payload = _coerce_mapping(metadata)
    services = [str(service) for service in cast(list[Any], payload.get("drain_services") or []) if str(service)]
    failed_at = payload.get("drain_failed_at")
    completed_at = payload.get("drain_completed_at")
    cancelled_at = payload.get("drain_cancelled_at")
    parsed_completed = _parse_datetime(completed_at)
    parsed_failed = _parse_datetime(failed_at)
    parsed_cancelled = _parse_datetime(cancelled_at)
    failed = parsed_failed is not None and (parsed_completed is None or parsed_failed >= parsed_completed)
    active = bool(payload.get("drain_at")) and not failed
    cancelled = (
        parsed_cancelled is not None
        and not active
        and (parsed_completed is None or parsed_cancelled >= parsed_completed)
        and (parsed_failed is None or parsed_cancelled >= parsed_failed)
    )
    acknowledged_at = payload.get("drain_acknowledged_at")
    status = "inactive"
    if failed:
        status = "failed"
    elif cancelled:
        status = "cancelled"
    elif completed_at:
        status = "completed"
    elif active and acknowledged_at:
        status = "acknowledged"
    elif active:
        status = "requested"
    return {
        "active": active,
        "status": status,
        "drain_requested_at": payload.get("drain_requested_at"),
        "drain_at": payload.get("drain_at"),
        "drained_by": payload.get("drained_by"),
        "drain_reason": payload.get("drain_reason"),
        "drain_services": services,
        "drain_acknowledged_at": acknowledged_at,
        "drain_completed_at": completed_at,
        "drain_result": payload.get("drain_result"),
        "drain_completion_note": payload.get("drain_completion_note"),
        "drain_failed_at": failed_at,
        "drain_cancelled_at": cancelled_at,
        "drain_cancelled_by": payload.get("drain_cancelled_by"),
        "drain_last_error": payload.get("drain_last_error"),
        "drain_retry_count": int(payload.get("drain_retry_count") or 0),
        "drain_retriable": bool(payload.get("drain_retriable")),
    }


def build_platform_node_actions(metadata: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    maintenance = platform_node_maintenance_state(metadata)
    refresh = platform_node_refresh_state(metadata)
    drain = platform_node_drain_state(metadata)
    actions: list[dict[str, Any]] = []
    if str(maintenance.get("status") or "") in {"requested", "acknowledged"}:
        actions.append(
            {
                "action": "maintenance",
                **maintenance,
            }
        )
    if str(refresh.get("status") or "") in {"requested", "acknowledged"}:
        actions.append(
            {
                "action": "refresh",
                **refresh,
            }
        )
    if str(drain.get("status") or "") in {"requested", "acknowledged"}:
        actions.append(
            {
                "action": "drain",
                **drain,
            }
        )
    return actions


def acknowledge_platform_node_action(
    node_name: str,
    *,
    action: str,
    acted_by: str,
    note: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    normalized = action.strip().casefold()
    if normalized == "refresh":
        updates: dict[str, Any] = {
            "refresh_acknowledged_at": _utc_now().isoformat(),
            "refresh_acknowledged_by": acted_by,
        }
        if note:
            updates["refresh_acknowledgement_note"] = note
        update_platform_node_metadata(node_name, updates, path=path)
        return _append_platform_node_action_history(
            node_name,
            action="refresh",
            transition="acknowledged",
            actor=acted_by,
            note=note,
            path=path,
        )
    if normalized == "maintenance":
        updates = {
            "maintenance_acknowledged_at": _utc_now().isoformat(),
            "maintenance_acknowledged_by": acted_by,
        }
        if note:
            updates["maintenance_acknowledgement_note"] = note
        update_platform_node_metadata(node_name, updates, path=path)
        return _append_platform_node_action_history(
            node_name,
            action="maintenance",
            transition="acknowledged",
            actor=acted_by,
            note=note,
            path=path,
        )
    if normalized == "drain":
        updates = {
            "drain_acknowledged_at": _utc_now().isoformat(),
            "drain_acknowledged_by": acted_by,
        }
        if note:
            updates["drain_acknowledgement_note"] = note
        update_platform_node_metadata(node_name, updates, path=path)
        return _append_platform_node_action_history(
            node_name,
            action="drain",
            transition="acknowledged",
            actor=acted_by,
            note=note,
            path=path,
        )
    raise ValueError(f"Unsupported platform node action: {action}")


def complete_platform_node_action(
    node_name: str,
    *,
    action: str,
    acted_by: str,
    result: str | None = None,
    note: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    normalized = action.strip().casefold()
    timestamp = _utc_now().isoformat()
    result_value = (result or "").strip().casefold()
    failure_result = result_value in {"failed", "failure", "error", "unsupported", "timeout"}
    if normalized == "refresh":
        retry_count = int(_read_platform_node_metadata(node_name, path=path).get("refresh_retry_count") or 0)
        updates: dict[str, Any] = {"refresh_completed_by": acted_by}
        if failure_result:
            updates.update(
                {
                    "refresh_pending": False,
                    "refresh_failed_at": timestamp,
                    "refresh_result": result or "failed",
                    "refresh_last_error": note or result or "refresh execution failed",
                    "refresh_retriable": True,
                    "refresh_retry_count": retry_count + 1,
                }
            )
        else:
            updates.update(
                {
                    "refresh_pending": False,
                    "refresh_completed_at": timestamp,
                    "refresh_fulfilled_at": timestamp,
                    "refresh_failed_at": None,
                    "refresh_last_error": None,
                    "refresh_retriable": False,
                }
            )
            if result:
                updates["refresh_result"] = result
            if note:
                updates["refresh_completion_note"] = note
        update_platform_node_metadata(node_name, updates, path=path)
        return _append_platform_node_action_history(
            node_name,
            action="refresh",
            transition="failed" if failure_result else "completed",
            actor=acted_by,
            note=note,
            result=result or ("failed" if failure_result else "success"),
            path=path,
        )
    if normalized == "maintenance":
        retry_count = int(_read_platform_node_metadata(node_name, path=path).get("maintenance_retry_count") or 0)
        updates = {"maintenance_completed_by": acted_by}
        if failure_result:
            updates.update(
                {
                    "maintenance_failed_at": timestamp,
                    "maintenance_result": result or "failed",
                    "maintenance_last_error": note or result or "maintenance execution failed",
                    "maintenance_retriable": True,
                    "maintenance_retry_count": retry_count + 1,
                }
            )
        else:
            updates.update(
                {
                    "maintenance_completed_at": timestamp,
                    "maintenance_failed_at": None,
                    "maintenance_last_error": None,
                    "maintenance_retriable": False,
                }
            )
            if result:
                updates["maintenance_result"] = result
            if note:
                updates["maintenance_completion_note"] = note
        update_platform_node_metadata(node_name, updates, path=path)
        return _append_platform_node_action_history(
            node_name,
            action="maintenance",
            transition="failed" if failure_result else "completed",
            actor=acted_by,
            note=note,
            result=result or ("failed" if failure_result else "success"),
            path=path,
        )
    if normalized == "drain":
        retry_count = int(_read_platform_node_metadata(node_name, path=path).get("drain_retry_count") or 0)
        updates = {"drain_completed_by": acted_by}
        if failure_result:
            updates.update(
                {
                    "drain_failed_at": timestamp,
                    "drain_result": result or "failed",
                    "drain_last_error": note or result or "drain execution failed",
                    "drain_retriable": True,
                    "drain_retry_count": retry_count + 1,
                }
            )
        else:
            updates.update(
                {
                    "drain_completed_at": timestamp,
                    "drain_failed_at": None,
                    "drain_last_error": None,
                    "drain_retriable": False,
                }
            )
            if result:
                updates["drain_result"] = result
            if note:
                updates["drain_completion_note"] = note
        update_platform_node_metadata(node_name, updates, path=path)
        return _append_platform_node_action_history(
            node_name,
            action="drain",
            transition="failed" if failure_result else "completed",
            actor=acted_by,
            note=note,
            result=result or ("failed" if failure_result else "success"),
            path=path,
        )
    raise ValueError(f"Unsupported platform node action: {action}")


def retry_platform_node_action(
    node_name: str,
    *,
    action: str,
    requested_by: str,
    path: str | Path | None = None,
) -> dict[str, Any]:
    metadata = _read_platform_node_metadata(node_name, path=path)
    normalized = action.strip().casefold()
    _append_platform_node_action_history(
        node_name,
        action=normalized,
        transition="retried",
        actor=requested_by,
        note="requeued by operator",
        path=path,
    )
    if normalized == "refresh":
        return request_platform_node_refresh(
            node_name,
            requested_by=requested_by,
            reason=str(metadata.get("refresh_request_reason") or "") or None,
            path=path,
        )
    if normalized == "drain":
        return start_platform_node_drain(
            node_name,
            drained_by=requested_by,
            reason=str(metadata.get("drain_reason") or "") or None,
            services=[str(item) for item in cast(list[Any], metadata.get("drain_services") or []) if str(item)],
            path=path,
        )
    if normalized == "maintenance":
        current = _utc_now()
        until = _parse_datetime(metadata.get("maintenance_until"))
        started = _parse_datetime(metadata.get("maintenance_at"))
        minutes = 60
        if until is not None:
            if started is not None and until > started:
                minutes = max(1, int((until - started).total_seconds() // 60))
            elif until > current:
                minutes = max(1, int((until - current).total_seconds() // 60))
        return start_platform_node_maintenance(
            node_name,
            minutes=minutes,
            maintenance_by=requested_by,
            reason=str(metadata.get("maintenance_reason") or "") or None,
            services=[str(item) for item in cast(list[Any], metadata.get("maintenance_services") or []) if str(item)],
            path=path,
        )
    raise ValueError(f"Unsupported platform node action: {action}")


def cancel_platform_node_action(
    node_name: str,
    *,
    action: str,
    cancelled_by: str,
    path: str | Path | None = None,
) -> dict[str, Any]:
    normalized = action.strip().casefold()
    timestamp = _utc_now().isoformat()
    if normalized == "refresh":
        update_platform_node_metadata(
            node_name,
            {
                "refresh_pending": False,
                "refresh_acknowledged_at": None,
                "refresh_cancelled_at": timestamp,
                "refresh_cancelled_by": cancelled_by,
                "refresh_retriable": False,
            },
            path=path,
        )
        return _append_platform_node_action_history(
            node_name,
            action="refresh",
            transition="cancelled",
            actor=cancelled_by,
            path=path,
        )
    if normalized == "maintenance":
        update_platform_node_metadata(
            node_name,
            {
                "maintenance_until": None,
                "maintenance_acknowledged_at": None,
                "maintenance_cancelled_at": timestamp,
                "maintenance_cancelled_by": cancelled_by,
                "maintenance_retriable": False,
            },
            path=path,
        )
        return _append_platform_node_action_history(
            node_name,
            action="maintenance",
            transition="cancelled",
            actor=cancelled_by,
            path=path,
        )
    if normalized == "drain":
        update_platform_node_metadata(
            node_name,
            {
                "drain_at": None,
                "drain_acknowledged_at": None,
                "drain_cancelled_at": timestamp,
                "drain_cancelled_by": cancelled_by,
                "drain_retriable": False,
            },
            path=path,
        )
        return _append_platform_node_action_history(
            node_name,
            action="drain",
            transition="cancelled",
            actor=cancelled_by,
            path=path,
        )
    raise ValueError(f"Unsupported platform node action: {action}")


def start_platform_node_drain(
    node_name: str,
    *,
    drained_by: str,
    reason: str | None = None,
    services: Sequence[str] | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    updates: dict[str, Any] = {
        "drain_requested_at": _utc_now().isoformat(),
        "drain_at": _utc_now().isoformat(),
        "drained_by": drained_by,
        "drain_services": [str(service).strip() for service in (services or []) if str(service).strip()],
        "drain_acknowledged_at": None,
        "drain_completed_at": None,
        "drain_result": None,
        "drain_completion_note": None,
        "drain_failed_at": None,
        "drain_cancelled_at": None,
        "drain_cancelled_by": None,
        "drain_last_error": None,
        "drain_retriable": False,
    }
    if reason:
        updates["drain_reason"] = reason
    update_platform_node_metadata(node_name, updates, path=path)
    return _append_platform_node_action_history(
        node_name,
        action="drain",
        transition="requested",
        actor=drained_by,
        note=reason,
        path=path,
    )


def clear_platform_node_drain(
    node_name: str,
    *,
    cleared_by: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    updates: dict[str, Any] = {
        "drain_at": None,
        "drained_by": None,
        "drain_reason": None,
        "drain_services": [],
        "drain_completed_at": _utc_now().isoformat(),
        "drain_result": None,
        "drain_completion_note": None,
        "drain_failed_at": None,
        "drain_last_error": None,
        "drain_retriable": False,
        "drain_cleared_at": _utc_now().isoformat(),
    }
    if cleared_by:
        updates["drain_cleared_by"] = cleared_by
    update_platform_node_metadata(node_name, updates, path=path)
    return _append_platform_node_action_history(
        node_name,
        action="drain",
        transition="cleared",
        actor=cleared_by,
        path=path,
    )


def start_platform_node_maintenance(
    node_name: str,
    *,
    minutes: int,
    maintenance_by: str,
    reason: str | None = None,
    services: Sequence[str] | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    updates: dict[str, Any] = {
        "maintenance_at": _utc_now().isoformat(),
        "maintenance_until": (_utc_now() + timedelta(minutes=minutes)).isoformat(),
        "maintenance_by": maintenance_by,
        "maintenance_services": [str(service).strip() for service in (services or []) if str(service).strip()],
        "maintenance_acknowledged_at": None,
        "maintenance_completed_at": None,
        "maintenance_result": None,
        "maintenance_completion_note": None,
        "maintenance_failed_at": None,
        "maintenance_cancelled_at": None,
        "maintenance_cancelled_by": None,
        "maintenance_last_error": None,
        "maintenance_retriable": False,
    }
    if reason:
        updates["maintenance_reason"] = reason
    update_platform_node_metadata(node_name, updates, path=path)
    return _append_platform_node_action_history(
        node_name,
        action="maintenance",
        transition="requested",
        actor=maintenance_by,
        note=reason,
        path=path,
    )


def clear_platform_node_maintenance(
    node_name: str,
    *,
    cleared_by: str | None = None,
    path: str | Path | None = None,
) -> dict[str, Any]:
    updates: dict[str, Any] = {
        "maintenance_until": None,
        "maintenance_by": None,
        "maintenance_reason": None,
        "maintenance_services": [],
        "maintenance_result": None,
        "maintenance_completion_note": None,
        "maintenance_failed_at": None,
        "maintenance_last_error": None,
        "maintenance_retriable": False,
        "maintenance_cleared_at": _utc_now().isoformat(),
    }
    if cleared_by:
        updates["maintenance_cleared_by"] = cleared_by
    update_platform_node_metadata(node_name, updates, path=path)
    return _append_platform_node_action_history(
        node_name,
        action="maintenance",
        transition="cleared",
        actor=cleared_by,
        path=path,
    )


def _classify_node_status(
    service_health: Mapping[str, Any],
    *,
    last_seen_at: object,
    stale_after_minutes: int,
) -> str:
    parsed_last_seen = _parse_datetime(last_seen_at)
    if parsed_last_seen is None or parsed_last_seen < (_utc_now() - timedelta(minutes=stale_after_minutes)):
        return "stale"
    overall_status = str(service_health.get("overall_status") or "unknown")
    if overall_status == "degraded":
        return "degraded"
    if overall_status == "healthy":
        return "healthy"
    return "unknown"


def build_platform_topology(
    *,
    local_profile: Mapping[str, Any],
    node_registry: list[Mapping[str, Any]] | None = None,
    stale_after_minutes: int | None = None,
) -> dict[str, Any]:
    stale_minutes = stale_after_minutes or settings.platform_node_stale_minutes
    local_service_health = _coerce_mapping(cast(Mapping[str, Any] | None, local_profile.get("service_health")))
    local_role_profile = _coerce_mapping(cast(Mapping[str, Any] | None, local_profile.get("role_profile")))
    local_node = {
        "node_name": str(local_profile.get("node_name") or ""),
        "node_role": str(local_profile.get("node_role") or "standalone"),
        "deployment_mode": str(local_profile.get("deployment_mode") or settings.platform_deployment_mode),
        "service_health": local_service_health,
        "role_profile": local_role_profile,
        "last_seen_at": str(local_service_health.get("services", {}).get("automation", {}).get("last_run") or _utc_now().isoformat()),
    }
    local_node["status"] = _classify_node_status(
        local_service_health,
        last_seen_at=local_node["last_seen_at"],
        stale_after_minutes=stale_minutes,
    )
    remote_nodes: list[dict[str, Any]] = []
    for item in node_registry or read_platform_node_registry():
        node_name = str(item.get("node_name") or "")
        if not node_name or node_name == local_node["node_name"]:
            continue
        entry = dict(item)
        role_profile = _coerce_mapping(cast(Mapping[str, Any] | None, entry.get("role_profile")))
        if not role_profile:
            role_profile = build_platform_role_profile(node_role=str(entry.get("node_role") or None))
        service_health = _coerce_mapping(cast(Mapping[str, Any] | None, entry.get("service_health")))
        entry["role_profile"] = role_profile
        entry["service_health"] = service_health
        entry["status"] = _classify_node_status(
            service_health,
            last_seen_at=entry.get("last_seen_at"),
            stale_after_minutes=stale_minutes,
        )
        entry["suppression"] = platform_node_suppression_state(cast(Mapping[str, Any] | None, entry.get("metadata")))
        entry["maintenance"] = platform_node_maintenance_state(cast(Mapping[str, Any] | None, entry.get("metadata")))
        entry["refresh"] = platform_node_refresh_state(cast(Mapping[str, Any] | None, entry.get("metadata")))
        entry["drain"] = platform_node_drain_state(cast(Mapping[str, Any] | None, entry.get("metadata")))
        entry["actions"] = build_platform_node_actions(cast(Mapping[str, Any] | None, entry.get("metadata")))
        entry["action_pressure"] = _platform_node_action_pressure(
            cast(Mapping[str, Any] | None, entry.get("metadata")),
            refresh=cast(Mapping[str, Any], entry["refresh"]),
            maintenance=cast(Mapping[str, Any], entry["maintenance"]),
            drain=cast(Mapping[str, Any], entry["drain"]),
        )
        entry["action_failures"] = [
            action_name
            for action_name, state in (
                ("maintenance", cast(dict[str, Any], entry["maintenance"])),
                ("refresh", cast(dict[str, Any], entry["refresh"])),
                ("drain", cast(dict[str, Any], entry["drain"])),
            )
            if str(state.get("status") or "") == "failed"
        ]
        entry["suppressed"] = bool(cast(dict[str, Any], entry["suppression"]).get("active"))
        entry["maintenance_active"] = bool(cast(dict[str, Any], entry["maintenance"]).get("active"))
        entry["refresh_pending"] = bool(cast(dict[str, Any], entry["refresh"]).get("pending"))
        entry["drained"] = bool(cast(dict[str, Any], entry["drain"]).get("active"))
        entry["repeated_failure_active"] = bool(cast(dict[str, Any], entry["action_pressure"]).get("repeated_failure_active"))
        entry["retry_pressure_active"] = bool(cast(dict[str, Any], entry["action_pressure"]).get("retry_pressure_active"))
        entry["stuck_actions_active"] = bool(cast(dict[str, Any], entry["action_pressure"]).get("stuck_actions_active"))
        remote_nodes.append(entry)
    remote_nodes.sort(
        key=lambda item: (
            {"degraded": 0, "stale": 1, "healthy": 2, "unknown": 3}.get(str(item.get("status") or "unknown"), 4),
            str(item.get("node_name") or "").casefold(),
        )
    )
    all_nodes = [local_node, *remote_nodes]
    return {
        "local_node": local_node,
        "remote_nodes": remote_nodes,
        "total_nodes": len(all_nodes),
        "remote_node_count": len(remote_nodes),
        "healthy_nodes": sum(1 for item in all_nodes if item.get("status") == "healthy"),
        "degraded_nodes": sum(1 for item in all_nodes if item.get("status") == "degraded"),
        "stale_nodes": sum(1 for item in all_nodes if item.get("status") == "stale"),
        "suppressed_nodes": sum(1 for item in remote_nodes if item.get("suppressed")),
        "maintenance_nodes": sum(1 for item in remote_nodes if item.get("maintenance_active")),
        "refresh_pending_nodes": sum(1 for item in remote_nodes if item.get("refresh_pending")),
        "drained_nodes": sum(1 for item in remote_nodes if item.get("drained")),
        "failed_action_nodes": sum(1 for item in remote_nodes if cast(list[str], item.get("action_failures") or [])),
        "repeated_failure_nodes": sum(1 for item in remote_nodes if item.get("repeated_failure_active")),
        "retry_pressure_nodes": sum(1 for item in remote_nodes if item.get("retry_pressure_active")),
        "stuck_action_nodes": sum(1 for item in remote_nodes if item.get("stuck_actions_active")),
    }


def build_node_heartbeat_payload(
    platform_profile: Mapping[str, Any],
    *,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "node_name": str(platform_profile.get("node_name") or ""),
        "node_role": str(platform_profile.get("node_role") or "standalone"),
        "deployment_mode": str(platform_profile.get("deployment_mode") or settings.platform_deployment_mode),
        "service_health": _coerce_mapping(cast(Mapping[str, Any] | None, platform_profile.get("service_health"))),
        "metadata": dict(metadata or {}),
        "last_seen_at": _utc_now().isoformat(),
    }


def _platform_heartbeat_url(manager_url: str) -> str:
    base = manager_url.rstrip("/") + "/"
    return urljoin(base, "platform/nodes/heartbeat")


def _platform_node_actions_url(manager_url: str, node_name: str) -> str:
    base = manager_url.rstrip("/") + "/"
    return urljoin(base, f"platform/nodes/{node_name}/actions")


def _platform_node_action_transition_url(manager_url: str, node_name: str, action: str, transition: str) -> str:
    base = manager_url.rstrip("/") + "/"
    return urljoin(base, f"platform/nodes/{node_name}/actions/{action}/{transition}")


def send_platform_node_heartbeat(
    *,
    manager_url: str,
    payload: Mapping[str, Any],
    bearer_token: str | None = None,
    timeout_seconds: float = 5.0,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    if bearer_token:
        headers["authorization"] = f"Bearer {bearer_token}"
    with httpx.Client(timeout=timeout_seconds, transport=transport) as client:
        response = client.post(
            _platform_heartbeat_url(manager_url),
            headers=headers,
            json=dict(payload),
        )
        response.raise_for_status()
        return cast(dict[str, Any], response.json())


def fetch_platform_node_actions(
    *,
    manager_url: str,
    node_name: str,
    bearer_token: str | None = None,
    timeout_seconds: float = 5.0,
    transport: httpx.BaseTransport | None = None,
) -> list[dict[str, Any]]:
    headers = {"content-type": "application/json"}
    if bearer_token:
        headers["authorization"] = f"Bearer {bearer_token}"
    with httpx.Client(timeout=timeout_seconds, transport=transport) as client:
        response = client.get(
            _platform_node_actions_url(manager_url, node_name),
            headers=headers,
        )
        response.raise_for_status()
        payload = cast(dict[str, Any], response.json())
    return [dict(item) for item in cast(list[dict[str, Any]], payload.get("actions") or [])]


def update_platform_node_action_remote(
    *,
    manager_url: str,
    node_name: str,
    action: str,
    transition: str,
    acted_by: str,
    result: str | None = None,
    note: str | None = None,
    bearer_token: str | None = None,
    timeout_seconds: float = 5.0,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    headers = {"content-type": "application/json"}
    if bearer_token:
        headers["authorization"] = f"Bearer {bearer_token}"
    payload: dict[str, Any] = {"acted_by": acted_by}
    if result:
        payload["result"] = result
    if note:
        payload["note"] = note
    with httpx.Client(timeout=timeout_seconds, transport=transport) as client:
        response = client.post(
            _platform_node_action_transition_url(manager_url, node_name, action, transition),
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        return cast(dict[str, Any], response.json())


def synchronize_platform_node_actions(
    *,
    manager_url: str,
    node_name: str,
    acted_by: str,
    actions: Sequence[Mapping[str, Any]] | None = None,
    executor: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    bearer_token: str | None = None,
    timeout_seconds: float = 5.0,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    pending_actions = [dict(item) for item in actions] if actions is not None else fetch_platform_node_actions(
        manager_url=manager_url,
        node_name=node_name,
        bearer_token=bearer_token,
        timeout_seconds=timeout_seconds,
        transport=transport,
    )
    acknowledged: list[str] = []
    completed: list[str] = []
    execution_results: list[dict[str, Any]] = []
    for action_payload in pending_actions:
        action_name = str(action_payload.get("action") or "").strip()
        status = str(action_payload.get("status") or "").strip().casefold()
        if not action_name:
            continue
        if status == "requested":
            update_platform_node_action_remote(
                manager_url=manager_url,
                node_name=node_name,
                action=action_name,
                transition="acknowledge",
                acted_by=acted_by,
                note="acknowledged by node heartbeat",
                bearer_token=bearer_token,
                timeout_seconds=timeout_seconds,
                transport=transport,
            )
            acknowledged.append(action_name)
        execution = executor(action_payload) if executor is not None else {"result": "success", "note": "completed by node heartbeat"}
        execution_results.append({"action": action_name, **dict(execution)})
        if status in {"requested", "acknowledged"}:
            update_platform_node_action_remote(
                manager_url=manager_url,
                node_name=node_name,
                action=action_name,
                transition="complete",
                acted_by=acted_by,
                result=str(dict(execution).get("result") or "success"),
                note=str(dict(execution).get("note") or "completed by node heartbeat"),
                bearer_token=bearer_token,
                timeout_seconds=timeout_seconds,
                transport=transport,
            )
            completed.append(action_name)
    return {
        "actions": pending_actions,
        "acknowledged": acknowledged,
        "completed": completed,
        "results": execution_results,
    }


def build_platform_service_health(
    *,
    automation_status: Mapping[str, Any] | None = None,
    tracker_health: Mapping[str, Any] | None = None,
    malware_health: Mapping[str, Any] | None = None,
    node_role: str | None = None,
) -> dict[str, Any]:
    automation_payload = _coerce_mapping(automation_status)
    role_profile = build_platform_role_profile(node_role=node_role)
    role_services = cast(dict[str, bool], role_profile["services"])
    services: dict[str, dict[str, Any]] = {}

    automation_enabled = bool(role_services.get("automation", True))
    automation_running = automation_enabled and bool(automation_payload.get("running", False))
    services["automation"] = _service_entry(
        name="automation",
        enabled=automation_enabled,
        status="disabled" if not automation_enabled else ("healthy" if automation_running else "degraded"),
        healthy=(not automation_enabled) or automation_running,
        last_run=automation_payload.get("last_run"),
        details={
            "interval_seconds": automation_payload.get("interval_seconds", settings.automation_interval_seconds),
            "tick_count": automation_payload.get("tick_count", 0),
            "error_count": automation_payload.get("error_count", 0),
        },
    )
    services["tracker_intel"] = _component_health_entry(
        name="tracker_intel",
        enabled=role_managed_service_enabled(
            "tracker_intel",
            configured=settings.tracker_block_enabled,
            node_role=node_role,
        ),
        payload=tracker_health,
    )
    services["malware_scanner"] = _component_health_entry(
        name="malware_scanner",
        enabled=role_managed_service_enabled(
            "malware_scanner",
            configured=True,
            node_role=node_role,
        ),
        payload=malware_health,
    )

    for service_name, (automation_key, settings_key) in _AUTOMATION_SERVICE_LABELS.items():
        services[service_name] = _automation_service_entry(
            service_name,
            cast(Mapping[str, Any] | None, automation_payload.get(automation_key)),
            enabled_by_default=role_managed_service_enabled(
                service_name,
                configured=bool(getattr(settings, settings_key)),
                node_role=node_role,
            ),
        )

    enabled_services = [entry for entry in services.values() if bool(entry["enabled"])]
    healthy_services = [entry for entry in enabled_services if bool(entry["healthy"])]
    degraded_services = [entry for entry in enabled_services if not bool(entry["healthy"])]
    pending_services = [entry for entry in enabled_services if str(entry["status"]) == "pending"]
    return {
        "role_profile": role_profile,
        "overall_status": "healthy" if not degraded_services else "degraded",
        "enabled_services": len(enabled_services),
        "healthy_services": len(healthy_services),
        "degraded_services": len(degraded_services),
        "pending_services": len(pending_services),
        "services": services,
    }


def build_platform_profile(
    *,
    automation_status: Mapping[str, Any] | None = None,
    tracker_health: Mapping[str, Any] | None = None,
    malware_health: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    node_role = normalize_platform_node_role()
    profile = {
        "node_name": settings.platform_node_name or socket.gethostname(),
        "node_role": node_role,
        "deployment_mode": settings.platform_deployment_mode,
        "role_profile": build_platform_role_profile(node_role=node_role),
        "service_health": build_platform_service_health(
            automation_status=automation_status,
            tracker_health=tracker_health,
            malware_health=malware_health,
            node_role=node_role,
        ),
    }
    profile["topology"] = build_platform_topology(local_profile=profile)
    return profile
