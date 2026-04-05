"""Storage primitives for Security Gateway SOC state."""
from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Generic, Protocol, Sequence, TypeVar

from pydantic import BaseModel

from .models import SocAlertRecord, SocCaseRecord, SocEventRecord

RecordT = TypeVar("RecordT", bound=BaseModel)


class EventIndexStore(Protocol):
    path: Path

    def append(self, event: SocEventRecord, *, event_store: "JsonlEventStore | None" = None) -> None: ...

    def get(self, event_id: str, *, event_store: "JsonlEventStore | None" = None) -> SocEventRecord | None: ...

    def query(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
        sort: str = "created_desc",
        limit: int = 100,
        event_store: "JsonlEventStore | None" = None,
    ) -> list[SocEventRecord]: ...

    def facet_counts(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
        limit: int = 5,
    ) -> dict[str, list[dict[str, object]]]: ...

    def timeline_counts(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
    ) -> dict[str, Any]: ...

    def stats(self, *, event_store: "JsonlEventStore | None" = None) -> "EventIndexStats": ...

    def rebuild(self, events: list[SocEventRecord], *, event_store: "JsonlEventStore | None" = None) -> None: ...


class JsonlEventStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: SocEventRecord) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json() + "\n")

    def list(self) -> list[SocEventRecord]:
        if not self.path.exists():
            return []
        events: list[SocEventRecord] = []
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                events.append(SocEventRecord.model_validate_json(raw))
            except Exception:
                continue
        return events

    def count(self) -> int:
        if not self.path.exists():
            return 0
        return sum(1 for raw in self.path.read_text(encoding="utf-8").splitlines() if raw.strip())

    def signature(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "path": str(self.path),
                "exists": False,
                "size_bytes": 0,
                "modified_ns": 0,
            }
        stat = self.path.stat()
        return {
            "path": str(self.path),
            "exists": True,
            "size_bytes": stat.st_size,
            "modified_ns": stat.st_mtime_ns,
        }

    def write(self, events: Sequence[SocEventRecord]) -> None:
        payload = "\n".join(event.model_dump_json() for event in events)
        if payload:
            payload += "\n"
        self.path.write_text(payload, encoding="utf-8")


class JsonEventIndexStore:
    _SCHEMA_VERSION = 2
    _TOKEN_PATTERN = re.compile(r"[a-z0-9_.:/-]{2,}")

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: SocEventRecord, *, event_store: JsonlEventStore | None = None) -> None:
        payload = self._read_payload()
        self._upsert_event(payload, event)
        payload["meta"] = self._build_meta(payload, event_store=event_store)
        self._write_payload(payload)

    def get(self, event_id: str, *, event_store: JsonlEventStore | None = None) -> SocEventRecord | None:
        payload = self._read_payload()
        document = payload["events"].get(event_id)
        if not isinstance(document, dict):
            return None
        raw_event = document.get("event")
        if not isinstance(raw_event, dict):
            return None
        try:
            return SocEventRecord.model_validate(raw_event)
        except Exception:
            return None

    def query(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
        sort: str = "created_desc",
        limit: int = 100,
        event_store: JsonlEventStore | None = None,
    ) -> list[SocEventRecord]:
        events: list[SocEventRecord] = []
        for document in self._filtered_documents(
            severity=severity,
            event_type=event_type,
            source=source,
            tag=tag,
            text=text,
            remote_ip=remote_ip,
            hostname=hostname,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            signer_name=signer_name,
            sha256=sha256,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            close_reason=close_reason,
            reject_code=reject_code,
            start_at=start_at,
            end_at=end_at,
            linked_alert_state=linked_alert_state,
        ):
            raw_event = document.get("event")
            if not isinstance(raw_event, dict):
                continue
            try:
                events.append(SocEventRecord.model_validate(raw_event))
            except Exception:
                continue
        self._sort_events(events, sort)
        return events[:limit]

    def facet_counts(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
        limit: int = 5,
    ) -> dict[str, list[dict[str, object]]]:
        counters: dict[str, Counter[str]] = {
            "event_type": Counter(),
            "source": Counter(),
            "severity": Counter(),
            "tag": Counter(),
            "document_type": Counter(),
            "remote_ip": Counter(),
            "device_id": Counter(),
            "process_name": Counter(),
            "flow_id": Counter(),
            "service_name": Counter(),
            "application_protocol": Counter(),
            "local_ip": Counter(),
            "local_port": Counter(),
            "remote_port": Counter(),
            "protocol": Counter(),
            "state": Counter(),
            "close_reason": Counter(),
            "reject_code": Counter(),
        }
        for document in self._filtered_documents(
            severity=severity,
            event_type=event_type,
            source=source,
            tag=tag,
            text=text,
            remote_ip=remote_ip,
            hostname=hostname,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            signer_name=signer_name,
            sha256=sha256,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            close_reason=close_reason,
            reject_code=reject_code,
            start_at=start_at,
            end_at=end_at,
            linked_alert_state=linked_alert_state,
        ):
            raw_event = document.get("event")
            if not isinstance(raw_event, dict):
                continue
            event_type_value = raw_event.get("event_type")
            if isinstance(event_type_value, str) and event_type_value:
                counters["event_type"][event_type_value] += 1
            source_value = raw_event.get("source")
            if isinstance(source_value, str) and source_value:
                counters["source"][source_value] += 1
            severity_value = raw_event.get("severity")
            if isinstance(severity_value, str) and severity_value:
                counters["severity"][severity_value] += 1
            tags = raw_event.get("tags")
            if isinstance(tags, list):
                for item in tags:
                    if isinstance(item, str) and item:
                        counters["tag"][item] += 1
            details = raw_event.get("details")
            if isinstance(details, dict):
                document_type_value = details.get("document_type")
                if isinstance(document_type_value, str) and document_type_value:
                    counters["document_type"][document_type_value] += 1
            observables = document.get("observables")
            if isinstance(observables, dict):
                for facet_key in (
                    "remote_ip",
                    "device_id",
                    "process_name",
                    "flow_id",
                    "service_name",
                    "application_protocol",
                    "local_ip",
                    "local_port",
                    "remote_port",
                    "protocol",
                    "state",
                ):
                    values = observables.get(facet_key)
                    if isinstance(values, list):
                        for item in values:
                            if isinstance(item, str) and item:
                                counters[facet_key][item] += 1
        bounded_limit = max(limit, 1)
        return {
            key: [{"value": value, "count": count} for value, count in counter.most_common(bounded_limit)]
            for key, counter in counters.items()
        }

    def timeline_counts(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
    ) -> dict[str, Any]:
        documents = self._filtered_documents(
            severity=severity,
            event_type=event_type,
            source=source,
            tag=tag,
            text=text,
            remote_ip=remote_ip,
            hostname=hostname,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            signer_name=signer_name,
            sha256=sha256,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            close_reason=close_reason,
            reject_code=reject_code,
            start_at=start_at,
            end_at=end_at,
            linked_alert_state=linked_alert_state,
        )
        if not documents:
            return {
                "bucket_unit": "day",
                "start_at": start_at.isoformat() if start_at is not None else None,
                "end_at": end_at.isoformat() if end_at is not None else None,
                "buckets": [],
            }
        created_values: list[datetime] = []
        for document in documents:
            created_at_raw = document.get("created_at")
            if not isinstance(created_at_raw, str):
                continue
            try:
                created_values.append(datetime.fromisoformat(created_at_raw).astimezone(UTC))
            except ValueError:
                continue
        if not created_values:
            return {
                "bucket_unit": "day",
                "start_at": start_at.isoformat() if start_at is not None else None,
                "end_at": end_at.isoformat() if end_at is not None else None,
                "buckets": [],
            }
        window_start = start_at or min(created_values)
        window_end = end_at or max(created_values)
        bucket_unit = self._bucket_unit_for_window(window_start, window_end)
        counts: Counter[str] = Counter()
        for created_at in created_values:
            counts[self._time_bucket(created_at, bucket_unit)] += 1
        return {
            "bucket_unit": bucket_unit,
            "start_at": window_start.isoformat(),
            "end_at": window_end.isoformat(),
            "buckets": [{"start_at": bucket, "count": count} for bucket, count in sorted(counts.items())],
        }

    def stats(self, *, event_store: JsonlEventStore | None = None) -> "EventIndexStats":
        payload = self._read_payload()
        source_signature = self._source_signature(payload)
        current = True
        if event_store is not None:
            current = source_signature == event_store.signature()
        return EventIndexStats(
            backend="json-event-index",
            indexed_event_count=len(payload["events"]),
            token_count=len(payload["token_index"]),
            index_path=str(self.path),
            current=current,
            indexed_at=self._indexed_at(payload),
            source_signature=source_signature,
            dimension_counts=self._dimension_counts(payload),
        )

    def rebuild(self, events: list[SocEventRecord], *, event_store: JsonlEventStore | None = None) -> None:
        self._write_payload(self._build_payload(events, event_store=event_store))

    def _read_payload(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._empty_payload()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return self._empty_payload()
        if not isinstance(payload, dict):
            return self._empty_payload()
        normalized = self._empty_payload()
        for key in normalized:
            value = payload.get(key)
            if isinstance(value, dict):
                normalized[key] = value
        return normalized

    def _write_payload(self, payload: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _build_payload(self, events: list[SocEventRecord], *, event_store: JsonlEventStore | None = None) -> dict[str, Any]:
        payload = self._empty_payload()
        for event in events:
            self._upsert_event(payload, event)
        payload["meta"] = self._build_meta(payload, event_store=event_store)
        return payload

    def _upsert_event(self, payload: dict[str, Any], event: SocEventRecord) -> None:
        document = self._event_document(event)
        payload["events"][event.event_id] = document
        for token in document["tokens"]:
            payload["token_index"].setdefault(token, [])
            if event.event_id not in payload["token_index"][token]:
                payload["token_index"][token].append(event.event_id)
        normalized_source = event.source.casefold()
        payload["source_index"].setdefault(normalized_source, [])
        if event.event_id not in payload["source_index"][normalized_source]:
            payload["source_index"][normalized_source].append(event.event_id)
        severity = event.severity.value
        payload["severity_index"].setdefault(severity, [])
        if event.event_id not in payload["severity_index"][severity]:
            payload["severity_index"][severity].append(event.event_id)
        created_at = event.created_at.astimezone(UTC)
        created_hour = self._time_bucket(created_at, "hour")
        payload["created_hour_index"].setdefault(created_hour, [])
        if event.event_id not in payload["created_hour_index"][created_hour]:
            payload["created_hour_index"][created_hour].append(event.event_id)
        created_day = self._time_bucket(created_at, "day")
        payload["created_day_index"].setdefault(created_day, [])
        if event.event_id not in payload["created_day_index"][created_day]:
            payload["created_day_index"][created_day].append(event.event_id)
        normalized_event_type = event.event_type.casefold()
        payload["event_type_index"].setdefault(normalized_event_type, [])
        if event.event_id not in payload["event_type_index"][normalized_event_type]:
            payload["event_type_index"][normalized_event_type].append(event.event_id)
        for candidate_tag in event.tags:
            normalized_tag = candidate_tag.casefold()
            payload["tag_index"].setdefault(normalized_tag, [])
            if event.event_id not in payload["tag_index"][normalized_tag]:
                payload["tag_index"][normalized_tag].append(event.event_id)
        for category, index_name in (
            ("remote_ip", "remote_ip_index"),
            ("hostname", "hostname_index"),
            ("filename", "filename_index"),
            ("artifact_path", "artifact_path_index"),
            ("session_key", "session_key_index"),
            ("device_id", "device_id_index"),
            ("process_name", "process_name_index"),
            ("process_guid", "process_guid_index"),
            ("signer_name", "signer_name_index"),
            ("sha256", "sha256_index"),
            ("flow_id", "flow_id_index"),
            ("service_name", "service_name_index"),
            ("application_protocol", "application_protocol_index"),
            ("local_ip", "local_ip_index"),
            ("local_port", "local_port_index"),
            ("remote_port", "remote_port_index"),
            ("protocol", "protocol_index"),
            ("state", "state_index"),
            ("close_reason", "close_reason_index"),
            ("reject_code", "reject_code_index"),
        ):
            for candidate in document["observables"][category]:
                payload[index_name].setdefault(candidate, [])
                if event.event_id not in payload[index_name][candidate]:
                    payload[index_name][candidate].append(event.event_id)

    def _event_document(self, event: SocEventRecord) -> dict[str, Any]:
        searchable_text = self._build_searchable_text(event)
        observables = self._extract_observables(event)
        return {
            "event": event.model_dump(mode="json"),
            "created_at": event.created_at.isoformat(),
            "linked_alert_id": event.linked_alert_id,
            "searchable_text": searchable_text,
            "tokens": sorted(self._tokenize(searchable_text)),
            "observables": observables,
        }

    def _build_searchable_text(self, event: SocEventRecord) -> str:
        fragments = [
            event.event_id,
            event.event_type,
            event.source,
            event.title,
            event.summary,
            *event.tags,
            *event.artifacts,
            json.dumps(event.details, sort_keys=True, separators=(",", ":"), default=str),
        ]
        return " ".join(fragment.casefold() for fragment in fragments if fragment)

    def _extract_observables(self, event: SocEventRecord) -> dict[str, list[str]]:
        details = event.details if isinstance(event.details, dict) else {}
        observables = {
            "remote_ip": sorted(self._extract_detail_values(details, {"remote_ip"})),
            "hostname": sorted(self._extract_detail_values(details, {"hostname"})),
            "filename": sorted(self._extract_detail_values(details, {"filename"})),
            "artifact_path": sorted(
                self._extract_detail_values(details, {"artifact_path"}) | {item.casefold() for item in event.artifacts}
            ),
            "session_key": sorted(self._extract_detail_values(details, {"session_key"})),
            "device_id": sorted(self._extract_detail_values(details, {"device_id"})),
            "process_name": sorted(self._extract_detail_values(details, {"process_name", "actor_process_name", "parent_process_name"})),
            "process_guid": sorted(self._extract_detail_values(details, {"process_guid", "parent_process_guid"})),
            "signer_name": sorted(self._extract_detail_values(details, {"signer_name"})),
            "sha256": sorted(self._extract_detail_values(details, {"sha256", "process_sha256", "actor_process_sha256", "parent_process_sha256"})),
            "flow_id": sorted(self._extract_detail_values(details, {"flow_id"})),
            "service_name": sorted(self._extract_detail_values(details, {"service_name", "service_names"})),
            "application_protocol": sorted(
                self._extract_detail_values(details, {"application_protocol", "application_protocols"})
            ),
            "local_ip": sorted(self._extract_detail_values(details, {"local_ip", "local_ips"})),
            "local_port": sorted(self._extract_detail_values(details, {"local_port", "local_ports"})),
            "remote_port": sorted(self._extract_detail_values(details, {"remote_port", "remote_ports"})),
            "protocol": sorted(self._extract_detail_values(details, {"protocol", "protocols"})),
            "state": sorted(self._extract_detail_values(details, {"state", "states"})),
            "close_reason": sorted(self._extract_detail_values(details, {"close_reason"})),
            "reject_code": sorted(self._extract_detail_values(details, {"reject_code"})),
        }
        return observables

    def _extract_detail_values(self, payload: Any, keys: set[str]) -> set[str]:
        values: set[str] = set()
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key.casefold() in keys:
                    if isinstance(value, str) and value.strip():
                        values.add(value.strip().casefold())
                    elif isinstance(value, int):
                        values.add(str(value))
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and item.strip():
                                values.add(item.strip().casefold())
                            elif isinstance(item, int):
                                values.add(str(item))
                values |= self._extract_detail_values(value, keys)
        elif isinstance(payload, list):
            for item in payload:
                values |= self._extract_detail_values(item, keys)
        return values

    @classmethod
    def _tokenize(cls, value: str) -> set[str]:
        return {token for token in cls._TOKEN_PATTERN.findall(value.casefold()) if token}

    @staticmethod
    def _intersect_ids(current: set[str] | None, candidates: list[str]) -> set[str]:
        candidate_set = set(candidates)
        return candidate_set if current is None else current & candidate_set

    @staticmethod
    def _sort_events(events: list[SocEventRecord], sort: str) -> None:
        severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        if sort == "created_asc":
            events.sort(key=lambda item: item.created_at)
        elif sort == "severity_desc":
            events.sort(key=lambda item: (severity_rank[item.severity.value], item.created_at), reverse=True)
        elif sort == "severity_asc":
            events.sort(key=lambda item: (severity_rank[item.severity.value], item.created_at))
        else:
            events.sort(key=lambda item: item.created_at, reverse=True)

    @staticmethod
    def _empty_payload() -> dict[str, Any]:
        return {
            "meta": {},
            "events": {},
            "token_index": {},
            "tag_index": {},
            "source_index": {},
            "severity_index": {},
            "created_hour_index": {},
            "created_day_index": {},
            "event_type_index": {},
            "remote_ip_index": {},
            "hostname_index": {},
            "filename_index": {},
            "artifact_path_index": {},
            "session_key_index": {},
            "device_id_index": {},
            "process_name_index": {},
            "process_guid_index": {},
            "signer_name_index": {},
            "sha256_index": {},
            "flow_id_index": {},
            "service_name_index": {},
            "application_protocol_index": {},
            "local_ip_index": {},
            "local_port_index": {},
            "remote_port_index": {},
            "protocol_index": {},
            "state_index": {},
            "close_reason_index": {},
            "reject_code_index": {},
        }

    @staticmethod
    def _document_matches_window(
        document: dict[str, Any],
        *,
        start_at: datetime | None,
        end_at: datetime | None,
        linked_alert_state: str | None,
    ) -> bool:
        if start_at is not None or end_at is not None:
            created_at_raw = document.get("created_at")
            if not isinstance(created_at_raw, str):
                return False
            try:
                created_at = datetime.fromisoformat(created_at_raw)
            except ValueError:
                return False
            if start_at is not None and created_at < start_at:
                return False
            if end_at is not None and created_at > end_at:
                return False
        linked_alert_id = document.get("linked_alert_id")
        if linked_alert_state == "linked" and not isinstance(linked_alert_id, str):
            return False
        if linked_alert_state == "unlinked" and isinstance(linked_alert_id, str) and linked_alert_id:
            return False
        return True

    def _filtered_documents(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
    ) -> list[dict[str, Any]]:
        payload = self._read_payload()
        candidate_ids: set[str] | None = None
        if severity is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["severity_index"].get(severity, []))
        if event_type is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["event_type_index"].get(event_type.casefold(), []))
        if source is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["source_index"].get(source.casefold(), []))
        if tag is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["tag_index"].get(tag.casefold(), []))
        if remote_ip is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["remote_ip_index"].get(remote_ip.casefold(), []))
        if hostname is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["hostname_index"].get(hostname.casefold(), []))
        if filename is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["filename_index"].get(filename.casefold(), []))
        if artifact_path is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["artifact_path_index"].get(artifact_path.casefold(), []))
        if session_key is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["session_key_index"].get(session_key.casefold(), []))
        if device_id is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["device_id_index"].get(device_id.casefold(), []))
        if process_name is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["process_name_index"].get(process_name.casefold(), []))
        if process_guid is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["process_guid_index"].get(process_guid.casefold(), []))
        if signer_name is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["signer_name_index"].get(signer_name.casefold(), []))
        if sha256 is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["sha256_index"].get(sha256.casefold(), []))
        if flow_id is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["flow_id_index"].get(flow_id.casefold(), []))
        if service_name is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["service_name_index"].get(service_name.casefold(), []))
        if application_protocol is not None:
            candidate_ids = self._intersect_ids(
                candidate_ids,
                payload["application_protocol_index"].get(application_protocol.casefold(), []),
            )
        if local_ip is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["local_ip_index"].get(local_ip.casefold(), []))
        if local_port is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["local_port_index"].get(local_port.casefold(), []))
        if remote_port is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["remote_port_index"].get(remote_port.casefold(), []))
        if protocol is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["protocol_index"].get(protocol.casefold(), []))
        if state is not None:
            candidate_ids = self._intersect_ids(candidate_ids, payload["state_index"].get(state.casefold(), []))
        if close_reason is not None:
            candidate_ids = self._intersect_ids(
                candidate_ids,
                payload["close_reason_index"].get(close_reason.casefold(), []),
            )
        if reject_code is not None:
            candidate_ids = self._intersect_ids(
                candidate_ids,
                payload["reject_code_index"].get(reject_code.casefold(), []),
            )
        normalized_text = (text or "").strip().casefold()
        if normalized_text:
            tokens = self._tokenize(normalized_text)
            if tokens:
                for token in tokens:
                    candidate_ids = self._intersect_ids(candidate_ids, payload["token_index"].get(token, []))
            elif candidate_ids is None:
                candidate_ids = set(payload["events"].keys())
        time_candidate_ids = self._candidate_ids_for_window(payload, start_at=start_at, end_at=end_at)
        if time_candidate_ids is not None:
            candidate_ids = self._intersect_ids(candidate_ids, list(time_candidate_ids))
        if candidate_ids is None:
            candidate_ids = set(payload["events"].keys())
        documents: list[dict[str, Any]] = []
        for event_id in candidate_ids:
            document = payload["events"].get(event_id)
            if not isinstance(document, dict):
                continue
            if not self._document_matches_window(
                document,
                start_at=start_at,
                end_at=end_at,
                linked_alert_state=linked_alert_state,
            ):
                continue
            searchable_text = str(document.get("searchable_text") or "")
            if normalized_text and normalized_text not in searchable_text:
                continue
            documents.append(document)
        return documents

    def _candidate_ids_for_window(
        self,
        payload: dict[str, Any],
        *,
        start_at: datetime | None,
        end_at: datetime | None,
    ) -> set[str] | None:
        if start_at is None and end_at is None:
            return None
        if start_at is not None and end_at is not None:
            bucket_unit = self._bucket_unit_for_window(start_at, end_at)
        else:
            bucket_unit = "day"
        index_name = "created_hour_index" if bucket_unit == "hour" else "created_day_index"
        bucket_index = payload.get(index_name)
        if not isinstance(bucket_index, dict):
            return None
        earliest = start_at.astimezone(UTC) if start_at is not None else None
        latest = end_at.astimezone(UTC) if end_at is not None else None
        candidate_ids: set[str] = set()
        for bucket_key, event_ids in bucket_index.items():
            if not isinstance(bucket_key, str) or not isinstance(event_ids, list):
                continue
            try:
                bucket_time = datetime.fromisoformat(bucket_key)
            except ValueError:
                continue
            if earliest is not None and bucket_unit == "hour" and bucket_time < earliest.replace(minute=0, second=0, microsecond=0):
                continue
            if latest is not None and bucket_unit == "hour" and bucket_time > latest.replace(minute=0, second=0, microsecond=0):
                continue
            if earliest is not None and bucket_unit == "day" and bucket_time < earliest.replace(hour=0, minute=0, second=0, microsecond=0):
                continue
            if latest is not None and bucket_unit == "day" and bucket_time > latest.replace(hour=0, minute=0, second=0, microsecond=0):
                continue
            candidate_ids.update(item for item in event_ids if isinstance(item, str))
        return candidate_ids

    @staticmethod
    def _bucket_unit_for_window(start_at: datetime, end_at: datetime) -> str:
        return "hour" if (end_at - start_at) <= timedelta(hours=48) else "day"

    @staticmethod
    def _time_bucket(created_at: datetime, bucket_unit: str) -> str:
        if bucket_unit == "hour":
            return created_at.replace(minute=0, second=0, microsecond=0).isoformat()
        return created_at.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    @staticmethod
    def _dimension_counts(payload: dict[str, Any]) -> dict[str, int]:
        return {
            "tokens": len(payload.get("token_index", {})),
            "tags": len(payload.get("tag_index", {})),
            "sources": len(payload.get("source_index", {})),
            "severities": len(payload.get("severity_index", {})),
            "created_hours": len(payload.get("created_hour_index", {})),
            "created_days": len(payload.get("created_day_index", {})),
            "event_types": len(payload.get("event_type_index", {})),
            "remote_ips": len(payload.get("remote_ip_index", {})),
            "filenames": len(payload.get("filename_index", {})),
            "artifact_paths": len(payload.get("artifact_path_index", {})),
            "session_keys": len(payload.get("session_key_index", {})),
            "device_ids": len(payload.get("device_id_index", {})),
            "process_names": len(payload.get("process_name_index", {})),
            "process_guids": len(payload.get("process_guid_index", {})),
            "signers": len(payload.get("signer_name_index", {})),
            "sha256": len(payload.get("sha256_index", {})),
            "flow_ids": len(payload.get("flow_id_index", {})),
            "service_names": len(payload.get("service_name_index", {})),
            "application_protocols": len(payload.get("application_protocol_index", {})),
            "local_ips": len(payload.get("local_ip_index", {})),
            "local_ports": len(payload.get("local_port_index", {})),
            "remote_ports": len(payload.get("remote_port_index", {})),
            "protocols": len(payload.get("protocol_index", {})),
            "states": len(payload.get("state_index", {})),
            "close_reasons": len(payload.get("close_reason_index", {})),
            "reject_codes": len(payload.get("reject_code_index", {})),
        }

    def _build_meta(self, payload: dict[str, Any], *, event_store: JsonlEventStore | None = None) -> dict[str, Any]:
        source_signature = event_store.signature() if event_store is not None else self._source_signature(payload)
        return {
            "schema_version": self._SCHEMA_VERSION,
            "indexed_at": datetime.now(UTC).isoformat(),
            "source_signature": source_signature,
            "indexed_event_count": len(payload["events"]),
        }

    @staticmethod
    def _source_signature(payload: dict[str, Any]) -> dict[str, Any]:
        meta = payload.get("meta")
        if not isinstance(meta, dict):
            return {}
        source_signature = meta.get("source_signature")
        return source_signature if isinstance(source_signature, dict) else {}

    @staticmethod
    def _indexed_at(payload: dict[str, Any]) -> str | None:
        meta = payload.get("meta")
        if not isinstance(meta, dict):
            return None
        value = meta.get("indexed_at")
        return value if isinstance(value, str) and value else None


class SqliteEventIndexStore:
    _TOKEN_PATTERN = re.compile(r"[a-z0-9_.:/-]{2,}")
    _SCHEMA_VERSION = 1
    _SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self._ensure_schema(connection)

    def append(self, event: SocEventRecord, *, event_store: JsonlEventStore | None = None) -> None:
        with self._connect() as connection:
            self._ensure_schema(connection)
            self._upsert_event(connection, event)
            self._set_meta(connection, "indexed_at", datetime.now(UTC).isoformat())
            self._set_meta(connection, "schema_version", self._SCHEMA_VERSION)
            self._set_meta(connection, "indexed_event_count", self._count_rows(connection, "events"))
            self._set_meta(
                connection,
                "source_signature",
                event_store.signature() if event_store is not None else self._read_meta(connection, "source_signature", {}),
            )

    def get(self, event_id: str, *, event_store: JsonlEventStore | None = None) -> SocEventRecord | None:
        del event_store
        with self._connect() as connection:
            self._ensure_schema(connection)
            row = connection.execute("SELECT event_json FROM events WHERE event_id = ?", (event_id,)).fetchone()
        if row is None:
            return None
        return self._parse_event_json(str(row["event_json"]))

    def query(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
        sort: str = "created_desc",
        limit: int = 100,
        event_store: JsonlEventStore | None = None,
    ) -> list[SocEventRecord]:
        del event_store
        with self._connect() as connection:
            self._ensure_schema(connection)
            rows = self._filtered_rows(
                connection,
                severity=severity,
                event_type=event_type,
                source=source,
                tag=tag,
                text=text,
                remote_ip=remote_ip,
                hostname=hostname,
                filename=filename,
                artifact_path=artifact_path,
                session_key=session_key,
                device_id=device_id,
                process_name=process_name,
                process_guid=process_guid,
                signer_name=signer_name,
                sha256=sha256,
                flow_id=flow_id,
                service_name=service_name,
                application_protocol=application_protocol,
                local_ip=local_ip,
                local_port=local_port,
                remote_port=remote_port,
                protocol=protocol,
                state=state,
                close_reason=close_reason,
                reject_code=reject_code,
                start_at=start_at,
                end_at=end_at,
                linked_alert_state=linked_alert_state,
                sort=sort,
                limit=limit,
            )
        events: list[SocEventRecord] = []
        for row in rows:
            event = self._parse_event_json(str(row["event_json"]))
            if event is not None:
                events.append(event)
        return events

    def facet_counts(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
        limit: int = 5,
    ) -> dict[str, list[dict[str, object]]]:
        counters: dict[str, Counter[str]] = {
            "event_type": Counter(),
            "source": Counter(),
            "severity": Counter(),
            "tag": Counter(),
            "document_type": Counter(),
            "remote_ip": Counter(),
            "device_id": Counter(),
            "process_name": Counter(),
            "flow_id": Counter(),
            "service_name": Counter(),
            "application_protocol": Counter(),
            "local_ip": Counter(),
            "local_port": Counter(),
            "remote_port": Counter(),
            "protocol": Counter(),
            "state": Counter(),
            "close_reason": Counter(),
            "reject_code": Counter(),
        }
        for event in self.query(
            severity=severity,
            event_type=event_type,
            source=source,
            tag=tag,
            text=text,
            remote_ip=remote_ip,
            hostname=hostname,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            signer_name=signer_name,
            sha256=sha256,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            close_reason=close_reason,
            reject_code=reject_code,
            start_at=start_at,
            end_at=end_at,
            linked_alert_state=linked_alert_state,
            sort="created_desc",
            limit=1_000_000,
        ):
            counters["event_type"][event.event_type] += 1
            counters["source"][event.source] += 1
            counters["severity"][event.severity.value] += 1
            for item in event.tags:
                counters["tag"][item] += 1
            details = event.details if isinstance(event.details, dict) else {}
            document_type_value = details.get("document_type")
            if isinstance(document_type_value, str) and document_type_value:
                counters["document_type"][document_type_value] += 1
            observables = self._extract_observables(event)
            for facet_key in (
                "remote_ip",
                "device_id",
                "process_name",
                "flow_id",
                "service_name",
                "application_protocol",
                "local_ip",
                "local_port",
                "remote_port",
                "protocol",
                "state",
                "close_reason",
                "reject_code",
            ):
                for item in observables[facet_key]:
                    counters[facet_key][item] += 1
        bounded_limit = max(limit, 1)
        return {
            key: [{"value": value, "count": count} for value, count in counter.most_common(bounded_limit)]
            for key, counter in counters.items()
        }

    def timeline_counts(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
    ) -> dict[str, Any]:
        rows = self.query(
            severity=severity,
            event_type=event_type,
            source=source,
            tag=tag,
            text=text,
            remote_ip=remote_ip,
            hostname=hostname,
            filename=filename,
            artifact_path=artifact_path,
            session_key=session_key,
            device_id=device_id,
            process_name=process_name,
            process_guid=process_guid,
            signer_name=signer_name,
            sha256=sha256,
            flow_id=flow_id,
            service_name=service_name,
            application_protocol=application_protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_port=remote_port,
            protocol=protocol,
            state=state,
            close_reason=close_reason,
            reject_code=reject_code,
            start_at=start_at,
            end_at=end_at,
            linked_alert_state=linked_alert_state,
            sort="created_desc",
            limit=1_000_000,
        )
        if not rows:
            return {
                "bucket_unit": "day",
                "start_at": start_at.isoformat() if start_at is not None else None,
                "end_at": end_at.isoformat() if end_at is not None else None,
                "buckets": [],
            }
        created_values = [item.created_at.astimezone(UTC) for item in rows]
        window_start = start_at or min(created_values)
        window_end = end_at or max(created_values)
        bucket_unit = self._bucket_unit_for_window(window_start, window_end)
        counts: Counter[str] = Counter()
        for created_at in created_values:
            counts[self._time_bucket(created_at, bucket_unit)] += 1
        return {
            "bucket_unit": bucket_unit,
            "start_at": window_start.isoformat(),
            "end_at": window_end.isoformat(),
            "buckets": [{"start_at": bucket, "count": count} for bucket, count in sorted(counts.items())],
        }

    def stats(self, *, event_store: JsonlEventStore | None = None) -> "EventIndexStats":
        with self._connect() as connection:
            self._ensure_schema(connection)
            source_signature = self._read_meta(connection, "source_signature", {})
            current = True
            if event_store is not None:
                current = source_signature == event_store.signature()
            return EventIndexStats(
                backend="sqlite-event-index",
                indexed_event_count=self._count_rows(connection, "events"),
                token_count=self._count_distinct(connection, "event_tokens", "token"),
                index_path=str(self.path),
                current=current,
                indexed_at=self._read_meta(connection, "indexed_at", None),
                source_signature=source_signature if isinstance(source_signature, dict) else {},
                dimension_counts={
                    "tokens": self._count_distinct(connection, "event_tokens", "token"),
                    "tags": self._count_distinct(connection, "event_tags", "tag"),
                    "sources": self._count_distinct(connection, "events", "source_norm"),
                    "severities": self._count_distinct(connection, "events", "severity"),
                    "created_hours": self._count_distinct_expr(connection, "events", "substr(created_at, 1, 13)"),
                    "created_days": self._count_distinct_expr(connection, "events", "substr(created_at, 1, 10)"),
                    "event_types": self._count_distinct(connection, "events", "event_type_norm"),
                    "remote_ips": self._count_observable_values(connection, "remote_ip"),
                    "filenames": self._count_observable_values(connection, "filename"),
                    "artifact_paths": self._count_observable_values(connection, "artifact_path"),
                    "session_keys": self._count_observable_values(connection, "session_key"),
                    "device_ids": self._count_observable_values(connection, "device_id"),
                    "process_names": self._count_observable_values(connection, "process_name"),
                    "process_guids": self._count_observable_values(connection, "process_guid"),
                    "signers": self._count_observable_values(connection, "signer_name"),
                    "sha256": self._count_observable_values(connection, "sha256"),
                    "flow_ids": self._count_observable_values(connection, "flow_id"),
                    "service_names": self._count_observable_values(connection, "service_name"),
                    "application_protocols": self._count_observable_values(connection, "application_protocol"),
                    "local_ips": self._count_observable_values(connection, "local_ip"),
                    "local_ports": self._count_observable_values(connection, "local_port"),
                    "remote_ports": self._count_observable_values(connection, "remote_port"),
                    "protocols": self._count_observable_values(connection, "protocol"),
                    "states": self._count_observable_values(connection, "state"),
                    "close_reasons": self._count_observable_values(connection, "close_reason"),
                    "reject_codes": self._count_observable_values(connection, "reject_code"),
                },
            )

    def rebuild(self, events: list[SocEventRecord], *, event_store: JsonlEventStore | None = None) -> None:
        with self._connect() as connection:
            self._ensure_schema(connection)
            with connection:
                for table_name in ("events", "event_tokens", "event_tags", "event_observables"):
                    connection.execute(f"DELETE FROM {table_name}")
                for event in events:
                    self._upsert_event(connection, event)
                self._set_meta(connection, "schema_version", self._SCHEMA_VERSION)
                self._set_meta(connection, "indexed_at", datetime.now(UTC).isoformat())
                self._set_meta(connection, "indexed_event_count", len(events))
                self._set_meta(connection, "source_signature", event_store.signature() if event_store is not None else {})

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA schema_version").fetchone()
        except sqlite3.DatabaseError:
            connection.close()
            self.path.unlink(missing_ok=True)
            connection = sqlite3.connect(str(self.path))
            connection.row_factory = sqlite3.Row
        return connection

    def _ensure_schema(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type_norm TEXT NOT NULL,
                source_norm TEXT NOT NULL,
                linked_alert_id TEXT,
                searchable_text TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS event_tokens (
                event_id TEXT NOT NULL,
                token TEXT NOT NULL,
                PRIMARY KEY (event_id, token)
            );
            CREATE TABLE IF NOT EXISTS event_tags (
                event_id TEXT NOT NULL,
                tag TEXT NOT NULL,
                PRIMARY KEY (event_id, tag)
            );
            CREATE TABLE IF NOT EXISTS event_observables (
                event_id TEXT NOT NULL,
                category TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (event_id, category, value)
            );
            CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_event_type_norm ON events(event_type_norm);
            CREATE INDEX IF NOT EXISTS idx_events_source_norm ON events(source_norm);
            CREATE INDEX IF NOT EXISTS idx_events_linked_alert_id ON events(linked_alert_id);
            CREATE INDEX IF NOT EXISTS idx_event_tokens_token ON event_tokens(token);
            CREATE INDEX IF NOT EXISTS idx_event_tags_tag ON event_tags(tag);
            CREATE INDEX IF NOT EXISTS idx_event_observables_category_value ON event_observables(category, value);
            """
        )

    def _upsert_event(self, connection: sqlite3.Connection, event: SocEventRecord) -> None:
        document = self._event_document(event)
        with connection:
            connection.execute("DELETE FROM event_tokens WHERE event_id = ?", (event.event_id,))
            connection.execute("DELETE FROM event_tags WHERE event_id = ?", (event.event_id,))
            connection.execute("DELETE FROM event_observables WHERE event_id = ?", (event.event_id,))
            connection.execute(
                """
                INSERT OR REPLACE INTO events (
                    event_id,
                    created_at,
                    severity,
                    event_type_norm,
                    source_norm,
                    linked_alert_id,
                    searchable_text,
                    event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.created_at.astimezone(UTC).isoformat(),
                    event.severity.value,
                    event.event_type.casefold(),
                    event.source.casefold(),
                    event.linked_alert_id,
                    document["searchable_text"],
                    event.model_dump_json(),
                ),
            )
            connection.executemany(
                "INSERT OR REPLACE INTO event_tokens (event_id, token) VALUES (?, ?)",
                [(event.event_id, token) for token in document["tokens"]],
            )
            connection.executemany(
                "INSERT OR REPLACE INTO event_tags (event_id, tag) VALUES (?, ?)",
                [(event.event_id, item.casefold()) for item in event.tags],
            )
            observable_rows: list[tuple[str, str, str]] = []
            for category, values in document["observables"].items():
                for value in values:
                    observable_rows.append((event.event_id, category, value))
            connection.executemany(
                "INSERT OR REPLACE INTO event_observables (event_id, category, value) VALUES (?, ?, ?)",
                observable_rows,
            )

    def _filtered_rows(
        self,
        connection: sqlite3.Connection,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        tag: str | None = None,
        text: str | None = None,
        remote_ip: str | None = None,
        hostname: str | None = None,
        filename: str | None = None,
        artifact_path: str | None = None,
        session_key: str | None = None,
        device_id: str | None = None,
        process_name: str | None = None,
        process_guid: str | None = None,
        signer_name: str | None = None,
        sha256: str | None = None,
        flow_id: str | None = None,
        service_name: str | None = None,
        application_protocol: str | None = None,
        local_ip: str | None = None,
        local_port: str | None = None,
        remote_port: str | None = None,
        protocol: str | None = None,
        state: str | None = None,
        close_reason: str | None = None,
        reject_code: str | None = None,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        linked_alert_state: str | None = None,
        sort: str = "created_desc",
        limit: int | None = None,
    ) -> list[sqlite3.Row]:
        conditions: list[str] = []
        params: list[Any] = []
        if severity is not None:
            conditions.append("e.severity = ?")
            params.append(severity)
        if event_type is not None:
            conditions.append("e.event_type_norm = ?")
            params.append(event_type.casefold())
        if source is not None:
            conditions.append("e.source_norm = ?")
            params.append(source.casefold())
        if tag is not None:
            conditions.append("EXISTS (SELECT 1 FROM event_tags t WHERE t.event_id = e.event_id AND t.tag = ?)")
            params.append(tag.casefold())
        for category, value in (
            ("remote_ip", remote_ip),
            ("hostname", hostname),
            ("filename", filename),
            ("artifact_path", artifact_path),
            ("session_key", session_key),
            ("device_id", device_id),
            ("process_name", process_name),
            ("process_guid", process_guid),
            ("signer_name", signer_name),
            ("sha256", sha256),
            ("flow_id", flow_id),
            ("service_name", service_name),
            ("application_protocol", application_protocol),
            ("local_ip", local_ip),
            ("local_port", local_port),
            ("remote_port", remote_port),
            ("protocol", protocol),
            ("state", state),
            ("close_reason", close_reason),
            ("reject_code", reject_code),
        ):
            if value is None:
                continue
            conditions.append(
                "EXISTS (SELECT 1 FROM event_observables o WHERE o.event_id = e.event_id AND o.category = ? AND o.value = ?)"
            )
            params.extend((category, value.casefold()))
        if start_at is not None:
            conditions.append("e.created_at >= ?")
            params.append(start_at.astimezone(UTC).isoformat())
        if end_at is not None:
            conditions.append("e.created_at <= ?")
            params.append(end_at.astimezone(UTC).isoformat())
        if linked_alert_state == "linked":
            conditions.append("e.linked_alert_id IS NOT NULL AND e.linked_alert_id != ''")
        elif linked_alert_state == "unlinked":
            conditions.append("(e.linked_alert_id IS NULL OR e.linked_alert_id = '')")
        normalized_text = (text or "").strip().casefold()
        if normalized_text:
            for token in sorted(self._tokenize(normalized_text)):
                conditions.append("EXISTS (SELECT 1 FROM event_tokens tok WHERE tok.event_id = e.event_id AND tok.token = ?)")
                params.append(token)
            conditions.append("e.searchable_text LIKE ?")
            params.append(f"%{normalized_text}%")
        sql = "SELECT e.event_json, e.created_at, e.severity FROM events e"
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        if sort == "created_asc":
            sql += " ORDER BY e.created_at ASC"
        elif sort == "severity_desc":
            sql += (
                " ORDER BY CASE e.severity "
                "WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END DESC, e.created_at DESC"
            )
        elif sort == "severity_asc":
            sql += (
                " ORDER BY CASE e.severity "
                "WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END ASC, e.created_at ASC"
            )
        else:
            sql += " ORDER BY e.created_at DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return connection.execute(sql, params).fetchall()

    @staticmethod
    def _parse_event_json(raw_value: str) -> SocEventRecord | None:
        try:
            return SocEventRecord.model_validate_json(raw_value)
        except Exception:
            return None

    def _event_document(self, event: SocEventRecord) -> dict[str, Any]:
        searchable_text = self._build_searchable_text(event)
        return {
            "searchable_text": searchable_text,
            "tokens": sorted(self._tokenize(searchable_text)),
            "observables": self._extract_observables(event),
        }

    def _build_searchable_text(self, event: SocEventRecord) -> str:
        fragments = [
            event.event_id,
            event.event_type,
            event.source,
            event.title,
            event.summary,
            *event.tags,
            *event.artifacts,
            json.dumps(event.details, sort_keys=True, separators=(",", ":"), default=str),
        ]
        return " ".join(fragment.casefold() for fragment in fragments if fragment)

    def _extract_observables(self, event: SocEventRecord) -> dict[str, list[str]]:
        details = event.details if isinstance(event.details, dict) else {}
        return {
            "remote_ip": sorted(self._extract_detail_values(details, {"remote_ip"})),
            "hostname": sorted(self._extract_detail_values(details, {"hostname"})),
            "filename": sorted(self._extract_detail_values(details, {"filename"})),
            "artifact_path": sorted(
                self._extract_detail_values(details, {"artifact_path"}) | {item.casefold() for item in event.artifacts}
            ),
            "session_key": sorted(self._extract_detail_values(details, {"session_key"})),
            "device_id": sorted(self._extract_detail_values(details, {"device_id"})),
            "process_name": sorted(self._extract_detail_values(details, {"process_name", "actor_process_name", "parent_process_name"})),
            "process_guid": sorted(self._extract_detail_values(details, {"process_guid", "parent_process_guid"})),
            "signer_name": sorted(self._extract_detail_values(details, {"signer_name"})),
            "sha256": sorted(self._extract_detail_values(details, {"sha256", "process_sha256", "actor_process_sha256", "parent_process_sha256"})),
            "flow_id": sorted(self._extract_detail_values(details, {"flow_id"})),
            "service_name": sorted(self._extract_detail_values(details, {"service_name", "service_names"})),
            "application_protocol": sorted(
                self._extract_detail_values(details, {"application_protocol", "application_protocols"})
            ),
            "local_ip": sorted(self._extract_detail_values(details, {"local_ip", "local_ips"})),
            "local_port": sorted(self._extract_detail_values(details, {"local_port", "local_ports"})),
            "remote_port": sorted(self._extract_detail_values(details, {"remote_port", "remote_ports"})),
            "protocol": sorted(self._extract_detail_values(details, {"protocol", "protocols"})),
            "state": sorted(self._extract_detail_values(details, {"state", "states"})),
            "close_reason": sorted(self._extract_detail_values(details, {"close_reason"})),
            "reject_code": sorted(self._extract_detail_values(details, {"reject_code"})),
        }

    def _extract_detail_values(self, payload: Any, keys: set[str]) -> set[str]:
        values: set[str] = set()
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key.casefold() in keys:
                    if isinstance(value, str) and value.strip():
                        values.add(value.strip().casefold())
                    elif isinstance(value, int):
                        values.add(str(value))
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and item.strip():
                                values.add(item.strip().casefold())
                            elif isinstance(item, int):
                                values.add(str(item))
                values |= self._extract_detail_values(value, keys)
        elif isinstance(payload, list):
            for item in payload:
                values |= self._extract_detail_values(item, keys)
        return values

    @classmethod
    def _tokenize(cls, value: str) -> set[str]:
        return {token for token in cls._TOKEN_PATTERN.findall(value.casefold()) if token}

    @staticmethod
    def _bucket_unit_for_window(start_at: datetime, end_at: datetime) -> str:
        return "hour" if (end_at - start_at) <= timedelta(hours=48) else "day"

    @staticmethod
    def _time_bucket(created_at: datetime, bucket_unit: str) -> str:
        if bucket_unit == "hour":
            return created_at.replace(minute=0, second=0, microsecond=0).isoformat()
        return created_at.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()

    @staticmethod
    def _count_rows(connection: sqlite3.Connection, table_name: str) -> int:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {table_name}").fetchone()
        return int(row["count"]) if row is not None else 0

    @staticmethod
    def _count_distinct(connection: sqlite3.Connection, table_name: str, column_name: str) -> int:
        row = connection.execute(f"SELECT COUNT(DISTINCT {column_name}) AS count FROM {table_name}").fetchone()
        return int(row["count"]) if row is not None else 0

    @staticmethod
    def _count_distinct_expr(connection: sqlite3.Connection, table_name: str, expression: str) -> int:
        row = connection.execute(f"SELECT COUNT(DISTINCT {expression}) AS count FROM {table_name}").fetchone()
        return int(row["count"]) if row is not None else 0

    @staticmethod
    def _count_observable_values(connection: sqlite3.Connection, category: str) -> int:
        row = connection.execute(
            "SELECT COUNT(DISTINCT value) AS count FROM event_observables WHERE category = ?",
            (category,),
        ).fetchone()
        return int(row["count"]) if row is not None else 0

    @staticmethod
    def _read_meta(connection: sqlite3.Connection, key: str, default: Any) -> Any:
        row = connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(str(row["value"]))
        except json.JSONDecodeError:
            return default

    @staticmethod
    def _set_meta(connection: sqlite3.Connection, key: str, value: Any) -> None:
        connection.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, json.dumps(value, sort_keys=True)),
        )


class JsonRecordStore(Generic[RecordT]):
    def __init__(self, path: str | Path, model_type: type[RecordT]) -> None:
        self.path = Path(path)
        self.model_type = model_type
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def read(self) -> list[RecordT]:
        if not self.path.exists():
            return []
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, list):
            return []
        records: list[RecordT] = []
        for item in payload:
            try:
                records.append(self.model_type.model_validate(item))
            except Exception:
                continue
        return records

    def write(self, records: list[RecordT]) -> None:
        payload = [record.model_dump(mode="json") for record in records]
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def count(self) -> int:
        return len(self.read())


@dataclass(frozen=True)
class EventIndexStats:
    backend: str
    indexed_event_count: int
    token_count: int
    index_path: str
    current: bool
    indexed_at: str | None
    source_signature: dict[str, Any]
    dimension_counts: dict[str, int]


@dataclass(frozen=True)
class SocStorageStats:
    backend: str
    event_count: int
    alert_count: int
    case_count: int
    event_index_backend: str
    event_indexed_count: int
    event_index_token_count: int
    event_index_current: bool
    event_index_indexed_at: str | None
    event_index_dimension_counts: dict[str, int]
    event_log_path: str
    event_index_path: str
    alert_store_path: str
    case_store_path: str


class SecurityOperationsStore:
    def __init__(
        self,
        *,
        event_store: JsonlEventStore,
        event_index_store: EventIndexStore,
        alert_store: JsonRecordStore[SocAlertRecord],
        case_store: JsonRecordStore[SocCaseRecord],
    ) -> None:
        self.event_store = event_store
        self.event_index_store = event_index_store
        self.alert_store = alert_store
        self.case_store = case_store

    @classmethod
    def from_paths(
        cls,
        *,
        event_log_path: str | Path,
        event_index_backend: str,
        event_index_path: str | Path,
        alert_store_path: str | Path,
        case_store_path: str | Path,
    ) -> "SecurityOperationsStore":
        normalized_backend = event_index_backend.strip().casefold()
        if normalized_backend == "json":
            event_index_store: EventIndexStore = JsonEventIndexStore(event_index_path)
        else:
            event_index_store = SqliteEventIndexStore(event_index_path)
        event_store = JsonlEventStore(event_log_path)
        store = cls(
            event_store=event_store,
            event_index_store=event_index_store,
            alert_store=JsonRecordStore(alert_store_path, SocAlertRecord),
            case_store=JsonRecordStore(case_store_path, SocCaseRecord),
        )
        if event_store.count() > 0 and store.event_index_store.stats(event_store=event_store).indexed_event_count == 0:
            store.event_index_store.rebuild(event_store.list(), event_store=event_store)
        return store

    def stats(self) -> SocStorageStats:
        index_stats = self.event_index_store.stats(event_store=self.event_store)
        return SocStorageStats(
            backend="json-file",
            event_count=self.event_store.count(),
            alert_count=self.alert_store.count(),
            case_count=self.case_store.count(),
            event_index_backend=index_stats.backend,
            event_indexed_count=index_stats.indexed_event_count,
            event_index_token_count=index_stats.token_count,
            event_index_current=index_stats.current,
            event_index_indexed_at=index_stats.indexed_at,
            event_index_dimension_counts=index_stats.dimension_counts,
            event_log_path=str(self.event_store.path),
            event_index_path=index_stats.index_path,
            alert_store_path=str(self.alert_store.path),
            case_store_path=str(self.case_store.path),
        )

    def replace_events(self, events: list[SocEventRecord]) -> None:
        self.event_store.write(events)
        self.event_index_store.rebuild(events, event_store=self.event_store)
