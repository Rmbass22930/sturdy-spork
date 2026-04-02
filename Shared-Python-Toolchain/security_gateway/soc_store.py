"""Storage primitives for Security Gateway SOC state."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, Sequence, TypeVar

from pydantic import BaseModel

from .models import SocAlertRecord, SocCaseRecord, SocEventRecord

RecordT = TypeVar("RecordT", bound=BaseModel)


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

    def write(self, events: Sequence[SocEventRecord]) -> None:
        payload = "\n".join(event.model_dump_json() for event in events)
        if payload:
            payload += "\n"
        self.path.write_text(payload, encoding="utf-8")


class JsonEventIndexStore:
    _TOKEN_PATTERN = re.compile(r"[a-z0-9_.:/-]{2,}")

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: SocEventRecord) -> None:
        payload = self._read_payload()
        self._upsert_event(payload, event)
        self._write_payload(payload)

    def get(self, event_id: str, *, event_store: JsonlEventStore | None = None) -> SocEventRecord | None:
        payload = self._ensure_current(event_store)
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
        sort: str = "created_desc",
        limit: int = 100,
        event_store: JsonlEventStore | None = None,
    ) -> list[SocEventRecord]:
        payload = self._ensure_current(event_store)
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
        normalized_text = (text or "").strip().casefold()
        if normalized_text:
            tokens = self._tokenize(normalized_text)
            if tokens:
                for token in tokens:
                    candidate_ids = self._intersect_ids(candidate_ids, payload["token_index"].get(token, []))
            elif candidate_ids is None:
                candidate_ids = set(payload["events"].keys())
        if candidate_ids is None:
            candidate_ids = set(payload["events"].keys())
        events: list[SocEventRecord] = []
        for event_id in candidate_ids:
            document = payload["events"].get(event_id)
            if not isinstance(document, dict):
                continue
            searchable_text = str(document.get("searchable_text") or "")
            if normalized_text and normalized_text not in searchable_text:
                continue
            raw_event = document.get("event")
            if not isinstance(raw_event, dict):
                continue
            try:
                events.append(SocEventRecord.model_validate(raw_event))
            except Exception:
                continue
        self._sort_events(events, sort)
        return events[:limit]

    def stats(self, *, event_store: JsonlEventStore | None = None) -> "EventIndexStats":
        payload = self._ensure_current(event_store)
        return EventIndexStats(
            backend="json-event-index",
            indexed_event_count=len(payload["events"]),
            token_count=len(payload["token_index"]),
            index_path=str(self.path),
        )

    def rebuild(self, events: list[SocEventRecord]) -> None:
        self._write_payload(self._build_payload(events))

    def _ensure_current(self, event_store: JsonlEventStore | None) -> dict[str, Any]:
        payload = self._read_payload()
        if event_store is None:
            return payload
        if len(payload["events"]) == event_store.count():
            return payload
        rebuilt = self._build_payload(event_store.list())
        self._write_payload(rebuilt)
        return rebuilt

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

    def _build_payload(self, events: list[SocEventRecord]) -> dict[str, Any]:
        payload = self._empty_payload()
        for event in events:
            self._upsert_event(payload, event)
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
        }
        return observables

    def _extract_detail_values(self, payload: Any, keys: set[str]) -> set[str]:
        values: set[str] = set()
        if isinstance(payload, dict):
            for key, value in payload.items():
                if key.casefold() in keys:
                    if isinstance(value, str) and value.strip():
                        values.add(value.strip().casefold())
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and item.strip():
                                values.add(item.strip().casefold())
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
            "events": {},
            "token_index": {},
            "tag_index": {},
            "source_index": {},
            "severity_index": {},
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
        }


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


@dataclass(frozen=True)
class SocStorageStats:
    backend: str
    event_count: int
    alert_count: int
    case_count: int
    event_index_backend: str
    event_indexed_count: int
    event_index_token_count: int
    event_log_path: str
    event_index_path: str
    alert_store_path: str
    case_store_path: str


class SecurityOperationsStore:
    def __init__(
        self,
        *,
        event_store: JsonlEventStore,
        event_index_store: JsonEventIndexStore,
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
        event_index_path: str | Path,
        alert_store_path: str | Path,
        case_store_path: str | Path,
    ) -> "SecurityOperationsStore":
        return cls(
            event_store=JsonlEventStore(event_log_path),
            event_index_store=JsonEventIndexStore(event_index_path),
            alert_store=JsonRecordStore(alert_store_path, SocAlertRecord),
            case_store=JsonRecordStore(case_store_path, SocCaseRecord),
        )

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
            event_log_path=str(self.event_store.path),
            event_index_path=index_stats.index_path,
            alert_store_path=str(self.alert_store.path),
            case_store_path=str(self.case_store.path),
        )

    def replace_events(self, events: list[SocEventRecord]) -> None:
        self.event_store.write(events)
        self.event_index_store.rebuild(events)
