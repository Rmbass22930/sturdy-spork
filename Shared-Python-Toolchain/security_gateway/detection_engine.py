"""Detection rules over stored SOC events."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Protocol

from .models import SocDetectionRuleRecord, SocDetectionRuleUpdate, SocEventRecord, SocSeverity

EventLister = Callable[[int], list[SocEventRecord]]
RuleCatalogEntry = dict[str, Any]
RuleCatalog = dict[str, RuleCatalogEntry]


@dataclass(frozen=True)
class DetectionFinding:
    rule_id: str
    key: str
    title: str
    summary: str
    severity: SocSeverity
    category: str = "correlation"
    related_events: tuple[SocEventRecord, ...] = ()


@dataclass(frozen=True)
class DetectionRuleDefinition:
    rule_id: str
    title: str
    description: str
    category: str
    default_parameters: dict[str, Any]


class DetectionRule(Protocol):
    definition: DetectionRuleDefinition

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None: ...


class EndpointHighRiskDeviceRule:
    definition = DetectionRuleDefinition(
        rule_id="endpoint_high_risk_device",
        title="Endpoint high-risk device",
        description="Correlates endpoint posture issues with risky access activity for the same device.",
        category="correlation",
        default_parameters={"window_hours": 24},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        device_id = event.details.get("device_id")
        if not isinstance(device_id, str) or not device_id:
            return None
        relevant_types = {"endpoint.telemetry_posture", "policy.access_decision"}
        if event.event_type not in relevant_types:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = [
            item
            for item in list_events(500)
            if item.created_at >= window_start
            and item.details.get("device_id") == device_id
            and item.event_type in relevant_types
        ]
        event_types = {item.event_type for item in related_events}
        if event_types != relevant_types:
            return None
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=device_id,
            title=f"Correlated endpoint risk for {device_id}",
            summary="The same endpoint reported posture issues and also triggered a risky access workflow.",
            severity=SocSeverity.critical,
            related_events=tuple(related_events),
        )


class RepeatedTrackerActivityRule:
    definition = DetectionRuleDefinition(
        rule_id="repeated_tracker_activity",
        title="Repeated tracker activity",
        description="Correlates repeated tracker blocks against the same hostname inside a short window.",
        category="correlation",
        default_parameters={"window_hours": 1, "minimum_hits": 3},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        if event.event_type != "privacy.tracker_block":
            return None
        hostname = event.details.get("hostname")
        if not isinstance(hostname, str) or not hostname:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        minimum_hits = int(parameters.get("minimum_hits", self.definition.default_parameters["minimum_hits"]))
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = [
            item
            for item in list_events(500)
            if item.created_at >= window_start
            and item.event_type == "privacy.tracker_block"
            and item.details.get("hostname") == hostname
        ]
        if len(related_events) < minimum_hits:
            return None
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=hostname,
            title=f"Repeated tracker activity for {hostname}",
            summary="Multiple tracker-block events hit the same hostname within one hour.",
            severity=SocSeverity.high,
            related_events=tuple(related_events),
        )


class RepeatedMalwareArtifactRule:
    definition = DetectionRuleDefinition(
        rule_id="repeated_malware_artifact",
        title="Repeated malware artifact",
        description="Correlates repeated malware detections against the same filename inside a short window.",
        category="correlation",
        default_parameters={"window_hours": 6, "minimum_hits": 2},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        if event.event_type != "endpoint.malware_detected":
            return None
        filename = event.details.get("filename")
        if not isinstance(filename, str) or not filename:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        minimum_hits = int(parameters.get("minimum_hits", self.definition.default_parameters["minimum_hits"]))
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = [
            item
            for item in list_events(500)
            if item.created_at >= window_start
            and item.event_type == "endpoint.malware_detected"
            and item.details.get("filename") == filename
        ]
        if len(related_events) < minimum_hits:
            return None
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=filename,
            title=f"Repeated malware detections for {filename}",
            summary="The same malware artifact was detected multiple times inside the configured window.",
            severity=SocSeverity.critical,
            related_events=tuple(related_events),
        )


class SuspiciousSourceAccessRule:
    _NETWORK_EVENT_TYPES = {"network.monitor.finding", "network.telemetry.connection"}
    _PACKET_EVENT_TYPES = {"packet.telemetry.session"}

    definition = DetectionRuleDefinition(
        rule_id="suspicious_source_access",
        title="Suspicious source access",
        description="Correlates denied or step-up access activity with recent suspicious network or packet telemetry for the same source IP.",
        category="correlation",
        default_parameters={"window_hours": 24, "minimum_network_hits": 3, "minimum_packet_count": 10},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        if event.event_type != "policy.access_decision":
            return None
        source_ip = event.details.get("source_ip")
        if not isinstance(source_ip, str) or not source_ip:
            return None
        decision = event.details.get("decision")
        if not isinstance(decision, str) or decision not in {"deny", "step_up"}:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        minimum_network_hits = int(
            parameters.get("minimum_network_hits", self.definition.default_parameters["minimum_network_hits"])
        )
        minimum_packet_count = int(
            parameters.get("minimum_packet_count", self.definition.default_parameters["minimum_packet_count"])
        )
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = [
            item
            for item in list_events(500)
            if item.created_at >= window_start
            and (
                (
                    item.event_type in self._NETWORK_EVENT_TYPES | self._PACKET_EVENT_TYPES
                    and self._telemetry_or_finding_matches(
                        item,
                        source_ip,
                        minimum_network_hits=minimum_network_hits,
                        minimum_packet_count=minimum_packet_count,
                    )
                )
                or item.event_id == event.event_id
            )
        ]
        if len(related_events) < 2:
            return None
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=source_ip,
            title=f"Suspicious source access from {source_ip}",
            summary="A suspicious remote source IP also triggered a denied or step-up access workflow.",
            severity=SocSeverity.critical if decision == "deny" else SocSeverity.high,
            related_events=tuple(related_events),
        )

    @staticmethod
    def _telemetry_or_finding_matches(
        event: SocEventRecord,
        source_ip: str,
        *,
        minimum_network_hits: int,
        minimum_packet_count: int,
    ) -> bool:
        if event.event_type == "network.monitor.finding":
            return SuspiciousSourceAccessRule._network_finding_matches(event, source_ip)
        if event.event_type == "network.telemetry.connection":
            return SuspiciousSourceAccessRule._network_telemetry_matches(
                event,
                source_ip,
                minimum_network_hits=minimum_network_hits,
            )
        if event.event_type == "packet.telemetry.session":
            return SuspiciousSourceAccessRule._packet_telemetry_matches(
                event,
                source_ip,
                minimum_packet_count=minimum_packet_count,
            )
        return False

    @staticmethod
    def _network_finding_matches(event: SocEventRecord, source_ip: str) -> bool:
        details = event.details.get("details")
        if not isinstance(details, dict):
            return False
        remote_ip = details.get("remote_ip")
        if remote_ip != source_ip:
            return False
        finding_type = details.get("finding_type")
        return finding_type in {"suspicious_remote_ip", "dos_candidate"}

    @staticmethod
    def _network_telemetry_matches(
        event: SocEventRecord,
        source_ip: str,
        *,
        minimum_network_hits: int,
    ) -> bool:
        remote_ip = event.details.get("remote_ip")
        if remote_ip != source_ip:
            return False
        sensitive_ports = event.details.get("sensitive_ports")
        if isinstance(sensitive_ports, list) and sensitive_ports:
            return True
        hit_count = event.details.get("hit_count")
        return isinstance(hit_count, int) and hit_count >= minimum_network_hits

    @staticmethod
    def _packet_telemetry_matches(
        event: SocEventRecord,
        source_ip: str,
        *,
        minimum_packet_count: int,
    ) -> bool:
        remote_ip = event.details.get("remote_ip")
        if remote_ip != source_ip:
            return False
        sensitive_ports = event.details.get("sensitive_ports")
        if isinstance(sensitive_ports, list) and sensitive_ports:
            return True
        packet_count = event.details.get("packet_count")
        return isinstance(packet_count, int) and packet_count >= minimum_packet_count


class PacketNetworkRemoteOverlapRule:
    _PACKET_EVENT_TYPES = {"packet.monitor.finding", "packet.telemetry.session"}
    _NETWORK_EVENT_TYPES = {"network.monitor.finding", "network.telemetry.connection"}

    definition = DetectionRuleDefinition(
        rule_id="packet_network_remote_overlap",
        title="Packet and network remote overlap",
        description="Correlates packet-session evidence with suspicious network monitor or normalized network telemetry for the same remote IP.",
        category="correlation",
        default_parameters={"window_hours": 24},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        if event.event_type not in self._PACKET_EVENT_TYPES | self._NETWORK_EVENT_TYPES:
            return None
        remote_ip = self._event_remote_ip(event)
        if not remote_ip:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = [
            item
            for item in list_events(500)
            if item.created_at >= window_start
            and item.event_type in self._PACKET_EVENT_TYPES | self._NETWORK_EVENT_TYPES
            and self._event_remote_ip(item) == remote_ip
        ]
        has_packet = any(item.event_type in self._PACKET_EVENT_TYPES for item in related_events)
        has_network = any(item.event_type in self._NETWORK_EVENT_TYPES for item in related_events)
        if not (has_packet and has_network):
            return None
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=remote_ip,
            title=f"Packet and network evidence for {remote_ip}",
            summary="The same remote IP produced suspicious packet-session evidence and a suspicious network monitor finding.",
            severity=self._severity_for_related_events(related_events),
            related_events=tuple(related_events),
        )

    @staticmethod
    def _event_remote_ip(event: SocEventRecord) -> str | None:
        top_level = event.details.get("remote_ip")
        if isinstance(top_level, str) and top_level:
            return top_level
        details = event.details.get("details")
        if isinstance(details, dict):
            remote_ip = details.get("remote_ip")
            if isinstance(remote_ip, str) and remote_ip:
                return remote_ip
        return None

    def _severity_for_related_events(self, related_events: list[SocEventRecord]) -> SocSeverity:
        for item in related_events:
            if item.event_type == "packet.telemetry.session":
                sensitive_ports = item.details.get("sensitive_ports")
                if isinstance(sensitive_ports, list) and sensitive_ports:
                    return SocSeverity.critical
                continue
            if item.event_type == "network.telemetry.connection":
                sensitive_ports = item.details.get("sensitive_ports")
                if isinstance(sensitive_ports, list) and sensitive_ports:
                    return SocSeverity.critical
                continue
            details = item.details.get("details")
            if not isinstance(details, dict):
                continue
            if item.event_type == "network.monitor.finding" and details.get("finding_type") == "dos_candidate":
                return SocSeverity.critical
            sensitive_ports = details.get("sensitive_ports")
            if isinstance(sensitive_ports, list) and sensitive_ports:
                return SocSeverity.critical
        return SocSeverity.high


class EndpointProcessFileOverlapRule:
    _PROCESS_EVENT_TYPE = "endpoint.telemetry.process"
    _FILE_EVENT_TYPE = "endpoint.telemetry.file"

    definition = DetectionRuleDefinition(
        rule_id="endpoint_process_file_overlap",
        title="Endpoint process and file overlap",
        description="Correlates suspicious endpoint process telemetry with file activity from the same process on the same device.",
        category="correlation",
        default_parameters={"window_hours": 24},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        if event.event_type not in {self._PROCESS_EVENT_TYPE, self._FILE_EVENT_TYPE}:
            return None
        device_id = self._event_device_id(event)
        identity = self._event_process_identity(event)
        if not device_id or not identity:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = [
            item
            for item in list_events(500)
            if item.created_at >= window_start
            and self._event_device_id(item) == device_id
            and self._event_process_identity(item) == identity
            and item.event_type in {self._PROCESS_EVENT_TYPE, self._FILE_EVENT_TYPE}
        ]
        has_suspicious_process = any(
            item.event_type == self._PROCESS_EVENT_TYPE and self._is_suspicious_process(item)
            for item in related_events
        )
        has_file_activity = any(item.event_type == self._FILE_EVENT_TYPE for item in related_events)
        if not (has_suspicious_process and has_file_activity):
            return None
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=f"{device_id}:{identity}",
            title=f"Suspicious process and file activity on {device_id}",
            summary="A suspicious endpoint process also performed file activity on the same device.",
            severity=self._severity_for_related_events(related_events),
            related_events=tuple(related_events),
        )

    @staticmethod
    def _event_device_id(event: SocEventRecord) -> str | None:
        device_id = event.details.get("device_id")
        return device_id if isinstance(device_id, str) and device_id else None

    @staticmethod
    def _event_process_identity(event: SocEventRecord) -> str | None:
        if event.event_type == "endpoint.telemetry.process":
            sha256 = event.details.get("sha256")
            if isinstance(sha256, str) and sha256:
                return sha256
            process_name = event.details.get("process_name")
            if isinstance(process_name, str) and process_name:
                return process_name.casefold()
            return None
        if event.event_type == "endpoint.telemetry.file":
            actor_sha256 = event.details.get("actor_process_sha256")
            if isinstance(actor_sha256, str) and actor_sha256:
                return actor_sha256
            actor_name = event.details.get("actor_process_name")
            if isinstance(actor_name, str) and actor_name:
                return actor_name.casefold()
        return None

    @staticmethod
    def _is_suspicious_process(event: SocEventRecord) -> bool:
        risk_flags = event.details.get("risk_flags")
        if isinstance(risk_flags, list) and risk_flags:
            return True
        remote_ips = event.details.get("remote_ips")
        return isinstance(remote_ips, list) and len(remote_ips) > 0

    @staticmethod
    def _severity_for_related_events(related_events: list[SocEventRecord]) -> SocSeverity:
        for item in related_events:
            if item.event_type != "endpoint.telemetry.file":
                continue
            verdict = str(item.details.get("verdict") or "").casefold()
            if verdict in {"malicious", "quarantined"}:
                return SocSeverity.critical
            risk_flags = item.details.get("risk_flags")
            if isinstance(risk_flags, list) and risk_flags:
                return SocSeverity.high
        return SocSeverity.high


class EndpointUnsignedNetworkProcessRule:
    _PROCESS_EVENT_TYPE = "endpoint.telemetry.process"

    definition = DetectionRuleDefinition(
        rule_id="endpoint_unsigned_network_process",
        title="Endpoint unsigned network process",
        description="Flags unsigned or low-reputation endpoint processes that also report live network connections.",
        category="correlation",
        default_parameters={"window_hours": 24},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        if event.event_type != self._PROCESS_EVENT_TYPE:
            return None
        if not self._is_suspicious_process(event):
            return None
        device_id = self._event_device_id(event)
        identity = EndpointProcessFileOverlapRule._event_process_identity(event)
        if not device_id or not identity:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = [
            item
            for item in list_events(500)
            if item.created_at >= window_start
            and item.event_type == self._PROCESS_EVENT_TYPE
            and self._event_device_id(item) == device_id
            and EndpointProcessFileOverlapRule._event_process_identity(item) == identity
        ]
        if not any(self._has_live_network(item) for item in related_events):
            return None
        process_name = str(event.details.get("process_name") or identity)
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=f"{device_id}:{identity}",
            title=f"Unsigned networked process on {device_id}: {process_name}",
            summary="An unsigned or low-reputation endpoint process also reported live network connections.",
            severity=self._severity_for_related_events(related_events),
            related_events=tuple(related_events),
        )

    @staticmethod
    def _event_device_id(event: SocEventRecord) -> str | None:
        device_id = event.details.get("device_id")
        return device_id if isinstance(device_id, str) and device_id else None

    @staticmethod
    def _is_suspicious_process(event: SocEventRecord) -> bool:
        signer_status = str(event.details.get("signer_status") or "").casefold()
        reputation = str(event.details.get("reputation") or "").casefold()
        risk_flags = event.details.get("risk_flags")
        return (
            signer_status in {"unsigned", "invalid", "unknown"}
            or reputation in {"unknown", "suspicious", "malicious"}
            or (isinstance(risk_flags, list) and len(risk_flags) > 0)
        )

    @staticmethod
    def _has_live_network(event: SocEventRecord) -> bool:
        remote_ips = event.details.get("remote_ips")
        if isinstance(remote_ips, list) and remote_ips:
            return True
        network_connections = event.details.get("network_connections")
        return isinstance(network_connections, list) and len(network_connections) > 0

    @staticmethod
    def _severity_for_related_events(related_events: list[SocEventRecord]) -> SocSeverity:
        for item in related_events:
            reputation = str(item.details.get("reputation") or "").casefold()
            if reputation == "malicious":
                return SocSeverity.critical
            risk_flags = item.details.get("risk_flags")
            if isinstance(risk_flags, list) and risk_flags:
                return SocSeverity.high
        return SocSeverity.high


class EndpointConnectionNetworkOverlapRule:
    _ENDPOINT_EVENT_TYPE = "endpoint.telemetry.connection"
    _NETWORK_EVENT_TYPES = {"network.telemetry.connection", "packet.telemetry.session"}

    definition = DetectionRuleDefinition(
        rule_id="endpoint_connection_network_overlap",
        title="Endpoint and network connection overlap",
        description="Correlates endpoint connection telemetry with network or packet telemetry for the same remote IP.",
        category="correlation",
        default_parameters={"window_hours": 24},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        if event.event_type not in {self._ENDPOINT_EVENT_TYPE} | self._NETWORK_EVENT_TYPES:
            return None
        remote_ip = self._event_remote_ip(event)
        if not remote_ip:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = [
            item
            for item in list_events(500)
            if item.created_at >= window_start
            and item.event_type in ({self._ENDPOINT_EVENT_TYPE} | self._NETWORK_EVENT_TYPES)
            and self._event_remote_ip(item) == remote_ip
        ]
        has_endpoint = any(item.event_type == self._ENDPOINT_EVENT_TYPE for item in related_events)
        has_network = any(item.event_type in self._NETWORK_EVENT_TYPES for item in related_events)
        if not (has_endpoint and has_network):
            return None
        endpoint_event = next((item for item in related_events if item.event_type == self._ENDPOINT_EVENT_TYPE), event)
        device_id = str(endpoint_event.details.get("device_id") or "unknown-device")
        process_name = str(endpoint_event.details.get("process_name") or "unknown-process")
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=f"{device_id}:{process_name}:{remote_ip}",
            title=f"Endpoint and network overlap for {remote_ip}",
            summary="The same remote IP appeared in endpoint connection telemetry and network/session telemetry.",
            severity=self._severity_for_related_events(related_events),
            related_events=tuple(related_events),
        )

    @staticmethod
    def _event_remote_ip(event: SocEventRecord) -> str | None:
        remote_ip = event.details.get("remote_ip")
        return remote_ip if isinstance(remote_ip, str) and remote_ip else None

    @staticmethod
    def _severity_for_related_events(related_events: list[SocEventRecord]) -> SocSeverity:
        for item in related_events:
            sensitive_ports = item.details.get("sensitive_ports")
            if isinstance(sensitive_ports, list) and sensitive_ports:
                return SocSeverity.critical
            risk_flags = item.details.get("risk_flags")
            if isinstance(risk_flags, list) and risk_flags:
                return SocSeverity.high
        return SocSeverity.high


class EndpointTimelineExecutionChainRule:
    _EVENT_TYPES = {
        "endpoint.telemetry.process",
        "endpoint.telemetry.connection",
        "endpoint.telemetry.file",
    }

    definition = DetectionRuleDefinition(
        rule_id="endpoint_timeline_execution_chain",
        title="Endpoint timeline execution chain",
        description="Detects an ordered endpoint process, connection, and file-activity chain for the same process identity.",
        category="correlation",
        default_parameters={"window_hours": 24},
    )

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
        parameters: dict[str, Any],
    ) -> DetectionFinding | None:
        if event.event_type not in self._EVENT_TYPES:
            return None
        device_id = self._event_device_id(event)
        identity = self._event_process_identity(event)
        if not device_id or not identity:
            return None
        window_hours = int(parameters.get("window_hours", self.definition.default_parameters["window_hours"]))
        window_start = event.created_at - timedelta(hours=window_hours)
        related_events = sorted(
            [
                item
                for item in list_events(500)
                if item.created_at >= window_start
                and item.event_type in self._EVENT_TYPES
                and self._event_device_id(item) == device_id
                and self._event_process_identity(item) == identity
            ],
            key=lambda item: item.created_at,
        )
        suspicious_process = next((item for item in related_events if self._is_suspicious_process(item)), None)
        if suspicious_process is None:
            return None
        connection_event = next(
            (
                item
                for item in related_events
                if item.event_type == "endpoint.telemetry.connection" and item.created_at >= suspicious_process.created_at
            ),
            None,
        )
        if connection_event is None:
            return None
        file_event = next(
            (
                item
                for item in related_events
                if item.event_type == "endpoint.telemetry.file"
                and item.created_at >= connection_event.created_at
                and self._is_suspicious_file(item)
            ),
            None,
        )
        if file_event is None:
            return None
        process_name = str(suspicious_process.details.get("process_name") or identity)
        correlation_identity = (
            str(suspicious_process.details.get("process_guid") or "").strip()
            or str(suspicious_process.details.get("sha256") or "").strip()
            or identity
        )
        remote_ip = str(connection_event.details.get("remote_ip") or "unknown-remote")
        return DetectionFinding(
            rule_id=self.definition.rule_id,
            key=f"{device_id}:{correlation_identity}",
            title=f"Endpoint execution chain on {device_id}: {process_name}",
            summary=(
                f"A suspicious process on {device_id} established a connection to {remote_ip} "
                "and then performed suspicious file activity."
            ),
            severity=self._severity_for_chain(file_event=file_event, process_event=suspicious_process),
            related_events=(suspicious_process, connection_event, file_event),
        )

    @staticmethod
    def _event_device_id(event: SocEventRecord) -> str | None:
        device_id = event.details.get("device_id")
        return device_id if isinstance(device_id, str) and device_id else None

    @staticmethod
    def _event_process_identity(event: SocEventRecord) -> str | None:
        sha256 = event.details.get("sha256")
        if isinstance(sha256, str) and sha256:
            return sha256
        process_guid = event.details.get("process_guid")
        if isinstance(process_guid, str) and process_guid:
            return process_guid
        actor_sha256 = event.details.get("actor_process_sha256")
        if isinstance(actor_sha256, str) and actor_sha256:
            return actor_sha256
        process_name = event.details.get("process_name")
        if isinstance(process_name, str) and process_name:
            return process_name.casefold()
        actor_name = event.details.get("actor_process_name")
        if isinstance(actor_name, str) and actor_name:
            return actor_name.casefold()
        return None

    @staticmethod
    def _is_suspicious_process(event: SocEventRecord) -> bool:
        if event.event_type != "endpoint.telemetry.process":
            return False
        signer_status = str(event.details.get("signer_status") or "").casefold()
        reputation = str(event.details.get("reputation") or "").casefold()
        risk_flags = event.details.get("risk_flags")
        command_line = str(event.details.get("command_line") or "").casefold()
        return (
            signer_status in {"unsigned", "invalid", "unknown"}
            or reputation in {"suspicious", "malicious", "unknown"}
            or (isinstance(risk_flags, list) and len(risk_flags) > 0)
            or "-enc " in command_line
            or " encodedcommand" in command_line
        )

    @staticmethod
    def _is_suspicious_file(event: SocEventRecord) -> bool:
        if event.event_type != "endpoint.telemetry.file":
            return False
        verdict = str(event.details.get("verdict") or "").casefold()
        operation = str(event.details.get("operation") or "").casefold()
        reputation = str(event.details.get("reputation") or "").casefold()
        risk_flags = event.details.get("risk_flags")
        return (
            verdict in {"malicious", "quarantined"}
            or operation in {"created", "written", "downloaded"}
            or reputation in {"suspicious", "malicious"}
            or (isinstance(risk_flags, list) and len(risk_flags) > 0)
        )

    @staticmethod
    def _severity_for_chain(*, file_event: SocEventRecord, process_event: SocEventRecord) -> SocSeverity:
        verdict = str(file_event.details.get("verdict") or "").casefold()
        reputation = str(file_event.details.get("reputation") or "").casefold()
        if verdict in {"malicious", "quarantined"} or reputation == "malicious":
            return SocSeverity.critical
        process_reputation = str(process_event.details.get("reputation") or "").casefold()
        if process_reputation == "malicious":
            return SocSeverity.critical
        return SocSeverity.high


class DetectionEngine:
    def __init__(self, catalog_path: str | Path) -> None:
        self.catalog_path = Path(catalog_path)
        self.catalog_path.parent.mkdir(parents=True, exist_ok=True)
        self._rules: dict[str, DetectionRule] = {
            EndpointHighRiskDeviceRule.definition.rule_id: EndpointHighRiskDeviceRule(),
            RepeatedTrackerActivityRule.definition.rule_id: RepeatedTrackerActivityRule(),
            RepeatedMalwareArtifactRule.definition.rule_id: RepeatedMalwareArtifactRule(),
            SuspiciousSourceAccessRule.definition.rule_id: SuspiciousSourceAccessRule(),
            PacketNetworkRemoteOverlapRule.definition.rule_id: PacketNetworkRemoteOverlapRule(),
            EndpointProcessFileOverlapRule.definition.rule_id: EndpointProcessFileOverlapRule(),
            EndpointUnsignedNetworkProcessRule.definition.rule_id: EndpointUnsignedNetworkProcessRule(),
            EndpointConnectionNetworkOverlapRule.definition.rule_id: EndpointConnectionNetworkOverlapRule(),
            EndpointTimelineExecutionChainRule.definition.rule_id: EndpointTimelineExecutionChainRule(),
        }
        self._definitions: dict[str, DetectionRuleDefinition] = {
            rule_id: rule.definition
            for rule_id, rule in self._rules.items()
        }

    def list_rules(self) -> list[SocDetectionRuleRecord]:
        return [self._build_rule_record(rule_id, overrides) for rule_id, overrides in self._load_catalog().items()]

    def get_rule(self, rule_id: str) -> SocDetectionRuleRecord:
        catalog = self._load_catalog()
        if rule_id not in catalog:
            raise KeyError(f"Detection rule not found: {rule_id}")
        return self._build_rule_record(rule_id, catalog[rule_id])

    def update_rule(self, rule_id: str, payload: SocDetectionRuleUpdate) -> SocDetectionRuleRecord:
        catalog = self._load_catalog()
        if rule_id not in catalog:
            raise KeyError(f"Detection rule not found: {rule_id}")
        next_payload: RuleCatalogEntry = dict(catalog[rule_id])
        if payload.enabled is not None:
            next_payload["enabled"] = payload.enabled
        if payload.parameters:
            next_parameters: dict[str, Any] = dict(next_payload.get("parameters", {}))
            next_parameters.update(payload.parameters)
            next_payload["parameters"] = next_parameters
        catalog[rule_id] = next_payload
        self._write_catalog(catalog)
        return self._build_rule_record(rule_id, next_payload)

    def evaluate(
        self,
        *,
        event: SocEventRecord,
        list_events: EventLister,
    ) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        catalog = self._load_catalog()
        for rule_id, rule in self._rules.items():
            rule_entry = catalog.get(rule_id, {})
            if not bool(rule_entry.get("enabled", True)):
                continue
            finding = rule.evaluate(
                event=event,
                list_events=list_events,
                parameters=dict(rule_entry.get("parameters", {})),
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def _load_catalog(self) -> RuleCatalog:
        defaults: RuleCatalog = {
            rule_id: {
                "enabled": True,
                "parameters": dict(definition.default_parameters),
            }
            for rule_id, definition in self._definitions.items()
        }
        if not self.catalog_path.exists():
            self._write_catalog(defaults)
            return defaults
        try:
            payload = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            self._write_catalog(defaults)
            return defaults
        if not isinstance(payload, dict):
            self._write_catalog(defaults)
            return defaults
        merged: RuleCatalog = {
            rule_id: {
                "enabled": entry["enabled"],
                "parameters": dict(entry["parameters"]),
            }
            for rule_id, entry in defaults.items()
        }
        for rule_id, value in payload.items():
            if rule_id not in merged or not isinstance(value, dict):
                continue
            if "enabled" in value:
                merged[rule_id]["enabled"] = bool(value["enabled"])
            raw_parameters = value.get("parameters")
            if isinstance(raw_parameters, dict):
                parameters = merged[rule_id].get("parameters")
                if isinstance(parameters, dict):
                    parameters.update(raw_parameters)
        self._write_catalog(merged)
        return merged

    def _write_catalog(self, payload: RuleCatalog) -> None:
        self.catalog_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _build_rule_record(self, rule_id: str, payload: dict[str, Any]) -> SocDetectionRuleRecord:
        definition = self._definitions[rule_id]
        return SocDetectionRuleRecord(
            rule_id=definition.rule_id,
            title=definition.title,
            description=definition.description,
            category=definition.category,
            enabled=bool(payload.get("enabled", True)),
            parameters=dict(payload.get("parameters", {})),
        )
