"""Pydantic models shared across modules."""
from __future__ import annotations

import math
from datetime import datetime
from enum import Enum
from ipaddress import ip_address
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class DeviceCompliance(str, Enum):
    compliant = "compliant"
    drifted = "drifted"
    compromised = "compromised"


class UserContext(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=254)
    groups: list[str] = Field(default_factory=list, max_length=32)
    geo_lat: float
    geo_lon: float
    last_login: datetime

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, value: list[str]) -> list[str]:
        for group in value:
            if not group or len(group) > 64:
                raise ValueError("Each group must be between 1 and 64 characters.")
        return value


class DeviceContext(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    os: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=64)
    compliance: DeviceCompliance
    is_encrypted: bool
    edr_active: bool


class EndpointProcessTelemetry(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    process_name: str = Field(min_length=1, max_length=256)
    process_guid: Optional[str] = Field(default=None, max_length=128)
    process_path: Optional[str] = Field(default=None, max_length=512)
    process_sha256: Optional[str] = Field(default=None, max_length=128)
    parent_process_name: Optional[str] = Field(default=None, max_length=256)
    parent_process_guid: Optional[str] = Field(default=None, max_length=128)
    parent_process_path: Optional[str] = Field(default=None, max_length=512)
    parent_process_sha256: Optional[str] = Field(default=None, max_length=128)
    parent_chain: list[str] = Field(default_factory=list, max_length=16)
    command_line: Optional[str] = Field(default=None, max_length=2_000)
    user_name: Optional[str] = Field(default=None, max_length=256)
    integrity_level: Optional[str] = Field(default=None, max_length=64)
    signer_name: Optional[str] = Field(default=None, max_length=256)
    signer_status: Optional[str] = Field(default=None, max_length=64)
    reputation: Optional[str] = Field(default=None, max_length=64)
    risk_flags: list[str] = Field(default_factory=list, max_length=32)
    remote_ips: list[str] = Field(default_factory=list, max_length=32)
    network_connections: list[dict[str, Any]] = Field(default_factory=list, max_length=64)

    @field_validator("parent_chain", "risk_flags", "remote_ips")
    @classmethod
    def validate_endpoint_telemetry_lists(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("List entries must be between 1 and 256 characters.")
        return value


class EndpointFileTelemetry(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    filename: str = Field(min_length=1, max_length=256)
    artifact_path: Optional[str] = Field(default=None, max_length=512)
    sha256: Optional[str] = Field(default=None, max_length=128)
    operation: str = Field(min_length=1, max_length=64)
    size_bytes: Optional[int] = Field(default=None, ge=0)
    verdict: Optional[str] = Field(default=None, max_length=256)
    actor_process_name: Optional[str] = Field(default=None, max_length=256)
    actor_process_sha256: Optional[str] = Field(default=None, max_length=128)
    signer_name: Optional[str] = Field(default=None, max_length=256)
    signer_status: Optional[str] = Field(default=None, max_length=64)
    reputation: Optional[str] = Field(default=None, max_length=64)
    file_extension: Optional[str] = Field(default=None, max_length=32)
    risk_flags: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("risk_flags")
    @classmethod
    def validate_file_risk_flags(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("Risk flags must be between 1 and 256 characters.")
        return value


class WebAuthnResponse(BaseModel):
    credential_id: str = Field(min_length=1, max_length=256)
    signature: str = Field(min_length=1, max_length=4096)
    challenge_id: str = Field(min_length=1, max_length=256)


class AccessRequest(BaseModel):
    user: UserContext
    device: DeviceContext
    resource: str = Field(min_length=1, max_length=256)
    privilege_level: str = Field(default="standard", min_length=1, max_length=32)
    threat_signals: Dict[str, float] = Field(default_factory=dict, max_length=32)
    mfa_token: Optional[str] = Field(default=None, max_length=512)
    dns_secure: Optional[bool] = None
    webauthn: Optional[WebAuthnResponse] = None
    source_ip: Optional[str] = None

    @field_validator("threat_signals")
    @classmethod
    def validate_threat_signals(cls, value: Dict[str, float]) -> Dict[str, float]:
        for key, signal in value.items():
            if not key or len(key) > 64:
                raise ValueError("Threat signal names must be between 1 and 64 characters.")
            if not math.isfinite(signal):
                raise ValueError("Threat signal values must be finite numbers.")
        return value

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return str(ip_address(value))


class Decision(str, Enum):
    allow = "allow"
    deny = "deny"
    step_up = "step_up"


class AccessIPBlockInfo(BaseModel):
    ip: str
    status: str
    reason: str
    blocked_by: Optional[str] = None
    expires_at: Optional[str] = None


class AccessDecision(BaseModel):
    decision: Decision
    risk_score: float
    reasons: list[str]
    issued_challenge: Optional[str] = None
    ip_block: Optional[AccessIPBlockInfo] = None


class CredentialLease(BaseModel):
    lease_id: str
    secret: str
    expires_at: datetime


class SocSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class SocAlertStatus(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    closed = "closed"


class SocCaseStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    contained = "contained"
    closed = "closed"


class SocEventIngest(BaseModel):
    event_type: str = Field(min_length=1, max_length=128)
    source: str = Field(default="security_gateway", min_length=1, max_length=64)
    severity: SocSeverity = SocSeverity.medium
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=2_000)
    details: Dict[str, Any] = Field(default_factory=dict)
    artifacts: list[str] = Field(default_factory=list, max_length=32)
    tags: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("artifacts", "tags")
    @classmethod
    def validate_string_lists(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("List entries must be between 1 and 256 characters.")
        return value


class SocEventRecord(SocEventIngest):
    event_id: str = Field(min_length=1, max_length=64)
    created_at: datetime
    linked_alert_id: Optional[str] = Field(default=None, max_length=64)


class SocAlertRecord(BaseModel):
    alert_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=2_000)
    severity: SocSeverity
    category: str = Field(default="event", min_length=1, max_length=64)
    status: SocAlertStatus = SocAlertStatus.open
    source_event_ids: list[str] = Field(default_factory=list, max_length=64)
    correlation_rule: Optional[str] = Field(default=None, max_length=128)
    correlation_key: Optional[str] = Field(default=None, max_length=256)
    linked_case_id: Optional[str] = Field(default=None, max_length=64)
    acknowledged_by: Optional[str] = Field(default=None, max_length=128)
    escalated_by: Optional[str] = Field(default=None, max_length=128)
    assignee: Optional[str] = Field(default=None, max_length=128)
    notes: list[str] = Field(default_factory=list, max_length=64)
    created_at: datetime
    updated_at: datetime

    @field_validator("source_event_ids", "notes")
    @classmethod
    def validate_record_lists(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 512:
                raise ValueError("List entries must be between 1 and 512 characters.")
        return value


class SocAlertUpdate(BaseModel):
    status: Optional[SocAlertStatus] = None
    assignee: Optional[str] = Field(default=None, max_length=128)
    note: Optional[str] = Field(default=None, max_length=512)
    acted_by: Optional[str] = Field(default=None, max_length=128)


class SocAlertPromoteCaseRequest(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    existing_case_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    assignee: Optional[str] = Field(default=None, max_length=128)
    note: Optional[str] = Field(default=None, max_length=512)
    acted_by: Optional[str] = Field(default=None, max_length=128)
    case_status: SocCaseStatus = SocCaseStatus.investigating
    alert_status: SocAlertStatus = SocAlertStatus.acknowledged


class SocCaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=2_000)
    severity: SocSeverity = SocSeverity.medium
    source_event_ids: list[str] = Field(default_factory=list, max_length=64)
    linked_alert_ids: list[str] = Field(default_factory=list, max_length=64)
    observables: list[str] = Field(default_factory=list, max_length=64)
    assignee: Optional[str] = Field(default=None, max_length=128)

    @field_validator("source_event_ids", "linked_alert_ids")
    @classmethod
    def validate_reference_lists(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 64:
                raise ValueError("Reference IDs must be between 1 and 64 characters.")
        return value

    @field_validator("observables")
    @classmethod
    def validate_observables(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("Observables must be between 1 and 256 characters.")
        return value


class SocPacketSessionCaseRequest(BaseModel):
    session_key: str = Field(min_length=1, max_length=256)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocPacketCaptureCaseRequest(BaseModel):
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocNetworkEvidenceCaseRequest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocProtocolEvidence(BaseModel):
    application_protocols: list[str] = Field(default_factory=list, max_length=32)
    hostnames: list[str] = Field(default_factory=list, max_length=32)
    indicators: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("application_protocols", "hostnames", "indicators")
    @classmethod
    def validate_protocol_evidence_lists(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("Protocol evidence entries must be between 1 and 256 characters.")
        return value


class SocNetworkSensorFlowIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    remote_port: int = Field(ge=1, le=65535)
    local_ip: str = Field(min_length=1, max_length=128)
    local_port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="tcp", min_length=1, max_length=32)
    state: str = Field(default="ESTABLISHED", min_length=1, max_length=64)
    flow_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    direction: str = Field(default="inbound", min_length=1, max_length=32)
    transport_family: Optional[str] = Field(default=None, min_length=1, max_length=32)
    service_name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    application_protocol: Optional[str] = Field(default=None, min_length=1, max_length=128)
    process_id: Optional[int] = Field(default=None, ge=0)
    process_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    hit_count: int = Field(default=1, ge=1, le=1_000_000)
    packet_count: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    byte_count: Optional[int] = Field(default=None, ge=0, le=10_000_000_000)
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    protocol_evidence: SocProtocolEvidence = Field(default_factory=SocProtocolEvidence)


class SocNetworkSensorSessionIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    local_ips: list[str] = Field(default_factory=list, max_length=32)
    local_ports: list[int] = Field(default_factory=list, max_length=64)
    remote_ports: list[int] = Field(default_factory=list, max_length=64)
    protocols: list[str] = Field(default_factory=list, max_length=32)
    transport_families: list[str] = Field(default_factory=list, max_length=32)
    service_names: list[str] = Field(default_factory=list, max_length=32)
    application_protocols: list[str] = Field(default_factory=list, max_length=32)
    flow_ids: list[str] = Field(default_factory=list, max_length=64)
    packet_count: int = Field(default=0, ge=0, le=10_000_000)
    total_packets: Optional[int] = Field(default=None, ge=0, le=10_000_000)
    sensitive_ports: list[int] = Field(default_factory=list, max_length=64)
    protocol_evidence: SocProtocolEvidence = Field(default_factory=SocProtocolEvidence)
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None

    @field_validator(
        "local_ips",
        "protocols",
        "transport_families",
        "service_names",
        "application_protocols",
        "flow_ids",
    )
    @classmethod
    def validate_sensor_session_string_lists(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("Session string entries must be between 1 and 256 characters.")
        return value


class SocNetworkSensorDnsIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=256)
    record_type: str = Field(default="A", min_length=1, max_length=32)
    local_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    flow_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    answers: list[str] = Field(default_factory=list, max_length=32)
    response_code: Optional[str] = Field(default=None, min_length=1, max_length=64)
    dns_secure: Optional[bool] = None
    observed_at: Optional[datetime] = None

    @field_validator("answers")
    @classmethod
    def validate_dns_answers(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("DNS answers must be between 1 and 256 characters.")
        return value


class SocNetworkSensorHttpIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=256)
    method: str = Field(min_length=1, max_length=32)
    path: str = Field(default="/", min_length=1, max_length=512)
    local_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    flow_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    user_agent: Optional[str] = Field(default=None, min_length=1, max_length=512)
    observed_at: Optional[datetime] = None


class SocNetworkSensorTlsIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    server_name: str = Field(min_length=1, max_length=256)
    local_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    flow_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    tls_version: Optional[str] = Field(default=None, min_length=1, max_length=64)
    ja3: Optional[str] = Field(default=None, min_length=1, max_length=128)
    ja3s: Optional[str] = Field(default=None, min_length=1, max_length=128)
    issuer: Optional[str] = Field(default=None, min_length=1, max_length=256)
    subject: Optional[str] = Field(default=None, min_length=1, max_length=256)
    observed_at: Optional[datetime] = None


class SocNetworkSensorCertificateIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=256)
    local_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    flow_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    serial_number: Optional[str] = Field(default=None, min_length=1, max_length=256)
    sha1: Optional[str] = Field(default=None, min_length=1, max_length=128)
    sha256: Optional[str] = Field(default=None, min_length=1, max_length=128)
    issuer: Optional[str] = Field(default=None, min_length=1, max_length=256)
    subject: Optional[str] = Field(default=None, min_length=1, max_length=256)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    ja3: Optional[str] = Field(default=None, min_length=1, max_length=128)
    ja3s: Optional[str] = Field(default=None, min_length=1, max_length=128)
    observed_at: Optional[datetime] = None


class SocNetworkSensorProxyIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=256)
    proxy_type: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    local_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    username: Optional[str] = Field(default=None, min_length=1, max_length=128)
    flow_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    observed_at: Optional[datetime] = None


class SocNetworkSensorAuthIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    outcome: str = Field(min_length=1, max_length=64)
    auth_protocol: str = Field(min_length=1, max_length=64)
    realm: Optional[str] = Field(default=None, min_length=1, max_length=256)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=256)
    local_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    flow_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    observed_at: Optional[datetime] = None


class SocNetworkSensorVpnIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    tunnel_type: str = Field(min_length=1, max_length=64)
    assigned_ip: str = Field(min_length=1, max_length=128)
    outcome: str = Field(min_length=1, max_length=64)
    gateway: Optional[str] = Field(default=None, min_length=1, max_length=256)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=256)
    session_event: Optional[str] = Field(default=None, min_length=1, max_length=64)
    close_reason: Optional[str] = Field(default=None, min_length=1, max_length=256)
    duration_seconds: Optional[int] = Field(default=None, ge=0)
    observed_at: Optional[datetime] = None


class SocNetworkSensorDhcpIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    assigned_ip: str = Field(min_length=1, max_length=128)
    mac_address: str = Field(min_length=1, max_length=64)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=256)
    lease_action: str = Field(min_length=1, max_length=64)
    observed_at: Optional[datetime] = None


class SocNetworkSensorDirectoryAuthIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    directory_service: str = Field(min_length=1, max_length=64)
    outcome: str = Field(min_length=1, max_length=64)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=256)
    realm: Optional[str] = Field(default=None, min_length=1, max_length=256)
    observed_at: Optional[datetime] = None


class SocNetworkSensorRadiusIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    username: str = Field(min_length=1, max_length=128)
    outcome: str = Field(min_length=1, max_length=64)
    reject_reason: Optional[str] = Field(default=None, min_length=1, max_length=256)
    reject_code: Optional[str] = Field(default=None, min_length=1, max_length=64)
    nas_identifier: Optional[str] = Field(default=None, min_length=1, max_length=256)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=256)
    realm: Optional[str] = Field(default=None, min_length=1, max_length=256)
    observed_at: Optional[datetime] = None


class SocNetworkSensorNacIngest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    mac_address: str = Field(min_length=1, max_length=64)
    hostname: Optional[str] = Field(default=None, min_length=1, max_length=256)
    posture: str = Field(min_length=1, max_length=64)
    previous_posture: Optional[str] = Field(default=None, min_length=1, max_length=64)
    transition_reason: Optional[str] = Field(default=None, min_length=1, max_length=256)
    action: str = Field(min_length=1, max_length=64)
    observed_at: Optional[datetime] = None


class SocNetworkSensorTelemetryIngest(BaseModel):
    sensor_name: str = Field(min_length=1, max_length=128)
    source: str = Field(default="external_sensor", min_length=1, max_length=64)
    checked_at: Optional[datetime] = None
    flows: list[SocNetworkSensorFlowIngest] = Field(default_factory=list, max_length=256)
    sessions: list[SocNetworkSensorSessionIngest] = Field(default_factory=list, max_length=256)
    dns_records: list[SocNetworkSensorDnsIngest] = Field(default_factory=list, max_length=256)
    http_records: list[SocNetworkSensorHttpIngest] = Field(default_factory=list, max_length=256)
    tls_records: list[SocNetworkSensorTlsIngest] = Field(default_factory=list, max_length=256)
    certificate_records: list[SocNetworkSensorCertificateIngest] = Field(default_factory=list, max_length=256)
    proxy_records: list[SocNetworkSensorProxyIngest] = Field(default_factory=list, max_length=256)
    auth_records: list[SocNetworkSensorAuthIngest] = Field(default_factory=list, max_length=256)
    vpn_records: list[SocNetworkSensorVpnIngest] = Field(default_factory=list, max_length=256)
    dhcp_records: list[SocNetworkSensorDhcpIngest] = Field(default_factory=list, max_length=256)
    directory_auth_records: list[SocNetworkSensorDirectoryAuthIngest] = Field(default_factory=list, max_length=256)
    radius_records: list[SocNetworkSensorRadiusIngest] = Field(default_factory=list, max_length=256)
    nac_records: list[SocNetworkSensorNacIngest] = Field(default_factory=list, max_length=256)
    tags: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("tags")
    @classmethod
    def validate_sensor_tags(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("Tags must be between 1 and 256 characters.")
        return value


class SocRemoteNodeCaseRequest(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocEndpointTimelineCaseRequest(BaseModel):
    device_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    process_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    process_guid: Optional[str] = Field(default=None, min_length=1, max_length=128)
    remote_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    signer_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    sha256: Optional[str] = Field(default=None, min_length=1, max_length=128)
    limit: int = Field(default=200, ge=1, le=500)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocEndpointQueryCaseRequest(BaseModel):
    limit: int = Field(default=200, ge=1, le=500)
    device_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    process_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    process_guid: Optional[str] = Field(default=None, min_length=1, max_length=128)
    remote_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    signer_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    sha256: Optional[str] = Field(default=None, min_length=1, max_length=128)
    filename: Optional[str] = Field(default=None, min_length=1, max_length=256)
    artifact_path: Optional[str] = Field(default=None, min_length=1, max_length=512)
    local_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    local_port: Optional[str] = Field(default=None, min_length=1, max_length=16)
    remote_port: Optional[str] = Field(default=None, min_length=1, max_length=16)
    protocol: Optional[str] = Field(default=None, min_length=1, max_length=32)
    state: Optional[str] = Field(default=None, min_length=1, max_length=64)
    document_type: Optional[str] = Field(default=None, min_length=1, max_length=64)
    parent_process_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    reputation: Optional[str] = Field(default=None, min_length=1, max_length=64)
    risk_flag: Optional[str] = Field(default=None, min_length=1, max_length=128)
    verdict: Optional[str] = Field(default=None, min_length=1, max_length=64)
    operation: Optional[str] = Field(default=None, min_length=1, max_length=64)
    file_extension: Optional[str] = Field(default=None, min_length=1, max_length=32)
    start_at: Optional[datetime] = None
    end_at: Optional[datetime] = None
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocEndpointLineageClusterCaseRequest(BaseModel):
    cluster_key: str = Field(min_length=1, max_length=256)
    device_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    process_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    process_guid: Optional[str] = Field(default=None, min_length=1, max_length=128)
    remote_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    signer_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    sha256: Optional[str] = Field(default=None, min_length=1, max_length=128)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocTelemetryClusterCaseRequest(BaseModel):
    cluster_by: str = Field(default="remote_ip", pattern="^(remote_ip|device_id|process_guid)$")
    cluster_key: str = Field(min_length=1, max_length=256)
    device_id: Optional[str] = Field(default=None, min_length=1, max_length=128)
    process_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    process_guid: Optional[str] = Field(default=None, min_length=1, max_length=128)
    remote_ip: Optional[str] = Field(default=None, min_length=1, max_length=128)
    signer_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    sha256: Optional[str] = Field(default=None, min_length=1, max_length=128)
    filename: Optional[str] = Field(default=None, min_length=1, max_length=256)
    artifact_path: Optional[str] = Field(default=None, min_length=1, max_length=512)
    session_key: Optional[str] = Field(default=None, min_length=1, max_length=256)
    start_at: Optional[datetime] = None
    end_at: Optional[datetime] = None
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocCaseEndpointTimelineClusterCaseRequest(BaseModel):
    cluster_by: str = Field(default="process", pattern="^(process|remote_ip)$")
    cluster_key: str = Field(min_length=1, max_length=256)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocCaseEndpointLineageClusterCaseRequest(BaseModel):
    cluster_key: str = Field(min_length=1, max_length=256)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocCaseRuleGroupCaseRequest(BaseModel):
    group_key: str = Field(min_length=1, max_length=256)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocCaseTelemetryClusterCaseRequest(BaseModel):
    cluster_by: str = Field(default="remote_ip", pattern="^(remote_ip|device_id|process_guid)$")
    cluster_key: str = Field(min_length=1, max_length=256)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


class SocDashboardViewStateUpdate(BaseModel):
    operational_reason_filter: Optional[str] = Field(default=None, max_length=128)
    hunt_cluster_mode: Optional[str] = Field(default=None, pattern="^(remote_ip|device_id|process_guid)$")
    hunt_cluster_value: Optional[str] = Field(default=None, max_length=256)
    hunt_cluster_key: Optional[str] = Field(default=None, max_length=256)
    hunt_cluster_action: Optional[str] = Field(default=None, pattern="^(events|existing_case|case|details)$")
    endpoint_timeline_cluster_mode: Optional[str] = Field(default=None, pattern="^(process|remote_ip)$")
    endpoint_timeline_cluster_key: Optional[str] = Field(default=None, max_length=256)
    endpoint_timeline_cluster_action: Optional[str] = Field(default=None, pattern="^(events|existing_case|case|details)$")
    endpoint_lineage_cluster_mode: Optional[str] = Field(default=None, pattern="^(device_id|process_guid|remote_ip|filename)$")
    endpoint_lineage_cluster_value: Optional[str] = Field(default=None, max_length=256)
    endpoint_lineage_cluster_key: Optional[str] = Field(default=None, max_length=256)
    endpoint_lineage_cluster_action: Optional[str] = Field(default=None, pattern="^(events|existing_case|case|details)$")


class SocCaseRecord(SocCaseCreate):
    case_id: str = Field(min_length=1, max_length=64)
    status: SocCaseStatus = SocCaseStatus.open
    notes: list[str] = Field(default_factory=list, max_length=64)
    created_at: datetime
    updated_at: datetime


class SocCaseUpdate(BaseModel):
    status: Optional[SocCaseStatus] = None
    assignee: Optional[str] = Field(default=None, max_length=128)
    note: Optional[str] = Field(default=None, max_length=512)
    observable: Optional[str] = Field(default=None, max_length=256)


class SocDetectionRuleRecord(BaseModel):
    rule_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=512)
    category: str = Field(default="correlation", min_length=1, max_length=64)
    enabled: bool = True
    parameters: Dict[str, Any] = Field(default_factory=dict)
    hit_count: int = 0
    open_alert_count: int = 0
    last_match_at: Optional[datetime] = None


class SocDetectionRuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)


class PlatformNodeAcknowledgeRequest(BaseModel):
    acknowledged_by: Optional[str] = Field(default=None, max_length=128)
    note: Optional[str] = Field(default=None, max_length=512)


class PlatformNodeSuppressRequest(BaseModel):
    suppressed_by: Optional[str] = Field(default=None, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=512)
    minutes: int = Field(default=60, ge=1, le=10_080)
    scopes: list[str] = Field(default_factory=lambda: ["remote_node_health"], max_length=16)


class PlatformNodeMaintenanceRequest(BaseModel):
    started_by: Optional[str] = Field(default=None, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=512)
    minutes: int = Field(default=60, ge=1, le=10_080)
    services: list[str] = Field(default_factory=list, max_length=32)


class PlatformNodeRefreshRequest(BaseModel):
    requested_by: Optional[str] = Field(default=None, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=512)


class PlatformNodeDrainRequest(BaseModel):
    drained_by: Optional[str] = Field(default=None, max_length=128)
    reason: Optional[str] = Field(default=None, max_length=512)
    services: list[str] = Field(default_factory=list, max_length=32)


class PlatformNodeActionUpdateRequest(BaseModel):
    acted_by: Optional[str] = Field(default=None, max_length=128)
    note: Optional[str] = Field(default=None, max_length=512)
    result: Optional[str] = Field(default=None, max_length=64)


class LinearAsksFormUpsert(BaseModel):
    form_key: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    url: str = Field(min_length=8, max_length=2048)
    description: Optional[str] = Field(default=None, max_length=512)
    category: Optional[str] = Field(default=None, max_length=64)
    team: Optional[str] = Field(default=None, max_length=64)
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Linear form URL must be an absolute http or https URL.")
        return value.strip()


class LinearAsksFormRecord(LinearAsksFormUpsert):
    created_at: datetime
    updated_at: datetime


class DockerResourceRecord(BaseModel):
    resource_key: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=8, max_length=2048)
    summary: str = Field(min_length=1, max_length=600)
    category: str = Field(min_length=1, max_length=64)
    announced_at: datetime
    toolchain_relevance: str = Field(min_length=1, max_length=600)

    @field_validator("url")
    @classmethod
    def validate_docker_resource_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Docker resource URL must be an absolute http or https URL.")
        return value.strip()


class ToolchainUpdateRecord(BaseModel):
    update_id: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=64)
    resource_type: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=8, max_length=2048)
    summary: str = Field(min_length=1, max_length=600)
    announced_at: Optional[datetime] = None
    first_seen_at: datetime
    last_seen_at: datetime
    status: str = Field(default="new", pattern="^(new|seen|applied|ignored)$")
    load_policy: str = Field(default="manual_review", pattern="^(safe_catalog|manual_review)$")
    loaded: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def validate_update_url(cls, value: str) -> str:
        parsed = urlparse(value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Toolchain update URL must be an absolute http or https URL.")
        return value.strip()


class ToolchainProviderRecord(BaseModel):
    provider_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    category: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=600)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    configured: bool = False
    enabled: bool = True
    auto_loaded: bool = False
    update_source: Optional[str] = Field(default=None, max_length=128)
    status: str = Field(default="partial", pattern="^(ready|partial|disabled)$")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def validate_provider_capabilities(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 128:
                raise ValueError("Capabilities must be between 1 and 128 characters.")
        return value


class ToolchainHealthRecord(BaseModel):
    check_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="warning", pattern="^(ok|warning|error)$")
    summary: str = Field(min_length=1, max_length=600)
    checked_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainSecurityCheckRecord(BaseModel):
    check_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="warning", pattern="^(ok|warning|error)$")
    severity: str = Field(default="medium", pattern="^(low|medium|high)$")
    summary: str = Field(min_length=1, max_length=600)
    checked_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainLanguageRecord(BaseModel):
    language_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="missing", pattern="^(available|missing)$")
    detected: bool = False
    primary_command: Optional[str] = Field(default=None, max_length=128)
    executable_path: Optional[str] = Field(default=None, max_length=1024)
    version: Optional[str] = Field(default=None, max_length=256)
    package_managers: list[str] = Field(default_factory=list, max_length=16)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("package_managers")
    @classmethod
    def validate_package_managers(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 128:
                raise ValueError("Package managers must be between 1 and 128 characters.")
        return value


class ToolchainLanguageHealthRecord(BaseModel):
    language_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="warning", pattern="^(ok|warning|error)$")
    summary: str = Field(min_length=1, max_length=600)
    checked_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainPackageManagerRecord(BaseModel):
    manager_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="missing", pattern="^(available|missing)$")
    detected: bool = False
    executable_path: Optional[str] = Field(default=None, max_length=1024)
    version: Optional[str] = Field(default=None, max_length=256)
    related_languages: list[str] = Field(default_factory=list, max_length=16)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("related_languages")
    @classmethod
    def validate_related_languages(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 128:
                raise ValueError("Related language entries must be between 1 and 128 characters.")
        return value


class ToolchainSecretSourceRecord(BaseModel):
    secret_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    source: str = Field(default="missing", pattern="^(env|static_config|vault_secret_ref|override_store|generated_runtime|missing)$")
    status: str = Field(default="warning", pattern="^(ok|warning|error)$")
    summary: str = Field(min_length=1, max_length=600)
    configured: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainProvisioningActionRecord(BaseModel):
    target_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    target_type: str = Field(min_length=1, max_length=32, pattern="^(language|package_manager)$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="pending", pattern="^(ready|pending)$")
    summary: str = Field(min_length=1, max_length=600)
    install_commands: list[str] = Field(default_factory=list, max_length=8)
    repair_commands: list[str] = Field(default_factory=list, max_length=8)
    verify_commands: list[str] = Field(default_factory=list, max_length=8)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("install_commands", "repair_commands", "verify_commands")
    @classmethod
    def validate_install_commands(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 512:
                raise ValueError("Install commands must be between 1 and 512 characters.")
        return value


class ToolchainPackageOperationRecord(BaseModel):
    manager_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    operation: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    command: list[str] = Field(default_factory=list, max_length=16)
    supported: bool = True
    dry_run: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("command")
    @classmethod
    def validate_operation_command(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("Command tokens must be between 1 and 256 characters.")
        return value


class ToolchainVersionPolicyResultRecord(BaseModel):
    target_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    target_type: str = Field(min_length=1, max_length=32, pattern="^(language|package_manager)$")
    title: str = Field(min_length=1, max_length=160)
    minimum_version: str = Field(min_length=1, max_length=64)
    current_version: Optional[str] = Field(default=None, max_length=256)
    status: str = Field(default="unknown", pattern="^(compliant|noncompliant|unknown)$")
    summary: str = Field(min_length=1, max_length=600)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainCacheEntryRecord(BaseModel):
    namespace: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    cache_key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    status: str = Field(default="fresh", pattern="^(fresh|stale|expired)$")
    source: str = Field(min_length=1, max_length=64)
    summary: str = Field(min_length=1, max_length=600)
    updated_at: datetime
    expires_at: Optional[datetime] = None
    payload: Any = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainSecretResolutionRecord(BaseModel):
    secret_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    source: str = Field(default="missing", pattern="^(env|static_config|vault_secret_ref|override_store|generated_runtime|missing)$")
    status: str = Field(default="unresolved", pattern="^(resolved|unresolved|error)$")
    summary: str = Field(min_length=1, max_length=600)
    masked_value: Optional[str] = Field(default=None, max_length=128)
    resolved_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainSecretMutationRecord(BaseModel):
    secret_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    action: str = Field(default="set", pattern="^(set|clear)$")
    source: str = Field(default="missing", pattern="^(vault_secret_ref|override_store|missing)$")
    status: str = Field(default="applied", pattern="^(applied|cleared|failed|not_found)$")
    summary: str = Field(min_length=1, max_length=600)
    updated_at: datetime
    masked_value: Optional[str] = Field(default=None, max_length=128)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainProviderTemplateRecord(BaseModel):
    provider_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    category: str = Field(min_length=1, max_length=64)
    description: str = Field(min_length=1, max_length=600)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    required_settings: list[str] = Field(default_factory=list, max_length=32)
    optional_settings: list[str] = Field(default_factory=list, max_length=32)
    update_source: Optional[str] = Field(default=None, max_length=128)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("capabilities", "required_settings", "optional_settings")
    @classmethod
    def validate_provider_template_lists(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 128:
                raise ValueError("Provider template list entries must be between 1 and 128 characters.")
        return value


class ToolchainPolicyEnforcementRecord(BaseModel):
    policy_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="warn", pattern="^(allow|warn|block)$")
    summary: str = Field(min_length=1, max_length=600)
    checked_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainProjectRecord(BaseModel):
    project_id: str = Field(min_length=1, max_length=256)
    root_path: str = Field(min_length=1, max_length=2048)
    title: str = Field(min_length=1, max_length=256)
    ecosystems: list[str] = Field(default_factory=list, max_length=32)
    manifests: list[str] = Field(default_factory=list, max_length=64)
    package_manager_ids: list[str] = Field(default_factory=list, max_length=32)
    dependency_files: list[str] = Field(default_factory=list, max_length=64)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("ecosystems", "manifests", "package_manager_ids", "dependency_files")
    @classmethod
    def validate_project_lists(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 512:
                raise ValueError("Project list entries must be between 1 and 512 characters.")
        return value


class ToolchainJobRecord(BaseModel):
    job_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="ready", pattern="^(ready|running|completed|failed)$")
    summary: str = Field(min_length=1, max_length=600)
    last_run_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainScheduleRecord(BaseModel):
    schedule_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    job_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="active", pattern="^(active|paused)$")
    interval_minutes: int = Field(ge=1, le=10_080)
    next_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    last_status: Optional[str] = Field(default=None, pattern="^(ready|running|completed|failed)$")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainSchedulerRuntimeRecord(BaseModel):
    enabled: bool = False
    running: bool = False
    poll_seconds: float = Field(default=60.0, ge=0.01, le=86_400.0)
    started_at: Optional[datetime] = None
    last_tick_at: Optional[datetime] = None
    last_run_count: int = Field(default=0, ge=0)
    summary: str = Field(min_length=1, max_length=600)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ToolchainBootstrapResultRecord(BaseModel):
    target_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="planned", pattern="^(planned|executed|failed|not_found)$")
    mode: str = Field(default="install", pattern="^(install|repair)$")
    summary: Optional[str] = Field(default=None, max_length=600)
    command: list[str] = Field(default_factory=list, max_length=32)
    project_path: Optional[str] = Field(default=None, max_length=2048)
    returncode: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    verify_command: list[str] = Field(default_factory=list, max_length=32)
    verify_returncode: Optional[int] = None
    verify_stdout: Optional[str] = None
    verify_stderr: Optional[str] = None
    verified: Optional[bool] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("command", "verify_command")
    @classmethod
    def validate_bootstrap_command(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item or len(item) > 256:
                raise ValueError("Bootstrap command tokens must be between 1 and 256 characters.")
        return value


class ToolchainPolicyGateRecord(BaseModel):
    gate_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9._-]*$")
    title: str = Field(min_length=1, max_length=160)
    status: str = Field(default="warn", pattern="^(allow|warn|block)$")
    summary: str = Field(min_length=1, max_length=600)
    evaluated_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict)
