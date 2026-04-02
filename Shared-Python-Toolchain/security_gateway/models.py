"""Pydantic models shared across modules."""
from __future__ import annotations

import math
from datetime import datetime
from enum import Enum
from ipaddress import ip_address
from typing import Any, Dict, Optional

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


class SocNetworkEvidenceCaseRequest(BaseModel):
    remote_ip: str = Field(min_length=1, max_length=128)
    title: Optional[str] = Field(default=None, min_length=1, max_length=160)
    summary: Optional[str] = Field(default=None, min_length=1, max_length=2_000)
    severity: Optional[SocSeverity] = None
    assignee: Optional[str] = Field(default=None, max_length=128)


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
