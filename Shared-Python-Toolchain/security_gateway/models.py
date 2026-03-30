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
