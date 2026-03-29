"""Pydantic models shared across modules."""
from __future__ import annotations

import math
from datetime import datetime
from enum import Enum
from ipaddress import ip_address
from typing import Dict, Optional

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
