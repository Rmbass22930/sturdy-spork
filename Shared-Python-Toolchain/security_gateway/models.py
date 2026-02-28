"""Pydantic models shared across modules."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, Optional

from pydantic import BaseModel, Field


class DeviceCompliance(str, Enum):
    compliant = "compliant"
    drifted = "drifted"
    compromised = "compromised"


class UserContext(BaseModel):
    user_id: str
    email: str
    groups: list[str] = Field(default_factory=list)
    geo_lat: float
    geo_lon: float
    last_login: datetime


class DeviceContext(BaseModel):
    device_id: str
    os: str
    os_version: str
    compliance: DeviceCompliance
    is_encrypted: bool
    edr_active: bool


class WebAuthnResponse(BaseModel):
    credential_id: str
    signature: str
    challenge_id: str


class AccessRequest(BaseModel):
    user: UserContext
    device: DeviceContext
    resource: str
    privilege_level: str = "standard"
    threat_signals: Dict[str, float] = Field(default_factory=dict)
    mfa_token: Optional[str] = None
    dns_secure: Optional[bool] = None
    webauthn: Optional[WebAuthnResponse] = None
    source_ip: Optional[str] = None


class Decision(str, Enum):
    allow = "allow"
    deny = "deny"
    step_up = "step_up"


class AccessDecision(BaseModel):
    decision: Decision
    risk_score: float
    reasons: list[str]
    issued_challenge: Optional[str] = None


class CredentialLease(BaseModel):
    lease_id: str
    secret: str
    expires_at: datetime
