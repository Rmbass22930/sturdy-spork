from datetime import datetime, timedelta, timezone

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_gateway.mfa import MFAService
from security_gateway.models import AccessRequest, DeviceCompliance, DeviceContext, Decision, UserContext, WebAuthnResponse
from security_gateway.policy import PolicyEngine
from security_gateway.utils import generate_totp
from security_gateway.config import settings


def _base_request(privilege: str = "standard") -> AccessRequest:
    user = UserContext(
        user_id="user-123",
        email="user@example.com",
        groups=["engineering"],
        geo_lat=37.7749,
        geo_lon=-122.4194,
        last_login=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    device = DeviceContext(
        device_id="device-1",
        os="macOS",
        os_version="15.0",
        compliance=DeviceCompliance.compliant,
        is_encrypted=True,
        edr_active=True,
    )
    return AccessRequest(user=user, device=device, resource="git", privilege_level=privilege)


def test_privileged_request_requires_mfa_step_up():
    mfa = MFAService()
    engine = PolicyEngine(mfa_service=mfa)
    decision = engine.evaluate(_base_request(privilege="privileged"))
    assert decision.decision == Decision.step_up
    assert decision.issued_challenge


def test_mfa_token_allows_privileged_access():
    mfa = MFAService()
    engine = PolicyEngine(mfa_service=mfa)
    request = _base_request(privilege="privileged")
    secret = mfa._get_secret(request.user.user_id)  # pylint: disable=protected-access
    timestep = mfa._timestep  # pylint: disable=protected-access
    token = generate_totp(secret, timestep)
    request.mfa_token = token
    decision = engine.evaluate(request)
    assert decision.decision == Decision.allow


def test_webauthn_response_allows_privileged_access():
    mfa = MFAService()
    engine = PolicyEngine(mfa_service=mfa)
    request = _base_request(privilege="privileged")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    credential_id = "cred-1"
    mfa.register_webauthn(request.user.user_id, credential_id, public_key_b64=base64.b64encode(public_key).decode())
    challenge = mfa.issue_challenge(request.user.user_id)
    signature = private_key.sign(challenge.challenge_id.encode())
    response = WebAuthnResponse(
        credential_id=credential_id,
        signature=base64.b64encode(signature).decode(),
        challenge_id=challenge.challenge_id,
    )
    request.webauthn = response
    decision = engine.evaluate(request)
    assert decision.decision == Decision.allow


def test_dns_insecure_adds_reason():
    engine = PolicyEngine()
    request = _base_request()
    request.dns_secure = False
    decision = engine.evaluate(request)
    assert "DNSSEC validation failed for resource" in decision.reasons


class DummyThreatResponder:
    def __init__(self):
        self.calls = []

    def trigger_rotation(self, source, severity, metadata=None):
        self.calls.append({"source": source, "severity": severity, "metadata": metadata})
        return True


def test_threat_signal_triggers_rotation():
    responder = DummyThreatResponder()
    engine = PolicyEngine(threat_responder=responder)
    request = _base_request()
    request.threat_signals = {"credential_leak": settings.threat_rotation_signal_threshold + 1}
    engine.evaluate(request)
    assert responder.calls
    assert responder.calls[0]["source"] == "threat_signal"


def test_risk_threshold_triggers_rotation_without_signal():
    responder = DummyThreatResponder()
    engine = PolicyEngine(threat_responder=responder)
    request = _base_request()
    request.device.compliance = DeviceCompliance.compromised
    request.device.is_encrypted = False
    request.device.edr_active = False
    engine.evaluate(request)
    assert responder.calls
    assert responder.calls[0]["source"] == "risk_score"


class DummyTraceRunner:
    def __init__(self):
        self.calls = []

    def trace(self, target, context=None):
        self.calls.append({"target": target, "context": context})
        return None


def test_traceroute_runs_only_for_corroborated_real_threat():
    trace_runner = DummyTraceRunner()
    engine = PolicyEngine(traceroute_runner=trace_runner)
    request = _base_request(privilege="privileged")
    request.source_ip = "203.0.113.10"
    request.device.compliance = DeviceCompliance.compromised
    request.device.is_encrypted = False
    request.device.edr_active = False
    request.dns_secure = False

    decision = engine.evaluate(request)

    assert decision.decision == Decision.deny
    assert len(trace_runner.calls) == 1
    assert trace_runner.calls[0]["target"] == "203.0.113.10"


def test_traceroute_does_not_run_on_uncorroborated_high_score():
    trace_runner = DummyTraceRunner()
    engine = PolicyEngine(traceroute_runner=trace_runner)
    request = _base_request()
    request.source_ip = "203.0.113.11"

    class FixedRisk:
        def score(self, request, dns_secure=None):
            return settings.max_risk_score

    engine.risk_calculator = FixedRisk()
    decision = engine.evaluate(request)

    assert decision.decision == Decision.deny
    assert trace_runner.calls == []
