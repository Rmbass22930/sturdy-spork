"""Risk scoring and zero-trust policy decisions."""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import List, Optional

from .alerts import AlertEvent, AlertLevel, alert_manager
from .config import settings
from .mfa import MFAService
from .models import AccessDecision, AccessRequest, Decision, DeviceCompliance
from .threat_response import ThreatResponseCoordinator
from .state import dns_security_cache
from .traceroute import TraceRouteRunner, TraceRouteResult


class RiskCalculator:
    def __init__(self, max_score: float = None):
        self.max_score = max_score or settings.max_risk_score

    def geo_distance_km(self, a_lat: float, a_lon: float, b_lat: float, b_lon: float) -> float:
        # Haversine formula
        radius = 6371.0
        lat1, lon1, lat2, lon2 = map(math.radians, [a_lat, a_lon, b_lat, b_lon])
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        return 2 * radius * math.asin(math.sqrt(h))

    def score(self, request: AccessRequest, dns_secure: Optional[bool] = None) -> float:
        score = 0.0
        device = request.device
        user = request.user

        if device.compliance == DeviceCompliance.drifted:
            score += 15
        elif device.compliance == DeviceCompliance.compromised:
            score += 40

        if not device.is_encrypted:
            score += 10
        if not device.edr_active:
            score += 10

        geo_distance = self.geo_distance_km(user.geo_lat, user.geo_lon, 0.0, 0.0)
        if geo_distance > settings.allowed_geo_radius_km:
            score += min(20, geo_distance / 25)

        now = datetime.now(timezone.utc)
        idle_hours = max(0.0, (now - user.last_login).total_seconds() / 3600)
        score += min(20, idle_hours / 2)

        if request.privilege_level == "privileged":
            score += 10

        if dns_secure is False:
            score += 10
        elif dns_secure is True:
            score = max(0.0, score - 5)

        for key, value in request.threat_signals.items():
            score += min(10, value)

        return min(score, self.max_score)


class PolicyEngine:
    def __init__(
        self,
        risk_calculator: RiskCalculator | None = None,
        mfa_service: MFAService | None = None,
        dns_cache=dns_security_cache,
        threat_responder: ThreatResponseCoordinator | None = None,
        traceroute_runner: TraceRouteRunner | None = None,
    ):
        self.risk_calculator = risk_calculator or RiskCalculator()
        self.mfa_service = mfa_service or MFAService()
        self.dns_cache = dns_cache
        self.threat_responder = threat_responder
        self.traceroute_runner = traceroute_runner or TraceRouteRunner(
            confirm_before_trace=settings.traceroute_require_confirmation,
            show_popup_results=settings.traceroute_show_popup_results,
            preview_lines=settings.traceroute_preview_lines,
        )

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        dns_secure = request.dns_secure
        if dns_secure is None and request.resource:
            dns_secure = self.dns_cache.get(request.resource)
        score = self.risk_calculator.score(request, dns_secure=dns_secure)
        self._handle_threat_response(request, score)
        reasons: List[str] = []

        if request.device.compliance == DeviceCompliance.compromised:
            reasons.append("Device reported as compromised")
        if not request.device.is_encrypted:
            reasons.append("Disk encryption disabled")
        if not request.device.edr_active:
            reasons.append("EDR agent inactive")
        if request.privilege_level == "privileged":
            reasons.append("Privileged resource requested")
        if dns_secure is False:
            reasons.append("DNSSEC validation failed for resource")

        trace_details: TraceRouteResult | None = None
        if (
            score >= settings.max_risk_score
            and request.source_ip
            and self._should_trace_real_threat(request, dns_secure=dns_secure)
        ):
            trace_context = f"resource={request.resource or 'unknown'}, score={score:.1f}"
            trace_details = self.traceroute_runner.trace(request.source_ip, context=trace_context)

        if score >= settings.max_risk_score:
            context = {"risk_score": score, "reasons": reasons, "source_ip": request.source_ip}
            if trace_details:
                context["traceroute"] = {
                    "target": trace_details.target,
                    "exit_code": trace_details.exit_code,
                    "error": trace_details.error,
                    "preview": trace_details.output.splitlines()[:5],
                    "declined": trace_details.declined,
                }
                if trace_details.declined:
                    reasons.append("Traceroute skipped by operator")
                else:
                    reasons.append("Traceroute captured for investigation")
            alert_manager.emit(
                AlertEvent(
                    level=AlertLevel.critical,
                    title="Access denied - high risk",
                    message=f"User {request.user.user_id} denied for {request.resource}",
                    context=context,
                )
            )
            return AccessDecision(decision=Decision.deny, risk_score=score, reasons=reasons + ["Risk above threshold"])

        requires_mfa = score >= settings.max_risk_score / 2 or request.privilege_level == "privileged"
        if requires_mfa:
            if not self.mfa_service.satisfy(request.user.user_id, request.mfa_token, request.webauthn):
                challenge = self.mfa_service.issue_challenge(request.user.user_id)
                reasons.append("Step-up MFA required")
                alert_manager.emit(
                    AlertEvent(
                        level=AlertLevel.warning,
                        title="Step-up MFA triggered",
                        message=f"User {request.user.user_id} requires MFA for {request.resource}",
                        context={"risk_score": score, "source_ip": request.source_ip},
                    )
                )
                return AccessDecision(
                    decision=Decision.step_up,
                    risk_score=score,
                    reasons=reasons,
                    issued_challenge=challenge.challenge_id,
                )

        return AccessDecision(decision=Decision.allow, risk_score=score, reasons=reasons)

    def _handle_threat_response(self, request: AccessRequest, score: float) -> None:
        if not self.threat_responder:
            return
        if not request.threat_signals and score < settings.threat_rotation_risk_threshold:
            return
        peak_signal = max(request.threat_signals.values(), default=0.0)
        metadata = {"resource": request.resource, "signals": request.threat_signals, "risk_score": score}
        if peak_signal >= settings.threat_rotation_signal_threshold:
            self.threat_responder.trigger_rotation("threat_signal", peak_signal, metadata)
        elif score >= settings.threat_rotation_risk_threshold:
            self.threat_responder.trigger_rotation("risk_score", score, metadata)

    def _should_trace_real_threat(self, request: AccessRequest, dns_secure: Optional[bool]) -> bool:
        corroborating_signals = 0
        if request.device.compliance == DeviceCompliance.compromised:
            corroborating_signals += 1
        if not request.device.is_encrypted:
            corroborating_signals += 1
        if not request.device.edr_active:
            corroborating_signals += 1
        if request.privilege_level == "privileged":
            corroborating_signals += 1
        if dns_secure is False:
            corroborating_signals += 1
        if any(value >= settings.threat_rotation_signal_threshold for value in request.threat_signals.values()):
            corroborating_signals += 1
        return corroborating_signals >= 2
