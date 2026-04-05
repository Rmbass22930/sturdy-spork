"""Policy gate evaluation built on top of toolchain enforcement state."""
from __future__ import annotations

from datetime import UTC, datetime

from security_gateway.models import ToolchainPolicyEnforcementRecord, ToolchainPolicyGateRecord
from toolchain_resources.policy_enforcement import ToolchainPolicyEnforcementRegistry


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ToolchainPolicyGateRegistry:
    def __init__(self, enforcement: ToolchainPolicyEnforcementRegistry) -> None:
        self.enforcement = enforcement

    def evaluate(self) -> list[ToolchainPolicyGateRecord]:
        now = _utc_now()
        decisions = {item.policy_id: item for item in self.enforcement.evaluate()}
        startup = self._startup_gate(now, decisions)
        ci = self._ci_gate(now, decisions)
        packaging = self._packaging_gate(now, decisions)
        return [startup, ci, packaging]

    def get_gate(self, gate_id: str) -> ToolchainPolicyGateRecord | None:
        for gate in self.evaluate():
            if gate.gate_id == gate_id:
                return gate
        return None

    @staticmethod
    def _startup_gate(
        now: datetime,
        decisions: dict[str, ToolchainPolicyEnforcementRecord],
    ) -> ToolchainPolicyGateRecord:
        statuses = [item.status for item in decisions.values()]
        status = "block" if "block" in statuses else "warn" if "warn" in statuses else "allow"
        return ToolchainPolicyGateRecord(
            gate_id="startup",
            title="Startup gate",
            status=status,
            summary=(
                "Startup is blocked by toolchain policy."
                if status == "block"
                else "Startup is allowed with warnings."
                if status == "warn"
                else "Startup gate passed."
            ),
            evaluated_at=now,
            metadata={"source_policies": {key: value.status for key, value in decisions.items()}},
        )

    @staticmethod
    def _ci_gate(
        now: datetime,
        decisions: dict[str, ToolchainPolicyEnforcementRecord],
    ) -> ToolchainPolicyGateRecord:
        security = decisions.get("security_baseline")
        versions = decisions.get("version_floor")
        runtime = decisions.get("runtime_bootstrap")
        if security and security.status == "block":
            status = "block"
        elif versions and versions.status == "warn":
            status = "block"
        elif security and security.status == "warn":
            status = "warn"
        elif runtime and runtime.status == "warn":
            status = "warn"
        else:
            status = "allow"
        return ToolchainPolicyGateRecord(
            gate_id="ci",
            title="CI gate",
            status=status,
            summary=(
                "CI gate is blocked by security or version policy."
                if status == "block"
                else "CI gate is allowed with warnings."
                if status == "warn"
                else "CI gate passed."
            ),
            evaluated_at=now,
            metadata={"source_policies": {key: value.status for key, value in decisions.items()}},
        )

    @staticmethod
    def _packaging_gate(
        now: datetime,
        decisions: dict[str, ToolchainPolicyEnforcementRecord],
    ) -> ToolchainPolicyGateRecord:
        security = decisions.get("security_baseline")
        versions = decisions.get("version_floor")
        runtime = decisions.get("runtime_bootstrap")
        if security and security.status == "block":
            status = "block"
        elif versions and versions.status == "warn":
            status = "block"
        elif runtime and runtime.status == "warn":
            status = "block"
        elif security and security.status == "warn":
            status = "warn"
        else:
            status = "allow"
        return ToolchainPolicyGateRecord(
            gate_id="packaging",
            title="Packaging gate",
            status=status,
            summary=(
                "Packaging is blocked until provisioning and policy issues are resolved."
                if status == "block"
                else "Packaging is allowed with warnings."
                if status == "warn"
                else "Packaging gate passed."
            ),
            evaluated_at=now,
            metadata={"source_policies": {key: value.status for key, value in decisions.items()}},
        )
