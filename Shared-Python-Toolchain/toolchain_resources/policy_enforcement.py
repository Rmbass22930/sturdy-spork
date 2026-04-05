"""Toolchain policy-enforcement decisions built from security and version state."""
from __future__ import annotations

from datetime import UTC, datetime

from security_gateway.models import ToolchainPolicyEnforcementRecord
from toolchain_resources.provisioning import ToolchainProvisioningRegistry
from toolchain_resources.security import ToolchainSecurityRegistry
from toolchain_resources.version_policy import ToolchainVersionPolicyRegistry


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ToolchainPolicyEnforcementRegistry:
    def __init__(
        self,
        security: ToolchainSecurityRegistry,
        version_policy: ToolchainVersionPolicyRegistry,
        provisioning: ToolchainProvisioningRegistry,
    ) -> None:
        self.security = security
        self.version_policy = version_policy
        self.provisioning = provisioning

    def evaluate(self) -> list[ToolchainPolicyEnforcementRecord]:
        now = _utc_now()
        records: list[ToolchainPolicyEnforcementRecord] = []
        security_checks = self.security.list_checks()
        version_results = self.version_policy.evaluate()
        provisioning_actions = self.provisioning.list_actions()
        blocking_security = [item for item in security_checks if item.status == "error"]
        warning_security = [item for item in security_checks if item.status == "warning"]
        noncompliant_versions = [item for item in version_results if item.status == "noncompliant"]
        pending_provisioning = [item for item in provisioning_actions if item.status == "pending"]
        records.append(
            ToolchainPolicyEnforcementRecord(
                policy_id="security_baseline",
                title="Security baseline",
                status="block" if blocking_security else "warn" if warning_security else "allow",
                summary=(
                    f"{len(blocking_security)} blocking security checks are failing."
                    if blocking_security
                    else f"{len(warning_security)} security checks are in warning state."
                    if warning_security
                    else "Security baseline checks are satisfied."
                ),
                checked_at=now,
                metadata={
                    "blocking_checks": [item.check_id for item in blocking_security],
                    "warning_checks": [item.check_id for item in warning_security],
                },
            )
        )
        records.append(
            ToolchainPolicyEnforcementRecord(
                policy_id="version_floor",
                title="Version floor",
                status="warn" if noncompliant_versions else "allow",
                summary=(
                    f"{len(noncompliant_versions)} language or package-manager versions are below policy."
                    if noncompliant_versions
                    else "Version policy is satisfied."
                ),
                checked_at=now,
                metadata={"noncompliant_targets": [item.target_id for item in noncompliant_versions]},
            )
        )
        records.append(
            ToolchainPolicyEnforcementRecord(
                policy_id="runtime_bootstrap",
                title="Runtime bootstrap",
                status="warn" if pending_provisioning else "allow",
                summary=(
                    f"{len(pending_provisioning)} toolchain components still need provisioning."
                    if pending_provisioning
                    else "Runtime bootstrap requirements are satisfied."
                ),
                checked_at=now,
                metadata={"pending_targets": [item.target_id for item in pending_provisioning[:10]]},
            )
        )
        return records

    def get_result(self, policy_id: str) -> ToolchainPolicyEnforcementRecord | None:
        for record in self.evaluate():
            if record.policy_id == policy_id:
                return record
        return None
