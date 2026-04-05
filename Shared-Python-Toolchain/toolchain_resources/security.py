"""Shared security validation for toolchain-wide configuration."""
from __future__ import annotations

import os
from datetime import UTC, datetime

from security_gateway.config import Settings
from security_gateway.models import ToolchainSecurityCheckRecord


class ToolchainSecurityRegistry:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _vault_configured(self) -> bool:
        return bool(self.settings.hashicorp_vault_url and self.settings.hashicorp_vault_token)

    def list_checks(self) -> list[ToolchainSecurityCheckRecord]:
        checked_at = datetime.now(UTC)
        vault_configured = self._vault_configured()
        operator_secret_backed = bool(self.settings.operator_bearer_secret_name and vault_configured)
        endpoint_secret_backed = bool(self.settings.endpoint_bearer_secret_name and vault_configured)

        checks = [
            ToolchainSecurityCheckRecord(
                check_id="operator-auth",
                title="Operator Bearer Authentication",
                status=(
                    "ok"
                    if self.settings.operator_bearer_token or operator_secret_backed
                    else "warning"
                    if self.settings.operator_allow_loopback_without_token
                    else "error"
                ),
                severity="high",
                summary=(
                    "Operator access is backed by a bearer token or Vault-managed secret."
                    if self.settings.operator_bearer_token or operator_secret_backed
                    else "Operator access falls back to loopback-without-token mode."
                    if self.settings.operator_allow_loopback_without_token
                    else "Operator access has no resolvable bearer token configured."
                ),
                checked_at=checked_at,
                metadata={
                    "static_token_configured": bool(self.settings.operator_bearer_token),
                    "secret_name": self.settings.operator_bearer_secret_name,
                    "loopback_bypass_enabled": self.settings.operator_allow_loopback_without_token,
                },
            ),
            ToolchainSecurityCheckRecord(
                check_id="endpoint-auth",
                title="Endpoint Bearer Authentication",
                status=(
                    "ok"
                    if self.settings.endpoint_bearer_token or endpoint_secret_backed
                    else "warning"
                    if self.settings.endpoint_allow_loopback_without_token
                    else "error"
                ),
                severity="high",
                summary=(
                    "Endpoint ingestion is backed by a bearer token or Vault-managed secret."
                    if self.settings.endpoint_bearer_token or endpoint_secret_backed
                    else "Endpoint ingestion falls back to loopback-without-token mode."
                    if self.settings.endpoint_allow_loopback_without_token
                    else "Endpoint ingestion has no resolvable bearer token configured."
                ),
                checked_at=checked_at,
                metadata={
                    "static_token_configured": bool(self.settings.endpoint_bearer_token),
                    "secret_name": self.settings.endpoint_bearer_secret_name,
                    "loopback_bypass_enabled": self.settings.endpoint_allow_loopback_without_token,
                },
            ),
            ToolchainSecurityCheckRecord(
                check_id="platform-manager-auth",
                title="Platform Manager Remote Authentication",
                status=(
                    "ok"
                    if self.settings.platform_manager_url and self.settings.platform_manager_bearer_token
                    else "warning"
                ),
                severity="medium",
                summary=(
                    "Remote platform manager URL and bearer token are configured."
                    if self.settings.platform_manager_url and self.settings.platform_manager_bearer_token
                    else "Remote platform manager is unset or missing its bearer token."
                ),
                checked_at=checked_at,
                metadata={
                    "manager_url": self.settings.platform_manager_url,
                    "bearer_token_configured": bool(self.settings.platform_manager_bearer_token),
                },
            ),
            ToolchainSecurityCheckRecord(
                check_id="vault-config",
                title="HashiCorp Vault Configuration",
                status=(
                    "ok"
                    if vault_configured
                    else "error"
                    if self.settings.hashicorp_vault_url or self.settings.hashicorp_vault_token
                    else "warning"
                ),
                severity="medium",
                summary=(
                    "Vault URL and token are configured."
                    if vault_configured
                    else "Vault configuration is partial."
                    if self.settings.hashicorp_vault_url or self.settings.hashicorp_vault_token
                    else "Vault is not configured."
                ),
                checked_at=checked_at,
                metadata={
                    "vault_url": self.settings.hashicorp_vault_url,
                    "token_configured": bool(self.settings.hashicorp_vault_token),
                    "mount": self.settings.hashicorp_vault_mount,
                },
            ),
            ToolchainSecurityCheckRecord(
                check_id="endpoint-telemetry-signing",
                title="Endpoint Telemetry Signing",
                status="ok" if self.settings.endpoint_telemetry_signing_key else "warning",
                severity="medium",
                summary=(
                    "Endpoint telemetry signing key is configured."
                    if self.settings.endpoint_telemetry_signing_key
                    else "Endpoint telemetry signing key is not configured."
                ),
                checked_at=checked_at,
                metadata={"key_configured": bool(self.settings.endpoint_telemetry_signing_key)},
            ),
            ToolchainSecurityCheckRecord(
                check_id="alert-webhook-tls",
                title="Alert Webhook TLS Verification",
                status=(
                    "warning"
                    if self.settings.alert_webhook_url and not self.settings.alert_webhook_verify_tls
                    else "ok"
                ),
                severity="medium" if self.settings.alert_webhook_url else "low",
                summary=(
                    "Alert webhook is configured without TLS verification."
                    if self.settings.alert_webhook_url and not self.settings.alert_webhook_verify_tls
                    else "Alert webhook is configured with TLS verification."
                    if self.settings.alert_webhook_url
                    else "Alert webhook is not configured."
                ),
                checked_at=checked_at,
                metadata={
                    "webhook_url": self.settings.alert_webhook_url,
                    "verify_tls": self.settings.alert_webhook_verify_tls,
                },
            ),
            ToolchainSecurityCheckRecord(
                check_id="pam-master-key",
                title="PAM Master Key Persistence",
                status="ok" if os.environ.get("SECURITY_GATEWAY_PAM_MASTER_KEY") else "warning",
                severity="high",
                summary=(
                    "PAM master key is explicitly configured."
                    if os.environ.get("SECURITY_GATEWAY_PAM_MASTER_KEY")
                    else "PAM master key is using a generated runtime value."
                ),
                checked_at=checked_at,
                metadata={"configured_via_env": bool(os.environ.get("SECURITY_GATEWAY_PAM_MASTER_KEY"))},
            ),
        ]
        return sorted(checks, key=lambda item: item.check_id)

    def get_check(self, check_id: str) -> ToolchainSecurityCheckRecord | None:
        for check in self.list_checks():
            if check.check_id == check_id:
                return check
        return None
