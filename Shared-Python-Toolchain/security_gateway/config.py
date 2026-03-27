"""Configuration primitives for the security gateway."""
from __future__ import annotations

import secrets
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURITY_GATEWAY_", env_file=".env")
    environment: str = Field("dev", description="Deployment environment tag")
    audit_log_path: str = Field("logs/audit.jsonl")
    ip_blocklist_path: str = Field("logs/blocked_ips.json")
    hashicorp_vault_url: Optional[str] = None
    hashicorp_vault_token: Optional[str] = None
    hashicorp_vault_mount: str = "secret"
    hashicorp_vault_namespace: Optional[str] = None
    doh_providers: List[HttpUrl] = Field(
        default_factory=lambda: [
            "https://cloudflare-dns.com/dns-query",
            "https://dns.quad9.net/dns-query",
        ]
    )
    tor_socks_proxy: str = "socks5h://127.0.0.1:9050"
    warp_endpoint: Optional[str] = None
    pam_master_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    allowed_geo_radius_km: float = 500.0
    max_risk_score: float = 75.0
    totp_window: int = 1
    automation_interval_seconds: float = 300.0
    alert_webhook_url: Optional[str] = None
    alert_enable_toast: bool = True
    threat_rotation_enabled: bool = True
    threat_rotation_signal_threshold: float = 8.0
    threat_rotation_risk_threshold: float = 60.0
    threat_rotation_cooldown_seconds: float = 120.0
    auto_block_enabled: bool = True
    auto_block_duration_minutes: int = 30
    traceroute_require_confirmation: bool = True
    traceroute_show_popup_results: bool = True
    traceroute_preview_lines: int = 6

@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
