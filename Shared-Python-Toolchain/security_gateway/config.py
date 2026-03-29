"""Configuration primitives for the security gateway."""
from __future__ import annotations

import os
import secrets
import sys
from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_report_output_dir() -> str:
    if getattr(sys, "frozen", False):
        return str(Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SecurityGateway" / "reports")
    return "output/pdf"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECURITY_GATEWAY_", env_file=".env")
    environment: str = Field("dev", description="Deployment environment tag")
    audit_log_path: str = Field("logs/audit.jsonl")
    ip_blocklist_path: str = Field("logs/blocked_ips.json")
    report_output_dir: str = Field(default_factory=_default_report_output_dir)
    hashicorp_vault_url: Optional[str] = None
    hashicorp_vault_token: Optional[str] = None
    hashicorp_vault_mount: str = "secret"
    hashicorp_vault_namespace: Optional[str] = None
    hashicorp_vault_timeout_seconds: float = 5.0
    hashicorp_vault_verify_tls: bool = True
    doh_providers: List[HttpUrl] = Field(
        default_factory=lambda: [
            "https://cloudflare-dns.com/dns-query",
            "https://dns.quad9.net/dns-query",
        ]
    )
    proxy_allowed_url_schemes: List[str] = Field(default_factory=lambda: ["http", "https"])
    proxy_allowed_hosts: List[str] = Field(default_factory=list)
    proxy_block_private_destinations: bool = True
    proxy_timeout_seconds: float = 10.0
    proxy_max_response_bytes: int = 1_048_576
    proxy_blocked_hosts: List[str] = Field(
        default_factory=lambda: [
            "169.254.169.254",
            "metadata.google.internal",
            "100.100.100.200",
        ]
    )
    tor_socks_proxy: str = "socks5h://127.0.0.1:9050"
    warp_endpoint: Optional[str] = None
    pam_master_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    allowed_geo_radius_km: float = 500.0
    max_risk_score: float = 75.0
    totp_window: int = 1
    automation_interval_seconds: float = 300.0
    automation_tracker_feed_refresh_enabled: bool = False
    automation_tracker_feed_refresh_every_ticks: int = 12
    automation_malware_feed_refresh_enabled: bool = False
    automation_malware_feed_refresh_every_ticks: int = 12
    automation_malware_rule_feed_refresh_enabled: bool = False
    automation_malware_rule_feed_refresh_every_ticks: int = 12
    public_rate_limit_window_seconds: float = 10.0
    access_evaluate_max_requests_per_window: int = 30
    dns_resolve_max_requests_per_window: int = 60
    proxy_request_max_requests_per_window: int = 20
    endpoint_bearer_token: Optional[str] = None
    endpoint_bearer_secret_name: Optional[str] = "endpoint-ingest-token"
    endpoint_allow_loopback_without_token: bool = True
    endpoint_telemetry_signing_key: Optional[str] = None
    endpoint_telemetry_max_records: int = 10_000
    endpoint_telemetry_retention_hours: float = 168.0
    endpoint_scan_max_upload_bytes: int = 5_242_880
    operator_bearer_token: Optional[str] = None
    operator_bearer_secret_name: Optional[str] = "operator-bearer-token"
    operator_allow_loopback_without_token: bool = True
    service_enable_api_docs: bool = False
    service_allowed_hosts: List[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1", "[::1]", "testserver", "testclient"]
    )
    websocket_allowed_origins: List[str] = Field(default_factory=list)
    websocket_max_messages_per_window: int = 30
    websocket_rate_window_seconds: float = 5.0
    alert_webhook_url: Optional[str] = None
    alert_webhook_timeout_seconds: float = 4.0
    alert_webhook_verify_tls: bool = True
    alert_enable_toast: bool = False
    threat_rotation_enabled: bool = True
    threat_rotation_signal_threshold: float = 8.0
    threat_rotation_risk_threshold: float = 60.0
    threat_rotation_cooldown_seconds: float = 120.0
    auto_block_enabled: bool = True
    auto_block_duration_minutes: int = 30
    tracker_block_enabled: bool = True
    tracker_domain_list_path: Optional[str] = None
    tracker_feed_urls: List[str] = Field(
        default_factory=lambda: [
            "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json",
            "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt",
            "https://raw.githubusercontent.com/easylist/easylist/master/easyprivacy/easyprivacy_general.txt",
        ]
    )
    tracker_feed_cache_path: str = Field("logs/tracker_feed_domains.json")
    tracker_feed_stale_hours: float = 168.0
    tracker_feed_disabled_urls: List[str] = Field(default_factory=list)
    tracker_feed_min_domains_per_source: int = 10
    tracker_feed_min_total_domains: int = 500
    tracker_feed_replace_ratio_floor: float = 0.5
    tracker_feed_verify_tls: bool = True
    tracker_feed_ca_bundle_path: Optional[str] = None
    tracker_offline_seed_path: Optional[str] = None
    malware_feed_urls: List[str] = Field(default_factory=list)
    malware_feed_cache_path: str = Field("logs/malware_feed_hashes.json")
    malware_feed_stale_hours: float = 168.0
    malware_feed_disabled_urls: List[str] = Field(default_factory=list)
    malware_feed_min_hashes_per_source: int = 1
    malware_feed_min_total_hashes: int = 1
    malware_feed_replace_ratio_floor: float = 0.5
    malware_feed_verify_tls: bool = True
    malware_feed_ca_bundle_path: Optional[str] = None
    malware_offline_hash_seed_path: Optional[str] = None
    malware_rule_feed_urls: List[str] = Field(default_factory=list)
    malware_rule_feed_cache_path: str = Field("logs/malware_rule_feed_rules.json")
    malware_rule_feed_stale_hours: float = 168.0
    malware_rule_feed_disabled_urls: List[str] = Field(default_factory=list)
    malware_rule_feed_min_rules_per_source: int = 1
    malware_rule_feed_min_total_rules: int = 1
    malware_rule_feed_replace_ratio_floor: float = 0.5
    malware_rule_feed_verify_tls: bool = True
    malware_rule_feed_ca_bundle_path: Optional[str] = None
    malware_offline_rule_seed_path: Optional[str] = None
    traceroute_require_confirmation: bool = False
    traceroute_show_popup_results: bool = False
    traceroute_preview_lines: int = 6

@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
