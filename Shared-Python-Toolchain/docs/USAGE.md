# Usage Guide

## Install
```
pip install -e .[dev]
```

## Run API
```
uvicorn security_gateway.service:app --reload
```
- Background automation (key rotation, proxy health, DNS telemetry) starts automatically with the API. Use `GET /automation/status` to confirm it’s running without blocking user workflows.

### REST endpoints
- `POST /access/evaluate` – run zero-trust policy evaluation (include `dns_secure` if you just resolved via `/dns/resolve`).
- `PUT /pam/secret`, `POST /pam/checkout`, `GET /pam/metrics` – manage privileged credentials + rotation insights.
- `GET /dns/resolve` – DoH lookup that records DNSSEC status for downstream risk scoring.
- `POST /tor/request`, `GET /proxy/health` – send proxied HTTP requests and verify Tor/WARP health.
- `GET /network/blocked-ips`, `POST /network/blocked-ips`, `DELETE /network/blocked-ips/{ip}`, `POST /network/blocked-ips/{ip}/promote` – review, block, unblock, and promote source IP blocks to permanent.
- `POST /endpoint/scan` – malware scan uploads prior to privileged flows.
- `GET /endpoint/malware-feeds/status`, `POST /endpoint/malware-feeds/refresh` – inspect and refresh malware IOC/hash feeds for the scanner.
- `GET /endpoint/malware-rule-feeds/status`, `POST /endpoint/malware-rule-feeds/refresh` – inspect and refresh malware rule/string feeds for the scanner.
- `POST /privacy/tracker-feeds/import`, `POST /endpoint/malware-feeds/import`, `POST /endpoint/malware-rule-feeds/import` – seed local caches from offline files.
- `GET /health/security` – consolidated detection/feed health summary for tracker intel, malware feeds, and automation state.
- `WS /ws` – real-time channel (sends `{"type":"ready"}` on connect, `ping` -> `pong`, other messages echoed as `echo:<message>`).
- Detection-content write routes (`*/refresh`, `*/import`) now require operator authorization.

## CLI examples
```
security-gateway evaluate examples/request.json
security-gateway dns example.com --record-type A
security-gateway pam-store db "super-secret"
security-gateway pam-checkout db --ttl-minutes 5
security-gateway pam-metrics
security-gateway proxy-request https://ifconfig.me --via tor
security-gateway proxy-health
security-gateway ip-block 203.0.113.10 --reason "confirmed attack" --duration-minutes 60
security-gateway ip-list
security-gateway ip-promote 203.0.113.10 --reason "confirmed attacker"
security-gateway ip-unblock 203.0.113.10 --reason "false positive"
security-gateway report-pdf
security-gateway report-pdf --time-window-hours 24 --min-risk-score 60 --no-events
security-gateway report-list
security-gateway report-open
security-gateway report-open security-summary-20260327-120000.pdf --print
security-gateway report-browser
security-gateway scan suspicious.bin
security-gateway malware-feed-status
security-gateway malware-feed-refresh
security-gateway malware-feed-refresh --url https://example.com/malware-hashes.txt
security-gateway malware-feed-import .\offline-hashes.txt
security-gateway malware-rule-feed-status
security-gateway malware-rule-feed-refresh
security-gateway malware-rule-feed-refresh --url https://example.com/malware-rules.json
security-gateway malware-rule-feed-import .\offline-rules.txt
security-gateway tracker-feed-import .\offline-trackers.txt
security-gateway health-status
security-gateway automation-run
security-gateway mfa-register-webauthn user-123 cred-abc BASE64PUBLICKEY==
security-gateway alert-test --level warning --title \"Suspicious\" --message \"Unusual login\"
```

## Tests
```
py -3.13 -m pytest
```

This now works directly from a normal checkout because pytest is configured to add the project root to `sys.path`.

## Security Gateway builds
```
.\scripts\build-security-gateway.ps1
```

The staged Security Gateway build is pinned to `Python 3.13`.

## Automation
- Background automation can now refresh tracker feeds, but it is off by default.
- Enable it with:
```
SECURITY_GATEWAY_AUTOMATION_TRACKER_FEED_REFRESH_ENABLED=true
```
- Control how often it runs relative to the main automation loop:
```
SECURITY_GATEWAY_AUTOMATION_TRACKER_FEED_REFRESH_EVERY_TICKS=12
```
- Malware feed refresh can also be enabled:
```
SECURITY_GATEWAY_AUTOMATION_MALWARE_FEED_REFRESH_ENABLED=true
SECURITY_GATEWAY_AUTOMATION_MALWARE_FEED_REFRESH_EVERY_TICKS=12
```
- Malware rule feed refresh can also be enabled:
```
SECURITY_GATEWAY_AUTOMATION_MALWARE_RULE_FEED_REFRESH_ENABLED=true
SECURITY_GATEWAY_AUTOMATION_MALWARE_RULE_FEED_REFRESH_EVERY_TICKS=12
```
- The automation status output includes tracker-feed, malware-feed, and malware-rule-feed refresh state, last result, and last error.

## Operator auth for feed management
- Feed refresh/import routes use `Authorization: Bearer <token>` when a token is configured.
- Configure it with:
```
SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN=replace-with-a-long-random-token
```
- For local-only development, the service can allow loopback callers to use these routes without a token:
```
SECURITY_GATEWAY_OPERATOR_ALLOW_LOOPBACK_WITHOUT_TOKEN=true
```
- To require the bearer token even on loopback:
```
SECURITY_GATEWAY_OPERATOR_ALLOW_LOOPBACK_WITHOUT_TOKEN=false
```
- Example:
```bash
curl -X POST http://127.0.0.1:8000/privacy/tracker-feeds/refresh \
  -H "Authorization: Bearer $SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"urls":["https://example.com/custom-tracker-list.txt"]}'
```

## Malware feed refresh
- Malware scanning can consume refreshable SHA-256 IOC/hash feeds in addition to the built-in heuristics.
- Refresh feeds with:
```
security-gateway malware-feed-refresh
security-gateway malware-feed-refresh --url https://example.com/malware-hashes.txt
security-gateway malware-feed-status
```
- API support:
  - `GET /endpoint/malware-feeds/status`
  - `POST /endpoint/malware-feeds/refresh`
  - `POST /endpoint/malware-feeds/import`
- Feed status includes:
  - last successful update time
  - last refresh attempt result
  - per-source hash counts
  - failure details from the most recent refresh
  - stale-cache detection
- Configure feed caching with:
```
SECURITY_GATEWAY_MALWARE_FEED_CACHE_PATH=logs/malware_feed_hashes.json
SECURITY_GATEWAY_MALWARE_FEED_STALE_HOURS=168
SECURITY_GATEWAY_MALWARE_FEED_DISABLED_URLS=["https://example.com/list2.txt"]
SECURITY_GATEWAY_MALWARE_FEED_MIN_HASHES_PER_SOURCE=1
SECURITY_GATEWAY_MALWARE_FEED_MIN_TOTAL_HASHES=1
SECURITY_GATEWAY_MALWARE_FEED_REPLACE_RATIO_FLOOR=0.5
SECURITY_GATEWAY_MALWARE_FEED_VERIFY_TLS=true
SECURITY_GATEWAY_MALWARE_FEED_CA_BUNDLE_PATH=C:\path\to\trusted-ca.pem
SECURITY_GATEWAY_MALWARE_FEED_URLS=["https://example.com/list1.txt","https://example.com/list2.json"]
```

## Malware rule feeds
- Malware scanning can also consume refreshable rule/string feeds for simple pattern-based detections.
- Refresh or import them with:
```
security-gateway malware-rule-feed-refresh
security-gateway malware-rule-feed-refresh --url https://example.com/malware-rules.json
security-gateway malware-rule-feed-import .\offline-rules.txt
security-gateway malware-rule-feed-status
```
- API support:
  - `GET /endpoint/malware-rule-feeds/status`
  - `POST /endpoint/malware-rule-feeds/refresh`
  - `POST /endpoint/malware-rule-feeds/import`
- Configure rule feeds with:
```
SECURITY_GATEWAY_MALWARE_RULE_FEED_CACHE_PATH=logs/malware_rule_feed_rules.json
SECURITY_GATEWAY_MALWARE_RULE_FEED_STALE_HOURS=168
SECURITY_GATEWAY_MALWARE_RULE_FEED_DISABLED_URLS=["https://example.com/list2.json"]
SECURITY_GATEWAY_MALWARE_RULE_FEED_MIN_RULES_PER_SOURCE=1
SECURITY_GATEWAY_MALWARE_RULE_FEED_MIN_TOTAL_RULES=1
SECURITY_GATEWAY_MALWARE_RULE_FEED_REPLACE_RATIO_FLOOR=0.5
SECURITY_GATEWAY_MALWARE_RULE_FEED_VERIFY_TLS=true
SECURITY_GATEWAY_MALWARE_RULE_FEED_CA_BUNDLE_PATH=C:\path\to\trusted-ca.pem
SECURITY_GATEWAY_MALWARE_RULE_FEED_URLS=["https://example.com/list1.txt","https://example.com/list2.json"]
```

## HashiCorp Vault backend
Set the following environment variables (or `.env`) to push PAM secrets into Vault KV v2:
```
export SECURITY_GATEWAY_HASHICORP_VAULT_URL=https://vault.example.com
export SECURITY_GATEWAY_HASHICORP_VAULT_TOKEN=s.xxxxx
export SECURITY_GATEWAY_HASHICORP_VAULT_MOUNT=secret
export SECURITY_GATEWAY_HASHICORP_VAULT_NAMESPACE=optional-ns
```
With these in place, `VaultClient` stores each rotated version at `secret/data/security-gateway/<name>/<version>` while still enforcing local encryption + metrics.

## Encryption defaults
- Privileged secrets use a shared `common_crypto.AES256GCMCipher`, which derives 256-bit AES keys via PBKDF2-HMAC-SHA256 (310k iterations) and seals data with AES-256-GCM.
- Associated data can be supplied by callers that need to bind ciphertexts to contextual metadata (e.g., service identifiers) without re-implementing crypto primitives.

## IP blocking
- Manual IP blocks can be created through the CLI or API and can expire automatically.
- Corroborated high-risk denials can trigger an automatic temporary IP block.
- Configure this with:
```
SECURITY_GATEWAY_AUTO_BLOCK_ENABLED=true
SECURITY_GATEWAY_AUTO_BLOCK_DURATION_MINUTES=30
```

## Anti-tracker blocking
- Tracker destinations are blocked at the application layer by default.
- Blocking applies to:
  - `GET /dns/resolve` for known or strongly heuristic tracker hostnames
  - `POST /tor/request` for known or strongly heuristic tracker URLs
- Known tracker domains are blocked immediately.
- Newer tracking methods are detected heuristically from combinations of:
  - tracker-style host labels
  - tracker-style URL path markers
  - tracking query parameters such as `gclid`, `fbclid`, `utm_*`, and similar keys
- Tracker blocks are audited as `privacy.tracker_block`.
- Review recent tracker blocks with:
  - `GET /privacy/tracker-events`
- To disable tracker blocking:
```
SECURITY_GATEWAY_TRACKER_BLOCK_ENABLED=false
```
- To add custom tracker domains, point this setting at a JSON array of domains:
```
SECURITY_GATEWAY_TRACKER_DOMAIN_LIST_PATH=C:\path\to\tracker-domains.json
```
- Tracker feed refresh is explicit and local-cache based. Runtime blocking reads only the cached domains file.
- Default feed sources are:
  - Disconnect tracking protection
  - AdGuard first-party tracking servers
  - EasyPrivacy
- Refresh feeds with:
```
security-gateway tracker-feed-refresh
security-gateway tracker-feed-refresh --url https://example.com/custom-tracker-list.txt
security-gateway tracker-feed-status
```
- API support:
  - `GET /privacy/tracker-feeds/status`
  - `POST /privacy/tracker-feeds/refresh`
  - `POST /privacy/tracker-feeds/import`
- Status reports include:
  - last successful update time
  - last refresh attempt result
  - per-source counts
  - failure details from the most recent refresh
  - stale-cache detection
- Feed cache path:
```
SECURITY_GATEWAY_TRACKER_FEED_CACHE_PATH=logs/tracker_feed_domains.json
```
- Mark the cache stale after this many hours:
```
SECURITY_GATEWAY_TRACKER_FEED_STALE_HOURS=168
```
- Disable specific feed URLs without removing them from the configured list:
```
SECURITY_GATEWAY_TRACKER_FEED_DISABLED_URLS=["https://example.com/list2.json"]
```
- Require at least this many domains from each source before accepting it:
```
SECURITY_GATEWAY_TRACKER_FEED_MIN_DOMAINS_PER_SOURCE=10
```
- Reject a refresh if the merged result is too small overall:
```
SECURITY_GATEWAY_TRACKER_FEED_MIN_TOTAL_DOMAINS=500
```
- Reject a refresh if it falls below this fraction of the previous cache size:
```
SECURITY_GATEWAY_TRACKER_FEED_REPLACE_RATIO_FLOOR=0.5
```
- Override default feed URLs with:
```
SECURITY_GATEWAY_TRACKER_FEED_URLS=["https://example.com/list1.txt","https://example.com/list2.json"]
```
- TLS and CA controls:
```
SECURITY_GATEWAY_TRACKER_FEED_VERIFY_TLS=true
SECURITY_GATEWAY_TRACKER_FEED_CA_BUNDLE_PATH=C:\path\to\trusted-ca.pem
```

## Offline seed files
- Airgapped environments can seed tracker, malware hash, and malware rule caches from local files before any network refresh is attempted.
- CLI import commands:
```
security-gateway tracker-feed-import .\offline-trackers.txt
security-gateway malware-feed-import .\offline-hashes.txt
security-gateway malware-rule-feed-import .\offline-rules.txt
```
- You can also point the service or CLI at seed files so they auto-populate empty caches on startup:
```
SECURITY_GATEWAY_TRACKER_OFFLINE_SEED_PATH=C:\feeds\trackers.txt
SECURITY_GATEWAY_MALWARE_OFFLINE_HASH_SEED_PATH=C:\feeds\malware-hashes.txt
SECURITY_GATEWAY_MALWARE_OFFLINE_RULE_SEED_PATH=C:\feeds\malware-rules.txt
```

## Security health
- `GET /health/security` and `security-gateway health-status` provide a consolidated view of:
  - tracker feed health
  - malware hash feed health
  - malware rule feed health
  - warnings for stale caches, failed refreshes, or disabled TLS verification

## Quiet operation defaults
- Desktop toast alerts are disabled by default.
- Traceroute confirmation prompts are disabled by default.
- Traceroute popup previews are disabled by default.
- Detection evidence still goes to the audit log and any configured webhook.
- To re-enable the local UI signals:
```
SECURITY_GATEWAY_ALERT_ENABLE_TOAST=true
SECURITY_GATEWAY_TRACEROUTE_REQUIRE_CONFIRMATION=true
SECURITY_GATEWAY_TRACEROUTE_SHOW_POPUP_RESULTS=true
```

## Reports
- In development, reports default to [J:\sturdy-spork\Shared-Python-Toolchain\output\pdf](/J:/sturdy-spork/Shared-Python-Toolchain/output/pdf).
- In the installed build, the default reports directory is `%LOCALAPPDATA%\SecurityGateway\reports`.
- The installer now creates that reports directory as part of setup.
- Use `security-gateway report-pdf` to generate a PDF, `security-gateway report-list` to see saved reports, and `security-gateway report-open [name]` to view the newest or named report.
- Add `--print` to `report-open` to send the report to the default printer.
- Use `security-gateway report-browser` for the built-in report browser with `Generate New`, `Open`, and `Print`.
- In the packaged build, launching `SecurityGateway.exe` with no arguments opens the report browser by default.
- Report generation filters:
  - `--time-window-hours <n>`
  - `--min-risk-score <n>`
  - `--blocked/--no-blocked`
  - `--potential/--no-potential`
  - `--events/--no-events`
- The report browser exposes the same filters directly in the window before generating a new report.
- API support:
  - `GET /reports` lists saved PDFs
  - `GET /reports/security-summary.pdf` generates a current summary PDF and accepts the same filter query parameters
  - `GET /reports/{name}` fetches a saved PDF

## Uninstall
- After running the installer, an elevated script is dropped at `C:\Program Files\SecurityGateway\Uninstall-SecurityGateway.ps1`. Run it as Administrator to remove the binary, PATH entry, desktop shortcut, and any residual data under `%ProgramData%\SecurityGateway` and `%LOCALAPPDATA%\SecurityGateway`.
