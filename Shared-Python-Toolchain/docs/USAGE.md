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
- `POST /endpoint/telemetry`, `POST /endpoint/scan` – authenticated endpoint-agent ingestion for posture and malware scan uploads.
- `GET /endpoint/telemetry/{device_id}` – operator-authenticated telemetry lookup.
- `GET /endpoint/malware-feeds/status`, `POST /endpoint/malware-feeds/refresh` – inspect and refresh malware IOC/hash feeds for the scanner.
- `GET /endpoint/malware-rule-feeds/status`, `POST /endpoint/malware-rule-feeds/refresh` – inspect and refresh malware rule/string feeds for the scanner.
- `POST /privacy/tracker-feeds/import`, `POST /endpoint/malware-feeds/import`, `POST /endpoint/malware-rule-feeds/import` – seed local caches from offline files.
- `GET /privacy/tracker-events`, `GET /reports`, `GET /reports/{report_name}`, `GET /reports/security-summary.pdf` – operator-authenticated audit/report visibility.
- `GET /health/security` – consolidated detection/feed health summary for tracker intel, malware feeds, and automation state.
- API docs/OpenAPI routes are disabled by default. Set `SECURITY_GATEWAY_SERVICE_ENABLE_API_DOCS=true` only for controlled development environments if you need `/docs`, `/redoc`, or `/openapi.json`.
- The service also enforces trusted `Host` headers. Set `SECURITY_GATEWAY_SERVICE_ALLOWED_HOSTS` to the exact hostnames clients should use in your environment.
- HTTP responses include baseline security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`) by default.
- Non-multipart request bodies are capped by `SECURITY_GATEWAY_SERVICE_MAX_REQUEST_BODY_BYTES` before route parsing begins. File uploads for `/endpoint/scan` still use their dedicated upload-size guard.
- Repeated bad bearer tokens are rate-limited on operator, endpoint-ingest, and operator WebSocket auth paths. Tune with `SECURITY_GATEWAY_AUTH_FAILURE_RATE_LIMIT_WINDOW_SECONDS`, `SECURITY_GATEWAY_OPERATOR_AUTH_MAX_FAILURES_PER_WINDOW`, and `SECURITY_GATEWAY_ENDPOINT_AUTH_MAX_FAILURES_PER_WINDOW`.
- Backend refresh and proxy failures return stable high-level API messages, while the detailed exception text is kept in audit events instead of being reflected directly to clients.
- HTTP responses also default to `Cache-Control: no-store` and `Pragma: no-cache` so browsers and intermediaries do not retain security-sensitive API or report content by default.
- Feed status, refresh/import, health, and report-list API responses no longer expose internal filesystem paths such as cache files or report directories.
- `WS /ws` – operator-authenticated health-only channel (sends `{"type":"ready","mode":"health_only"}` on connect, `ping`/`health` -> `pong`, unsupported messages return a structured unsupported response).
- Operator-managed routes now require operator authorization:
  - `PUT /pam/secret`, `POST /pam/checkout`, `GET /pam/metrics`
  - `GET /endpoint/telemetry/{device_id}`
  - `GET /privacy/tracker-events`
  - `GET /reports*`
  - `GET|POST|DELETE /network/blocked-ips*`
  - `GET /automation/status`
  - `WS /ws`
  - detection-content write routes (`*/refresh`, `*/import`)
- Endpoint-ingest routes require endpoint authentication:
  - `POST /endpoint/telemetry`
  - `POST /endpoint/scan`

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
- Operator-managed routes use `Authorization: Bearer <token>` when a token is configured.
- Configure it with:
```
SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN=replace-with-a-long-random-token
```
- For local-only development, the service can allow loopback callers to use these routes without a token:
```
SECURITY_GATEWAY_OPERATOR_ALLOW_LOOPBACK_WITHOUT_TOKEN=true
```
- For secret-store-backed operator auth, the service first checks the PAM/Vault secret named by:
```
SECURITY_GATEWAY_OPERATOR_BEARER_SECRET_NAME=operator-bearer-token
```
- If that secret is absent, the service falls back to:
```
SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN=replace-me
```
- To require the bearer token even on loopback:
```
SECURITY_GATEWAY_OPERATOR_ALLOW_LOOPBACK_WITHOUT_TOKEN=false
```
- Endpoint-agent ingestion can use a separate bearer token source:
```
SECURITY_GATEWAY_ENDPOINT_BEARER_SECRET_NAME=endpoint-ingest-token
SECURITY_GATEWAY_ENDPOINT_BEARER_TOKEN=replace-me
SECURITY_GATEWAY_ENDPOINT_ALLOW_LOOPBACK_WITHOUT_TOKEN=false
```
- Telemetry signing and retention can be configured independently:
```
SECURITY_GATEWAY_ENDPOINT_TELEMETRY_SIGNING_KEY=replace-me
SECURITY_GATEWAY_ENDPOINT_TELEMETRY_MAX_RECORDS=10000
SECURITY_GATEWAY_ENDPOINT_TELEMETRY_RETENTION_HOURS=168
```
- If `SECURITY_GATEWAY_ENDPOINT_TELEMETRY_SIGNING_KEY` is unset, telemetry signing falls back to `SECURITY_GATEWAY_PAM_MASTER_KEY` so signatures stay stable across restarts when the PAM master key is stable.
- Alert webhooks are constrained to HTTPS public destinations and can be tuned with:
```
SECURITY_GATEWAY_ALERT_WEBHOOK_URL=https://alerts.example.com/hook
SECURITY_GATEWAY_ALERT_WEBHOOK_TIMEOUT_SECONDS=4
SECURITY_GATEWAY_ALERT_WEBHOOK_VERIFY_TLS=true
```
- Webhook URLs with plain HTTP, embedded credentials, localhost, or private/link-local/reserved destinations are rejected and fail closed.
- Example:
```bash
curl -X POST http://127.0.0.1:8000/privacy/tracker-feeds/refresh \
  -H "Authorization: Bearer $SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"urls":["https://example.com/custom-tracker-list.txt"]}'
```
- Example endpoint telemetry publish:
```bash
curl -X POST http://127.0.0.1:8000/endpoint/telemetry \
  -H "Authorization: Bearer $SECURITY_GATEWAY_ENDPOINT_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"device_id":"device-42","os":"Windows","os_version":"11","compliance":"compliant","is_encrypted":true,"edr_active":true}'
```
- The same header should be used for:
  - PAM secret storage and checkout
  - blocked-IP administration
  - automation status checks
  - websocket connections to `/ws`
- A practical bootstrap flow is: start with a loopback-only session or temporary `SECURITY_GATEWAY_OPERATOR_BEARER_TOKEN`, store the long-lived operator token in PAM as `operator-bearer-token`, then remove the static fallback token.
- PAM secret names may contain letters, numbers, `.`, `_`, `-`, `:`, and `/`, must not start or end with `.` or `/`, and are limited to 64 characters.
- PAM checkout TTLs are limited to `1`-`480` minutes, and secret values must be non-empty.
- Browser-based WebSocket clients should also send an allowed `Origin` header.
- Configure WebSocket origin/rate controls with:
```
SECURITY_GATEWAY_WEBSOCKET_ALLOWED_ORIGINS=[]
SECURITY_GATEWAY_WEBSOCKET_MAX_MESSAGES_PER_WINDOW=30
SECURITY_GATEWAY_WEBSOCKET_RATE_WINDOW_SECONDS=5
```
- If `SECURITY_GATEWAY_WEBSOCKET_ALLOWED_ORIGINS` is populated, browser origins outside that set are rejected.

## Outbound proxy guardrails
- `POST /tor/request` and `security-gateway proxy-request` now reject unsafe proxy targets before issuing a request.
- Allowed URL schemes are HTTP and HTTPS by default.
- Localhost, private-network, link-local, reserved, multicast, unspecified, and metadata-style destinations are blocked by default.
- The shared proxy route only allows `GET` and `HEAD` methods.
- Upstream proxy requests time out after `SECURITY_GATEWAY_PROXY_TIMEOUT_SECONDS` and response bodies are capped by `SECURITY_GATEWAY_PROXY_MAX_RESPONSE_BYTES`.
- Configure these controls with:
```
SECURITY_GATEWAY_PROXY_ALLOWED_URL_SCHEMES=["http","https"]
SECURITY_GATEWAY_PROXY_ALLOWED_HOSTS=[]
SECURITY_GATEWAY_PROXY_BLOCK_PRIVATE_DESTINATIONS=true
SECURITY_GATEWAY_PROXY_TIMEOUT_SECONDS=10
SECURITY_GATEWAY_PROXY_MAX_RESPONSE_BYTES=1048576
SECURITY_GATEWAY_PROXY_BLOCKED_HOSTS=["169.254.169.254","metadata.google.internal","100.100.100.200"]
```
- If you want to restrict proxying to a fixed host allowlist, populate `SECURITY_GATEWAY_PROXY_ALLOWED_HOSTS`.

## Endpoint upload limits
- `POST /endpoint/scan` reads uploads in bounded chunks and rejects files larger than `SECURITY_GATEWAY_ENDPOINT_SCAN_MAX_UPLOAD_BYTES`.
- Configure the default limit with:
```
SECURITY_GATEWAY_ENDPOINT_SCAN_MAX_UPLOAD_BYTES=5242880
```

## Public route rate limits
- `POST /access/evaluate`, `GET /dns/resolve`, and `POST /tor/request` apply per-client request budgets and return `429 Too Many Requests` with `Retry-After` when exceeded.
- Configure the shared window and per-route budgets with:
```
SECURITY_GATEWAY_PUBLIC_RATE_LIMIT_WINDOW_SECONDS=10
SECURITY_GATEWAY_ACCESS_EVALUATE_MAX_REQUESTS_PER_WINDOW=30
SECURITY_GATEWAY_DNS_RESOLVE_MAX_REQUESTS_PER_WINDOW=60
SECURITY_GATEWAY_PROXY_REQUEST_MAX_REQUESTS_PER_WINDOW=20
```

## Public input validation
- `POST /access/evaluate` now enforces bounded identifiers and collections:
  - user IDs and device IDs: up to `128` characters
  - groups: up to `32` entries, each up to `64` characters
  - resource: up to `256` characters
  - threat signal map: up to `32` entries with finite numeric values
  - `source_ip`: must be a valid IPv4 or IPv6 literal when provided
- `GET /dns/resolve` only accepts DNS hostnames up to `253` characters and record types from:
  - `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS`, `PTR`, `SRV`, `TXT`

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
- Network refreshes only accept public HTTPS feed URLs.
- Embedded credentials, localhost, metadata-style hosts, and private or link-local destinations are rejected before any request is sent.

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
- Rule-feed refreshes use the same public-HTTPS validation as malware hash feeds.

## HashiCorp Vault backend
Set the following environment variables (or `.env`) to push PAM secrets into Vault KV v2:
```
export SECURITY_GATEWAY_HASHICORP_VAULT_URL=https://vault.example.com
export SECURITY_GATEWAY_HASHICORP_VAULT_TOKEN=s.xxxxx
export SECURITY_GATEWAY_HASHICORP_VAULT_MOUNT=secret
export SECURITY_GATEWAY_HASHICORP_VAULT_NAMESPACE=optional-ns
export SECURITY_GATEWAY_HASHICORP_VAULT_TIMEOUT_SECONDS=5
export SECURITY_GATEWAY_HASHICORP_VAULT_VERIFY_TLS=true
```
With these in place, `VaultClient` stores each rotated version at `secret/data/security-gateway/<name>/<version>` while still enforcing local encryption + metrics.
- The Vault URL must use HTTPS, must not include embedded credentials, must include a hostname, and Vault reads and writes do not follow redirects.

## Encryption defaults
- Privileged secrets use a shared `common_crypto.AES256GCMCipher`, which derives 256-bit AES keys via PBKDF2-HMAC-SHA256 (310k iterations) and seals data with AES-256-GCM.
- Associated data can be supplied by callers that need to bind ciphertexts to contextual metadata (e.g., service identifiers) without re-implementing crypto primitives.
- Keep `SECURITY_GATEWAY_PAM_MASTER_KEY` stable across restarts so bootstrap-version secrets, including operator bearer secrets stored in PAM, remain readable after a service restart.

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
- DoH providers must use public HTTPS endpoints. Localhost, embedded credentials, metadata-style hosts, and private-network destinations are rejected during resolver setup.
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
- Tracker feed refreshes only fetch from public HTTPS hosts and reject localhost, metadata-style hosts, embedded credentials, and private-network destinations.

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
- Report and tracker-event query bounds:
  - `max_events`: `1`-`500`
  - `time_window_hours`: `>0` and `<=2160` (`90` days)
  - `min_risk_score`: `0`-`100`

## Uninstall
- After running the installer, an elevated script is dropped at `C:\Program Files\SecurityGateway\Uninstall-SecurityGateway.ps1`. Run it as Administrator to remove the binary, PATH entry, desktop shortcut, and any residual data under `%ProgramData%\SecurityGateway` and `%LOCALAPPDATA%\SecurityGateway`.
