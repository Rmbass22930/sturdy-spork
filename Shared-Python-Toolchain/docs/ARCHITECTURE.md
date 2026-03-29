# Security Gateway Architecture

## Goals
- Enforce zero-trust access to applications.
- Require phishing-resistant MFA and session risk scoring.
- Mediate privileged access with credential checkout and session recording stubs.
- Provide anonymous routing (Tor) and encrypted DNS resolution for outbound traffic.
- Tie endpoint posture and malware scanning into every policy decision.
- Ship as a modular Python service with REST + CLI interfaces so teams can extend it.

## Components
1. **security_gateway/policy.py**
   - `PolicyEngine` orchestrates device/user signals, MFA status, endpoint posture, and threat intel to decide allow/deny or step-up.
   - Uses `RiskCalculator` to combine heuristics (geo velocity, device compliance, known malware) into a normalized risk score.
   - When a request is denied for high risk, the embedded traceroute runner (with operator confirmation to avoid false positives) captures a back-trace to the source IP, validates the target as a public hostname or IP, displays the results locally, and attaches the preview to alerts/audit logs.

2. **security_gateway/mfa.py**
   - Wraps WebAuthn/FIDO2 (mocked) and TOTP factors. Provides challenge issuance + verification as first-class steps during `/access/evaluate`.

3. **security_gateway/pam.py**
    - `VaultClient` encrypts passwords/API keys, rotates them daily, and issues short-lived checkout tokens.
    - Supports pluggable backends (in-memory or HashiCorp Vault KV v2) plus JSONL audit logging and rotation metrics exposed via API/CLI.
    - Uses the configured PAM master key for bootstrap-version secret recovery so operator credentials stored in PAM can be reused after a restart.
    - Validates secret names, rejects empty secret values, and bounds lease TTLs so control-plane callers cannot create pathological secret identifiers or indefinite leases.
    - The HashiCorp Vault backend now enforces HTTPS endpoint configuration, explicit TLS/timeout settings, and redirect-free secret reads and writes before secrets are sent off-box.

4. **security_gateway/dns.py**
   - `SecureDNSResolver` performs DNS over HTTPS (Cloudflare + Quad9). Validates responses via DNSSEC flags when available.
   - DoH provider endpoints are validated as public HTTPS destinations before the resolver will use them.

5. **security_gateway/tor.py**
   - Provides pluggable outbound proxying via Tor or Cloudflare WARP. Enforces outbound URL validation for the shared proxy path so non-HTTP(S), localhost, private-network, link-local, and metadata-style targets are rejected before requests are sent.
   - Streams upstream responses through explicit timeout and maximum-body guardrails so operator proxying cannot buffer arbitrarily large responses in memory.

6. **security_gateway/endpoint.py**
    - `EndpointTelemetry` ingests device posture (disk encryption, EDR status) and signs it for tamper resistance.
    - Telemetry signatures now derive from configured stable key material, and the in-memory record store is bounded by retention age and maximum record count.
    - `MalwareScanner` runs files through local heuristics plus refreshable malware hash feeds and simple string/rule feeds before the file is handed to a privileged workflow.
    - Upload scanning is bounded by a configured maximum file size before payloads are materialized in memory.
   - Feed refreshes support explicit TLS verification controls, custom CA bundles, local-cache imports for airgapped environments, health reporting for stale or failed detection content, and public-HTTPS URL validation before any refresh request leaves the process.

7. **security_gateway/service.py**
    - FastAPI service that exposes: `/access/evaluate`, `/pam/checkout`, `/dns/resolve`, `/endpoint/scan`, `/endpoint/malware-feeds/*`, `/endpoint/malware-rule-feeds/*`, `/privacy/tracker-feeds/*`, `/health/security`, `/tor/request`.
    - PAM operations, IP block management, automation status, detection-content refresh/import routes, tracker-event views, and report endpoints require operator authorization via a bearer token, preferring a PAM/Vault-backed operator secret and falling back to a static bootstrap token only when needed.
    - Endpoint ingestion (`POST /endpoint/telemetry`, `POST /endpoint/scan`) uses a separate endpoint-agent bearer credential, while telemetry reads stay on the operator control plane.
    - FastAPI docs metadata endpoints are disabled by default so the deployed service does not advertise an OpenAPI surface unless an operator explicitly enables it for development.
    - Trusted host enforcement rejects unexpected `Host` headers before request handling so same-host origin logic and downstream routing do not trust arbitrary hostnames.
    - Response middleware adds baseline anti-sniffing, anti-framing, and privacy-oriented security headers across the HTTP surface by default.
    - The same middleware applies no-store cache directives so secrets, reports, telemetry, and policy responses are not cached by browsers or intermediaries by default.
    - Non-multipart request bodies are bounded before model parsing so oversized JSON/control-plane payloads are rejected early instead of consuming arbitrary memory.
    - Repeated operator and endpoint bearer-token failures are rate-limited across HTTP and the operator WebSocket path to slow brute-force attempts.
    - Proxy and feed-refresh routes keep detailed backend exceptions in audit events while returning stable high-level API errors to clients.
    - Feed/status/report APIs strip internal filesystem paths before returning JSON so cache files and report directories are not disclosed over the HTTP surface.
    - Public-facing HTTP routes apply lightweight per-client rate limits so policy evaluation, DNS lookups, and proxying cannot be spammed indefinitely from one source.
    - Public request models and DNS lookups validate bounded identifiers, finite signal maps, literal source IPs, hostnames, and record types before invoking policy or DoH providers.
    - Operator-facing report and tracker-event endpoints validate filter/query bounds before touching the audit log so pathological PDF requests cannot trigger whole-log scans.
    - The WebSocket channel is also operator-gated, origin-aware for browser clients, rate-limited per connection, and limited to health-style control messages instead of arbitrary echo traffic.
   - Emits audit events to stdout + JSONL for SIEM ingestion.

8. **security_gateway/automation.py**
   - Supervises background rotation + health tasks so protections stay on without user intervention, including optional tracker, malware hash feed, and malware rule feed refreshes.

9. **security_gateway/cli.py**
   - Typer-powered CLI for quick demos (policy evaluation, DNS lookup, Tor fetch, scanning files, automation control).

10. **security_gateway/alerts.py**
   - Delivers alerts to optional webhooks or local toast notifications.
   - Webhook delivery validates HTTPS-only public destinations and fails closed when the configured endpoint is unsafe.

11. **security_gateway/soc.py**
   - Provides a lightweight SOC layer with persisted security events, analyst alerts, and cases.
   - High and critical events automatically promote into analyst-facing alerts, while cases track triage, ownership, and containment workflow.
   - Correlation rules now group related event patterns into higher-level analyst alerts, including repeated tracker activity and endpoints that combine posture drift/compromise with risky access outcomes.
   - Dashboard summaries expose queue health, severity/status counts, recent correlations, and active case workload for analyst triage.
   - This is the first milestone toward a broader security-operations platform; it is intentionally lightweight and file-backed rather than a full SIEM/SOC stack.

## Data Flow
1. A client invokes `/access/evaluate` with user/device/app context.
2. PolicyEngine pulls the latest telemetry, verifies MFA, and can request PAM credentials if the resource is privileged.
3. If outbound calls are needed, responses flow through Tor/WARP proxies and DNS queries use DoH.
4. Endpoint uploads optionally pass through the MalwareScanner; verdicts influence future risk scoring.
5. DNS queries via `/dns/resolve` record their DNSSEC validation status so the policy engine can reduce/increase risk scores based on live data.

## Extensibility
- Each module isolates vendor-specific code so swapping Tor for WARP or adding a new DoH provider requires small edits.
- Configuration lives in `security_gateway/config.py` plus `.env` support for secrets.
- Detection feeds can be bootstrapped from local files for offline environments and then refreshed later when a trusted public HTTPS network path becomes available.
- Tests target the policy engine, DNS resolver, and CLI flows using pytest + httpx mocks.

## SOC Roadmap
- Security Gateway is not a full Security Onion Pro equivalent today.
- The current direction is staged:
  - phase 1: persisted SOC events, alerts, cases, and analyst APIs
  - phase 2: richer event correlation, escalation workflows, and dashboards
  - phase 3: broader telemetry ingestion, durable background jobs, and external integrations
