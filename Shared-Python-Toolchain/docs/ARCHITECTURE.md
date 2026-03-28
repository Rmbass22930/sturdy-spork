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
   - When a request is denied for high risk, the embedded traceroute runner (with operator confirmation to avoid false positives) captures a back-trace to the source IP, displays the results locally, and attaches the preview to alerts/audit logs.

2. **security_gateway/mfa.py**
   - Wraps WebAuthn/FIDO2 (mocked) and TOTP factors. Provides challenge issuance + verification as first-class steps during `/access/evaluate`.

3. **security_gateway/pam.py**
   - `VaultClient` encrypts passwords/API keys, rotates them daily, and issues short-lived checkout tokens.
   - Supports pluggable backends (in-memory or HashiCorp Vault KV v2) plus JSONL audit logging and rotation metrics exposed via API/CLI.

4. **security_gateway/dns.py**
   - `SecureDNSResolver` performs DNS over HTTPS (Cloudflare + Quad9). Validates responses via DNSSEC flags when available.

5. **security_gateway/tor.py**
   - Provides pluggable outbound proxying via Tor or Cloudflare WARP. Enforces outbound URL validation for the shared proxy path so non-HTTP(S), localhost, private-network, link-local, and metadata-style targets are rejected before requests are sent.

6. **security_gateway/endpoint.py**
   - `EndpointTelemetry` ingests device posture (disk encryption, EDR status) and signs it for tamper resistance.
   - `MalwareScanner` runs files through local heuristics plus refreshable malware hash feeds and simple string/rule feeds before the file is handed to a privileged workflow.
   - Feed refreshes support explicit TLS verification controls, custom CA bundles, local-cache imports for airgapped environments, and health reporting for stale or failed detection content.

7. **security_gateway/service.py**
   - FastAPI service that exposes: `/access/evaluate`, `/pam/checkout`, `/dns/resolve`, `/endpoint/scan`, `/endpoint/malware-feeds/*`, `/endpoint/malware-rule-feeds/*`, `/privacy/tracker-feeds/*`, `/health/security`, `/tor/request`.
   - PAM operations, IP block management, automation status, and detection-content refresh/import routes require operator authorization via a bearer token, with an explicit loopback-only fallback for local-only development.
   - The WebSocket channel is also operator-gated and limited to health-style control messages instead of arbitrary echo traffic.
   - Emits audit events to stdout + JSONL for SIEM ingestion.

8. **security_gateway/automation.py**
   - Supervises background rotation + health tasks so protections stay on without user intervention, including optional tracker, malware hash feed, and malware rule feed refreshes.

9. **security_gateway/cli.py**
   - Typer-powered CLI for quick demos (policy evaluation, DNS lookup, Tor fetch, scanning files, automation control).

## Data Flow
1. A client invokes `/access/evaluate` with user/device/app context.
2. PolicyEngine pulls the latest telemetry, verifies MFA, and can request PAM credentials if the resource is privileged.
3. If outbound calls are needed, responses flow through Tor/WARP proxies and DNS queries use DoH.
4. Endpoint uploads optionally pass through the MalwareScanner; verdicts influence future risk scoring.
5. DNS queries via `/dns/resolve` record their DNSSEC validation status so the policy engine can reduce/increase risk scores based on live data.

## Extensibility
- Each module isolates vendor-specific code so swapping Tor for WARP or adding a new DoH provider requires small edits.
- Configuration lives in `security_gateway/config.py` plus `.env` support for secrets.
- Detection feeds can be bootstrapped from local files for offline environments and then refreshed later when a trusted network path becomes available.
- Tests target the policy engine, DNS resolver, and CLI flows using pytest + httpx mocks.
