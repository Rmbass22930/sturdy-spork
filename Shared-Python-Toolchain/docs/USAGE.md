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
- `WS /ws` – real-time channel (sends `{"type":"ready"}` on connect, `ping` -> `pong`, other messages echoed as `echo:<message>`).

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
security-gateway report-list
security-gateway report-open
security-gateway report-open security-summary-20260327-120000.pdf --print
security-gateway report-browser
security-gateway scan suspicious.bin
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

## Quiet operation defaults
- Desktop toast alerts are disabled by default.
- Traceroute popup previews are disabled by default.
- Detection evidence still goes to the audit log and any configured webhook.
- To re-enable the local UI signals:
```
SECURITY_GATEWAY_ALERT_ENABLE_TOAST=true
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
- API support:
  - `GET /reports` lists saved PDFs
  - `GET /reports/security-summary.pdf` generates a current summary PDF
  - `GET /reports/{name}` fetches a saved PDF

## Uninstall
- After running the installer, an elevated script is dropped at `C:\Program Files\SecurityGateway\Uninstall-SecurityGateway.ps1`. Run it as Administrator to remove the binary, PATH entry, desktop shortcut, and any residual data under `%ProgramData%\SecurityGateway` and `%LOCALAPPDATA%\SecurityGateway`.
