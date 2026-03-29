# Security Gateway Release Notes

Date: 2026-03-29
Version: 0.1.0.0

## Summary

This release finalizes the renamed shared Python toolchain and hardens the Security Gateway service, packaging, and installer flow for local deployment.

## Security Hardening

- Removed trust in the inbound `Host` header for WebSocket origin validation.
- Required operator authentication for `/tor/request` to prevent open-proxy behavior.
- Changed operator and endpoint loopback token bypass defaults to fail closed.
- Removed silent fallback from PAM-backed bearer token lookup to static config tokens.
- Fixed PAM key rotation so rotated secrets remain readable after service restart when using a persistent backend.
- Added startup validation so broken PAM-backed auth backends fail fast instead of degrading at request time.
- Added `/health/security` auth-backend status reporting for operator and endpoint bearer token state.

## Quality and Verification

- Full Python test suite passed: `161 passed`
- `py -3.14 -m mypy security_gateway` passed clean
- `py -3.13 -m ruff check security_gateway tests` passed clean
- Smoke-tested rebuilt executables:
  - `SecurityGateway.exe --help` executed successfully
  - `SecurityGatewayInstaller.exe` launched successfully as a responsive process

## Packaging Changes

- Added Windows version metadata to both executables.
- Removed dev-only `IPython` and `pytest` content from the packaged Security Gateway payload.
- Rebuilt release artifacts to `F:\created software`.

## Release Artifacts

- `F:\created software\SecurityGateway.exe`
  - SHA-256: `22FA2EDF87776D41F9F7033477CB80C157209AAA510277CFE3E4AB579BEDE0D5`
- `F:\created software\SecurityGatewayInstaller.exe`
  - SHA-256: `1504D3B6CF546C5666EED2046B0DCC4A7FBCF8E1132813F2DC6BF9FF23947B8E`

## Relevant Commits

- `61b20a4` Surface auth backend health in status endpoint
- `7d0c6e2` Tighten Security Gateway packaging metadata
