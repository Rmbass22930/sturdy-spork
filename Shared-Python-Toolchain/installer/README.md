# SecurityGateway Installer Notes

The PyInstaller bootstrap (`installer/installer.py`) can now fetch external programs and payloads from the internet before finishing setup.

## Build flow

Use [scripts/build-security-gateway.ps1](/J:/_shared_toolchains/Shared-Python-Toolchain/scripts/build-security-gateway.ps1) to build the app and installer together.

- It builds `SecurityGateway.exe` first into a staged location.
- It passes that exact staged payload into `SecurityGatewayInstaller.spec`.
- The installer spec now fails fast if `SECURITY_GATEWAY_PAYLOAD_PATH` is not provided.
- The staged build is pinned to `Python 3.13`.
- By default, the build only publishes `SecurityGatewayInstaller.exe` into the output folder.
- The payload and uninstaller are still built into staged locations for local install refreshes.
- If you need the legacy full release bundle in the output folder, build with `-PublishFullBundle`.
- Full bundle mode emits:
  - `SecurityGateway-build.zip`
  - `SecurityGateway-build-unpack.cmd`
  - `SecurityGateway-build-manifest.json`

This avoids silently embedding a stale `dist\SecurityGateway.exe`.

Use [scripts/sync-security-gateway-release.ps1](/J:/_shared_toolchains/Shared-Python-Toolchain/scripts/sync-security-gateway-release.ps1) to refresh the local installed copy at:
- `C:\Program Files\SecurityGateway`

If you explicitly provide `-PortableRoot`, the sync script can also copy the installer bundle to a portable target. Portable fan-out is no longer the default.

The sync script validates copied file hashes against the generated build manifest when full bundle mode is used.

## Payload / Guide Overrides

- `SECURITY_GATEWAY_PAYLOAD_URL` (or pass `--payload-url`) points to the latest `SecurityGateway.exe`. Optionally pair with `SECURITY_GATEWAY_PAYLOAD_SHA256`.
- `SECURITY_GATEWAY_GUIDE_URL` (or `--guide-url`) points to an updated PDF install guide.

If the overrides are not provided, the embedded payload/guide bundled with the installer are used.

## Dependency Manifest

- The installer looks for a JSON manifest (`installer/dependencies.json` by default). You can override via:
  - `--dependency-manifest <file-or-url>`
  - `SECURITY_GATEWAY_DEPENDENCY_MANIFEST` (file path)
  - `SECURITY_GATEWAY_DEPENDENCY_MANIFEST_URL` (URL)
- Each entry supports either a `winget_id` or a `url` with optional `sha256`, `installer_args`, and `run_installer` flags.

Example entry (see the default `dependencies.json`):

```json
{
  "name": "Cloudflare WARP",
  "winget_id": "Cloudflare.WARP",
  "winget_args": ["--silent"]
}
```

During setup the installer ensures each dependency is installed (using `winget` when possible, otherwise downloading the installer and executing it). This makes it easy to keep VPN clients, Tor, or other prerequisites updated automatically.

If a dependency install fails or times out, the installer now prompts to:
- retry the dependency
- continue without that dependency
- abort setup

For smoke tests or recovery installs, you can bypass dependency installation entirely with:

```powershell
SecurityGatewayInstaller.exe --skip-dependencies
```
