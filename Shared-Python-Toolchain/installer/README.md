# SecurityGateway Installer Notes

The PyInstaller bootstrap (`installer/installer.py`) can now fetch external programs and payloads from the internet before finishing setup.

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
