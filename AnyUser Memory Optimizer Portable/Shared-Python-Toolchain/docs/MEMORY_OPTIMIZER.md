# Memory Optimizer Utility

The `memory-optimizer` CLI maximizes available physical RAM on Windows hosts by proactively reserving idle memory and releasing it under pressure.

## Installation

After installing project dependencies run:

```powershell
pip install -e .
```

This registers the `memory-optimizer` entry point defined in `pyproject.toml`.

## Usage

Show current statistics:

```powershell
memory-optimizer status
```

Continuously rebalance RAM while keeping at least 1 GB free and limiting reservations to 6 GB:

```powershell
memory-optimizer run --min-free-mb 1024 --max-reserve-mb 6144 --block-size-mb 256
```

Reserve 512 MB immediately (useful for smoke tests):

```powershell
memory-optimizer reserve 512 --tag smoke
```

Statistics can optionally be persisted to disk using `--stats-path path\to\stats.json`. Stop the daemon with `Ctrl+C`; all allocations are released automatically.

When persisting stats that include sensitive telemetry, provide `--stats-key your-passphrase` alongside `--stats-path` to wrap the JSON in AES-256-GCM encryption (PBKDF2-HMAC-SHA256 derived keys). The resulting file stores a base64 payload that you can decrypt with `common_crypto.AES256GCMCipher` or the new helper:

```powershell
memory-optimizer stats-decrypt stats.enc --stats-key (Read-Host -AsSecureString)
```
Use `--output plaintext.json` to write the decrypted JSON instead of printing it.

## Hyper-V Autostart

The recommended VM platform on Windows 11 is Hyper-V because it ships with the OS, supports automatic startup/shutdown, and exposes a robust PowerShell surface for automation. Enable it via:

```powershell
memory-optimizer hyperv-enable
# or run scripts\enable_hyperv.ps1
```

After creating a VM (for example `SecurityLab`), wire memory optimization + VM launch at every logon:

```powershell
memory-optimizer autostart-run --hyperv-vm-name SecurityLab `
  --min-free-mb 1024 --vm-wait-free-mb 2048 `
  --block-size-mb 256 --idle-seconds 180
```

Inside the VM, browse to `http://<host-ip>:8765/` to see a single button that safely stops the VM via the host control panel. Adjust the bind address/port with `--control-panel-host`/`--control-panel-port`, or disable it entirely with `--disable-control-panel`.

To register everything as a scheduled task so it starts whenever Windows loads, run the built-in helper:

```powershell
memory-optimizer hyperv-setup SecurityLab
```

This command enables Hyper-V (unless `--skip-enable-hyperv` is set), writes a PowerShell bootstrap script under `%ProgramData%\MemoryOptimizer\StartMemoryOptimizer.ps1`, and registers a scheduled task `MemoryOptimizerHyperV` that executes the optimizer at every logon.

To remove the automation later without touching other registry entries:

```powershell
memory-optimizer hyperv-uninstall
```

This safely unregisters the scheduled task and deletes the generated script, leaving Hyper-V itself untouched.

## Privacy Route Gate

`autostart-run` and `hyperv-setup` support privacy preflight commands.

```powershell
memory-optimizer autostart-run --hyperv-vm-name SecurityLab `
  --privacy-up-command "Start-Process -FilePath 'C:\Program Files\OpenVPN\bin\openvpn-gui.exe'" `
  --privacy-check-command "if ((Test-NetConnection 1.1.1.1 -Port 443).TcpTestSucceeded) { exit 0 } else { exit 1 }" `
  --privacy-check-retries 10 --privacy-check-interval 3
```

Behavior:
- Default is fail-closed (startup aborts if privacy setup/check fails).
- Use `--allow-unsafe-network-start` to continue anyway (best-effort mode).

