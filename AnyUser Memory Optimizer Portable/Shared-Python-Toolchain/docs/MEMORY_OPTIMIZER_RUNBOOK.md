# Memory Optimizer + Hyper-V VM Runbook (J:)

## Paths
- Source root: `J:\gdrive\BallisticTarget\src\Shared-Python-Toolchain`
- CLI module: `memory_optimizer.cli`
- Setup executable: `J:\gdrive\BallisticTarget\src\dist\HyperVSetup.exe`

## 1. Open elevated PowerShell (recommended)
Run PowerShell as **Administrator** when enabling Hyper-V features.

## 2. Enable Hyper-V features (admin)
```powershell
Set-Location 'J:\gdrive\BallisticTarget\src\Shared-Python-Toolchain'
python -m memory_optimizer.cli hyperv-enable
```
Reboot if prompted by Windows feature installation.

## 3. Configure startup integration
Recommended (uses scheduled task when permitted):
```powershell
Set-Location 'J:\gdrive\BallisticTarget\src\Shared-Python-Toolchain'
python -m memory_optimizer.cli hyperv-setup SecurityLab
```

Behavior:
- If scheduled-task registration succeeds: startup mode = `scheduled_task`
- If access is denied: automatic fallback to per-user startup registry key (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`), startup mode = `run_key`

## 4. Validate setup
```powershell
python -m memory_optimizer.cli status
python -m memory_optimizer.cli hyperv-setup SecurityLab --skip-enable-hyperv --script-path 'J:\gdrive\BallisticTarget\src\Shared-Python-Toolchain\temp\StartMemoryOptimizer.ps1'
```
The second command should return JSON with `startup_mode`.

## 5. Remove setup (cleanup)
```powershell
python -m memory_optimizer.cli hyperv-uninstall --script-path 'J:\gdrive\BallisticTarget\src\Shared-Python-Toolchain\temp\StartMemoryOptimizer.ps1'
```
This removes scheduled-task registration when possible and also removes run-key fallback entry.

## 6. Build artifacts from source
```powershell
Set-Location 'J:\gdrive\BallisticTarget\src\Shared-Python-Toolchain'
python -m PyInstaller --clean -y HyperVSetup.spec
```
Output executable:
- `J:\gdrive\BallisticTarget\src\dist\HyperVSetup.exe`

## 7. Smoke test executable
```powershell
cmd /c ""J:\gdrive\BallisticTarget\src\dist\HyperVSetup.exe" --help"
```

## Notes
- `hyperv-enable` requires admin rights; non-admin shells will fail with an elevation-required error.
- VM operations require Hyper-V installed and a valid VM name.

## 8. Optional privacy gate (fail-closed)

Embed privacy route setup/verification into startup registration:

```powershell
Set-Location 'J:\gdrive\BallisticTarget\src\Shared-Python-Toolchain'
python -m memory_optimizer.cli hyperv-setup SecurityLab `
  --privacy-up-command "Start-Process -FilePath 'C:\Program Files\OpenVPN\bin\openvpn-gui.exe'" `
  --privacy-check-command "if ((Test-NetConnection 1.1.1.1 -Port 443).TcpTestSucceeded) { exit 0 } else { exit 1 }" `
  --privacy-check-retries 10 --privacy-check-interval 3
```

- Default behavior is fail-closed.
- Add `--allow-unsafe-network-start` only when you intentionally want best-effort startup.

