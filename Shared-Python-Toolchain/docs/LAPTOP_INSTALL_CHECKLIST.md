# Security Gateway Laptop Install Checklist

Date: 2026-03-29
Target build: 0.1.0.0

## Files to Copy

- `F:\created software\SecurityGateway.exe`
- `F:\created software\SecurityGatewayInstaller.exe`

## Artifact Verification

Before running anything on the laptop, verify hashes:

- `SecurityGateway.exe`
  - `22FA2EDF87776D41F9F7033477CB80C157209AAA510277CFE3E4AB579BEDE0D5`
- `SecurityGatewayInstaller.exe`
  - `1504D3B6CF546C5666EED2046B0DCC4A7FBCF8E1132813F2DC6BF9FF23947B8E`

PowerShell command:

```powershell
Get-FileHash .\SecurityGateway.exe, .\SecurityGatewayInstaller.exe -Algorithm SHA256
```

## Install Procedure

1. Copy both executables to a local folder on the laptop.
2. Open an elevated PowerShell or run the installer with administrator rights.
3. Launch `SecurityGatewayInstaller.exe`.
4. Let the installer complete file copy, PATH update, shortcut creation, and scheduled task registration.
5. If Windows SmartScreen prompts, verify the file name and hash before allowing execution.

## Post-Install Checks

1. Confirm the app exists at `C:\Program Files\SecurityGateway\SecurityGateway.exe`.
2. Confirm desktop shortcut(s) were created.
3. Confirm the scheduled task `SecurityGatewayAutomation` exists.
4. Open a new terminal and run:

```powershell
security-gateway --help
```

5. Confirm the command prints CLI help without extraction or startup errors.

## Functional Smoke Checks

Run these from a new terminal after install:

```powershell
security-gateway health-status
security-gateway proxy-health
```

Expected result:

- commands run successfully
- no packaging extraction failure
- health output returns structured status

## If Something Fails

- Recheck the SHA-256 hashes before rerunning the installer.
- Make sure the installer was launched with administrator rights.
- Close any stale `SecurityGatewayInstaller.exe` processes before retrying.
- If PATH does not update in the current shell, open a new terminal session.
- If needed, use `C:\Program Files\SecurityGateway\Uninstall-SecurityGateway.ps1` from an elevated PowerShell session, then reinstall.
