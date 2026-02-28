ChatGPT 5.4 Codex Setup (Windows)

Important (required):
- You must be logged into ChatGPT/OpenAI before using Codex.
- Each user must sign in with their own ChatGPT account.

This setup matches your setup style:
- Writes user config: %USERPROFILE%\.codex\config.toml
- Writes project config: <SourceDir>\.codex\config.toml
- Sets model in both places to gpt-5.4-codex
- Adds logincodex helper to PowerShell profile
- Creates desktop shortcuts: Codex ChatGPT 5.4.lnk on user and public desktops (when writable)

PowerShell requirements:
- Required: PowerShell 7+ (pwsh)
- `run-setup.cmd` checks/upgrades PowerShell before setup continues.
- Install latest if needed:
  .\install-latest-powershell.ps1
  or
  .\run-install-powershell.cmd
- If scripts are blocked, run once:
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

Python requirements:
- Required: Python 3
- `run-setup.cmd` checks/upgrades Python before setup continues.
- Install latest if needed:
  .\install-latest-python.ps1
  or
  .\run-install-python.cmd

Step-by-step:
1. Open your source-code folder in File Explorer.
2. Open PowerShell in that folder.
3. Run setup:
   & "C:\Path\To\Shared-Python-Toolchain\setup-codex-chatgpt54.ps1" -SourceDir (Get-Location) -LoginNow
4. Complete ChatGPT login with the user's own account.
5. Verify:
   codex login status
   (must show Logged in)
6. Start:
   codex

Desktop shortcut behavior:
- Opens PowerShell in the source directory
- Runs login check
- Shows: ChatGPT login confirmed. Default model: gpt-5.4-codex
- Launches codex

Session starter (optional):
- `Start_Codex54.cmd` runs `Start_Codex54.ps1` to launch codex in that folder.

