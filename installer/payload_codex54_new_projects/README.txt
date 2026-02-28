Codex 5.4 (BallisticTarget) - New Projects Setup
================================================

Use this package to set Codex model `gpt-5.4-codex` for any new project.

Included
- setup-codex-chatgpt54.ps1
- run-setup.cmd
- run-install-powershell.cmd
- install-latest-powershell.ps1
- run-install-python.cmd
- install-latest-python.ps1
- logincodex.ps1
- Start_Codex54.ps1
- Start_Codex54.cmd
- codex_profile.ps1
- codex54 new projects.pdf

Quick Start
1. Open a terminal in the project folder you want to use.
2. Run:
   "<path-to-this-package>\run-setup.cmd"
   (This checks/upgrades PowerShell 7+ and Python 3 before setup continues.)
3. Choose where the new project should be created:
   - Desktop
   - Jump drive (USB/removable)
   - Custom path
4. Enter project folder name.
5. Complete ChatGPT login when prompted.

Optional direct mode
- You can bypass prompts and target a specific folder:
  run-setup.cmd "D:\Projects\MyNewProject"

What setup does
- Writes user config: %USERPROFILE%\.codex\config.toml
- Writes project config: <ProjectFolder>\.codex\config.toml
- Sets both to model: gpt-5.4-codex
- Adds `logincodex` helper into your PowerShell profile
- Creates desktop shortcuts: Codex ChatGPT 5.4.lnk on user and public desktops (when writable)

Notes
- `Start_Codex54.ps1` and `codex_profile.ps1` are optional project helpers.
- Codex 5.4 uses PowerShell 7+ (`pwsh`).
- If PowerShell is missing/outdated, run:
  run-install-powershell.cmd
- Codex 5.4 uses Python 3.
- If Python is missing/outdated, run:
  run-install-python.cmd
- If scripts are blocked, run once:
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

