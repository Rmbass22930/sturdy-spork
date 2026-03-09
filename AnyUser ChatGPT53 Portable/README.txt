AnyUser ChatGPT 5.3 Portable (USB)

Goal
- Install ChatGPT/Codex 5.3 setup from a jump drive for any user machine.
- Uses PowerShell installer flow with dependency setup.
- Requires Administrator privileges (UAC prompt is automatic).

Quick start
1) Run prepare-usb-payload.cmd (builds ChatGPT53-Codex-Setup folder in this package).
2) Copy this whole folder to jump drive.
3) On target machine, run install-anyuser-chatgpt53.exe (or run-from-jump-drive.cmd if you prefer a console window).
4) Review INFO-SHEET-STORAGE.txt before continuing install.

What installer does
- Enforces Administrator privileges before running install steps.
- Ties Codex session/auth to version 5 using `%USERPROFILE%\.codex-gpt5`.
- Ensures PowerShell 7+ using install-latest-powershell.ps1 (winget when available, otherwise a direct GitHub download + silent install).
- Ensures Python 3 + pip trust packages using install-latest-python.ps1 (winget when available, otherwise a direct python.org download + silent install).
- Runs setup-codex-chatgpt53.ps1 against selected source directory.
- Optionally copies payload to local disk so it works after USB removal.
- Verifies key commands at end (pwsh, python, codex when available).

Default local payload location
- C:\ProgramData\AnyUserChatGPT53\ChatGPT53-Codex-Setup

Desktop icons created by installer:
- PowerShell (Admin) -> open-admin-powershell.ps1
- AnyUser ChatGPT53 Installer (Admin) -> install-anyuser-chatgpt53.ps1

Shortcut locking
- Shortcuts are automatically ACL-locked on every detected desktop after install. Users can run `unlock-shortcuts.cmd` (prompts for admin) to temporarily unlock them, edit/move as needed, then rerun the installer to lock them again.
- Original permissions are stored in `C:\ProgramData\AnyUserChatGPT\shortcut-locks.json`.


