ChatGPT 5.3 Codex Setup (Windows)

What this bundle does:
- Sets Codex default model to gpt-5.3-codex
- Adds reusable logincodex command to your PowerShell profile
- Creates desktop shortcut: Codex ChatGPT 5.3.lnk
- Shortcut opens in your source working directory
- Supports login by ChatGPT device auth or OPENAI_API_KEY

Important:
- Each user must sign in with their own ChatGPT/OpenAI account.
- This package does not copy or transfer anyone else's login session.

PowerShell requirements:
- Recommended: PowerShell 7+ (pwsh)
- If needed, install latest PowerShell:
  - .\install-latest-powershell.ps1
  - or .\run-install-powershell.cmd
- If script execution is blocked, run once in PowerShell:
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

Step-by-step setup:
1. Put this setup folder where you can access it.
2. Open File Explorer to your source-code folder (the folder containing your project files).
3. Open PowerShell in that source folder:
   - Click the Explorer address bar, type powershell, press Enter.
   - Or Shift+Right-click in the folder and choose Open in Terminal.
4. In that PowerShell window, run the setup script from this package path:
   & "C:\Path\To\ChatGPT53-Codex-Setup\setup-codex-chatgpt53.ps1" -SourceDir (Get-Location) -LoginNow
5. Close PowerShell and open a new PowerShell window.
6. In your source folder, run:
   logincodex
7. Verify login:
   codex login status
8. Start Codex with default model gpt-5.3-codex:
   codex

Shortcut behavior:
- Desktop shortcut "Codex ChatGPT 5.3.lnk" logs in and starts codex.
- It opens in the source directory you passed to -SourceDir during setup.
