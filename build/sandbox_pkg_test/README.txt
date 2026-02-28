ChatGPT 5.3 Codex Setup (Windows)

What this bundle does:
- Sets Codex default model to gpt-5.3-codex
- Adds a reusable logincodex command to the user's PowerShell profile
- Creates a desktop shortcut: Codex ChatGPT 5.3.lnk
- Supports login by ChatGPT account (device auth) or OPENAI_API_KEY

Important:
- Your friend must use their own ChatGPT/OpenAI account.
- This does not transfer your login session or credentials.

How to use:
1. Install Codex CLI first.
2. Open PowerShell in this folder.
3. Run:
   .\setup-codex-chatgpt53.ps1
   or
   .\run-setup.cmd
4. Open a new PowerShell window.
5. Run:
   logincodex
6. Verify:
   codex login status

Optional:
- Immediate login while setting up:
  .\setup-codex-chatgpt53.ps1 -LoginNow
