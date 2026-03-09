# Start_Codex53.ps1
# Launch Codex in THIS folder using your preferred model.
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\Start_Codex53.ps1
#   .\Start_Codex53.ps1 exec "say hello in one word"

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default model (edit this later to upgrade versions)
$Model = "gpt-5.3-codex"

# Match Codex 5.4 launcher behavior: default to user-level Codex home
# unless CODEX_FORCE_PROJECT_HOME is explicitly enabled.
if ($env:CODEX_FORCE_PROJECT_HOME -eq "1") {
  $projectCodexHome = Join-Path $PSScriptRoot ".codex-home"
  New-Item -ItemType Directory -Force -Path $projectCodexHome | Out-Null
  $env:CODEX_HOME = $projectCodexHome
} elseif ([string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
  $env:CODEX_HOME = Join-Path $env:USERPROFILE ".codex"
}
if (Test-Path Env:OPENAI_API_KEY) {
  Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
}

function Ensure-CodexLogin {
  $statusText = (& codex login status 2>&1 | Out-String)
  $needsLogin = ($LASTEXITCODE -ne 0) -or ($statusText -match 'Not logged in|revoked|expired|invalid|unauthorized|401')
  if ($needsLogin) {
    Write-Host "[codex] Auth missing or revoked. Reinitializing login..."
    & codex login --device-auth
    $statusText = (& codex login status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $statusText -match 'Not logged in|revoked|expired|invalid|unauthorized|401') {
      throw "Codex login failed after reinitialization."
    }
  }
}

function cx {
  param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Args
  )
  Ensure-CodexLogin
  # -C makes Codex treat this folder as the working directory
  codex -m $Model -C "$PSScriptRoot" @Args
}

# If you run Start_Codex53.ps1 with no args, open interactive Codex.
if ($Args.Count -eq 0) {
  cx
} else {
  cx @Args
}
