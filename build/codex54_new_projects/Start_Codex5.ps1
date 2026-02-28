# Start_Codex5.ps1
# Minimal launcher for ChatGPT 5 model, matching working 5.3 behavior.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Model = "gpt-5.4-codex"

# Force ChatGPT-account auth path (e.g., Pro plan) by default.
$env:CODEX_HOME = Join-Path $env:USERPROFILE ".codex"
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
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
  )
  Ensure-CodexLogin
  codex -m $Model -C "$PSScriptRoot" @Args
}

if ($Args.Count -eq 0) {
  cx
} else {
  cx @Args
}

