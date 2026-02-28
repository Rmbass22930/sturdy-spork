function Set-CodexHome {
  [CmdletBinding()]
  param()

  $env:CODEX_HOME = Join-Path $env:USERPROFILE ".codex"
  New-Item -ItemType Directory -Force -Path $env:CODEX_HOME | Out-Null
}

function logincodex {
  [CmdletBinding()]
  param([switch]$Force)
  $ErrorActionPreference = "Stop"

  Set-CodexHome

  if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
    Write-Error "codex CLI not found on PATH."
    return
  }

  if (-not $Force) {
    $statusText = (& codex login status 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0 -and $statusText -notmatch "Not logged in") {
      Write-Host "Already logged in using ChatGPT."
      return
    }
  }

  if (Test-Path Env:OPENAI_API_KEY) {
    Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
  }
  & codex login --device-auth
}
