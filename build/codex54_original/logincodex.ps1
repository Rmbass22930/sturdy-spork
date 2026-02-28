function Set-CodexHome {
  [CmdletBinding()]
  param([string]$BasePath = (Get-Location).Path)

  $candidate = Join-Path $BasePath ".codex-home"
  try {
    New-Item -ItemType Directory -Force -Path $candidate | Out-Null
    $env:CODEX_HOME = $candidate
    return
  } catch {
    # Fallback for locked folders.
  }

  $fallback = Join-Path $env:TEMP "codex-home"
  New-Item -ItemType Directory -Force -Path $fallback | Out-Null
  $env:CODEX_HOME = $fallback
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

  if ($env:OPENAI_API_KEY) {
    $env:OPENAI_API_KEY | & codex login --with-api-key
  } else {
    & codex login --device-auth
  }
}
