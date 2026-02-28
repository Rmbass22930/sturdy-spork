function logincodex {
  [CmdletBinding()]
  param([switch]$Force)
  $ErrorActionPreference = "Stop"

  if (-not (Get-Command codex -ErrorAction SilentlyContinue)) {
    Write-Error "codex CLI not found on PATH."
    return
  }

  if (-not $Force) {
    $statusText = (& codex login status 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0 -and $statusText -match "Logged in") {
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
