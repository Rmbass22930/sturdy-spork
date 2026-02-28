function logincodex {
  [CmdletBinding()]
  param([switch]$Reset)
  $ErrorActionPreference = "Stop"

  if ([string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
    $env:CODEX_HOME = Join-Path $env:USERPROFILE ".codex"
  }

  if ($Reset) {
    & codex logout | Out-Null
  }

  if (-not [string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)) {
    $env:OPENAI_API_KEY | & codex login --with-api-key
  } else {
    & codex login --device-auth
  }
}
