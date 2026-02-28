function logincodex {
  [CmdletBinding()]
  param([switch]$Reset)
  $ErrorActionPreference = "Stop"

  $env:CODEX_HOME = Join-Path $env:USERPROFILE ".codex"
  New-Item -ItemType Directory -Force -Path $env:CODEX_HOME | Out-Null

  if ($Reset) {
    & codex logout | Out-Null
  }

  if (Test-Path Env:OPENAI_API_KEY) {
    Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
  }
  & codex login --device-auth
}
