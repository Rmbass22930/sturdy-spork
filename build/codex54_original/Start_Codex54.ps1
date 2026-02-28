# Start_Codex54.ps1
# Launch Codex in THIS folder using your preferred model.
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\Start_Codex54.ps1
#   .\Start_Codex54.ps1 exec "say hello in one word"

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

# Improve readability for plain-text output (including WARNING lines).
try {
  $raw = $Host.UI.RawUI
  $raw.BackgroundColor = "Black"
  $raw.ForegroundColor = "White"
} catch {}

# Default model (edit this later to upgrade versions)
$Model = "gpt-5.4-codex"

# Keep Codex state inside the project so launches do not depend on locked profile paths.
$codexHome = Join-Path $PSScriptRoot ".codex-home"
New-Item -ItemType Directory -Force -Path $codexHome | Out-Null
$env:CODEX_HOME = $codexHome
$codexBin = "codex.cmd"

function Invoke-CodexRun {
  param(
    [string[]]$CodexArgs,
    [switch]$ExecMode
  )

  $oldErrorAction = $ErrorActionPreference
  $oldNativePref = $PSNativeCommandUseErrorActionPreference
  $ErrorActionPreference = "Continue"
  $PSNativeCommandUseErrorActionPreference = $false
  try {
    $output = & $codexBin @CodexArgs 2>&1
    $output | ForEach-Object { $_ }
    $text = ($output | Out-String)
    $lastCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $oldErrorAction
    $PSNativeCommandUseErrorActionPreference = $oldNativePref
  }

  $apiDisconnected =
    ($text -match "stream disconnected before completion") -or
    ($text -match "error sending request for url \(https://api\.openai\.com/v1/responses\)")

  if ($apiDisconnected) {
    Write-Warning "OpenAI API/network is unavailable. HTTPS fallback is disabled."
    if ($env:CODEX_SANDBOX_NETWORK_OPTIONAL -eq "1") {
      Write-Warning "Network failure treated as non-fatal because CODEX_SANDBOX_NETWORK_OPTIONAL=1."
      return 0
    }
  }

  return $lastCode
}

function cx {
  param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Args
  )
  # -C makes Codex treat this folder as the working directory.
  # Codex CLI supports --skip-git-repo-check only for `exec`.
  if ($Args.Count -gt 0 -and $Args[0] -eq "exec") {
    $execTail = @()
    if ($Args.Count -gt 1) {
      $execTail = $Args[1..($Args.Count - 1)]
    }
    $runArgs = @("-m", $Model, "-C", "$PSScriptRoot", "exec", "--skip-git-repo-check") + $execTail
    $code = Invoke-CodexRun -CodexArgs $runArgs -ExecMode
    if ($code -ne 0) { exit $code }
    return
  }
  $runArgs = @("-m", $Model, "-C", "$PSScriptRoot") + $Args
  $code = Invoke-CodexRun -CodexArgs $runArgs
  if ($code -ne 0) { exit $code }
}

# If you run Start_Codex54.ps1 with no args, open interactive Codex.
if ($Args.Count -eq 0) {
  cx
} else {
  cx @Args
}

