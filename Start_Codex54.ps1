# Start_Codex54.ps1
# Stable launcher for Codex ChatGPT 5.4

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$Model = "gpt-5.4-codex"

if ([string]::IsNullOrWhiteSpace($env:CODEX_HOME) -and $env:CODEX_FORCE_PROJECT_HOME -ne "1") {
  $env:CODEX_HOME = Join-Path $env:USERPROFILE ".codex"
}
if ($env:CODEX_FORCE_PROJECT_HOME -eq "1") {
  $projectHome = Join-Path $PSScriptRoot ".codex-home"
  New-Item -ItemType Directory -Force -Path $projectHome | Out-Null
  $env:CODEX_HOME = $projectHome
}

$codexCommand = Get-Command codex.cmd -ErrorAction SilentlyContinue
if (-not $codexCommand) { $codexCommand = Get-Command codex -ErrorAction SilentlyContinue }
if (-not $codexCommand) {
  Write-Error "Codex CLI not found on PATH."
  exit 127
}
$codexBin = $codexCommand.Source

function Invoke-CodexFiltered {
  param([string[]]$Args)

  $staleArg0WarningPattern = "(?i)^WARNING:\s+failed to clean up stale arg0 temp dirs:"

  $tempRoot = Join-Path $env:LOCALAPPDATA "CodexTemp"
  New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

  $prevTemp = $env:TEMP
  $prevTmp = $env:TMP
  $env:TEMP = $tempRoot
  $env:TMP = $tempRoot

  try {
    $oldErrorAction = $ErrorActionPreference
    $oldNativePref = $PSNativeCommandUseErrorActionPreference
    $ErrorActionPreference = "Continue"
    $PSNativeCommandUseErrorActionPreference = $false
    try {
      $output = & $codexBin @Args 2>&1
      foreach ($line in $output) {
        $s = [string]$line
        if ($s -match $staleArg0WarningPattern) { continue }
        $line
      }
      return $LASTEXITCODE
    } finally {
      $ErrorActionPreference = $oldErrorAction
      $PSNativeCommandUseErrorActionPreference = $oldNativePref
    }
  } finally {
    $env:TEMP = $prevTemp
    $env:TMP = $prevTmp
  }
}

function cx {
  param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$CliArgs = @()
  )

  $CliArgs = @($CliArgs)
  if ($CliArgs.Count -gt 0 -and $CliArgs[0] -eq "exec") {
    $tail = @()
    if ($CliArgs.Count -gt 1) { $tail = $CliArgs[1..($CliArgs.Count - 1)] }
    $runArgs = @("--search", "-m", $Model, "-C", "$PSScriptRoot", "exec", "--skip-git-repo-check") + $tail
    $code = Invoke-CodexFiltered -Args $runArgs
    if ($code -ne 0) { exit $code }
    return
  }

  $runArgs = @("--search", "--no-alt-screen", "-m", $Model, "-C", "$PSScriptRoot") + $CliArgs
  $code = Invoke-CodexFiltered -Args $runArgs
  if ($code -ne 0) { exit $code }
}

if ($Args.Count -eq 0) {
  cx
} else {
  cx @Args
}

