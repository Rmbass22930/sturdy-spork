# Start_Codex54.ps1
# Thin wrapper around the shared Codex launcher.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $PSScriptRoot 'codex_launcher_common.ps1'
if (-not (Test-Path -LiteralPath $launcher)) {
  Write-Error "Missing launcher helper: $launcher"
  exit 1
}

. $launcher
Invoke-CodexLauncher -Model 'gpt-5.4-codex' -LauncherName 'Start_Codex54' -WorkingDirectory $PSScriptRoot -CliArgs $Args -EnableSearch
