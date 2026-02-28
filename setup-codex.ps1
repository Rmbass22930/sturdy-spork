param(
  [switch]$ProjectOnly,
  [switch]$UserOnly,
  [switch]$Launch
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[codex-setup] $msg" }

function Ensure-UserConfig {
  $userDir  = Join-Path $env:USERPROFILE ".codex"
  $userFile = Join-Path $userDir "config.toml"

  New-Item -ItemType Directory -Force -Path $userDir | Out-Null

  @"
model = `"gpt-5.3-codex`"
"@ | Set-Content -Encoding UTF8 -Path $userFile

  Write-Info "Wrote user config: $userFile"
  Get-Content $userFile | ForEach-Object { "  $_" }
}

function Ensure-ProjectConfig {
  $projDir  = Join-Path (Get-Location) ".codex"
  $projFile = Join-Path $projDir "config.toml"

  New-Item -ItemType Directory -Force -Path $projDir | Out-Null

  @"
model = `"gpt-5.3-codex`"
"@ | Set-Content -Encoding UTF8 -Path $projFile

  Write-Info "Wrote project config: $projFile"
  Get-Content $projFile | ForEach-Object { "  $_" }
}

function Test-Codex {
  $cmd = Get-Command codex -ErrorAction SilentlyContinue
  if (-not $cmd) { throw "codex not found on PATH. Install/update it, then re-run." }
  Write-Info "codex found: $($cmd.Source)"
  try {
    $v = & codex --version 2>$null
    if ($v) { Write-Info "codex version: $v" }
  } catch { }
  Write-Info "When Codex opens, type: /model  (inside Codex) to confirm."
}

if ($UserOnly -and $ProjectOnly) { throw "Pick only one: -UserOnly or -ProjectOnly (or neither for both)." }

if ($UserOnly) { Ensure-UserConfig }
elseif ($ProjectOnly) { Ensure-ProjectConfig }
else { Ensure-UserConfig; Ensure-ProjectConfig }

Test-Codex

if ($Launch) {
  Write-Info "Launching codex..."
  & codex
}
