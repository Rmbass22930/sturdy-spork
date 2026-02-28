param(
  [switch]$ProjectOnly,
  [switch]$UserOnly,
  [switch]$Launch
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[codex-setup] $msg" }
function Write-Warn($msg) { Write-Host "[codex-setup] WARNING: $msg" -ForegroundColor Yellow }

# Default to the user Codex home so ChatGPT login persists and is shared with 5.3.
# Optional override for project-scoped auth/session:
#   setx CODEX_FORCE_PROJECT_HOME 1
if ($env:CODEX_FORCE_PROJECT_HOME -eq "1") {
  $projectCodexHome = Join-Path (Get-Location) ".codex-home"
  New-Item -ItemType Directory -Force -Path $projectCodexHome | Out-Null
  $env:CODEX_HOME = $projectCodexHome
  Write-Info "Using project CODEX_HOME: $projectCodexHome"
}
else {
  $userCodexHome = Join-Path $env:USERPROFILE ".codex"
  New-Item -ItemType Directory -Force -Path $userCodexHome | Out-Null
  $env:CODEX_HOME = $userCodexHome
  Write-Info "Using user CODEX_HOME: $userCodexHome"
}

function Ensure-UserConfig {
  $userDir  = Join-Path $env:USERPROFILE ".codex"
  $userFile = Join-Path $userDir "config.toml"
  try {
    New-Item -ItemType Directory -Force -Path $userDir | Out-Null

@"
model = `"gpt-5.4-codex`"
"@ | Set-Content -Encoding UTF8 -Path $userFile

    Write-Info "Wrote user config: $userFile"
    Get-Content $userFile | ForEach-Object { "  $_" }
    return $true
  } catch {
    Write-Warn "Could not write user config at $userFile. $($_.Exception.Message)"
    return $false
  }
}

function Ensure-ProjectConfig {
  $projDir  = Join-Path (Get-Location) ".codex"
  $projFile = Join-Path $projDir "config.toml"

  New-Item -ItemType Directory -Force -Path $projDir | Out-Null

@"
model = `"gpt-5.4-codex`"
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

if ($UserOnly) {
  if (-not (Ensure-UserConfig)) {
    throw "User config update failed. Re-run without -UserOnly to keep project config working, or fix write access to $env:USERPROFILE\.codex."
  }
}
elseif ($ProjectOnly) {
  Ensure-ProjectConfig
}
else {
  Ensure-UserConfig | Out-Null
  Ensure-ProjectConfig
}

Test-Codex

if ($Launch) {
  Write-Info "Launching codex..."
  & codex
}


