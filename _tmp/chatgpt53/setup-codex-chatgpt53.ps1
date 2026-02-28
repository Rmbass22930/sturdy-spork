param(
  [switch]$LoginNow,
  [string]$SourceDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[codex-setup] $msg" }

function Resolve-SourceDir {
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) {
    throw "SourceDir cannot be empty."
  }

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "SourceDir does not exist: $Path"
  }

  return (Resolve-Path -LiteralPath $Path).Path
}

function Write-ModelConfig {
  param([string]$ConfigPath)

  $dir = Split-Path -Parent $ConfigPath
  New-Item -ItemType Directory -Force -Path $dir | Out-Null

@"
model = "gpt-5.3-codex"
"@ | Set-Content -Path $ConfigPath -Encoding Ascii
}

function Get-PreferredPowerShell {
  $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
  if ($pwsh) {
    return @{ Exe = $pwsh.Source; Name = "PowerShell 7+"; Icon = "$($pwsh.Source),0" }
  }

  return @{ Exe = "powershell.exe"; Name = "Windows PowerShell"; Icon = "$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,0" }
}

function Ensure-DesktopShortcut {
  param(
    [string]$WorkingDir,
    [string]$HelperPath
  )

  $desktopPath = [Environment]::GetFolderPath("Desktop")
  if ([string]::IsNullOrWhiteSpace($desktopPath)) {
    Write-Info "Desktop path not found; skipping shortcut creation."
    return
  }

  New-Item -ItemType Directory -Force -Path $desktopPath | Out-Null

  $shell = Get-PreferredPowerShell
  $sourceEscaped = $WorkingDir.Replace("'", "''")
  $helperEscaped = $HelperPath.Replace("'", "''")

  $cmdParts = @(
    "Set-Location -LiteralPath '$sourceEscaped'",
    ". '$helperEscaped'",
    "logincodex",
    '$statusText = (& codex login status 2>&1 | Out-String)',
    'if ($statusText -notmatch "Logged in") { Write-Host "You must be logged into ChatGPT before using Codex."; return }',
    'Write-Host "ChatGPT login confirmed. Default model: gpt-5.3-codex"',
    'codex'
  )
  $command = ($cmdParts -join '; ')

  $shortcutPath = Join-Path $desktopPath "Codex ChatGPT 5.3.lnk"
  $wsh = New-Object -ComObject WScript.Shell
  $shortcut = $wsh.CreateShortcut($shortcutPath)
  $shortcut.TargetPath = $shell.Exe
  $shortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -Command `"$command`""
  $shortcut.WorkingDirectory = $WorkingDir
  $shortcut.IconLocation = $shell.Icon
  $shortcut.Save()

  Write-Info "Created desktop shortcut: $shortcutPath"
  Write-Info "Shortcut shell: $($shell.Name)"
  Write-Info "Shortcut working directory: $WorkingDir"
}

$resolvedSourceDir = Resolve-SourceDir -Path $SourceDir
Write-Info "Using source directory: $resolvedSourceDir"

$codexCmd = Get-Command codex -ErrorAction SilentlyContinue
if (-not $codexCmd) {
  throw "codex CLI not found on PATH. Install Codex first, then re-run."
}

# User-level config (same behavior as your own setup)
$userConfigFile = Join-Path $env:USERPROFILE '.codex\config.toml'
Write-ModelConfig -ConfigPath $userConfigFile
Write-Info "Set user default model to gpt-5.3-codex in $userConfigFile"

# Project-level config in source folder (same behavior as your own setup)
$projectConfigFile = Join-Path $resolvedSourceDir '.codex\config.toml'
Write-ModelConfig -ConfigPath $projectConfigFile
Write-Info "Set project default model to gpt-5.3-codex in $projectConfigFile"

$profilePath = $PROFILE.CurrentUserCurrentHost
$profileDir = Split-Path -Parent $profilePath
New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
if (-not (Test-Path $profilePath)) {
  New-Item -ItemType File -Path $profilePath -Force | Out-Null
}

$helperPath = Join-Path $PSScriptRoot 'logincodex.ps1'
if (-not (Test-Path $helperPath)) {
  throw "Missing helper file: $helperPath"
}

$markerStart = '# >>> codex helper import >>>'
$helperPathEscaped = $helperPath.Replace("'", "''")
$profileBlock = @"
# >>> codex helper import >>>
. '$helperPathEscaped'
# <<< codex helper import <<<
"@

$currentProfile = Get-Content -Raw -Path $profilePath
if ($currentProfile -match [regex]::Escape($markerStart)) {
  $pattern = '(?s)# >>> codex helper import >>>.*?# <<< codex helper import <<<\r?\n?'
  $updatedProfile = [regex]::Replace($currentProfile, $pattern, $profileBlock + "`r`n")
} else {
  if ($currentProfile.Length -gt 0 -and -not $currentProfile.EndsWith("`r`n")) {
    $currentProfile += "`r`n"
  }
  $updatedProfile = $currentProfile + $profileBlock + "`r`n"
}

Set-Content -Path $profilePath -Value $updatedProfile -Encoding Ascii
Write-Info "Installed helper import in $profilePath"

Ensure-DesktopShortcut -WorkingDir $resolvedSourceDir -HelperPath $helperPath

if ($LoginNow) {
  . $helperPath
  logincodex
  $statusText = (& codex login status 2>&1 | Out-String)
  if ($statusText -match 'Logged in') {
    Write-Info 'ChatGPT login confirmed. Default model: gpt-5.3-codex'
  } else {
    Write-Info 'You must be logged into ChatGPT before using Codex. Run: logincodex'
  }
} else {
  Write-Info 'You must be logged into ChatGPT before using Codex. Run: logincodex'
}
