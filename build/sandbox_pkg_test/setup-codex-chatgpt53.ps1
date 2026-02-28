param(
  [switch]$LoginNow
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[codex-setup] $msg" }

function Ensure-DesktopShortcut {
  $desktopPath = Join-Path $env:USERPROFILE 'Desktop'
  if ([string]::IsNullOrWhiteSpace($desktopPath)) {
    Write-Info "Desktop path not found; skipping shortcut creation."
    return
  }

  New-Item -ItemType Directory -Force -Path $desktopPath | Out-Null

  $shortcutPath = Join-Path $desktopPath "Codex ChatGPT 5.3.lnk"
  $wsh = New-Object -ComObject WScript.Shell
  $shortcut = $wsh.CreateShortcut($shortcutPath)
  $shortcut.TargetPath = "powershell.exe"
  $shortcut.Arguments = '-NoExit -ExecutionPolicy Bypass -Command "logincodex; codex"'
  $shortcut.WorkingDirectory = $env:USERPROFILE
  $shortcut.IconLocation = "$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe,0"
  $shortcut.Save()

  Write-Info "Created desktop shortcut: $shortcutPath"
}

$codexCmd = Get-Command codex -ErrorAction SilentlyContinue
if (-not $codexCmd) {
  throw "codex CLI not found on PATH. Install Codex first, then re-run."
}

$userCodexDir = Join-Path $env:USERPROFILE ".codex"
$userConfigFile = Join-Path $userCodexDir "config.toml"
New-Item -ItemType Directory -Force -Path $userCodexDir | Out-Null

@"
model = "gpt-5.3-codex"
"@ | Set-Content -Path $userConfigFile -Encoding Ascii

Write-Info "Set default model to gpt-5.3-codex in $userConfigFile"

$profilePath = Join-Path $env:USERPROFILE 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'
$profileDir = Split-Path -Parent $profilePath
New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
if (-not (Test-Path $profilePath)) {
  New-Item -ItemType File -Path $profilePath -Force | Out-Null
}

$helperPath = Join-Path $PSScriptRoot "logincodex.ps1"
if (-not (Test-Path $helperPath)) {
  throw "Missing helper file: $helperPath"
}

$markerStart = "# >>> codex helper import >>>"
$profileBlock = @"
# >>> codex helper import >>>
. '$helperPath'
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

Ensure-DesktopShortcut

if ($LoginNow) {
  . $helperPath
  logincodex
} else {
  Write-Info "Open a new PowerShell window and run: logincodex"
}

