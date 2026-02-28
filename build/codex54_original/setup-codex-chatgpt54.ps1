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
model = "gpt-5.4-codex"
"@ | Set-Content -Path $ConfigPath -Encoding Ascii
}

function Get-PreferredPowerShell {
  $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
  if ($pwsh) {
    try {
      $v = [version](& $pwsh.Source -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')
      if ($v.Major -ge 7) {
        return @{ Exe = $pwsh.Source; Name = "PowerShell $v"; Icon = "$($pwsh.Source),0" }
      }
    } catch { }
  }

  $powershellExe = Get-Command powershell.exe -ErrorAction SilentlyContinue
  if ($powershellExe) {
    Write-Info "pwsh 7+ not found; using Windows PowerShell shortcut fallback."
    return @{ Exe = $powershellExe.Source; Name = "Windows PowerShell"; Icon = "$($powershellExe.Source),0" }
  }

  throw "No PowerShell executable found to create desktop shortcut."
}

function Get-PythonRunner {
  $python = Get-Command python -ErrorAction SilentlyContinue
  if ($python) {
    return @{ Exe = $python.Source; PrefixArgs = @(); Name = "python" }
  }

  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) {
    try {
      & $py.Source -3 --version | Out-Null
      return @{ Exe = $py.Source; PrefixArgs = @("-3"); Name = "py -3" }
    } catch { }
  }

  throw "Python 3 is required for Codex 5.4. Run run-install-python.cmd, then re-run setup."
}

function Assert-PythonReady {
  $runner = Get-PythonRunner
  try {
    $args = @()
    $args += $runner.PrefixArgs
    $args += @("-c", "import sys; print('.'.join(map(str, sys.version_info[:3])))")
    $v = [version](& $runner.Exe @args)
    if ($v.Major -lt 3) {
      throw "Detected Python version is below 3.x."
    }
    Write-Info "Python ready: $v via $($runner.Name)"
  } catch {
    throw "Python 3 is required for Codex 5.4. Run run-install-python.cmd, then re-run setup."
  }
}

function Get-DesktopShortcutPaths {
  $shortcutNames = @("Codex ChatGPT 5.3.lnk", "Codex ChatGPT 5.lnk")
  $desktopCandidates = @()
  $targetDesktops = @()

  $desktopFromShell = [Environment]::GetFolderPath('Desktop')
  if (-not [string]::IsNullOrWhiteSpace($desktopFromShell)) {
    $desktopCandidates += $desktopFromShell
  }

  if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    $desktopFromProfile = Join-Path $env:USERPROFILE 'Desktop'
    if (-not [string]::IsNullOrWhiteSpace($desktopFromProfile)) {
      $desktopCandidates += $desktopFromProfile
    }

    $desktopFromOneDrive = Join-Path $env:USERPROFILE 'OneDrive\Desktop'
    if (-not [string]::IsNullOrWhiteSpace($desktopFromOneDrive)) {
      $desktopCandidates += $desktopFromOneDrive
    }
  }

  $uniqueCandidates = @($desktopCandidates | Select-Object -Unique)
  foreach ($candidate in $uniqueCandidates) {
    if (Test-Path -LiteralPath $candidate) {
      $targetDesktops += $candidate
    }
  }

  if ($targetDesktops.Count -eq 0 -and $uniqueCandidates.Count -gt 0) {
    $targetDesktops += $uniqueCandidates[0]
  }

  $commonDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
  if (-not [string]::IsNullOrWhiteSpace($commonDesktop)) {
    $targetDesktops += $commonDesktop
  }

  $targetDesktops = @($targetDesktops | Select-Object -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($targetDesktops.Count -eq 0) { return @() }

  $items = @()
  foreach ($dir in $targetDesktops) {
    foreach ($shortcutName in $shortcutNames) {
      $items += [pscustomobject]@{
        Name = $shortcutName
        Path = (Join-Path $dir $shortcutName)
      }
    }
  }
  return $items
}

function Ensure-DesktopShortcut {
  param([string]$WorkingDir)

  $shortcutItems = Get-DesktopShortcutPaths
  if ($shortcutItems.Count -eq 0) {
    Write-Info "Desktop paths not found; skipping shortcut creation."
    return
  }

  $shell = Get-PreferredPowerShell
  $launcherScript53 = Join-Path $WorkingDir 'Start_Codex53.ps1'
  $launcherScript5 = Join-Path $WorkingDir 'Start_Codex5.ps1'
  $launcherCmd = Join-Path $WorkingDir 'Start_Codex54.cmd'
  $launcherScript = Join-Path $WorkingDir 'Start_Codex54.ps1'
  $hasLauncherScript53 = Test-Path -LiteralPath $launcherScript53
  $hasLauncherScript5 = Test-Path -LiteralPath $launcherScript5
  $hasLauncherCmd = Test-Path -LiteralPath $launcherCmd
  $hasLauncherScript = Test-Path -LiteralPath $launcherScript

  $wsh = New-Object -ComObject WScript.Shell
  $created = @()
  $failed = @()

  foreach ($item in $shortcutItems) {
    $shortcutPath = $item.Path
    $shortcutDir = Split-Path -Parent $shortcutPath
    try {
      New-Item -ItemType Directory -Force -Path $shortcutDir | Out-Null
      $shortcut = $wsh.CreateShortcut($shortcutPath)
      $shortcut.TargetPath = $shell.Exe
      if ($item.Name -like '*5.3*' -and $hasLauncherScript53) {
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$launcherScript53`""
      } elseif ($hasLauncherScript5) {
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$launcherScript5`""
      } elseif ($hasLauncherCmd) {
        $shortcut.TargetPath = $launcherCmd
        $shortcut.Arguments = ""
      } elseif ($hasLauncherScript) {
        $shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$launcherScript`""
      } else {
        $sourceEscaped = $WorkingDir.Replace("'", "''")
        $cmdParts = @(
          "Set-Location -LiteralPath '$sourceEscaped'",
          "logincodex",
          '$statusText = (& codex login status 2>&1 | Out-String)',
          'if ($LASTEXITCODE -ne 0 -or $statusText -match ''Not logged in'') { Write-Host "You must be logged into ChatGPT before using Codex."; return }',
          'Write-Host "ChatGPT login confirmed. Default model: gpt-5.4-codex"',
          'codex'
        )
        $command = ($cmdParts -join '; ')
        $shortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -Command `"$command`""
      }
      $shortcut.WorkingDirectory = $WorkingDir
      $shortcut.IconLocation = $shell.Icon
      $shortcut.Save()
      $created += $shortcutPath
    } catch {
      $failed += "$shortcutPath ($($_.Exception.Message))"
      try {
        $fallbackCmd = [System.IO.Path]::ChangeExtension($shortcutPath, ".cmd")
        @(
          "@echo off"
          "setlocal EnableExtensions"
          "cd /d `"$WorkingDir`""
          "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$WorkingDir\Start_Codex5.ps1`""
        ) | Set-Content -Path $fallbackCmd -Encoding Ascii
        $created += $fallbackCmd
      } catch {
        $failed += "$shortcutDir (fallback cmd failed: $($_.Exception.Message))"
      }
    }
  }

  foreach ($path in $created) {
    Write-Info "Created desktop shortcut: $path"
  }
  foreach ($path in $failed) {
    Write-Info "Could not create desktop shortcut: $path"
  }
  Write-Info "Shortcut shell: $($shell.Name)"
  Write-Info "Shortcut working directory: $WorkingDir"
}

$resolvedSourceDir = Resolve-SourceDir -Path $SourceDir
Write-Info "Using source directory: $resolvedSourceDir"

$codexCmd = Get-Command codex -ErrorAction SilentlyContinue
if (-not $codexCmd) {
  throw "codex CLI not found on PATH. Install Codex first, then re-run."
}

Assert-PythonReady

# User-level config (same behavior as your own setup)
$userConfigFile = Join-Path $env:USERPROFILE '.codex\config.toml'
Write-ModelConfig -ConfigPath $userConfigFile
Write-Info "Set user default model to gpt-5.4-codex in $userConfigFile"

# Project-level config in source folder (same behavior as your own setup)
$projectConfigFile = Join-Path $resolvedSourceDir '.codex\config.toml'
Write-ModelConfig -ConfigPath $projectConfigFile
Write-Info "Set project default model to gpt-5.4-codex in $projectConfigFile"

$profilePath = Join-Path $env:USERPROFILE 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'
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

Ensure-DesktopShortcut -WorkingDir $resolvedSourceDir

if ($LoginNow) {
  . $helperPath
  logincodex
}

$statusText = (& codex login status 2>&1 | Out-String)
if ($LASTEXITCODE -eq 0 -and $statusText -notmatch 'Not logged in') {
  Write-Info 'ChatGPT login confirmed. Default model: gpt-5.4-codex'
} else {
  Write-Info 'You must be logged into ChatGPT before using Codex. Run: logincodex'
}





