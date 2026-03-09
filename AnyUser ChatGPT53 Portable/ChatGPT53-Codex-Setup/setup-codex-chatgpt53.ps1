param(
  [switch]$LoginNow,
  [string]$SourceDir = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
$Model = "gpt-5-codex"
$VersionSessionHome = Join-Path $env:USERPROFILE ".codex-gpt5"

function Write-Info($msg) { Write-Host "[codex-setup] $msg" }

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($id)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevated {
  if (Test-IsAdmin) { return }

  $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
  foreach ($entry in $PSBoundParameters.GetEnumerator()) {
    $key = $entry.Key
    $value = $entry.Value
    if ($value -is [switch] -or $value -is [bool]) {
      if ([bool]$value) { $argList += ('-{0}' -f $key) }
    } elseif ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
      $argList += ('-{0}' -f $key)
      $argList += ('"{0}"' -f ([string]$value).Replace('"','\"'))
    }
  }

  $joined = [string]::Join(' ', $argList)
  Write-Host '[codex-setup] Requesting Administrator privileges...' -ForegroundColor Yellow
  try {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $joined -WorkingDirectory (Split-Path -Parent $PSCommandPath) -ErrorAction Stop | Out-Null
  } catch {
    throw 'Administrator approval is required to continue Codex setup.'
  }
  exit 0
}

function Assert-Elevated {
  if (-not (Test-IsAdmin)) {
    throw 'Administrator privileges are required to run ChatGPT 5.3 Codex setup.'
  }
  Write-Info 'Running with Administrator privileges.'
}

function Set-VersionSessionHome {
  New-Item -ItemType Directory -Force -Path $VersionSessionHome | Out-Null
  $env:CODEX_HOME = $VersionSessionHome
  Write-Info "Using version-tied CODEX_HOME: $VersionSessionHome"
}

function Clear-ApiKeyEnvironment {
  foreach ($name in @('OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_ORG_ID')) {
    Remove-Item -Path ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
  }
}

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
model = "$Model"
"@ | Set-Content -Path $ConfigPath -Encoding Ascii
}

function Get-PreferredPowerShell {
  $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
  if (-not $pwsh) {
    throw "PowerShell 7+ (pwsh) is required for Codex 5.3. Run run-install-powershell.cmd, then re-run setup."
  }

  try {
    $v = [version](& $pwsh.Source -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')
    if ($v.Major -lt 7) {
      throw "Detected pwsh version is below 7."
    }
    return @{ Exe = $pwsh.Source; Name = "PowerShell $v"; Icon = "$($pwsh.Source),0" }
  } catch {
    throw "PowerShell 7+ (pwsh) is required for Codex 5.3. Run run-install-powershell.cmd, then re-run setup."
  }
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

  throw "Python 3 is required for Codex 5.3. Run run-install-python.cmd, then re-run setup."
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
    throw "Python 3 is required for Codex 5.3. Run run-install-python.cmd, then re-run setup."
  }
}

function Resolve-DesktopPath {
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $null
  }

  try {
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  } catch {
    Write-Info "Skipping desktop target $Path: $($_.Exception.Message)"
    return $null
  }
}

function Lock-DesktopShortcut {
  param([string]$ShortcutPath)

  if ([string]::IsNullOrWhiteSpace($ShortcutPath)) {
    return
  }

  try {
    if (-not (Test-Path -LiteralPath $ShortcutPath)) { return }
    $current = [System.IO.File]::GetAttributes($ShortcutPath)
    if (($current -band [System.IO.FileAttributes]::ReadOnly) -ne 0) { return }
    $newValue = $current -bor [System.IO.FileAttributes]::ReadOnly
    [System.IO.File]::SetAttributes($ShortcutPath, $newValue)
  } catch {
    Write-Info "Could not lock desktop icon $ShortcutPath: $($_.Exception.Message)"
  }
}

function Get-DesktopShortcutPaths {
  $shortcutDefs = @(
    @{ Name = "Codex ChatGPT 5.3.lnk"; Model = "gpt-5.3-codex" },
    @{ Name = "Codex ChatGPT 5.lnk"; Model = $Model }
  )
  $userDesktopCandidates = @()
  $targetDesktops = @()

  $desktopFromShell = [Environment]::GetFolderPath('Desktop')
  if (-not [string]::IsNullOrWhiteSpace($desktopFromShell)) {
    $userDesktopCandidates += $desktopFromShell
  }

  if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    $desktopFromProfile = Join-Path $env:USERPROFILE 'Desktop'
    if (-not [string]::IsNullOrWhiteSpace($desktopFromProfile)) {
      $userDesktopCandidates += $desktopFromProfile
    }

    $desktopFromOneDrive = Join-Path $env:USERPROFILE 'OneDrive\Desktop'
    if (-not [string]::IsNullOrWhiteSpace($desktopFromOneDrive)) {
      $userDesktopCandidates += $desktopFromOneDrive
    }
  }

  $uniqueCandidates = @($userDesktopCandidates | Select-Object -Unique)
  foreach ($candidate in $uniqueCandidates) {
    $resolved = Resolve-DesktopPath -Path $candidate
    if ($resolved) { $targetDesktops += $resolved }
  }

  if ($targetDesktops.Count -eq 0 -and $uniqueCandidates.Count -gt 0) {
    $fallback = Resolve-DesktopPath -Path $uniqueCandidates[0]
    if ($fallback) { $targetDesktops += $fallback }
  }

  $commonDesktop = Resolve-DesktopPath -Path ([Environment]::GetFolderPath('CommonDesktopDirectory'))
  if ($commonDesktop) {
    $targetDesktops += $commonDesktop
  }

  $targetDesktops = @($targetDesktops | Select-Object -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  if ($targetDesktops.Count -eq 0) { return @() }

  $items = @()
  foreach ($dir in $targetDesktops) {
    foreach ($def in $shortcutDefs) {
      $items += [pscustomobject]@{
        Name = $def.Name
        Model = $def.Model
        Path = (Join-Path $dir $def.Name)
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
  $sourceEscaped = $WorkingDir.Replace("'", "''")

  $wsh = New-Object -ComObject WScript.Shell
  $created = @()
  $failed = @()

  foreach ($item in $shortcutItems) {
    $shortcutPath = $item.Path
    $shortcutDir = Split-Path -Parent $shortcutPath
    try {
      $cmdParts = @(
        'Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue',
        'Remove-Item Env:OPENAI_BASE_URL -ErrorAction SilentlyContinue',
        'Remove-Item Env:OPENAI_ORG_ID -ErrorAction SilentlyContinue',
        "Set-Location -LiteralPath '$sourceEscaped'",
        "logincodex",
        '$statusText = (& codex login status 2>&1 | Out-String)',
        'if ($LASTEXITCODE -ne 0 -or $statusText -match ''Not logged in'') { Write-Host "You must be logged into ChatGPT before using Codex."; return }',
        "`$env:CODEX_HOME = '$($VersionSessionHome.Replace("'","''"))'",
        "Write-Host `"ChatGPT login confirmed. Model: $($item.Model)`"",
        "codex -m $($item.Model)"
      )
      $command = ($cmdParts -join '; ')

      New-Item -ItemType Directory -Force -Path $shortcutDir | Out-Null
      $shortcut = $wsh.CreateShortcut($shortcutPath)
      $shortcut.TargetPath = $shell.Exe
      $shortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -Command `"$command`""
      $shortcut.WorkingDirectory = $WorkingDir
      $shortcut.IconLocation = $shell.Icon
      $shortcut.Save()
      Lock-DesktopShortcut -ShortcutPath $shortcutPath
      $created += $shortcutPath
    } catch {
      $failed += "$shortcutPath ($($_.Exception.Message))"
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

Ensure-Elevated
Assert-Elevated

$resolvedSourceDir = Resolve-SourceDir -Path $SourceDir
Write-Info "Using source directory: $resolvedSourceDir"

$codexCmd = Get-Command codex -ErrorAction SilentlyContinue
if (-not $codexCmd) {
  throw "codex CLI not found on PATH. Install Codex first, then re-run."
}

Clear-ApiKeyEnvironment
Set-VersionSessionHome

Assert-PythonReady

# User-level config (same behavior as your own setup)
$userConfigFile = Join-Path $env:USERPROFILE '.codex\config.toml'
Write-ModelConfig -ConfigPath $userConfigFile
Write-Info "Set user default model to $Model in $userConfigFile"

# Project-level config in source folder (same behavior as your own setup)
$projectConfigFile = Join-Path $resolvedSourceDir '.codex\config.toml'
Write-ModelConfig -ConfigPath $projectConfigFile
Write-Info "Set project default model to $Model in $projectConfigFile"

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
if (Test-Path -LiteralPath '$helperPath') { . '$helperPath' }
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
  Clear-ApiKeyEnvironment
  Set-VersionSessionHome
  . $helperPath
  logincodex
  $statusText = (& codex login status 2>&1 | Out-String)
  if ($LASTEXITCODE -eq 0 -and $statusText -notmatch 'Not logged in') {
    Write-Info "ChatGPT login confirmed. Default model: $Model"
  } else {
    throw 'ChatGPT login is required. Complete `logincodex` with a ChatGPT subscription account.'
  }
} else {
  Write-Info 'ChatGPT subscription login required. Run: logincodex'
}



