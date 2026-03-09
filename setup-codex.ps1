param(
  [switch]$ProjectOnly,
  [switch]$UserOnly,
  [switch]$Launch,
  [switch]$SkipDesktopShortcuts
)

$ErrorActionPreference = "Stop"
$script:SetupScriptRoot = Split-Path -Parent $PSCommandPath

function Write-Info($msg) { Write-Host "[codex-setup] $msg" }

function Write-ModelConfigFile {
  param([string]$ConfigPath)

  $dir = Split-Path -Parent $ConfigPath
  New-Item -ItemType Directory -Force -Path $dir | Out-Null

  if (Test-Path -LiteralPath $ConfigPath) {
    try {
      [System.IO.File]::SetAttributes($ConfigPath, [System.IO.FileAttributes]::Normal)
    } catch {
      Write-Info "Could not reset attributes on $($ConfigPath): $($_.Exception.Message)"
    }
  }

@"
model = `"gpt-5.4-codex`"
"@ | Set-Content -Encoding UTF8 -Path $ConfigPath -Force
}

function Ensure-UserConfig {
  $userFile = Join-Path $env:USERPROFILE ".codex\config.toml"
  Write-ModelConfigFile -ConfigPath $userFile
  Write-Info "Wrote user config: $userFile"
  Get-Content $userFile | ForEach-Object { "  $_" }
}

function Ensure-ProjectConfig {
  $projectDir = Join-Path (Get-Location).Path ".codex"
  $projFile = Join-Path $projectDir "config.toml"
  Write-ModelConfigFile -ConfigPath $projFile
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

function Get-DesktopDirectories {
  $candidates = @()

  $shellDesktop = [Environment]::GetFolderPath('Desktop')
  if (-not [string]::IsNullOrWhiteSpace($shellDesktop)) { $candidates += $shellDesktop }

  if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    $candidates += (Join-Path $env:USERPROFILE 'Desktop')
    $candidates += (Join-Path $env:USERPROFILE 'OneDrive\Desktop')
  }

  $commonDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
  if (-not [string]::IsNullOrWhiteSpace($commonDesktop)) { $candidates += $commonDesktop }

  $directories = @()
  foreach ($candidate in ($candidates | Select-Object -Unique)) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    try {
      New-Item -ItemType Directory -Force -Path $candidate | Out-Null
      $directories += (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path
    } catch {
      Write-Info "Skipping desktop target $($candidate): $($_.Exception.Message)"
    }
  }
  return @($directories | Select-Object -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Get-PreferredShell {
  $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
  if ($pwsh) {
    try {
      $version = [version](& $pwsh.Source -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')
      if ($version.Major -ge 7) {
        return @{ Exe = $pwsh.Source; Name = "PowerShell $version"; Icon = "$($pwsh.Source),0" }
      }
    } catch { }
  }

  $windowsPowerShell = Get-Command powershell.exe -ErrorAction SilentlyContinue
  if ($windowsPowerShell) {
    return @{ Exe = $windowsPowerShell.Source; Name = "Windows PowerShell"; Icon = "$($windowsPowerShell.Source),0" }
  }

  throw "No PowerShell executable available for shortcut creation."
}

function Lock-DesktopShortcut {
  param([string]$ShortcutPath)

  if ([string]::IsNullOrWhiteSpace($ShortcutPath)) { return }
  if (-not (Test-Path -LiteralPath $ShortcutPath)) { return }

  try {
    $current = [System.IO.File]::GetAttributes($ShortcutPath)
    if (($current -band [System.IO.FileAttributes]::ReadOnly) -ne 0) { return }
    [System.IO.File]::SetAttributes($ShortcutPath, $current -bor [System.IO.FileAttributes]::ReadOnly)
  } catch {
    Write-Info "Could not lock shortcut $($ShortcutPath): $($_.Exception.Message)"
  }
}

function Unlock-DesktopShortcut {
  param([string]$ShortcutPath)

  if ([string]::IsNullOrWhiteSpace($ShortcutPath)) { return }
  if (-not (Test-Path -LiteralPath $ShortcutPath)) { return }

  try {
    [System.IO.File]::SetAttributes($ShortcutPath, [System.IO.FileAttributes]::Normal)
  } catch {
    Write-Info "Could not unlock shortcut $($ShortcutPath): $($_.Exception.Message)"
  }
}

function Ensure-DesktopShortcuts {
  param([string]$LauncherScript)

  $fallbackLauncher = Resolve-Path -LiteralPath $LauncherScript -ErrorAction Stop
  $desktopDirs = Get-DesktopDirectories
  if ($desktopDirs.Count -eq 0) {
    Write-Info "No desktop directories detected; skipping shortcut refresh."
    return
  }

  $shell = Get-PreferredShell
  $wsh = New-Object -ComObject WScript.Shell
  $launcher54Cmd = Join-Path $script:SetupScriptRoot 'Start_Codex54.cmd'
  $launcher54Ps1 = Join-Path $script:SetupScriptRoot 'Start_Codex54.ps1'
  $launcher5Cmd = Join-Path $script:SetupScriptRoot 'Start_Codex5.cmd'
  $launcher5Ps1 = Join-Path $script:SetupScriptRoot 'Start_Codex5.ps1'
  $launcher53Ps1 = Join-Path $script:SetupScriptRoot 'Start_Codex53.ps1'

  foreach ($desktop in $desktopDirs) {
    $namesToCreate = @('Codex ChatGPT 5.4.lnk', 'Codex ChatGPT 5.lnk')
    $legacyPath = Join-Path $desktop 'Codex ChatGPT 5.3.lnk'
    if ((Test-Path -LiteralPath $legacyPath) -or (Test-Path -LiteralPath $launcher53Ps1)) {
      $namesToCreate += 'Codex ChatGPT 5.3.lnk'
    }

    foreach ($name in ($namesToCreate | Select-Object -Unique)) {
      $shortcutPath = Join-Path $desktop $name
      try {
        Unlock-DesktopShortcut -ShortcutPath $shortcutPath
        if (Test-Path -LiteralPath $shortcutPath) {
          try {
            Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction Stop
          } catch {
            Write-Info "Could not remove existing shortcut $($shortcutPath): $($_.Exception.Message)"
          }
        }
        $shortcut = $wsh.CreateShortcut($shortcutPath)
        $launcherSpec = $null
        if ($name -like '*5.4*') {
          if (Test-Path -LiteralPath $launcher54Cmd) { $launcherSpec = @{ Type = 'cmd'; Path = $launcher54Cmd } }
          elseif (Test-Path -LiteralPath $launcher54Ps1) { $launcherSpec = @{ Type = 'ps1'; Path = $launcher54Ps1 } }
        } elseif ($name -like '*5.3*') {
          if (Test-Path -LiteralPath $launcher53Ps1) { $launcherSpec = @{ Type = 'ps1'; Path = $launcher53Ps1 } }
        }
        if (-not $launcherSpec) {
          if (Test-Path -LiteralPath $launcher5Cmd) {
            $launcherSpec = @{ Type = 'cmd'; Path = $launcher5Cmd }
          } elseif (Test-Path -LiteralPath $launcher5Ps1) {
            $launcherSpec = @{ Type = 'ps1'; Path = $launcher5Ps1 }
          } else {
            $launcherSpec = @{ Type = 'ps1'; Path = $fallbackLauncher.Path }
          }
        }

        $workingDir = Split-Path -Parent $launcherSpec.Path
        if ($launcherSpec.Type -eq 'cmd') {
          $shortcut.TargetPath = $launcherSpec.Path
          $shortcut.Arguments = ""
        } else {
          $shortcut.TargetPath = $shell.Exe
          $shortcut.Arguments = "-NoExit -ExecutionPolicy Bypass -File `"$($launcherSpec.Path)`""
        }
        $shortcut.WorkingDirectory = $workingDir
        $shortcut.IconLocation = $shell.Icon
        $shortcut.Save()
        Lock-DesktopShortcut -ShortcutPath $shortcutPath
        Write-Info "Updated shortcut: $shortcutPath"
      } catch {
        Write-Info "Could not update shortcut $($shortcutPath): $($_.Exception.Message)"
        try {
          $fallbackCmd = [System.IO.Path]::ChangeExtension($shortcutPath, '.cmd')
          @(
            '@echo off',
            'setlocal EnableExtensions',
            "cd /d `"$workingDir`"",
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$($launcher.Path)`""
          ) | Set-Content -Path $fallbackCmd -Encoding Ascii
          Lock-DesktopShortcut -ShortcutPath $fallbackCmd
          Write-Info "Created fallback launcher: $fallbackCmd"
        } catch {
          Write-Info "Fallback creation failed for $($shortcutPath): $($_.Exception.Message)"
        }
      }
    }
  }

  Write-Info "Shortcut shell: $($shell.Name)"
  Write-Info "Shortcut working directory: $script:SetupScriptRoot"
}

if ($UserOnly -and $ProjectOnly) { throw "Pick only one: -UserOnly or -ProjectOnly (or neither for both)." }

if ($UserOnly) { Ensure-UserConfig }
elseif ($ProjectOnly) { Ensure-ProjectConfig }
else { Ensure-UserConfig; Ensure-ProjectConfig }

Test-Codex

if (-not $SkipDesktopShortcuts) {
  try {
    $launcherPath = Join-Path $script:SetupScriptRoot 'Start_Codex5.ps1'
    Ensure-DesktopShortcuts -LauncherScript $launcherPath
  } catch {
    Write-Info "Desktop shortcut refresh skipped: $($_.Exception.Message)"
  }
} else {
  Write-Info "Desktop shortcut refresh skipped by request."
}

if ($Launch) {
  Write-Info "Launching codex..."
  & codex
}
