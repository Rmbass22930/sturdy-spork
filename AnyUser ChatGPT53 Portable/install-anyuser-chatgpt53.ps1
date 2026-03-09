[CmdletBinding()]
param(
  [string]$PayloadRoot,
  [string]$SourceDir,
  [string]$InstallRoot = 'C:\ProgramData\AnyUserChatGPT',
  [switch]$CopyToLocal,
  [switch]$SkipDependencyInstall,
  [switch]$SkipGitInstall,
  [switch]$SkipCodexInstall,
  [switch]$SkipCodexSetup,
  [switch]$NonInteractive,
  [switch]$AcknowledgeInfoSheet
)

$ErrorActionPreference = 'Stop'
$VersionSessionHome = Join-Path $env:USERPROFILE '.codex-gpt5'

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevated {
  if (Test-IsAdmin) { return }

  $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
  foreach ($entry in $PSBoundParameters.GetEnumerator()) {
    $k = $entry.Key
    $v = $entry.Value
    if ($v -is [switch] -or $v -is [bool]) {
      if ([bool]$v) { $argList += ('-{0}' -f $k) }
    } elseif ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) {
      $argList += ('-{0}' -f $k)
      $argList += ('"{0}"' -f ([string]$v).Replace('"','\"'))
    }
  }

  $joined = [string]::Join(' ', $argList)
  Write-Host 'Requesting Administrator elevation...' -ForegroundColor Yellow
  try {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $joined -ErrorAction Stop | Out-Null
  } catch {
    throw "Administrator elevation is required. Re-run and accept the UAC prompt."
  }
  exit 0
}

function Assert-Elevated {
  if (-not (Test-IsAdmin)) {
    throw "Administrator privileges are required for this installer."
  }
  Write-Host 'Running with Administrator privileges.' -ForegroundColor Green
}

function Clear-ApiKeyEnvironment {
  foreach ($name in @('OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_ORG_ID')) {
    Remove-Item -Path ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
  }
}

function Set-VersionSessionHome {
  New-Item -ItemType Directory -Force -Path $VersionSessionHome | Out-Null
  $env:CODEX_HOME = $VersionSessionHome
  Write-Host "Using version-tied CODEX_HOME: $VersionSessionHome" -ForegroundColor Cyan
}

function Assert-ChatGPTLogin {
  $statusText = (& codex login status 2>&1 | Out-String)
  if ($LASTEXITCODE -ne 0 -or $statusText -match 'Not logged in') {
    throw 'ChatGPT subscription login is required. Run `logincodex` and sign in with the user ChatGPT account.'
  }
  Write-Host 'ChatGPT login confirmed (subscription auth).' -ForegroundColor Green
}

function Show-FirstReadNotice {
  Write-Host ''
  Write-Host 'FIRST READ BEFORE RUNNING INSTALLER:' -ForegroundColor Yellow
  Write-Host 'Make sure you are logged into ChatGPT first.' -ForegroundColor Yellow
  Write-Host 'This installer depends on ChatGPT subscription login to complete setup.' -ForegroundColor Yellow
  Write-Host ''
}

function Read-Default([string]$Prompt, [string]$Default) {
  $raw = Read-Host "$Prompt [$Default]"
  if ([string]::IsNullOrWhiteSpace($raw)) { return $Default }
  return $raw.Trim()
}

function Read-YesNo([string]$Prompt, [bool]$DefaultYes) {
  $defaultToken = if ($DefaultYes) { 'Y/n' } else { 'y/N' }
  $raw = Read-Host "$Prompt ($defaultToken)"
  if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultYes }
  $v = $raw.Trim().ToLowerInvariant()
  return ($v -eq 'y' -or $v -eq 'yes' -or $v -eq 'true' -or $v -eq '1')
}

function Show-InfoSheet {
  $sheetPath = Join-Path (Split-Path -Parent $PSCommandPath) 'INFO-SHEET-STORAGE.txt'
  if (-not (Test-Path -LiteralPath $sheetPath)) {
    Write-Host 'INFO-SHEET-STORAGE.txt not found; continuing.' -ForegroundColor Yellow
    return
  }

  Write-Host ''
  Write-Host 'Required pre-install information sheet:' -ForegroundColor Cyan
  Write-Host "  $sheetPath"

  try { Start-Process notepad.exe -ArgumentList ('"{0}"' -f $sheetPath) | Out-Null } catch { }
  Get-Content -Path $sheetPath | ForEach-Object { Write-Host $_ }

  if ($AcknowledgeInfoSheet) { return }
  if ($NonInteractive) {
    throw 'NonInteractive mode requires -AcknowledgeInfoSheet after reviewing INFO-SHEET-STORAGE.txt.'
  }

  $answer = Read-Host 'Type YES to confirm you reviewed INFO-SHEET-STORAGE.txt'
  if ($answer -ne 'YES') {
    throw 'Installation stopped: info sheet was not acknowledged.'
  }
}

function Resolve-PayloadRoot([string]$ExplicitPath) {
  if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
    if (Test-Path -LiteralPath $ExplicitPath) { return (Resolve-Path -LiteralPath $ExplicitPath).Path }
    throw "Payload root not found: $ExplicitPath"
  }

  $scriptRoot = Split-Path -Parent $PSCommandPath
  $candidates = @(
    (Join-Path $scriptRoot 'ChatGPT53-Codex-Setup'),
    (Join-Path (Split-Path -Parent $scriptRoot) 'ChatGPT53-Codex-Setup')
  )

  foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
  }

  throw 'Could not find ChatGPT53-Codex-Setup payload. Run prepare-usb-payload.cmd first or pass -PayloadRoot.'
}

function Get-DefaultSourceDir {
  $candidates = @()
  if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    $candidates += @(
      (Join-Path $env:USERPROFILE 'source'),
      (Join-Path $env:USERPROFILE 'projects'),
      (Join-Path $env:USERPROFILE 'Desktop'),
      $env:USERPROFILE
    )
  }
  $firstExisting = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if ($firstExisting) { return (Resolve-Path -LiteralPath $firstExisting).Path }
  return (Get-Location).Path
}

function Invoke-StepScript([string]$ScriptPath) {
  if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Missing installer script: $ScriptPath"
  }

  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath
  if ($LASTEXITCODE -ne 0) {
    throw "Script failed: $ScriptPath (exit $LASTEXITCODE)"
  }
}

function Ensure-Git {
  $git = Get-Command git -ErrorAction SilentlyContinue
  if ($git) { return }

  $winget = Get-Command winget -ErrorAction SilentlyContinue
  $choco = Get-Command choco -ErrorAction SilentlyContinue

  if ($winget) {
    Write-Host 'Git not found. Attempting install via winget...' -ForegroundColor Cyan
    & $winget.Source install --id Git.Git --source winget --accept-source-agreements --accept-package-agreements
  } elseif ($choco) {
    Write-Host 'Git not found. Attempting install via Chocolatey...' -ForegroundColor Cyan
    & $choco.Source install git -y
  } else {
    throw 'Git missing and no package manager found (winget/choco). Install Git manually from https://git-scm.com/download/win'
  }

  if ($LASTEXITCODE -ne 0) {
    throw 'Automatic Git install failed. Install Git manually, then rerun installer.'
  }

  $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
  $git = Get-Command git -ErrorAction SilentlyContinue
  if (-not $git) {
    throw 'Git still not detected on PATH after install. Open a new terminal and run: git --version'
  }
}

function Ensure-CodexCli {
  $codex = Get-Command codex -ErrorAction SilentlyContinue
  if ($codex) { return }

  Write-Host 'Codex CLI not found. Attempting install...' -ForegroundColor Cyan
  $npm = Get-Command npm -ErrorAction SilentlyContinue
  if (-not $npm) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($winget) {
      Write-Host 'npm not found. Installing Node.js LTS via winget...' -ForegroundColor Cyan
      & $winget.Source install --id OpenJS.NodeJS.LTS --source winget --accept-source-agreements --accept-package-agreements
    } elseif ($choco) {
      Write-Host 'npm not found. Installing Node.js LTS via Chocolatey...' -ForegroundColor Cyan
      & $choco.Source install nodejs-lts -y
    } else {
      throw 'Codex CLI missing and npm unavailable. Install Node.js LTS + npm, then run: npm install -g @openai/codex'
    }
    if ($LASTEXITCODE -ne 0) {
      throw 'Node.js install failed. Install Node.js LTS manually, then run: npm install -g @openai/codex'
    }
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $npm) {
      throw 'npm still not found after install. Open new terminal and run: npm --version'
    }
  }

  & $npm.Source install -g @openai/codex
  if ($LASTEXITCODE -ne 0) {
    & $npm.Source install -g codex
    if ($LASTEXITCODE -ne 0) {
      throw 'Automatic Codex CLI install failed. Run: npm install -g @openai/codex, then rerun installer.'
    }
  }

  $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
  $codex = Get-Command codex -ErrorAction SilentlyContinue
  if (-not $codex) {
    throw 'Codex CLI still not detected on PATH after install. Open a new terminal and run: codex --version'
  }
}

function Get-DesktopPaths {
  $list = @([Environment]::GetFolderPath('Desktop'))
  if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    $list += Join-Path $env:USERPROFILE 'Desktop'
    $oneDriveCandidates = @($env:OneDrive, $env:OneDriveCommercial, $env:OneDriveConsumer) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    foreach ($candidate in $oneDriveCandidates) {
      $list += Join-Path $candidate 'Desktop'
    }
    $list += Join-Path $env:USERPROFILE 'OneDrive\Desktop'
  }
  $list += [Environment]::GetFolderPath('CommonDesktopDirectory')
  return @($list | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
}

function Get-ShortcutLockStorePath([string]$Root) {
  if ([string]::IsNullOrWhiteSpace($Root)) {
    throw 'InstallRoot cannot be blank when locking shortcuts.'
  }
  return Join-Path $Root 'shortcut-locks.json'
}

function Load-ShortcutLockRecords([string]$StorePath) {
  if (-not (Test-Path -LiteralPath $StorePath)) { return @() }
  try {
    $raw = Get-Content -LiteralPath $StorePath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $parsed) { return @() }
    if ($parsed.PSObject.Properties.Name -contains 'Locks') {
      return @($parsed.Locks)
    }
    return @($parsed)
  } catch {
    Write-Host "Could not parse shortcut lock store ($StorePath): $($_.Exception.Message)" -ForegroundColor Yellow
    return @()
  }
}

function Save-ShortcutLockRecords([string]$StorePath, [array]$Records) {
  $payload = @{
    Version = 1
    SavedOn = (Get-Date).ToString('o')
    Locks   = @($Records | Where-Object { $_ -and $_.Path })
  }
  $folder = Split-Path -Parent $StorePath
  if (-not (Test-Path -LiteralPath $folder)) {
    New-Item -ItemType Directory -Force -Path $folder | Out-Null
  }
  $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StorePath -Encoding UTF8
}

function New-ShortcutAccessRule {
  param(
    [string]$Identity,
    [System.Security.AccessControl.FileSystemRights]$Rights
  )
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
  $propagation = [System.Security.AccessControl.PropagationFlags]::None
  $accessType  = [System.Security.AccessControl.AccessControlType]::Allow
  return New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Rights, $inheritance, $propagation, $accessType)
}

function Lock-DesktopShortcuts {
  param(
    [string[]]$ShortcutPaths,
    [string]$StorePath
  )

  if (-not $ShortcutPaths -or [string]::IsNullOrWhiteSpace($StorePath)) { return }

  $knownRecords = @{}
  foreach ($record in (Load-ShortcutLockRecords -StorePath $StorePath)) {
    if ($null -ne $record -and -not [string]::IsNullOrWhiteSpace($record.Path)) {
      $knownRecords[$record.Path.ToLowerInvariant()] = $record
    }
  }

  foreach ($shortcut in $ShortcutPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
    if (-not (Test-Path -LiteralPath $shortcut)) { continue }
    $resolved = (Resolve-Path -LiteralPath $shortcut).Path
    $key = $resolved.ToLowerInvariant()
    try {
      $acl = Get-Acl -LiteralPath $resolved
      if (-not $knownRecords.ContainsKey($key)) {
        $knownRecords[$key] = [pscustomobject]@{
          Path         = $resolved
          OriginalSddl = $acl.Sddl
          LockedOn     = (Get-Date).ToString('o')
        }
      }

      $existingRules = @($acl.Access)
      foreach ($rule in $existingRules) {
        [void]$acl.RemoveAccessRule($rule)
      }
      $acl.SetAccessRuleProtection($true, $false)

      foreach ($identity in @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
        $acl.AddAccessRule((New-ShortcutAccessRule -Identity $identity -Rights ([System.Security.AccessControl.FileSystemRights]::FullControl)))
      }
      foreach ($identity in @('BUILTIN\Users', 'NT AUTHORITY\Authenticated Users')) {
        try {
          $acl.AddAccessRule((New-ShortcutAccessRule -Identity $identity -Rights ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)))
        } catch {
          Write-Host "Could not apply ACL for $identity on $resolved: $($_.Exception.Message)" -ForegroundColor Yellow
        }
      }

      Set-Acl -LiteralPath $resolved -AclObject $acl
      try {
        $fileInfo = Get-Item -LiteralPath $resolved -Force
        $fileInfo.Attributes = $fileInfo.Attributes -bor [System.IO.FileAttributes]::ReadOnly
      } catch { }

      Write-Host "Locked shortcut ACL: $resolved" -ForegroundColor Cyan
    } catch {
      Write-Host "Failed to lock shortcut $resolved: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }

  $finalRecords = $knownRecords.GetEnumerator() | Sort-Object Name | ForEach-Object { $_.Value }
  Save-ShortcutLockRecords -StorePath $StorePath -Records $finalRecords
}

function Create-AdminShortcuts([string]$InstallerPath) {
  $shell = New-Object -ComObject WScript.Shell
  $psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
  $adminPs = Join-Path (Split-Path -Parent $InstallerPath) 'open-admin-powershell.ps1'
  $createdShortcuts = New-Object System.Collections.Generic.List[string]

  function New-Shortcut {
    param(
      [string]$DesktopPath,
      [string]$Name,
      [string]$Target,
      [string]$Arguments
    )

    New-Item -ItemType Directory -Force -Path $DesktopPath | Out-Null
    $path = Join-Path $DesktopPath $Name
    $shortcut = $shell.CreateShortcut($path)
    $shortcut.TargetPath = $Target
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = Split-Path -Parent $InstallerPath
    $shortcut.IconLocation = "$psExe,0"
    $shortcut.Save()
    return $path
  }

  foreach ($desktop in Get-DesktopPaths) {
    try {
      $adminShortcut = New-Shortcut -DesktopPath $desktop -Name 'PowerShell (Admin).lnk' -Target $psExe -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$adminPs`""
      $installerShortcut = New-Shortcut -DesktopPath $desktop -Name 'AnyUser ChatGPT53 Installer (Admin).lnk' -Target $psExe -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$InstallerPath`""
      [void]$createdShortcuts.Add($adminShortcut)
      [void]$createdShortcuts.Add($installerShortcut)
      Write-Host "Created shortcuts on $desktop:" -ForegroundColor Green
      Write-Host "  $adminShortcut"
      Write-Host "  $installerShortcut"
    } catch {
      Write-Host "Could not create shortcuts on ${desktop}: $($_.Exception.Message)" -ForegroundColor Yellow
    }
  }

  return @($createdShortcuts | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

function Verify-Environment {
  Write-Host ''
  Write-Host 'Verification:' -ForegroundColor Cyan

  $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
  if ($pwsh) { Write-Host "  pwsh: $($pwsh.Source) ($(& $pwsh.Source -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'))" } else { Write-Host '  pwsh: NOT FOUND' }

  $python = Get-Command python -ErrorAction SilentlyContinue
  if ($python) { Write-Host "  python: $($python.Source) ($(& $python.Source --version 2>&1))" } else { Write-Host '  python: NOT FOUND' }

  $git = Get-Command git -ErrorAction SilentlyContinue
  if ($git) { Write-Host "  git: $($git.Source) ($(& $git.Source --version 2>&1))" } else { Write-Host '  git: NOT FOUND' }

  $codex = Get-Command codex -ErrorAction SilentlyContinue
  if ($codex) { Write-Host "  codex: $($codex.Source) ($(& $codex.Source --version 2>&1))" } else { Write-Host '  codex: NOT FOUND on PATH' }
}

Ensure-Elevated
Assert-Elevated
Show-FirstReadNotice
Clear-ApiKeyEnvironment
Set-VersionSessionHome
Show-InfoSheet
$PayloadRoot = Resolve-PayloadRoot $PayloadRoot
if ([string]::IsNullOrWhiteSpace($SourceDir)) { $SourceDir = Get-DefaultSourceDir }

$payloadRootResolved = (Resolve-Path -LiteralPath $PayloadRoot).Path
if ((-not [string]::IsNullOrWhiteSpace($SourceDir)) -and (Test-Path -LiteralPath $SourceDir) -and ((Resolve-Path -LiteralPath $SourceDir).Path -like "$payloadRootResolved*")) {
  $SourceDir = Get-DefaultSourceDir
}

if (-not $NonInteractive) {
  $PayloadRoot = Read-Default 'Payload root' $PayloadRoot
  if (-not (Test-Path -LiteralPath $PayloadRoot)) { throw "Payload root not found: $PayloadRoot" }

  if (Read-YesNo 'Copy payload to local disk (recommended for unplugged use)?' $true) { $CopyToLocal = $true }
  $SourceDir = Read-Default 'Source code directory to configure on this machine' $SourceDir
  if (-not $PSBoundParameters.ContainsKey('SkipDependencyInstall')) { if (Read-YesNo 'Skip dependency setup (PowerShell/Python checks)?' $false) { $SkipDependencyInstall = $true } }
  if (-not $PSBoundParameters.ContainsKey('SkipGitInstall')) { if (Read-YesNo 'Skip Git install/check?' $false) { $SkipGitInstall = $true } }
  if (-not $PSBoundParameters.ContainsKey('SkipCodexInstall')) { if (Read-YesNo 'Skip Codex CLI install/check?' $false) { $SkipCodexInstall = $true } }
  if (-not $PSBoundParameters.ContainsKey('SkipCodexSetup')) { if (Read-YesNo 'Skip Codex setup step (config/profile/shortcuts)?' $false) { $SkipCodexSetup = $true } }
}

if (-not (Test-Path -LiteralPath $SourceDir)) { throw "SourceDir not found: $SourceDir" }
$SourceDir = (Resolve-Path -LiteralPath $SourceDir).Path

if ($CopyToLocal) {
  $localPayload = Join-Path $InstallRoot 'ChatGPT53-Codex-Setup'
  New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
  if (Test-Path -LiteralPath $localPayload) { Remove-Item -LiteralPath $localPayload -Recurse -Force }
  Copy-Item -LiteralPath $PayloadRoot -Destination $localPayload -Recurse -Force
  $PayloadRoot = $localPayload
}

Write-Host 'Using:' -ForegroundColor Cyan
Write-Host "  PayloadRoot: $PayloadRoot"
Write-Host "  SourceDir:   $SourceDir"

if (-not $SkipDependencyInstall) {
  Invoke-StepScript -ScriptPath (Join-Path $PayloadRoot 'install-latest-powershell.ps1')
  Invoke-StepScript -ScriptPath (Join-Path $PayloadRoot 'install-latest-python.ps1')
}
if (-not $SkipGitInstall) { Ensure-Git }
if (-not $SkipCodexInstall) { Ensure-CodexCli }

if (-not $SkipCodexSetup) {
  $setupScript = Join-Path $PayloadRoot 'setup-codex-chatgpt53.ps1'
  if (-not (Test-Path -LiteralPath $setupScript)) { throw "Missing setup script: $setupScript" }
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript -SourceDir $SourceDir -LoginNow
  if ($LASTEXITCODE -ne 0) { throw "setup-codex-chatgpt53.ps1 failed with exit code $LASTEXITCODE" }
  Assert-ChatGPTLogin
}

$shortcutPaths = Create-AdminShortcuts -InstallerPath $PSCommandPath
try {
  $lockStore = Get-ShortcutLockStorePath -Root $InstallRoot
  Lock-DesktopShortcuts -ShortcutPaths $shortcutPaths -StorePath $lockStore
  Write-Host "Shortcut ACL store: $lockStore" -ForegroundColor Cyan
} catch {
  Write-Host "Shortcut locking skipped: $($_.Exception.Message)" -ForegroundColor Yellow
}
Verify-Environment
Write-Host ''
Write-Host 'AnyUser ChatGPT portable installation complete.' -ForegroundColor Green
