[CmdletBinding()]
param(
  [string]$InstallRoot = 'C:\ProgramData\AnyUserChatGPT'
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevated {
  if (Test-IsAdmin) { return }

  $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-InstallRoot', ('"{0}"' -f $InstallRoot))
  Write-Host 'Requesting Administrator elevation for shortcut unlock...' -ForegroundColor Yellow
  try {
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList ([string]::Join(' ', $argList)) -ErrorAction Stop | Out-Null
  } catch {
    throw 'Administrator privileges are required to unlock shortcuts.'
  }
  exit 0
}

function Assert-Elevated {
  if (-not (Test-IsAdmin)) {
    throw 'Administrator privileges are required to unlock shortcuts.'
  }
  Write-Host 'Running unlock utility with Administrator privileges.' -ForegroundColor Green
}

function Get-LockStorePath([string]$Root) {
  if ([string]::IsNullOrWhiteSpace($Root)) {
    throw 'InstallRoot cannot be empty.'
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
    if ($parsed.PSObject.Properties.Name -contains 'Locks') { return @($parsed.Locks) }
    return @($parsed)
  } catch {
    throw "Could not parse shortcut lock store ($StorePath): $($_.Exception.Message)"
  }
}

Ensure-Elevated
Assert-Elevated

$storePath = Get-LockStorePath -Root $InstallRoot
if (-not (Test-Path -LiteralPath $storePath)) {
  Write-Host "No shortcut lock store found at $storePath" -ForegroundColor Yellow
  return
}

$records = Load-ShortcutLockRecords -StorePath $storePath
if (-not $records -or $records.Count -eq 0) {
  Write-Host 'Shortcut lock store is empty; nothing to unlock.' -ForegroundColor Yellow
  return
}

$restored = 0
foreach ($record in $records) {
  if (-not $record.Path -or -not $record.OriginalSddl) { continue }
  if (-not (Test-Path -LiteralPath $record.Path)) {
    Write-Host "Shortcut missing, skipping unlock: $($record.Path)" -ForegroundColor Yellow
    continue
  }

  try {
    $fileSecurity = New-Object System.Security.AccessControl.FileSecurity
    $fileSecurity.SetSecurityDescriptorSddlForm($record.OriginalSddl)
    Set-Acl -LiteralPath $record.Path -AclObject $fileSecurity
    try {
      $item = Get-Item -LiteralPath $record.Path -Force
      if ($item.Attributes.HasFlag([System.IO.FileAttributes]::ReadOnly)) {
        $item.Attributes = $item.Attributes -band -bnot [System.IO.FileAttributes]::ReadOnly
      }
    } catch { }
    Write-Host "Unlocked shortcut: $($record.Path)" -ForegroundColor Cyan
    $restored++
  } catch {
    Write-Host "Failed to unlock $($record.Path): $($_.Exception.Message)" -ForegroundColor Yellow
  }
}

if ($restored -gt 0) {
  Write-Host ''
  Write-Host 'Shortcuts restored to their original ACLs. You can re-run the installer to relock them after changes.' -ForegroundColor Green
} else {
  Write-Host 'No shortcuts were unlocked.' -ForegroundColor Yellow
}

