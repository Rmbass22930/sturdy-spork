[CmdletBinding()]
param(
  [string]$ProjectRoot,
  [string]$InstallRoot = 'C:\ProgramData\AnyUserMemoryOptimizer',
  [string]$VMName,
  [string]$PythonPath,
  [switch]$SkipEnableHyperV,
  [switch]$SkipDependencyInstall,
  [switch]$CopyToLocal,
  [switch]$NonInteractive,
  [ValidateSet('none','malwarebytes','custom')]
  [string]$PrivacyMode,
  [string]$PrivacyUpCommand,
  [string]$PrivacyCheckCommand,
  [int]$PrivacyCheckRetries = 10,
  [double]$PrivacyCheckInterval = 3.0,
  [switch]$AllowUnsafeNetworkStart,
  [string]$TaskName = 'MemoryOptimizerHyperV'
)

$ErrorActionPreference = 'Stop'

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

function Resolve-Python([string]$Candidate) {
  if (-not [string]::IsNullOrWhiteSpace($Candidate)) {
    if (Test-Path -LiteralPath $Candidate) { return $Candidate }
    throw "Python path not found: $Candidate"
  }

  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  if ($pyLauncher) {
    try {
      $resolved = & $pyLauncher.Source -3 -c "import sys; print(sys.executable)"
      if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($resolved)) { return $resolved.Trim() }
    } catch { }
  }

  $python = Get-Command python -ErrorAction SilentlyContinue
  if ($python) { return $python.Source }

  $fallback = 'C:\Python314\python.exe'
  if (Test-Path -LiteralPath $fallback) { return $fallback }

  throw 'Python executable not found. Install Python 3 or pass -PythonPath.'
}

function Resolve-ProjectRoot([string]$ExplicitPath) {
  if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
    if (Test-Path -LiteralPath $ExplicitPath) { return (Resolve-Path -LiteralPath $ExplicitPath).Path }
    throw "Project root not found: $ExplicitPath"
  }

  $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
  $candidates = @(
    (Join-Path $scriptRoot 'Shared-Python-Toolchain'),
    (Join-Path (Split-Path -Parent $scriptRoot) 'Shared-Python-Toolchain'),
    'J:\_shared_toolchains\Shared-Python-Toolchain'
  )
  foreach ($c in $candidates) {
    if (Test-Path -LiteralPath $c) { return (Resolve-Path -LiteralPath $c).Path }
  }

  throw 'Could not find Shared-Python-Toolchain. Place it in/next to this folder or pass -ProjectRoot.'
}

function Ensure-Dependencies([string]$PythonExe, [string]$Root) {
  Write-Host 'Installing/repairing dependencies (pip install -e .)...' -ForegroundColor Cyan
  Push-Location $Root
  try {
    & $PythonExe -m pip install -e .
    if ($LASTEXITCODE -ne 0) {
      throw "Dependency installation failed with exit code $LASTEXITCODE"
    }
  }
  finally {
    Pop-Location
  }
}

$ProjectRoot = Resolve-ProjectRoot $ProjectRoot
$PythonPath = Resolve-Python $PythonPath

if (-not $NonInteractive) {
  $ProjectRoot = Read-Default 'Source project root' $ProjectRoot
  if (-not (Test-Path -LiteralPath $ProjectRoot)) { throw "Project root not found: $ProjectRoot" }

  $copyChoice = Read-YesNo 'Copy project to local disk so it works after USB removal?' $true
  if ($copyChoice) { $CopyToLocal = $true }

  $VMName = Read-Default 'Hyper-V VM name' (if ($VMName) { $VMName } else { 'SecurityLab' })

  if ([string]::IsNullOrWhiteSpace($PrivacyMode)) {
    $PrivacyMode = (Read-Default 'Privacy mode (none/malwarebytes/custom)' 'malwarebytes').ToLowerInvariant()
  }

  if (-not $PSBoundParameters.ContainsKey('SkipEnableHyperV')) {
    $skip = Read-YesNo 'Skip enabling Hyper-V features now?' $true
    if ($skip) { $SkipEnableHyperV = $true }
  }

  if (-not $PSBoundParameters.ContainsKey('SkipDependencyInstall')) {
    $skipDeps = Read-YesNo 'Skip dependency install/repair?' $false
    if ($skipDeps) { $SkipDependencyInstall = $true }
  }

  if (-not $PSBoundParameters.ContainsKey('AllowUnsafeNetworkStart')) {
    $unsafe = Read-YesNo 'Allow unsafe network start if privacy checks fail?' $false
    if ($unsafe) { $AllowUnsafeNetworkStart = $true }
  }
}

if ([string]::IsNullOrWhiteSpace($VMName)) {
  throw 'VM name is required. Pass -VMName or run interactively.'
}

if ($CopyToLocal) {
  $destRoot = Join-Path $InstallRoot 'Shared-Python-Toolchain'
  Write-Host "Copying project to local path: $destRoot" -ForegroundColor Cyan
  New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
  if (Test-Path -LiteralPath $destRoot) {
    Remove-Item -LiteralPath $destRoot -Recurse -Force
  }
  Copy-Item -LiteralPath $ProjectRoot -Destination $destRoot -Recurse -Force
  $ProjectRoot = $destRoot
}

if (-not $SkipDependencyInstall) {
  Ensure-Dependencies -PythonExe $PythonPath -Root $ProjectRoot
}

switch ($PrivacyMode) {
  'none' {
    $PrivacyUpCommand = $null
    $PrivacyCheckCommand = $null
  }
  'malwarebytes' {
    if ([string]::IsNullOrWhiteSpace($PrivacyUpCommand)) {
      $PrivacyUpCommand = "if ((Get-Service -Name 'MBVpnTunnelService' -ErrorAction SilentlyContinue).Status -ne 'Running') { Start-Service -Name 'MBVpnTunnelService' -ErrorAction Stop }; Start-Sleep -Seconds 3"
    }
    if ([string]::IsNullOrWhiteSpace($PrivacyCheckCommand)) {
      $PrivacyCheckCommand = "`$svc = Get-Service -Name 'MBVpnTunnelService' -ErrorAction SilentlyContinue; if (`$svc -and `$svc.Status -eq 'Running') { exit 0 } else { exit 1 }"
    }
  }
  'custom' {
    if ([string]::IsNullOrWhiteSpace($PrivacyUpCommand)) {
      if ($NonInteractive) { throw 'Custom privacy mode requires -PrivacyUpCommand.' }
      $PrivacyUpCommand = Read-Host 'Enter privacy up PowerShell command'
    }
    if ([string]::IsNullOrWhiteSpace($PrivacyCheckCommand)) {
      if ($NonInteractive) { throw 'Custom privacy mode requires -PrivacyCheckCommand.' }
      $PrivacyCheckCommand = Read-Host 'Enter privacy check PowerShell command (must exit 0 when valid)'
    }
  }
  default {
    throw "Unsupported privacy mode: $PrivacyMode"
  }
}

$ScriptPath = Join-Path $ProjectRoot 'temp\StartMemoryOptimizer.ps1'
$WorkingDirectory = Split-Path -Parent $ProjectRoot

$cliArgs = @(
  '-m', 'memory_optimizer.cli', 'hyperv-setup',
  $VMName,
  '--task-name', $TaskName,
  '--python-path', $PythonPath,
  '--script-path', $ScriptPath,
  '--working-directory', $WorkingDirectory,
  '--privacy-check-retries', "$PrivacyCheckRetries",
  '--privacy-check-interval', "$PrivacyCheckInterval"
)

if ($SkipEnableHyperV) { $cliArgs += '--skip-enable-hyperv' }
if ($AllowUnsafeNetworkStart) { $cliArgs += '--allow-unsafe-network-start' }
if (-not [string]::IsNullOrWhiteSpace($PrivacyUpCommand)) { $cliArgs += @('--privacy-up-command', $PrivacyUpCommand) }
if (-not [string]::IsNullOrWhiteSpace($PrivacyCheckCommand)) { $cliArgs += @('--privacy-check-command', $PrivacyCheckCommand) }

Write-Host 'Applying Memory Optimizer setup...' -ForegroundColor Cyan
Write-Host "  ProjectRoot: $ProjectRoot"
Write-Host "  VMName: $VMName"
Write-Host "  PythonPath: $PythonPath"
Write-Host "  PrivacyMode: $PrivacyMode"
Write-Host "  SkipEnableHyperV: $SkipEnableHyperV"

Push-Location $ProjectRoot
try {
  & $PythonPath @cliArgs
  if ($LASTEXITCODE -ne 0) {
    throw "memory_optimizer setup failed with exit code $LASTEXITCODE"
  }
}
finally {
  Pop-Location
}

Write-Host ''
Write-Host 'AnyUser portable installation finished.' -ForegroundColor Green
Write-Host "Startup script: $ScriptPath"
Write-Host 'If startup_mode is run_key, it is already configured for current user logon.'
