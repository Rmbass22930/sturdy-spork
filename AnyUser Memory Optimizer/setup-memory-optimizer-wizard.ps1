[CmdletBinding()]
param(
  [string]$ProjectRoot = 'J:\_shared_toolchains\Shared-Python-Toolchain',
  [string]$VMName,
  [string]$PythonPath,
  [switch]$SkipEnableHyperV,
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

  $py = Get-Command python -ErrorAction SilentlyContinue
  if ($py) { return $py.Source }

  $fallback = 'C:\Python314\python.exe'
  if (Test-Path -LiteralPath $fallback) { return $fallback }

  throw 'Python executable not found. Install Python or pass -PythonPath.'
}

if (-not (Test-Path -LiteralPath $ProjectRoot)) {
  throw "Project root not found: $ProjectRoot"
}

$PythonPath = Resolve-Python $PythonPath

if (-not $NonInteractive) {
  $ProjectRoot = Read-Default 'Project root' $ProjectRoot
  if (-not (Test-Path -LiteralPath $ProjectRoot)) {
    throw "Project root not found: $ProjectRoot"
  }

  $VMName = Read-Default 'Hyper-V VM name' (if ($VMName) { $VMName } else { 'SecurityLab' })

  if ([string]::IsNullOrWhiteSpace($PrivacyMode)) {
    $usePrivacy = Read-YesNo 'Enable privacy gate before VM launch?' $true
    if (-not $usePrivacy) {
      $PrivacyMode = 'none'
    }
  }

  if ([string]::IsNullOrWhiteSpace($PrivacyMode) -or $PrivacyMode -eq 'none') {
    $picked = Read-Default 'Privacy mode (none/malwarebytes/custom)' 'malwarebytes'
    $PrivacyMode = $picked.ToLowerInvariant()
  }

  if (-not $PSBoundParameters.ContainsKey('SkipEnableHyperV')) {
    $skip = Read-YesNo 'Skip enabling Hyper-V features now?' $true
    if ($skip) { $SkipEnableHyperV = $true }
  }

  if (-not $PSBoundParameters.ContainsKey('AllowUnsafeNetworkStart')) {
    $unsafe = Read-YesNo 'Allow unsafe network start if privacy checks fail?' $false
    if ($unsafe) { $AllowUnsafeNetworkStart = $true }
  }
}

if ([string]::IsNullOrWhiteSpace($VMName)) {
  throw 'VM name is required. Pass -VMName or use interactive mode.'
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

$args = @(
  '-m', 'memory_optimizer.cli', 'hyperv-setup',
  $VMName,
  '--task-name', $TaskName,
  '--python-path', $PythonPath,
  '--script-path', $ScriptPath,
  '--working-directory', (Split-Path -Parent $ProjectRoot),
  '--privacy-check-retries', "$PrivacyCheckRetries",
  '--privacy-check-interval', "$PrivacyCheckInterval"
)

if ($SkipEnableHyperV) { $args += '--skip-enable-hyperv' }
if ($AllowUnsafeNetworkStart) { $args += '--allow-unsafe-network-start' }
if (-not [string]::IsNullOrWhiteSpace($PrivacyUpCommand)) {
  $args += @('--privacy-up-command', $PrivacyUpCommand)
}
if (-not [string]::IsNullOrWhiteSpace($PrivacyCheckCommand)) {
  $args += @('--privacy-check-command', $PrivacyCheckCommand)
}

Write-Host 'Running setup with:' -ForegroundColor Cyan
Write-Host "  ProjectRoot: $ProjectRoot"
Write-Host "  VMName: $VMName"
Write-Host "  PythonPath: $PythonPath"
Write-Host "  PrivacyMode: $PrivacyMode"
Write-Host "  SkipEnableHyperV: $SkipEnableHyperV"
Write-Host "  AllowUnsafeNetworkStart: $AllowUnsafeNetworkStart"

Push-Location $ProjectRoot
try {
  & $PythonPath @args
  $code = $LASTEXITCODE
  if ($code -ne 0) {
    throw "memory_optimizer setup failed with exit code $code"
  }
  Write-Host 'AnyUser Memory Optimizer setup complete.' -ForegroundColor Green
}
finally {
  Pop-Location
}
