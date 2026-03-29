[CmdletBinding()]
param(
    [string]$OutputRoot = "F:\created software",
    [string]$InstallRoot = "C:\Program Files\SecurityGateway",
    [switch]$SkipInstalled,
    [string]$PortableRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$outputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$installRoot = [System.IO.Path]::GetFullPath($InstallRoot)
$portableRoot = if ([string]::IsNullOrWhiteSpace($PortableRoot)) { $null } else { [System.IO.Path]::GetFullPath($PortableRoot) }

$manifestPath = Join-Path $outputRoot "SecurityGateway-build-manifest.json"
$bundleUnpackPath = Join-Path $outputRoot "SecurityGateway-build-unpack.cmd"

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Missing build manifest: $manifestPath"
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$required = @(
    "SecurityGateway.exe",
    "SecurityGateway-Uninstall.exe",
    "SecurityGatewayInstaller.exe",
    "SecurityGateway-build.zip"
)
foreach ($name in $required) {
    $candidate = Join-Path $outputRoot $name
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Missing expected artifact: $candidate"
    }
}
if (-not (Test-Path -LiteralPath $bundleUnpackPath)) {
    throw "Missing bundle unpack helper: $bundleUnpackPath"
}

function Get-ManifestEntry {
    param([string]$Name)
    $entry = $manifest.files | Where-Object { $_.name -eq $Name } | Select-Object -First 1
    if (-not $entry) {
        throw "Manifest entry not found for $Name"
    }
    return $entry
}

function Assert-HashMatchesManifest {
    param(
        [string]$Path,
        [string]$Name
    )
    $entry = Get-ManifestEntry -Name $Name
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($hash -ne $entry.sha256) {
        throw "Hash mismatch for $Name at $Path"
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$summary = [ordered]@{
    output_root = $outputRoot
    install_root = $installRoot
    portable_root = $portableRoot
    git_commit = $manifest.git_commit
    built_at_utc = $manifest.built_at_utc
    installed_sync = if ($SkipInstalled) { "skipped" } else { "pending" }
    portable_sync = if ($null -eq $portableRoot) { "skipped" } else { "pending" }
}

if (-not $SkipInstalled) {
    if (-not (Test-IsAdministrator)) {
        throw "Administrator rights are required to update $installRoot. Re-run the sync script from an elevated PowerShell session, or use -SkipInstalled."
    }
    New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
    Get-Process SecurityGateway -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath (Join-Path $outputRoot "SecurityGateway.exe") -Destination (Join-Path $installRoot "SecurityGateway.exe") -Force
    Copy-Item -LiteralPath (Join-Path $outputRoot "SecurityGateway-Uninstall.exe") -Destination (Join-Path $installRoot "SecurityGateway-Uninstall.exe") -Force
    Assert-HashMatchesManifest -Path (Join-Path $installRoot "SecurityGateway.exe") -Name "SecurityGateway.exe"
    Assert-HashMatchesManifest -Path (Join-Path $installRoot "SecurityGateway-Uninstall.exe") -Name "SecurityGateway-Uninstall.exe"
    $summary.installed_sync = "ok"
}

if ($null -ne $portableRoot) {
    New-Item -ItemType Directory -Force -Path $portableRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $outputRoot "SecurityGatewayInstaller.exe") -Destination (Join-Path $portableRoot "SecurityGatewayInstaller.exe") -Force
    Copy-Item -LiteralPath (Join-Path $outputRoot "SecurityGateway-build.zip") -Destination (Join-Path $portableRoot "SecurityGateway-build.zip") -Force
    Copy-Item -LiteralPath $bundleUnpackPath -Destination (Join-Path $portableRoot "SecurityGateway-build-unpack.cmd") -Force
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $portableRoot "SecurityGateway-build-manifest.json") -Force
    Assert-HashMatchesManifest -Path (Join-Path $portableRoot "SecurityGatewayInstaller.exe") -Name "SecurityGatewayInstaller.exe"
    Assert-HashMatchesManifest -Path (Join-Path $portableRoot "SecurityGateway-build.zip") -Name "SecurityGateway-build.zip"
    $summary.portable_sync = "ok"
}

$summary | ConvertTo-Json -Depth 4
