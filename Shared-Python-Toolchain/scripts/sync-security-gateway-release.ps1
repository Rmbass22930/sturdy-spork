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
    "SecurityGateway",
    "SecurityGateway-Uninstall",
    "SecurityGateway-build.zip"
)
foreach ($name in $required) {
    $candidate = Join-Path $outputRoot $name
    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "Missing expected artifact: $candidate"
    }
}
$installerArtifact = Join-Path $outputRoot "SecurityGatewayInstaller.exe"
$installerBundleArtifact = Join-Path $outputRoot "SecurityGatewayInstaller\SecurityGatewayInstaller.exe"
if (-not (Test-Path -LiteralPath $installerArtifact) -and -not (Test-Path -LiteralPath $installerBundleArtifact)) {
    throw "Missing expected installer artifact under $outputRoot"
}
if (-not (Test-Path -LiteralPath $bundleUnpackPath)) {
    throw "Missing bundle unpack helper: $bundleUnpackPath"
}
$appBundlePath = Join-Path $outputRoot "SecurityGateway"
$appExePath = Join-Path $appBundlePath "SecurityGateway.exe"
$uninstallBundlePath = Join-Path $outputRoot "SecurityGateway-Uninstall"
$uninstallExePath = Join-Path $uninstallBundlePath "SecurityGateway-Uninstall.exe"
if (-not (Test-Path -LiteralPath $appExePath)) {
    throw "Missing app bundle executable: $appExePath"
}
if (-not (Test-Path -LiteralPath $uninstallExePath)) {
    throw "Missing uninstaller bundle executable: $uninstallExePath"
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

function Repair-ShortcutIfPresent {
    param(
        [string]$ShortcutPath,
        [string]$ExpectedTarget,
        [string]$ExpectedArguments,
        [string]$ExpectedWorkingDirectory
    )

    if (-not (Test-Path -LiteralPath $ShortcutPath)) {
        return $null
    }

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $changed = $false

    if ($shortcut.TargetPath -ne $ExpectedTarget) {
        $shortcut.TargetPath = $ExpectedTarget
        $changed = $true
    }
    if ($shortcut.Arguments -ne $ExpectedArguments) {
        $shortcut.Arguments = $ExpectedArguments
        $changed = $true
    }
    if ($shortcut.WorkingDirectory -ne $ExpectedWorkingDirectory) {
        $shortcut.WorkingDirectory = $ExpectedWorkingDirectory
        $changed = $true
    }

    if ($changed) {
        $shortcut.Save()
    }

    return [ordered]@{
        path = $ShortcutPath
        target = $ExpectedTarget
        arguments = $ExpectedArguments
        working_directory = $ExpectedWorkingDirectory
        repaired = $changed
    }
}

function Repair-InstalledShortcuts {
    param(
        [string]$InstallRoot
    )

    $expectedTarget = Join-Path $InstallRoot "SecurityGateway.exe"
    $taskbarShortcut = Join-Path $env:APPDATA "Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\SecurityGateway.lnk"
    $desktopRoots = @(
        Join-Path $env:USERPROFILE "Desktop",
        Join-Path $env:USERPROFILE "OneDrive\Desktop"
    )
    $startMenuRoots = @(
        Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Security Gateway",
        Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Security Gateway"
    )
    $shortcutSpecs = @(
        [ordered]@{ Name = "SecurityGateway.lnk"; Arguments = "" },
        [ordered]@{ Name = "SecurityGateway SOC Dashboard.lnk"; Arguments = "soc-dashboard" }
    )
    $results = @()
    $mainShortcutRoots = @($taskbarShortcut)
    foreach ($root in $desktopRoots + $startMenuRoots) {
        foreach ($spec in $shortcutSpecs) {
            $mainShortcutRoots += (Join-Path $root $spec.Name)
        }
    }

    foreach ($shortcutPath in $mainShortcutRoots) {
        $expectedArguments = ""
        if ($shortcutPath -like "*SecurityGateway SOC Dashboard.lnk") {
            $expectedArguments = "soc-dashboard"
        }
        $result = Repair-ShortcutIfPresent -ShortcutPath $shortcutPath -ExpectedTarget $expectedTarget -ExpectedArguments $expectedArguments -ExpectedWorkingDirectory $InstallRoot
        if ($null -ne $result) {
            $results += $result
        }
    }
    return $results
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
    Get-ChildItem -LiteralPath $appBundlePath | Copy-Item -Destination $installRoot -Recurse -Force
    $installedUninstallRoot = Join-Path $installRoot "uninstall"
    Remove-Item -LiteralPath $installedUninstallRoot -Force -Recurse -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $installedUninstallRoot | Out-Null
    Get-ChildItem -LiteralPath $uninstallBundlePath | Copy-Item -Destination $installedUninstallRoot -Recurse -Force
    Assert-HashMatchesManifest -Path (Join-Path $installRoot "SecurityGateway.exe") -Name "SecurityGateway.exe"
    Assert-HashMatchesManifest -Path (Join-Path $installedUninstallRoot "SecurityGateway-Uninstall.exe") -Name "SecurityGateway-Uninstall.exe"
    Copy-Item -LiteralPath (Join-Path $installedUninstallRoot "SecurityGateway-Uninstall.exe") -Destination (Join-Path $installRoot "SecurityGateway-Uninstall.exe") -Force
    $summary.shortcuts = Repair-InstalledShortcuts -InstallRoot $installRoot
    $summary.installed_sync = "ok"
}

if ($null -ne $portableRoot) {
    New-Item -ItemType Directory -Force -Path $portableRoot | Out-Null
    $portableInstallerFile = Join-Path $portableRoot "SecurityGatewayInstaller.exe"
    $portableInstallerDir = Join-Path $portableRoot "SecurityGatewayInstaller"
    if (Test-Path -LiteralPath $installerBundleArtifact) {
        Remove-Item -LiteralPath $portableInstallerFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $portableInstallerDir -Force -Recurse -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath (Join-Path $outputRoot "SecurityGatewayInstaller") -Destination $portableInstallerDir -Recurse -Force
        $portableInstallerPath = Join-Path $portableInstallerDir "SecurityGatewayInstaller.exe"
    } else {
        Remove-Item -LiteralPath $portableInstallerDir -Force -Recurse -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $installerArtifact -Destination $portableInstallerFile -Force
        $portableInstallerPath = $portableInstallerFile
    }
    Copy-Item -LiteralPath (Join-Path $outputRoot "SecurityGateway-build.zip") -Destination (Join-Path $portableRoot "SecurityGateway-build.zip") -Force
    Copy-Item -LiteralPath $bundleUnpackPath -Destination (Join-Path $portableRoot "SecurityGateway-build-unpack.cmd") -Force
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $portableRoot "SecurityGateway-build-manifest.json") -Force
    Assert-HashMatchesManifest -Path $portableInstallerPath -Name "SecurityGatewayInstaller.exe"
    Assert-HashMatchesManifest -Path (Join-Path $portableRoot "SecurityGateway-build.zip") -Name "SecurityGateway-build.zip"
    $summary.portable_sync = "ok"
}

$summary | ConvertTo-Json -Depth 4
