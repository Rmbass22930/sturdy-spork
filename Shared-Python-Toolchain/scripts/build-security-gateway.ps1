[CmdletBinding()]
param(
    [string]$Python = "py",
    [string[]]$PythonArgs = @("-3.13"),
    [string]$OutputRoot = "$PSScriptRoot\..\dist",
    [string]$InstallerSpec = "SecurityGatewayInstaller.spec",
    [switch]$PublishFullBundle
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$stageRoot = Join-Path $projectRoot "_pyi_stage"
$appDist = Join-Path $stageRoot "app-dist"
$appWork = Join-Path $stageRoot "app-build"
$uninstallDist = Join-Path $stageRoot "uninstall-dist"
$uninstallWork = Join-Path $stageRoot "uninstall-build"
$installerDist = Join-Path $stageRoot "installer-dist"
$installerWork = Join-Path $stageRoot "installer-build"

$finalApp = Join-Path $outputRoot "SecurityGateway"
$finalUninstaller = Join-Path $outputRoot "SecurityGateway-Uninstall"
$installerName = [System.IO.Path]::GetFileNameWithoutExtension($InstallerSpec) -replace '\.spec$',''
if ([string]::IsNullOrWhiteSpace($installerName)) {
    $installerName = "SecurityGatewayInstaller"
}
$finalInstaller = Join-Path $outputRoot ($installerName + ".exe")
$finalInstallerDir = Join-Path $outputRoot $installerName
$finalBundle = Join-Path $outputRoot "SecurityGateway-build.zip"
$finalBundleUnpack = Join-Path $outputRoot "SecurityGateway-build-unpack.cmd"
$finalManifest = Join-Path $outputRoot "SecurityGateway-build-manifest.json"

function Resolve-BuiltExecutablePath {
    param(
        [string]$DistRoot,
        [string]$Name
    )
    $onedirPath = Join-Path (Join-Path $DistRoot $Name) ($Name + ".exe")
    if (Test-Path -LiteralPath $onedirPath) {
        return [System.IO.Path]::GetFullPath($onedirPath)
    }
    $onefilePath = Join-Path $DistRoot ($Name + ".exe")
    if (Test-Path -LiteralPath $onefilePath) {
        return [System.IO.Path]::GetFullPath($onefilePath)
    }
    throw "Expected executable was not created for $Name under $DistRoot"
}

function Publish-BuiltArtifact {
    param(
        [string]$DistRoot,
        [string]$Name,
        [string]$FileDestination,
        [string]$DirectoryDestination
    )
    $sourceDir = Join-Path $DistRoot $Name
    if (Test-Path -LiteralPath $sourceDir) {
        Remove-Item -LiteralPath $FileDestination -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $DirectoryDestination -Force -Recurse -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $DirectoryDestination | Out-Null
        Get-ChildItem -LiteralPath $sourceDir -Force | Copy-Item -Destination $DirectoryDestination -Recurse -Force
        return Resolve-BuiltExecutablePath -DistRoot $DistRoot -Name $Name
    }
    $sourceFile = Join-Path $DistRoot ($Name + ".exe")
    if (Test-Path -LiteralPath $sourceFile) {
        Remove-Item -LiteralPath $DirectoryDestination -Force -Recurse -ErrorAction SilentlyContinue
        Copy-Item -Force $sourceFile $FileDestination
        return [System.IO.Path]::GetFullPath($FileDestination)
    }
    throw "Expected artifact was not created for $Name under $DistRoot"
}

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
Remove-Item -LiteralPath $appDist,$appWork,$uninstallDist,$uninstallWork,$installerDist,$installerWork -Force -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $appDist,$appWork,$uninstallDist,$uninstallWork,$installerDist,$installerWork | Out-Null

Push-Location $projectRoot
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = $projectRoot
    & $Python @PythonArgs -m PyInstaller `
        --noconfirm `
        --clean `
        --distpath $appDist `
        --workpath $appWork `
        (Join-Path $projectRoot "SecurityGateway.spec")

    if ($LASTEXITCODE -ne 0) {
        throw "SecurityGateway payload build failed with exit code $LASTEXITCODE"
    }

    $payloadPath = Resolve-BuiltExecutablePath -DistRoot $appDist -Name "SecurityGateway"

    & $Python @PythonArgs -m PyInstaller `
        --noconfirm `
        --clean `
        --distpath $uninstallDist `
        --workpath $uninstallWork `
        (Join-Path $projectRoot "Uninstall.spec")

    if ($LASTEXITCODE -ne 0) {
        throw "SecurityGateway uninstaller build failed with exit code $LASTEXITCODE"
    }

    $uninstallerPath = Resolve-BuiltExecutablePath -DistRoot $uninstallDist -Name "SecurityGateway-Uninstall"

    $env:SECURITY_GATEWAY_PAYLOAD_PATH = $payloadPath
    $env:SECURITY_GATEWAY_UNINSTALLER_PATH = $uninstallerPath
    & $Python @PythonArgs -m PyInstaller `
        --noconfirm `
        --clean `
        --distpath $installerDist `
        --workpath $installerWork `
        (Join-Path $projectRoot $InstallerSpec)

    if ($LASTEXITCODE -ne 0) {
        throw "SecurityGateway installer build failed with exit code $LASTEXITCODE"
    }

    $installerPath = Publish-BuiltArtifact `
        -DistRoot $installerDist `
        -Name $installerName `
        -FileDestination $finalInstaller `
        -DirectoryDestination $finalInstallerDir

    if ($PublishFullBundle) {
        $publishedPayloadPath = Publish-BuiltArtifact `
            -DistRoot $appDist `
            -Name "SecurityGateway" `
            -FileDestination (Join-Path $outputRoot "SecurityGateway.exe") `
            -DirectoryDestination $finalApp
        $publishedUninstallerPath = Publish-BuiltArtifact `
            -DistRoot $uninstallDist `
            -Name "SecurityGateway-Uninstall" `
            -FileDestination (Join-Path $outputRoot "SecurityGateway-Uninstall.exe") `
            -DirectoryDestination $finalUninstaller

        if (Test-Path -LiteralPath $finalBundle) {
            Remove-Item -LiteralPath $finalBundle -Force
        }
        $bundleItems = @("SecurityGateway", "SecurityGateway-Uninstall")
        if (Test-Path -LiteralPath $finalInstallerDir) {
            $bundleItems += $installerName
        } else {
            $bundleItems += ($installerName + ".exe")
        }
        tar -a -c -f $finalBundle -C $outputRoot @bundleItems
        if ($LASTEXITCODE -ne 0) {
            throw "SecurityGateway bundle creation failed with exit code $LASTEXITCODE"
        }

        @"
@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
set "ZIP_PATH=%SCRIPT_DIR%SecurityGateway-build.zip"
set "TARGET_DIR=%SCRIPT_DIR%SecurityGateway-build-unpacked"
if not exist "%ZIP_PATH%" (
  echo Missing bundle: "%ZIP_PATH%"
  pause
  exit /b 1
)
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"
powershell -NoProfile -Command "Expand-Archive -LiteralPath '%ZIP_PATH%' -DestinationPath '%TARGET_DIR%' -Force"
if errorlevel 1 (
  echo Failed to unpack SecurityGateway-build.zip
  pause
  exit /b 1
)
start "" "%TARGET_DIR%"
exit /b 0
"@ | Set-Content -LiteralPath $finalBundleUnpack -Encoding ASCII

        $gitCommit = $null
        try {
            $gitCommit = (git -C $projectRoot rev-parse HEAD 2>$null).Trim()
            if ([string]::IsNullOrWhiteSpace($gitCommit)) {
                $gitCommit = $null
            }
        } catch {
            $gitCommit = $null
        }

        $files = @($publishedPayloadPath, $publishedUninstallerPath, $installerPath, $finalBundle)
        $manifest = [ordered]@{
            build_name = "SecurityGateway"
            built_at_utc = (Get-Date).ToUniversalTime().ToString("o")
            source_root = $projectRoot
            git_commit = $gitCommit
            files = @()
        }
        foreach ($file in $files) {
            $item = Get-Item -LiteralPath $file
            $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
            $manifest.files += [ordered]@{
                name = $item.Name
                path = $item.FullName
                size = $item.Length
                sha256 = $hash
                last_write_time_utc = $item.LastWriteTimeUtc.ToString("o")
            }
        }
        $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $finalManifest -Encoding UTF8
    }
}
finally {
    Remove-Item Env:\SECURITY_GATEWAY_PAYLOAD_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:\SECURITY_GATEWAY_UNINSTALLER_PATH -ErrorAction SilentlyContinue
    if ($null -eq $previousPythonPath) {
        Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue
    } else {
        $env:PYTHONPATH = $previousPythonPath
    }
    Pop-Location
}

Write-Host ""
Write-Host "Build complete:" -ForegroundColor Green
if ($PublishFullBundle) {
    Get-Item $publishedPayloadPath, $publishedUninstallerPath, $installerPath, $finalBundle, $finalManifest | Select-Object FullName, Length, LastWriteTime
} else {
    Get-Item $installerPath, $payloadPath, $uninstallerPath | Select-Object FullName, Length, LastWriteTime
}
