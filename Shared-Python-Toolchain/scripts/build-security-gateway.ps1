[CmdletBinding()]
param(
    [string]$Python = "py",
    [string[]]$PythonArgs = @("-3.13"),
    [string]$OutputRoot = "$PSScriptRoot\..\dist"
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

$finalApp = Join-Path $outputRoot "SecurityGateway.exe"
$finalUninstaller = Join-Path $outputRoot "SecurityGateway-Uninstall.exe"
$finalInstaller = Join-Path $outputRoot "SecurityGatewayInstaller.exe"

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

    $payloadPath = Join-Path $appDist "SecurityGateway.exe"
    if (-not (Test-Path $payloadPath)) {
        throw "Expected SecurityGateway payload was not created: $payloadPath"
    }

    & $Python @PythonArgs -m PyInstaller `
        --noconfirm `
        --clean `
        --distpath $uninstallDist `
        --workpath $uninstallWork `
        (Join-Path $projectRoot "Uninstall.spec")

    if ($LASTEXITCODE -ne 0) {
        throw "SecurityGateway uninstaller build failed with exit code $LASTEXITCODE"
    }

    $uninstallerPath = Join-Path $uninstallDist "SecurityGateway-Uninstall.exe"
    if (-not (Test-Path $uninstallerPath)) {
        throw "Expected SecurityGateway uninstaller was not created: $uninstallerPath"
    }

    $env:SECURITY_GATEWAY_PAYLOAD_PATH = $payloadPath
    $env:SECURITY_GATEWAY_UNINSTALLER_PATH = $uninstallerPath
    & $Python @PythonArgs -m PyInstaller `
        --noconfirm `
        --clean `
        --distpath $installerDist `
        --workpath $installerWork `
        (Join-Path $projectRoot "SecurityGatewayInstaller.spec")

    if ($LASTEXITCODE -ne 0) {
        throw "SecurityGateway installer build failed with exit code $LASTEXITCODE"
    }

    $installerPath = Join-Path $installerDist "SecurityGatewayInstaller.exe"
    if (-not (Test-Path $installerPath)) {
        throw "Expected SecurityGateway installer was not created: $installerPath"
    }

    Copy-Item -Force $payloadPath $finalApp
    Copy-Item -Force $uninstallerPath $finalUninstaller
    Copy-Item -Force $installerPath $finalInstaller
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
Get-Item $finalApp, $finalUninstaller, $finalInstaller | Select-Object FullName, Length, LastWriteTime
