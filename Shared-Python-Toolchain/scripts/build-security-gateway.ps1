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
$installerDist = Join-Path $stageRoot "installer-dist"
$installerWork = Join-Path $stageRoot "installer-build"

$finalApp = Join-Path $outputRoot "SecurityGateway.exe"
$finalInstaller = Join-Path $outputRoot "SecurityGatewayInstaller.exe"

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
Remove-Item -LiteralPath $appDist,$appWork,$installerDist,$installerWork -Force -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $appDist,$appWork,$installerDist,$installerWork | Out-Null

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

    $env:SECURITY_GATEWAY_PAYLOAD_PATH = $payloadPath
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
    Copy-Item -Force $installerPath $finalInstaller
}
finally {
    Remove-Item Env:\SECURITY_GATEWAY_PAYLOAD_PATH -ErrorAction SilentlyContinue
    if ($null -eq $previousPythonPath) {
        Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue
    } else {
        $env:PYTHONPATH = $previousPythonPath
    }
    Pop-Location
}

Write-Host ""
Write-Host "Build complete:" -ForegroundColor Green
Get-Item $finalApp, $finalInstaller | Select-Object FullName, Length, LastWriteTime
