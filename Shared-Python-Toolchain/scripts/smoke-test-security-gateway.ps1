[CmdletBinding()]
param(
    [string]$Python = "py",
    [string[]]$PythonArgs = @("-3.13"),
    [string]$WorkRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$WorkRoot = if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    Join-Path ([System.IO.Path]::GetTempPath()) "SecurityGatewaySmoke"
} else {
    $WorkRoot
}
$workRoot = [System.IO.Path]::GetFullPath($WorkRoot)
$distRoot = Join-Path $workRoot "dist"
$installRoot = Join-Path $workRoot "install"
$buildScript = Join-Path $PSScriptRoot "build-security-gateway.ps1"
$runtimeRoot = Join-Path $workRoot "runtime"
$appRuntimeRoot = Join-Path $workRoot "app-localappdata"

Write-Host "Preparing smoke-test workspace..." -ForegroundColor Cyan
Remove-Item -LiteralPath $distRoot,$installRoot,$appRuntimeRoot -Force -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
Remove-Item -LiteralPath $runtimeRoot -Force -Recurse -ErrorAction SilentlyContinue

Get-ChildItem ([System.IO.Path]::GetTempPath()) -Directory -Filter "_MEI*" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddMinutes(-10) } |
    ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Force -Recurse -ErrorAction SilentlyContinue
    }

Write-Host "Building installer into $distRoot" -ForegroundColor Cyan
$previousRuntimeTmpDir = $env:SECURITY_GATEWAY_RUNTIME_TMPDIR
$env:SECURITY_GATEWAY_RUNTIME_TMPDIR = $runtimeRoot
& $buildScript -Python $Python -PythonArgs $PythonArgs -OutputRoot $distRoot -InstallerSpec "SecurityGatewayInstallerConsole.spec"
if ($null -eq $previousRuntimeTmpDir) {
    Remove-Item Env:\SECURITY_GATEWAY_RUNTIME_TMPDIR -ErrorAction SilentlyContinue
} else {
    $env:SECURITY_GATEWAY_RUNTIME_TMPDIR = $previousRuntimeTmpDir
}
if ($LASTEXITCODE -ne 0) {
    throw "Build failed with exit code $LASTEXITCODE"
}

$payloadPath = Join-Path $projectRoot "_pyi_stage\app-dist\SecurityGateway\SecurityGateway.exe"
$uninstallerPath = Join-Path $projectRoot "_pyi_stage\uninstall-dist\SecurityGateway-Uninstall\SecurityGateway-Uninstall.exe"
if (-not (Test-Path -LiteralPath $payloadPath)) {
    throw "Payload not found after build: $payloadPath"
}
if (-not (Test-Path -LiteralPath $uninstallerPath)) {
    throw "Uninstaller not found after build: $uninstallerPath"
}

Write-Host "Running repo-local smoke install into $installRoot" -ForegroundColor Cyan
$previousPayloadPath = $env:SECURITY_GATEWAY_PAYLOAD_PATH
$previousUninstallerPath = $env:SECURITY_GATEWAY_UNINSTALLER_PATH
$env:SECURITY_GATEWAY_PAYLOAD_PATH = $payloadPath
$env:SECURITY_GATEWAY_UNINSTALLER_PATH = $uninstallerPath
Push-Location $projectRoot
try {
    & $Python @PythonArgs "installer\installer.py" --console --smoke-test --install-dir $installRoot
}
finally {
    Pop-Location
    if ($null -eq $previousPayloadPath) {
        Remove-Item Env:\SECURITY_GATEWAY_PAYLOAD_PATH -ErrorAction SilentlyContinue
    } else {
        $env:SECURITY_GATEWAY_PAYLOAD_PATH = $previousPayloadPath
    }
    if ($null -eq $previousUninstallerPath) {
        Remove-Item Env:\SECURITY_GATEWAY_UNINSTALLER_PATH -ErrorAction SilentlyContinue
    } else {
        $env:SECURITY_GATEWAY_UNINSTALLER_PATH = $previousUninstallerPath
    }
}
if ($LASTEXITCODE -ne 0) {
    throw "Smoke install failed with exit code $LASTEXITCODE"
}

$expected = @(
    (Join-Path $installRoot "SecurityGateway.exe"),
    (Join-Path $installRoot "uninstall\SecurityGateway-Uninstall.exe"),
    (Join-Path $installRoot "Uninstall-SecurityGateway.ps1"),
    (Join-Path $installRoot "Register-SecurityGatewayMonitor.ps1"),
    (Join-Path $installRoot "user_path_backup.txt"),
    (Join-Path $installRoot "user-data\reports")
)

$missing = @($expected | Where-Object { -not (Test-Path -LiteralPath $_) })
if ($missing.Count -gt 0) {
    throw "Smoke install completed but expected output is missing: $($missing -join ', ')"
}

Write-Host "Validating installed payload parity..." -ForegroundColor Cyan
$installedPayload = Join-Path $installRoot "SecurityGateway.exe"
$installedUninstaller = Join-Path $installRoot "uninstall\SecurityGateway-Uninstall.exe"
$payloadHash = (Get-FileHash -LiteralPath $payloadPath -Algorithm SHA256).Hash
$installedPayloadHash = (Get-FileHash -LiteralPath $installedPayload -Algorithm SHA256).Hash
$uninstallerHash = (Get-FileHash -LiteralPath $uninstallerPath -Algorithm SHA256).Hash
$installedUninstallerHash = (Get-FileHash -LiteralPath $installedUninstaller -Algorithm SHA256).Hash
if ($payloadHash -ne $installedPayloadHash) {
    throw "Installed payload hash does not match staged payload."
}
if ($uninstallerHash -ne $installedUninstallerHash) {
    throw "Installed uninstaller hash does not match staged uninstaller."
}

$uninstallScript = Get-Content -LiteralPath (Join-Path $installRoot "Uninstall-SecurityGateway.ps1") -Raw
$registerScript = Get-Content -LiteralPath (Join-Path $installRoot "Register-SecurityGatewayMonitor.ps1") -Raw
if ($uninstallScript -notmatch [regex]::Escape($installRoot)) {
    throw "Uninstall script does not target the smoke install root."
}
if ($uninstallScript -notmatch [regex]::Escape((Join-Path $installRoot "user-data"))) {
    throw "Uninstall script does not target the smoke user-data root."
}
if ($registerScript -notmatch [regex]::Escape((Join-Path $installRoot "SecurityGateway.exe"))) {
    throw "Startup registration script does not target the installed payload."
}

Write-Host "Launching installed payload headlessly..." -ForegroundColor Cyan
$smokeEnv = @{
    LOCALAPPDATA = $appRuntimeRoot
    SECURITY_GATEWAY_RUNTIME_DATA_DIR = (Join-Path $installRoot "user-data")
    SECURITY_GATEWAY_HOST_MONITOR_ENABLED = "false"
    SECURITY_GATEWAY_NETWORK_MONITOR_ENABLED = "false"
    SECURITY_GATEWAY_PACKET_MONITOR_ENABLED = "false"
    SECURITY_GATEWAY_STREAM_MONITOR_ENABLED = "false"
    SECURITY_GATEWAY_AUTOMATION_TRACKER_FEED_REFRESH_ENABLED = "false"
    SECURITY_GATEWAY_AUTOMATION_MALWARE_FEED_REFRESH_ENABLED = "false"
    SECURITY_GATEWAY_AUTOMATION_MALWARE_RULE_FEED_REFRESH_ENABLED = "false"
}
New-Item -ItemType Directory -Force -Path $appRuntimeRoot | Out-Null
$process = Start-Process `
    -FilePath $installedPayload `
    -ArgumentList "smoke-check" `
    -PassThru `
    -Wait `
    -WindowStyle Hidden `
    -Environment $smokeEnv
if ($process.ExitCode -ne 0) {
    throw "Installed payload smoke-check failed with exit code $($process.ExitCode)."
}

$auditLog = Join-Path $installRoot "user-data\logs\audit.jsonl"
if (-not (Test-Path -LiteralPath $auditLog)) {
    throw "Installed payload did not create an audit log during smoke-check."
}
$auditText = Get-Content -LiteralPath $auditLog -Raw
if ($auditText -notmatch "automation\.tick") {
    throw "Installed payload did not log automation.tick during smoke-check."
}

Write-Host "Running installed uninstaller against smoke install..." -ForegroundColor Cyan
& $installedUninstaller
if ($LASTEXITCODE -ne 0) {
    throw "Installed uninstaller failed with exit code $LASTEXITCODE"
}
Start-Sleep -Seconds 4
if (Test-Path -LiteralPath $installRoot) {
    throw "Installed uninstaller did not remove the smoke install root."
}
if (Test-Path -LiteralPath (Join-Path $appRuntimeRoot "SecurityGateway")) {
    throw "Installed uninstaller did not clean the smoke runtime data root."
}

Write-Host ""
Write-Host "Smoke test complete:" -ForegroundColor Green
$reportItems = @($payloadPath, $uninstallerPath)
Get-Item -Path $reportItems | Select-Object FullName, Length, LastWriteTime
