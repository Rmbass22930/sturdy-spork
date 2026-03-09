[CmdletBinding()]
param(
    [string]$PayloadZip = "installer\BallisticTargetInstaller.zip"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSCommandPath | Split-Path -Parent
Set-Location $repoRoot

if (-not (Test-Path $PayloadZip)) {
    throw "Payload ZIP not found: $PayloadZip"
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bt_payload_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null
try {
    Write-Host "Extracting $PayloadZip to $tempDir ..."
    Expand-Archive -LiteralPath $PayloadZip -DestinationPath $tempDir -Force

    $requiredFiles = @(
        "Install.cmd",
        "BallisticTargetGUI.exe",
        "Uninstall.exe",
        "README.txt"
    )
    foreach ($file in $requiredFiles) {
        $path = Join-Path $tempDir $file
        if (-not (Test-Path $path)) {
            throw "Smoke test failed: missing $file inside payload ZIP."
        }
    }

    Write-Host "Smoke test passed: payload ZIP contains required files." -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
