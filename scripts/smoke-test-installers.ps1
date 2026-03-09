[CmdletBinding()]
param(
    [string]$PayloadZip = "installer\BallisticTargetInstaller.zip",
    [string]$ChecksumsPath = "CHECKSUMS.txt"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSCommandPath | Split-Path -Parent
Set-Location $repoRoot

if (-not (Test-Path $PayloadZip)) {
    throw "Payload ZIP not found: $PayloadZip"
}
if (-not (Test-Path $ChecksumsPath)) {
    throw "Checksums file not found: $ChecksumsPath"
}

function Get-SedPayloadFiles {
    param([string]$SedPath)
    $lines = Get-Content -Path $SedPath
    foreach ($line in $lines) {
        if ($line -match '^FILE\d+=(.+)$') {
            $matches[1].Trim()
        }
    }
}

$sedPaths = @(
    "installer\BallisticTargetInstaller.sed",
    "installer\InstallBallistic.sed"
)
$expectedPayloadFiles = $sedPaths |
    ForEach-Object { Get-SedPayloadFiles $_ } |
    Sort-Object -Unique

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bt_payload_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempDir | Out-Null
try {
    Write-Host "Extracting $PayloadZip to $tempDir ..."
    Expand-Archive -LiteralPath $PayloadZip -DestinationPath $tempDir -Force

    foreach ($file in $expectedPayloadFiles) {
        $payloadPath = Join-Path $repoRoot "installer\payload\$file"
        if (-not (Test-Path $payloadPath)) {
            throw "Smoke test failed: missing $file in installer\payload."
        }
        $zipPath = Join-Path $tempDir $file
        if (-not (Test-Path $zipPath)) {
            throw "Smoke test failed: missing $file inside payload ZIP."
        }
    }

    $checksumEntries = @{}
    foreach ($line in Get-Content -Path $ChecksumsPath) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2) {
            $checksumEntries[$parts[0]] = $parts[1]
        }
    }

    $requiredArtifacts = @(
        "BallisticTargetGUI.exe",
        "EnvironmentalsGeoGUI.exe",
        "BallisticTargetInstaller.zip",
        "BallisticTargetSetup.exe",
        "InstallBallistic.exe"
    )
    foreach ($artifact in $requiredArtifacts) {
        if (-not $checksumEntries.ContainsKey($artifact)) {
            throw "Smoke test failed: CHECKSUMS.txt missing $artifact."
        }
    }

    Write-Host "Smoke test passed: payload files, ZIP contents, and checksums are in sync." -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}
