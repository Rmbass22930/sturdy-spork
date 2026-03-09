[CmdletBinding()]
param(
    [string[]]$OutputRoot = @("G:\", "H:\")
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $PSCommandPath
$repoRoot = Split-Path -Parent $here
Set-Location $repoRoot

function Invoke-Step {
    param(
        [string]$Label,
        [scriptblock]$Action
    )
    Write-Host "==> $Label"
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

Invoke-Step "PyInstaller BallisticTargetGUI" {
    python -m PyInstaller BallisticTargetGUI.spec
}

Copy-Item -Path "dist\BallisticTargetGUI.exe" -Destination "BallisticTargetGUI.exe" -Force
Copy-Item -Path "dist\BallisticTargetGUI.exe" -Destination "installer\payload\BallisticTargetGUI.exe" -Force

Invoke-Step "PyInstaller Uninstall.exe" {
    python -m PyInstaller "installer\Uninstall.py" --onefile --name Uninstall
}

Copy-Item -Path "dist\Uninstall.exe" -Destination "installer\payload\Uninstall.exe" -Force

if (Test-Path "installer\BallisticTargetInstaller.zip") {
    Remove-Item "installer\BallisticTargetInstaller.zip" -Force
}
Invoke-Step "Zip payload" {
    Compress-Archive -Path "installer/payload/*" -DestinationPath "installer/BallisticTargetInstaller.zip" -Force
}

Push-Location installer
Invoke-Step "IExpress BallisticTargetSetup.exe" {
    cmd /c "iexpress /N BallisticTargetInstaller.sed"
}
Invoke-Step "IExpress InstallBallistic.exe" {
    cmd /c "iexpress /N InstallBallistic.sed"
}
Pop-Location

$artifactPaths = @(
    "BallisticTargetGUI.exe",
    "installer\BallisticTargetInstaller.zip",
    "installer\BallisticTargetSetup.exe",
    "installer\InstallBallistic.exe"
)

$hashLines = foreach ($relative in $artifactPaths) {
    $full = Join-Path $repoRoot $relative
    if (-not (Test-Path $full)) {
        throw "Missing artifact: $relative"
    }
    $hash = Get-FileHash -Path $full -Algorithm SHA256
    "{0,-25} {1}" -f (Split-Path $relative -Leaf), $hash.Hash
}
Set-Content -Path (Join-Path $repoRoot "CHECKSUMS.txt") -Value $hashLines

if ($OutputRoot) {
    foreach ($root in $OutputRoot) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }
        try {
            if (-not (Test-Path $root)) {
                New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
            }
        }
        catch {
            Write-Warning "Skipping copy to $root ($($_.Exception.Message))"
            continue
        }

        foreach ($item in $artifactPaths + @("CHECKSUMS.txt")) {
            $src = Join-Path $repoRoot $item
            if (-not (Test-Path $src)) {
                throw "Missing file for copy: $item"
            }
            $dest = Join-Path $root (Split-Path $item -Leaf)
            Copy-Item -Path $src -Destination $dest -Force
        }
        Write-Host "Copied artifacts to $root"
    }
}
Write-Host "Build complete."
