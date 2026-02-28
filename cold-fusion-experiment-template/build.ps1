$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$appDir = Join-Path $root "app"
$distDir = Join-Path $root "dist"
$pyzPath = Join-Path $distDir "scenario-runner.pyz"

New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$pythonCmd = $null
try {
    py -3 --version | Out-Null
    $pythonCmd = @("py", "-3")
} catch {
    try {
        python --version | Out-Null
        $pythonCmd = @("python")
    } catch {
        throw "Python not found. Install Python 3 and ensure either 'py' or 'python' is on PATH."
    }
}

$pythonExe = $pythonCmd[0]
$pythonArgs = @()
if ($pythonCmd.Count -gt 1) {
    $pythonArgs = $pythonCmd[1..($pythonCmd.Count - 1)]
}

& $pythonExe @pythonArgs -m zipapp $appDir -o $pyzPath
if ($LASTEXITCODE -ne 0) { throw "zipapp build failed with exit code $LASTEXITCODE" }
Copy-Item -Force (Join-Path $root "scenarios.json") (Join-Path $distDir "scenarios.json")

Write-Output "BUILT: $pyzPath"
Write-Output "COPIED: $distDir\\scenarios.json"
