[CmdletBinding()]
param(
    [string[]]$OutputRoot = @("G:\", "H:\")
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSCommandPath | Split-Path -Parent
Set-Location $repoRoot

& "$repoRoot\scripts\build-installer.ps1" -OutputRoot $OutputRoot
& "$repoRoot\scripts\smoke-test-installers.ps1"
Write-Host "CI build + smoke test completed."
