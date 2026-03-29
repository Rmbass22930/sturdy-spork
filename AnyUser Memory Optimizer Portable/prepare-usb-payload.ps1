[CmdletBinding()]
param(
  [string]$SourceProject = 'J:\_shared_toolchains\Shared-Python-Toolchain'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dest = Join-Path $root 'Shared-Python-Toolchain'

if (-not (Test-Path -LiteralPath $SourceProject)) {
  throw "Source project not found: $SourceProject"
}

Write-Host "Preparing USB payload..." -ForegroundColor Cyan
Write-Host "  Source: $SourceProject"
Write-Host "  Dest:   $dest"

if (Test-Path -LiteralPath $dest) {
  Remove-Item -LiteralPath $dest -Recurse -Force
}

Copy-Item -LiteralPath $SourceProject -Destination $dest -Recurse -Force
Write-Host 'USB payload ready.' -ForegroundColor Green
