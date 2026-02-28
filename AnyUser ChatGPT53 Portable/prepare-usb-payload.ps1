[CmdletBinding()]
param(
  [string]$SourcePayload = 'J:\gdrive\BallisticTarget\src\build\codex53_original'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$dest = Join-Path $root 'ChatGPT53-Codex-Setup'

if (-not (Test-Path -LiteralPath $SourcePayload)) {
  throw "Source payload not found: $SourcePayload"
}

Write-Host "Preparing ChatGPT53 USB payload..." -ForegroundColor Cyan
Write-Host "  Source: $SourcePayload"
Write-Host "  Dest:   $dest"

if (Test-Path -LiteralPath $dest) {
  Remove-Item -LiteralPath $dest -Recurse -Force
}

Copy-Item -LiteralPath $SourcePayload -Destination $dest -Recurse -Force
Write-Host 'ChatGPT53 USB payload ready.' -ForegroundColor Green
