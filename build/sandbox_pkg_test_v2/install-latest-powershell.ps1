$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[powershell-install] $msg" }

$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if ($pwsh) {
  try {
    $v = & $pwsh.Source -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
    Write-Info "PowerShell 7+ detected: $v"
    Write-Info "If you still want to upgrade: winget upgrade --id Microsoft.PowerShell --source winget"
    exit 0
  } catch {
    Write-Info "PowerShell 7+ detected."
    exit 0
  }
}

$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) {
  Write-Info "winget not found. Install App Installer from Microsoft Store, then run this script again."
  Write-Info "Manual download: https://github.com/PowerShell/PowerShell/releases/latest"
  exit 1
}

Write-Info "Installing/upgrading Microsoft PowerShell via winget..."
& winget install --id Microsoft.PowerShell --source winget --accept-source-agreements --accept-package-agreements
if ($LASTEXITCODE -ne 0) {
  Write-Info "Install command returned code $LASTEXITCODE. Trying upgrade command..."
  & winget upgrade --id Microsoft.PowerShell --source winget --accept-source-agreements --accept-package-agreements
}

$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if ($pwsh) {
  $v = & $pwsh.Source -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
  Write-Info "Installed/available PowerShell version: $v"
  Write-Info "Open PowerShell 7 using command: pwsh"
  exit 0
}

Write-Info "PowerShell 7 was not detected after install."
Write-Info "Manual download: https://github.com/PowerShell/PowerShell/releases/latest"
exit 1
