$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[powershell-install] $msg" }
function Write-Step($msg) { Write-Host "  $msg" }

function Get-InstalledPwshVersion {
  $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
  if (-not $pwsh) {
    return $null
  }

  try {
    $v = & $pwsh.Source -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
    if ([string]::IsNullOrWhiteSpace($v)) {
      return $null
    }
    return [version]$v.Trim()
  } catch {
    return $null
  }
}

function Show-ManualInstallSteps {
  param([string]$Reason)

  Write-Info $Reason
  Write-Info "Manual install/upgrade steps:"
  Write-Step "1) Open Microsoft Store and install/update App Installer (adds winget)."
  Write-Step "2) Open PowerShell and run:"
  Write-Step "   winget install --id Microsoft.PowerShell --source winget"
  Write-Step "   or, if already installed:"
  Write-Step "   winget upgrade --id Microsoft.PowerShell --source winget"
  Write-Step "3) If winget is unavailable, download latest PowerShell from:"
  Write-Step "   https://github.com/PowerShell/PowerShell/releases/latest"
  Write-Step "4) Run the installer, reopen terminal, then verify:"
  Write-Step '   pwsh -NoLogo -NoProfile -Command "$PSVersionTable.PSVersion"'
}

$before = Get-InstalledPwshVersion
if ($before) {
  Write-Info "Detected PowerShell 7+: $before"
} else {
  Write-Info "PowerShell 7+ not detected."
}

$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) {
  Show-ManualInstallSteps -Reason "winget not found, so automatic install/upgrade cannot run."
  exit 1
}

Write-Info "Checking for latest Microsoft PowerShell via winget..."
& winget upgrade --id Microsoft.PowerShell --source winget --accept-source-agreements --accept-package-agreements
$upgradeCode = $LASTEXITCODE

if ($upgradeCode -ne 0) {
  Write-Info "winget upgrade exit code: $upgradeCode. Trying install command..."
  & winget install --id Microsoft.PowerShell --source winget --accept-source-agreements --accept-package-agreements
  $installCode = $LASTEXITCODE
  if ($installCode -ne 0) {
    Show-ManualInstallSteps -Reason "Automatic upgrade/install failed (upgrade=$upgradeCode, install=$installCode)."
    exit 1
  }
}

$after = Get-InstalledPwshVersion
if (-not $after) {
  Show-ManualInstallSteps -Reason "PowerShell 7+ still not detected after install/upgrade."
  exit 1
}

if ($before -and $after -gt $before) {
  Write-Info "PowerShell upgraded: $before -> $after"
} elseif ($before -and $after -eq $before) {
  Write-Info "PowerShell is already current enough for Codex 5.4: $after"
} else {
  Write-Info "PowerShell installed: $after"
}

Write-Info "Use PowerShell 7+ for Codex 5.4 with command: pwsh"
exit 0

