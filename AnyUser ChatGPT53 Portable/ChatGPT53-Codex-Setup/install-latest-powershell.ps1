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

function Enable-Tls12 {
  try {
    $current = [Net.ServicePointManager]::SecurityProtocol
    $tls12 = [Net.SecurityProtocolType]::Tls12
    if (($current -band $tls12) -ne $tls12) {
      [Net.ServicePointManager]::SecurityProtocol = $current -bor $tls12
    }
  } catch {
    Write-Info "Could not adjust TLS security protocol: $($_.Exception.Message)"
  }
}

function Get-LatestPwshAsset {
  Enable-Tls12
  try {
    $headers = @{
      "User-Agent" = "AnyUserChatGPTInstaller"
      "Accept" = "application/vnd.github+json"
    }
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest' -Headers $headers -ErrorAction Stop
    if (-not $release) { return $null }
    $asset = $release.assets | Where-Object { $_.name -match 'PowerShell-.*-win-x64\.msi$' } | Select-Object -First 1
    if (-not $asset) { return $null }
    $version = $release.tag_name
    if (-not [string]::IsNullOrWhiteSpace($version)) {
      $version = $version.TrimStart('v','V')
    }
    return [pscustomobject]@{
      Version = $version
      Url     = $asset.browser_download_url
      Name    = $asset.name
    }
  } catch {
    Write-Info "Failed to query GitHub for latest PowerShell release: $($_.Exception.Message)"
    return $null
  }
}

function Install-PwshFromGithub {
  $asset = Get-LatestPwshAsset
  if (-not $asset) { return $false }

  $tempFile = Join-Path ([IO.Path]::GetTempPath()) $asset.Name
  Write-Info "Downloading PowerShell $($asset.Version) from GitHub..."
  try {
    Invoke-WebRequest -Uri $asset.Url -OutFile $tempFile -UseBasicParsing -ErrorAction Stop
  } catch {
    Write-Info "Download failed: $($_.Exception.Message)"
    if (Test-Path -LiteralPath $tempFile) { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
    return $false
  }

  try {
    Write-Info "Running PowerShell installer..."
    $msiArgs = @(
      '/i', $tempFile,
      '/qn', '/norestart',
      'ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1',
      'ENABLE_PSREMOTING=1',
      'REGISTER_MANIFEST=1'
    )
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
    if ($process.ExitCode -ne 0) {
      Write-Info "msiexec exited with code $($process.ExitCode)"
      return $false
    }
    Write-Info "PowerShell $($asset.Version) installed via GitHub package."
    return $true
  } catch {
    Write-Info "msiexec failed: $($_.Exception.Message)"
    return $false
  } finally {
    if (Test-Path -LiteralPath $tempFile) {
      Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
    }
  }
}

$before = Get-InstalledPwshVersion
if ($before) {
  Write-Info "Detected PowerShell 7+: $before"
} else {
  Write-Info "PowerShell 7+ not detected."
}

$winget = Get-Command winget -ErrorAction SilentlyContinue
$pwshInstalled = $false

if ($winget) {
  Write-Info "Checking for latest Microsoft PowerShell via winget..."
  & winget upgrade --id Microsoft.PowerShell --source winget --accept-source-agreements --accept-package-agreements
  if ($LASTEXITCODE -eq 0) {
    $pwshInstalled = $true
  } else {
    $upgradeCode = $LASTEXITCODE
    Write-Info "winget upgrade exit code: $upgradeCode. Trying install command..."
    & winget install --id Microsoft.PowerShell --source winget --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -eq 0) {
      $pwshInstalled = $true
    } else {
      Write-Info "winget install failed with exit code $LASTEXITCODE"
    }
  }
} else {
  Write-Info "winget not found. Falling back to GitHub installer."
}

if (-not $pwshInstalled) {
  Write-Info "Attempting direct download + silent install from GitHub releases..."
  $pwshInstalled = Install-PwshFromGithub
}

if (-not $pwshInstalled) {
  Show-ManualInstallSteps -Reason "Automatic PowerShell install failed after winget/GitHub attempts."
  exit 1
}

$after = Get-InstalledPwshVersion
if (-not $after) {
  Show-ManualInstallSteps -Reason "PowerShell 7+ still not detected after install/upgrade."
  exit 1
}

if ($before -and $after -gt $before) {
  Write-Info "PowerShell upgraded: $before -> $after"
} elseif ($before -and $after -eq $before) {
  Write-Info "PowerShell is already current enough for Codex 5.3: $after"
} else {
  Write-Info "PowerShell installed: $after"
}

Write-Info "Use PowerShell 7+ for Codex 5.3 with command: pwsh"
exit 0
