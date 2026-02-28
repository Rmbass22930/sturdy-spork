$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[python-install] $msg" }
function Write-Step($msg) { Write-Host "  $msg" }

function Refresh-PathFromSystem {
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $parts = @()

  if (-not [string]::IsNullOrWhiteSpace($machinePath)) {
    $parts += $machinePath
  }
  if (-not [string]::IsNullOrWhiteSpace($userPath)) {
    $parts += $userPath
  }

  if ($parts.Count -gt 0) {
    $env:Path = ($parts -join ";")
  }
}

function Get-PythonRunner {
  $python = Get-Command python -ErrorAction SilentlyContinue
  if ($python) {
    return @{ Exe = $python.Source; PrefixArgs = @(); Name = "python" }
  }

  $py = Get-Command py -ErrorAction SilentlyContinue
  if ($py) {
    try {
      & $py.Source -3 --version | Out-Null
      return @{ Exe = $py.Source; PrefixArgs = @("-3"); Name = "py -3" }
    } catch { }
  }

  return $null
}

function Get-PythonVersion {
  param($Runner)

  if (-not $Runner) {
    return $null
  }

  try {
    $args = @()
    $args += $Runner.PrefixArgs
    $args += @("-c", "import sys; print('.'.join(map(str, sys.version_info[:3])))")
    $output = & $Runner.Exe @args
    if ([string]::IsNullOrWhiteSpace($output)) {
      return $null
    }
    return [version]$output.Trim()
  } catch {
    return $null
  }
}

function Show-ManualInstallSteps {
  param([string]$Reason)

  Write-Info $Reason
  Write-Info "Manual install/upgrade steps:"
  Write-Step "1) Open Microsoft Store and install/update App Installer (adds winget)."
  Write-Step "2) Or download latest Python 3 from: https://www.python.org/downloads/windows/"
  Write-Step "3) In installer, enable 'Add python.exe to PATH' and include pip."
  Write-Step "4) Reopen terminal, then run:"
  Write-Step '   python -m pip install --upgrade pip certifi truststore --trusted-host pypi.org --trusted-host files.pythonhosted.org'
  Write-Step "5) Verify:"
  Write-Step '   python --version'
}

$beforeRunner = Get-PythonRunner
$beforeVersion = Get-PythonVersion -Runner $beforeRunner
if ($beforeVersion) {
  Write-Info "Detected Python: $beforeVersion via $($beforeRunner.Name)"
} else {
  Write-Info "Python 3 not detected."
}

$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) {
  Show-ManualInstallSteps -Reason "winget not found, so automatic install/upgrade cannot run."
  exit 1
}

Write-Info "Checking for latest Python 3 via winget..."
& winget upgrade --id Python.Python.3 --source winget --accept-source-agreements --accept-package-agreements
$upgradeCode = $LASTEXITCODE

if ($upgradeCode -ne 0) {
  Write-Info "winget upgrade exit code: $upgradeCode. Trying install command..."
  & winget install --id Python.Python.3 --source winget --accept-source-agreements --accept-package-agreements --override "InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_launcher=1"
  $installCode = $LASTEXITCODE
  if ($installCode -ne 0) {
    Show-ManualInstallSteps -Reason "Automatic upgrade/install failed (upgrade=$upgradeCode, install=$installCode)."
    exit 1
  }
}

Refresh-PathFromSystem

$afterRunner = Get-PythonRunner
$afterVersion = Get-PythonVersion -Runner $afterRunner
if (-not $afterVersion) {
  Show-ManualInstallSteps -Reason "Python 3 still not detected after install/upgrade."
  exit 1
}
if ($afterVersion.Major -lt 3) {
  Show-ManualInstallSteps -Reason "Detected Python version is below 3.x."
  exit 1
}

if ($beforeVersion -and $afterVersion -gt $beforeVersion) {
  Write-Info "Python upgraded: $beforeVersion -> $afterVersion"
} elseif ($beforeVersion -and $afterVersion -eq $beforeVersion) {
  Write-Info "Python is already current enough for Codex 5.3: $afterVersion"
} else {
  Write-Info "Python installed: $afterVersion"
}

Write-Info "Updating pip + trust packages (pip, certifi, truststore)..."
$pipArgs = @()
$pipArgs += $afterRunner.PrefixArgs
$pipArgs += @(
  "-m", "pip", "install", "--upgrade",
  "pip", "certifi", "truststore",
  "--trusted-host", "pypi.org",
  "--trusted-host", "files.pythonhosted.org"
)
& $afterRunner.Exe @pipArgs
$pipCode = $LASTEXITCODE
if ($pipCode -ne 0) {
  Show-ManualInstallSteps -Reason "Pip trust package setup failed (exit=$pipCode)."
  exit 1
}

Write-Info "Python setup complete for Codex 5.3."
Write-Info "Use Python command: $($afterRunner.Name)"
Write-Info "Detected version: $afterVersion"
exit 0
