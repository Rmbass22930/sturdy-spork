# Start_Codex5.ps1
# Launch Codex 5.x in this folder with durable ChatGPT auth handling.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

# Force preflight login so auth repairs run before every invocation unless caller overrides.
$env:CODEX_PREFLIGHT_LOGIN_CHECK = "1"

try {
  $raw = $Host.UI.RawUI
  $raw.BackgroundColor = "Black"
  $raw.ForegroundColor = "White"
} catch {}

$Model = "gpt-5.4-codex"

# Match newer launchers: prefer user Codex home unless project scope forced.
if ([string]::IsNullOrWhiteSpace($env:CODEX_HOME) -and $env:CODEX_FORCE_PROJECT_HOME -ne "1") {
  $env:CODEX_HOME = Join-Path $env:USERPROFILE ".codex"
}
if ($env:CODEX_FORCE_PROJECT_HOME -eq "1") {
  $codexHome = Join-Path $PSScriptRoot ".codex-home"
  New-Item -ItemType Directory -Force -Path $codexHome | Out-Null
  $env:CODEX_HOME = $codexHome
}
$codexCommand = Get-Command codex.cmd -ErrorAction SilentlyContinue
if (-not $codexCommand) { $codexCommand = Get-Command codex -ErrorAction SilentlyContinue }
if (-not $codexCommand) {
  Write-Error "Codex CLI not found on PATH. Install/update Codex CLI, then run Start_Codex5 again."
  exit 127
}
$codexBin = $codexCommand.Source

function Read-ApiKeyFromPrompt {
  try {
    $secure = Read-Host "Enter OPENAI_API_KEY (leave blank to use device login)" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
      return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
  } catch {
    return ""
  }
}

function Persist-ApiKeyForUser {
  param([string]$ApiKey)

  if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    return
  }

  $env:OPENAI_API_KEY = $ApiKey
  try {
    & setx OPENAI_API_KEY $ApiKey | Out-Null
    Write-Warning "Saved OPENAI_API_KEY for future terminals."
  } catch {
    Write-Warning "Could not persist OPENAI_API_KEY with setx. Using it for this session only."
  }
}

function Invoke-ApiKeyLogin {
  param([string]$ApiKey)

  if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    return $false
  }

  $ApiKey | & $codexBin login --with-api-key
  return ($LASTEXITCODE -eq 0)
}

function Test-LoggedInStatusText {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) {
    return $false
  }

  $hasNotLoggedIn = $Text -match "(?i)\bnot logged in\b"
  $hasLoggedIn = $Text -match "(?i)\blogged in\b"
  $hasAuthenticated = $Text -match "(?i)\bauthenticated\b"
  return (-not $hasNotLoggedIn) -and ($hasLoggedIn -or $hasAuthenticated)
}

function Test-LocalCodexAuthExists {
  $paths = @()
  if (-not [string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
    $paths += (Join-Path $env:CODEX_HOME "auth.json")
  }
  $paths += (Join-Path $env:USERPROFILE ".codex\auth.json")
  $paths += (Join-Path $PSScriptRoot ".codex-home\auth.json")

  foreach ($path in ($paths | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    try {
      $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
      if ([string]::IsNullOrWhiteSpace($raw)) { continue }
      $j = $raw | ConvertFrom-Json -ErrorAction Stop
      if ($null -eq $j) { continue }
      $authMode = [string]$j.auth_mode
      $token = [string]$j.tokens.access_token
      if ($authMode -eq "chatgpt" -and -not [string]::IsNullOrWhiteSpace($token) -and $token.Length -gt 20) {
        return $true
      }
      $apiKey = [string]$j.OPENAI_API_KEY
      if (-not [string]::IsNullOrWhiteSpace($apiKey) -and $apiKey.Length -gt 20) {
        return $true
      }
    } catch {
      continue
    }
  }
  return $false
}

function Ensure-CodexLogin {
  if (Test-LocalCodexAuthExists) {
    return $true
  }

  $oldErrorAction = $ErrorActionPreference
  $oldNativePref = $PSNativeCommandUseErrorActionPreference
  $ErrorActionPreference = "Continue"
  $PSNativeCommandUseErrorActionPreference = $false
  try {
    $statusOutput = & $codexBin login status 2>&1
    $statusText = ($statusOutput | Out-String)
    $statusCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $oldErrorAction
    $PSNativeCommandUseErrorActionPreference = $oldNativePref
  }

  if ((Test-LoggedInStatusText -Text $statusText) -or ($statusCode -eq 0 -and $statusText -notmatch "Not logged in")) {
    return $true
  }

  Write-Warning "Codex is not logged in. Starting login flow..."
  if (-not [string]::IsNullOrWhiteSpace($env:OPENAI_API_KEY)) {
    Write-Warning "Applying OPENAI_API_KEY automatically."
    if (-not (Invoke-ApiKeyLogin -ApiKey $env:OPENAI_API_KEY)) {
      Write-Warning "API key login failed. Falling back to device login."
      & $codexBin login --device-auth
    }
  } else {
    $enteredApiKey = Read-ApiKeyFromPrompt
    if (-not [string]::IsNullOrWhiteSpace($enteredApiKey)) {
      Persist-ApiKeyForUser -ApiKey $enteredApiKey
      if (-not (Invoke-ApiKeyLogin -ApiKey $enteredApiKey)) {
        Write-Warning "Entered API key login failed. Falling back to device login."
        & $codexBin login --device-auth
      }
    } else {
      & $codexBin login --device-auth
    }
  }

  $oldErrorAction = $ErrorActionPreference
  $oldNativePref = $PSNativeCommandUseErrorActionPreference
  $ErrorActionPreference = "Continue"
  $PSNativeCommandUseErrorActionPreference = $false
  try {
    $postStatusOutput = & $codexBin login status 2>&1
    $postStatusText = ($postStatusOutput | Out-String)
    $postStatusCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $oldErrorAction
    $PSNativeCommandUseErrorActionPreference = $oldNativePref
  }

  if ((Test-LoggedInStatusText -Text $postStatusText) -or ($postStatusCode -eq 0 -and $postStatusText -notmatch "Not logged in")) {
    return $true
  }

  Write-Error "Codex login failed or was cancelled."
  return $false
}

function Test-AuthRevokedText {
  param([string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) {
    return $false
  }

  return (
    ($Text -match "Not logged in") -or
    ($Text -match "authentication failed") -or
    ($Text -match "invalid[_ -]?api[_ -]?key") -or
    ($Text -match "api key.*revoked") -or
    ($Text -match "token.*revoked") -or
    ($Text -match "401 Unauthorized")
  )
}

function Invoke-CodexRun {
  param(
    [string[]]$CodexArgs,
    [switch]$ExecMode
  )

  if (-not $ExecMode) {
    & $codexBin @CodexArgs
    return $LASTEXITCODE
  }

  $oldErrorAction = $ErrorActionPreference
  $oldNativePref = $PSNativeCommandUseErrorActionPreference
  $ErrorActionPreference = "Continue"
  $PSNativeCommandUseErrorActionPreference = $false
  try {
    $output = & $codexBin @CodexArgs 2>&1
    $output | ForEach-Object { $_ }
    $text = ($output | Out-String)
    $lastCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $oldErrorAction
    $PSNativeCommandUseErrorActionPreference = $oldNativePref
  }

  if (Test-AuthRevokedText -Text $text) {
    Write-Warning "Codex auth appears revoked/expired. Starting login flow and retrying once."
    if (-not (Ensure-CodexLogin)) {
      return 1
    }

    $oldErrorAction = $ErrorActionPreference
    $oldNativePref = $PSNativeCommandUseErrorActionPreference
    $ErrorActionPreference = "Continue"
    $PSNativeCommandUseErrorActionPreference = $false
    try {
      $retryOutput = & $codexBin @CodexArgs 2>&1
      $retryOutput | ForEach-Object { $_ }
      $text = ($retryOutput | Out-String)
      $lastCode = $LASTEXITCODE
    } finally {
      $ErrorActionPreference = $oldErrorAction
      $PSNativeCommandUseErrorActionPreference = $oldNativePref
    }
  }

  $apiDisconnected =
    ($text -match "stream disconnected before completion") -or
    ($text -match "error sending request for url \(https://api\.openai\.com/v1/responses\)")

  if ($apiDisconnected) {
    Write-Warning "OpenAI API/network is unavailable. HTTPS fallback is disabled."
    if ($env:CODEX_SANDBOX_NETWORK_OPTIONAL -eq "1") {
      Write-Warning "Network failure treated as non-fatal because CODEX_SANDBOX_NETWORK_OPTIONAL=1."
      return 0
    }
  }

  return $lastCode
}

function cx {
  param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$CliArgs = @()
  )
  $CliArgs = @($CliArgs)
  $skipPreflightLogin = ($env:CODEX_PREFLIGHT_LOGIN_CHECK -ne "1")
  if (-not $skipPreflightLogin -and -not ($CliArgs.Count -gt 0 -and $CliArgs[0] -eq "login")) {
    if (-not (Ensure-CodexLogin)) { exit 1 }
  }
  if ($CliArgs.Count -gt 0 -and $CliArgs[0] -eq "exec") {
    $execTail = @()
    if ($CliArgs.Count -gt 1) {
      $execTail = $CliArgs[1..($CliArgs.Count - 1)]
    }
    $runArgs = @("--search", "-m", $Model, "-C", "$PSScriptRoot", "exec", "--skip-git-repo-check") + $execTail
    $code = Invoke-CodexRun -CodexArgs $runArgs -ExecMode
    if ($code -ne 0) { exit $code }
    return
  }
  $runArgs = @("--search", "--no-alt-screen", "-m", $Model, "-C", "$PSScriptRoot") + $CliArgs
  $code = Invoke-CodexRun -CodexArgs $runArgs
  if ($code -ne 0) { exit $code }
}

if ($Args.Count -eq 0) {
  cx
} else {
  cx @Args
}

