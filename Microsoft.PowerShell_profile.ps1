# --- High-contrast console theme ---
try {
  $raw = $Host.UI.RawUI
  $raw.BackgroundColor = "Black"
  $raw.ForegroundColor = "White"
} catch {}

try {
  $pd = $Host.PrivateData
  $pd.ErrorForegroundColor = "Red"
  $pd.ErrorBackgroundColor = "Black"
  $pd.WarningForegroundColor = "White"
  $pd.WarningBackgroundColor = "DarkRed"
  $pd.DebugForegroundColor = "Cyan"
  $pd.DebugBackgroundColor = "Black"
  $pd.VerboseForegroundColor = "Green"
  $pd.VerboseBackgroundColor = "Black"
  $pd.ProgressForegroundColor = "Black"
  $pd.ProgressBackgroundColor = "DarkCyan"
} catch {}

if ($PSStyle) {
  $PSStyle.Formatting.TableHeader = $PSStyle.Foreground.BrightCyan
  $PSStyle.Formatting.Error = $PSStyle.Foreground.BrightRed
  $PSStyle.Formatting.Warning = "$($PSStyle.Background.Red)$($PSStyle.Foreground.BrightWhite)"
  $PSStyle.Formatting.Verbose = $PSStyle.Foreground.BrightGreen
  $PSStyle.Formatting.Debug = $PSStyle.Foreground.BrightCyan
  $PSStyle.FileInfo.Directory = $PSStyle.Foreground.BrightBlue
  $PSStyle.FileInfo.Executable = $PSStyle.Foreground.BrightGreen
  $PSStyle.FileInfo.SymbolicLink = $PSStyle.Foreground.BrightMagenta
}

if (Get-Module -ListAvailable -Name PSReadLine) {
  Set-PSReadLineOption -Colors @{
    "Command" = "White"
    "Parameter" = "Cyan"
    "Operator" = "Gray"
    "Variable" = "Yellow"
    "String" = "Green"
    "Number" = "Magenta"
    "Type" = "DarkCyan"
    "Comment" = "DarkGray"
    "Keyword" = "Blue"
    "Error" = "Red"
    "Selection" = "DarkCyan"
  }
}

$ErrorView = "ConciseView"

# --- Codex / ChatGPT runner (auto-login when token is invalid) ---
$Global:CX_MODEL = "gpt-5.4-codex"

function Invoke-CodexExec {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Prompt,
    [string]$Model = $Global:CX_MODEL
  )

  $ErrorActionPreference = "Stop"
  $args = @("-m", $Model, "exec", "--skip-git-repo-check", $Prompt)

  try {
    codex @args
    return
  } catch {
    $msg = $_.Exception.Message
    if ($msg -match "refresh token was revoked|could not be refreshed|Unauthorized|invalid.*token|authentication") {
      Write-Host "`nCodex auth looks expired/revoked. Starting login..." -ForegroundColor Yellow
      codex login | Out-Host
      codex @args
      return
    }
    throw
  }
}

function cx {
  param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Rest
  )
  Invoke-CodexExec -Prompt ($Rest -join " ")
}

Set-Alias codex54 cx
Set-Alias chatgpt54 cx

function Set-CxModel {
  param([Parameter(Mandatory=$true)][string]$Model)
  $Global:CX_MODEL = $Model
  Write-Host "Codex model set to: $Global:CX_MODEL" -ForegroundColor Cyan
}
