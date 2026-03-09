# Start_Codex53.ps1
# Launch Codex in THIS folder using your preferred model.
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\Start_Codex53.ps1
#   .\Start_Codex53.ps1 exec "say hello in one word"

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default model (edit this later to upgrade versions)
$Model = "gpt-5.3-codex"

# Mirror Codex 5.4 launch behavior: prefer the user-level Codex home
# unless CODEX_FORCE_PROJECT_HOME is explicitly set.
if ($env:CODEX_FORCE_PROJECT_HOME -eq "1") {
  $projectCodexHome = Join-Path $PSScriptRoot ".codex-home"
  New-Item -ItemType Directory -Force -Path $projectCodexHome | Out-Null
  $env:CODEX_HOME = $projectCodexHome
} elseif ([string]::IsNullOrWhiteSpace($env:CODEX_HOME)) {
  $env:CODEX_HOME = Join-Path $env:USERPROFILE ".codex"
}
if (Test-Path Env:OPENAI_API_KEY) {
  Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue
}

function cx {
  param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Args
  )
  # -C makes Codex treat this folder as the working directory
  codex -m $Model -C "$PSScriptRoot" @Args
}

# If you run Start_Codex53.ps1 with no args, open interactive Codex.
if ($Args.Count -eq 0) {
  cx
} else {
  cx @Args
}
