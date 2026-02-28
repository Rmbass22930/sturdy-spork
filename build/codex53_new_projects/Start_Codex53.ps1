# Start_Codex53.ps1
# Launch Codex in THIS folder using your preferred model.
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\Start_Codex53.ps1
#   .\Start_Codex53.ps1 exec "say hello in one word"

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default model (edit this later to upgrade versions)
$Model = "gpt-5.3-codex"

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
