# Start_Codex5.ps1
# Minimal launcher for ChatGPT 5 model, matching working 5.3 behavior.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Model = "gpt-5.4-codex"

function cx {
  param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
  )
  codex -m $Model -C "$PSScriptRoot" @Args
}

if ($Args.Count -eq 0) {
  cx
} else {
  cx @Args
}

