# codex_profile.ps1 (project-local)
# Always use ChatGPT/Codex 5.4 by default; easy to update later.

$script:CODEX_MODEL = "gpt-5.4-codex"   # <-- change this later when new version comes out

function cx {
    param(
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$Args
    )
    # Codex CLI supports --skip-git-repo-check only with `exec`.
    if ($Args.Count -gt 0 -and $Args[0] -eq "exec") {
        $execTail = @()
        if ($Args.Count -gt 1) {
            $execTail = $Args[1..($Args.Count - 1)]
        }
        codex -m $script:CODEX_MODEL exec --skip-git-repo-check @execTail
        return
    }
    codex -m $script:CODEX_MODEL @Args
}

Set-Alias Codex54 cx

Write-Host "Loaded project Codex profile. Model = $script:CODEX_MODEL" -ForegroundColor Green


