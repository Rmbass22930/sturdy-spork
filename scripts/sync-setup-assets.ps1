[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Write-Status {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Host $Message
    }
}

$mappings = @(
    @{
        Source = 'codex_launcher_common.ps1'
        Targets = @(
            'Shared-Python-Toolchain/codex_launcher_common.ps1',
            'Shared-Python-Toolchain-NewProjects/codex_launcher_common.ps1',
            'installer/payload_codex54_new_projects/codex_launcher_common.ps1',
            'AnyUser Memory Optimizer Portable/Shared-Python-Toolchain/codex_launcher_common.ps1'
        )
    },
    @{
        Source = 'Start_Codex5.ps1'
        Targets = @(
            'Shared-Python-Toolchain/Start_Codex5.ps1',
            'Shared-Python-Toolchain-NewProjects/Start_Codex5.ps1',
            'installer/payload_codex54_new_projects/Start_Codex5.ps1'
        )
    },
    @{
        Source = 'Start_Codex53.ps1'
        Targets = @(
            'Shared-Python-Toolchain/Start_Codex53.ps1',
            'Shared-Python-Toolchain-NewProjects/Start_Codex53.ps1',
            'installer/payload_codex54_new_projects/Start_Codex53.ps1'
        )
    },
    @{
        Source = 'Start_Codex54.ps1'
        Targets = @(
            'Shared-Python-Toolchain/Start_Codex54.ps1',
            'Shared-Python-Toolchain-NewProjects/Start_Codex54.ps1',
            'installer/payload_codex54_new_projects/Start_Codex54.ps1',
            'AnyUser Memory Optimizer Portable/Shared-Python-Toolchain/Start_Codex54.ps1'
        )
    },
    @{
        Source = 'Start_Codex54.cmd'
        Targets = @(
            'Shared-Python-Toolchain/Start_Codex54.cmd',
            'Shared-Python-Toolchain-NewProjects/Start_Codex54.cmd',
            'installer/payload_codex54_new_projects/Start_Codex54.cmd',
            'AnyUser Memory Optimizer Portable/Shared-Python-Toolchain/Start_Codex54.cmd'
        )
    },
    @{
        Source = 'setup-codex54.ps1'
        Targets = @(
            'Shared-Python-Toolchain/setup-codex54.ps1',
            'Shared-Python-Toolchain-NewProjects/setup-codex54.ps1',
            'AnyUser Memory Optimizer Portable/Shared-Python-Toolchain/setup-codex54.ps1'
        )
    },
    @{
        Source = 'Shared-Python-Toolchain/README.txt'
        Targets = @(
            'AnyUser Memory Optimizer Portable/Shared-Python-Toolchain/README.txt'
        )
    },
    @{
        Source = 'Shared-Python-Toolchain/logincodex.ps1'
        Targets = @(
            'AnyUser Memory Optimizer Portable/Shared-Python-Toolchain/logincodex.ps1'
        )
    },
    @{
        Source = 'Shared-Python-Toolchain/run-setup.cmd'
        Targets = @(
            'AnyUser Memory Optimizer Portable/Shared-Python-Toolchain/run-setup.cmd'
        )
    },
    @{
        Source = 'codex_profile.ps1'
        Targets = @(
            'installer/payload_codex54_new_projects/codex_profile.ps1'
        )
    }
)

$differences = New-Object System.Collections.Generic.List[string]
$updates = New-Object System.Collections.Generic.List[string]

foreach ($entry in $mappings) {
    $sourcePath = Join-Path $repoRoot $entry.Source
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw "Missing source file: $($entry.Source)"
    }

    $sourceHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
    foreach ($targetRelative in $entry.Targets) {
        $targetPath = Join-Path $repoRoot $targetRelative
        $targetDir = Split-Path -Parent $targetPath
        if (-not (Test-Path -LiteralPath $targetDir)) {
            New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
        }

        $targetHash = if (Test-Path -LiteralPath $targetPath) {
            (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash
        } else {
            $null
        }

        if ($targetHash -eq $sourceHash) {
            Write-Status "OK  $targetRelative"
            continue
        }

        $differences.Add("$($entry.Source) -> $targetRelative") | Out-Null
        if ($Check) {
            Write-Status "DIFF $targetRelative"
            continue
        }

        Copy-Item -LiteralPath $sourcePath -Destination $targetPath -Force
        $updates.Add("$($entry.Source) -> $targetRelative") | Out-Null
        Write-Status "SYNC $targetRelative"
    }
}

if ($Check -and $differences.Count -gt 0) {
    Write-Error ("Setup asset sync required:`n" + (($differences | Sort-Object) -join "`n"))
}

if (-not $Check) {
    if ($updates.Count -eq 0) {
        Write-Status 'Setup assets already in sync.'
    } else {
        Write-Status ("Updated setup assets:`n" + (($updates | Sort-Object) -join "`n"))
    }
}
