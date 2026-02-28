<#
.SYNOPSIS
    Cleans up old log files across multiple Windows servers.
.DESCRIPTION
    Reads a JSON configuration file that defines servers, log directories, and
    retention policies. For each target it connects with PowerShell remoting
    (or runs locally) and deletes files older than the configured retention
    window. Designed to run as a scheduled task without calling any external
    APIs.
.PARAMETER ConfigPath
    Path to the JSON file describing servers and log cleanup rules.
.PARAMETER Credential
    Optional credential for remoting. If omitted, the current scheduled-task
    identity is used.
.PARAMETER ThrottleLimit
    Maximum number of parallel remote operations. Applies when Invoke-Command
    fans out to multiple servers.
.PARAMETER LogDirectory
    Folder for execution logs. When omitted, logs stream to the console only.
.PARAMETER RemoveEmptyDirectories
    After deleting files, remove directories that become empty.
.EXAMPLE
    .\Cleanup-Logs.ps1 -ConfigPath .\logcleanup.config.json -LogDirectory C:\Logs\CleanupLogs
.NOTES
    Requires PowerShell remoting enabled on target servers. Designed for
    Windows 10 / PowerShell 7 as a scheduled task.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ })]
    [string]$ConfigPath,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$ThrottleLimit = 8,

    [Parameter()]
    [string]$LogDirectory,

    [Parameter()]
    [switch]$RemoveEmptyDirectories
)

$ErrorActionPreference = 'Stop'

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$timestamp][$Level] $Message"
    Write-Host $line
    if ($script:LogFilePath) {
        Add-Content -Path $script:LogFilePath -Value $line
    }
}

if ($LogDirectory) {
    $resolvedLogDir = Resolve-Path -LiteralPath (New-Item -ItemType Directory -Force -Path $LogDirectory) | Select-Object -First 1 -ExpandProperty Path
    $script:LogFilePath = Join-Path $resolvedLogDir ("LogCleanup_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
} else {
    $script:LogFilePath = $null
}

$configRaw = Get-Content -LiteralPath $ConfigPath -Raw
try {
    $config = $configRaw | ConvertFrom-Json -Depth 10
} catch {
    throw "Failed to parse configuration at '$ConfigPath': $($_.Exception.Message)"
}

if (-not $config.Targets) {
    throw 'Configuration must include at least one entry in "Targets".'
}

$globalDefaults = @{
    RetentionDays     = [int]($config.Global.RetentionDays ?? 30)
    Recurse           = [bool]($config.Global.Recurse ?? $true)
    IncludeExtensions = @($config.Global.Extensions)
    ExcludePatterns   = @($config.Global.ExcludePatterns)
    MinFileSizeMB     = [int]($config.Global.MinFileSizeMB ?? 0)
}

$cleanupScriptBlock = {
    param(
        [string]$TargetPath,
        [datetime]$Cutoff,
        [bool]$Recurse,
        [string[]]$IncludeExtensions,
        [string[]]$ExcludePatterns,
        [int]$MinFileSizeBytes,
        [switch]$PruneEmptyDirs
    )

    $result = [ordered]@{
        Path        = $TargetPath
        Deleted     = 0
        SizeBytes   = 0
        Skipped     = 0
        Errors      = 0
        Messages    = @()
    }

    if (-not (Test-Path -LiteralPath $TargetPath)) {
        $result.Messages += "Path not found"
        return $result
    }

    $searchParams = @{ Path = $TargetPath; File = $true; ErrorAction = 'SilentlyContinue'; Recurse = $Recurse }
    $candidates = Get-ChildItem @searchParams | Where-Object { $_.LastWriteTime -lt $Cutoff }

    if ($IncludeExtensions -and $IncludeExtensions.Count -gt 0) {
        $extFilter = $IncludeExtensions | ForEach-Object { ($_ ?? '').Trim().ToLowerInvariant() } | Where-Object { $_ }
        if ($extFilter.Count -gt 0) {
            $candidates = $candidates | Where-Object {
                $ext = ($_.Extension ?? '').ToLowerInvariant()
                if (-not $ext) {
                    return ($extFilter -contains '[noext]')
                }
                return $extFilter -contains $ext
            }
        }
    }

    if ($ExcludePatterns -and $ExcludePatterns.Count -gt 0) {
        foreach ($pattern in $ExcludePatterns) {
            $wildcard = $pattern.Trim()
            if ([string]::IsNullOrWhiteSpace($wildcard)) { continue }
            $candidates = $candidates | Where-Object { $_.Name -notlike $wildcard }
        }
    }

    if ($MinFileSizeBytes -gt 0) {
        $candidates = $candidates | Where-Object { $_.Length -ge $MinFileSizeBytes }
    }

    foreach ($file in $candidates) {
        try {
            $length = $file.Length
            Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop
            $result.Deleted++
            $result.SizeBytes += $length
        } catch {
            $result.Errors++
            $result.Messages += "Failed to delete $($file.FullName): $($_.Exception.Message)"
        }
    }

    if ($PruneEmptyDirs) {
        $dirs = Get-ChildItem -LiteralPath $TargetPath -Directory -Recurse:$Recurse -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
        foreach ($dir in $dirs) {
            try {
                $hasChildren = Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $hasChildren) {
                    Remove-Item -LiteralPath $dir.FullName -Force -ErrorAction Stop
                }
            } catch {
                $result.Messages += "Failed to prune directory $($dir.FullName): $($_.Exception.Message)"
            }
        }
    }

    return $result
}

$jobs = @()
$cutoffCache = @{}

foreach ($target in @($config.Targets)) {
    if (-not $target.Paths) { continue }
    $server = if ([string]::IsNullOrWhiteSpace($target.Server)) { 'localhost' } else { $target.Server }
    $paths = @($target.Paths)

    foreach ($pathEntry in $paths) {
        $path = $pathEntry.Path
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        $retention = [int]($pathEntry.RetentionDays ?? $globalDefaults.RetentionDays)
        if ($retention -le 0) { $retention = $globalDefaults.RetentionDays }
        $cutoff = (Get-Date).AddDays(-1 * [math]::Abs($retention))
        $recurse = [bool]($pathEntry.Recurse ?? $globalDefaults.Recurse)
        $includeExt = @($pathEntry.IncludeExtensions)
        if (-not $includeExt -or $includeExt.Count -eq 0) { $includeExt = $globalDefaults.IncludeExtensions }
        $exclude = @($pathEntry.ExcludePatterns)
        if (-not $exclude -or $exclude.Count -eq 0) { $exclude = $globalDefaults.ExcludePatterns }
        $minSizeBytes = 0
        $minSize = [int]($pathEntry.MinFileSizeMB ?? $globalDefaults.MinFileSizeMB)
        if ($minSize -gt 0) { $minSizeBytes = $minSize * 1MB }

        $actionDescription = "Delete files older than $retention days from $path on $server"
        if (-not $PSCmdlet.ShouldProcess($actionDescription)) { continue }

        $invokeParams = @{
            ScriptBlock = $cleanupScriptBlock
            ArgumentList = @($path, $cutoff, $recurse, $includeExt, $exclude, $minSizeBytes, $RemoveEmptyDirectories)
            ErrorAction = 'Stop'
        }

        $isLocal = $server -in @('.', 'localhost', $env:COMPUTERNAME)
        if ($isLocal) {
            Write-Log "Running local cleanup: $actionDescription"
            $result = & $cleanupScriptBlock @invokeParams.ArgumentList
            $jobs += [pscustomobject]@{ Server = $server; Result = $result }
            continue
        }

        Write-Log "Queueing cleanup on $server for $path"
        $invokeParams.ComputerName = $server
        if ($Credential) { $invokeParams.Credential = $Credential }
        $invokeParams.ThrottleLimit = $ThrottleLimit

        try {
            $remoteResult = Invoke-Command @invokeParams
            $jobs += [pscustomobject]@{ Server = $server; Result = $remoteResult }
        } catch {
            Write-Log "Failed to run cleanup on $server ($path): $($_.Exception.Message)" -Level 'ERROR'
        }
    }
}

if ($jobs.Count -eq 0) {
    Write-Log 'No cleanup work executed.' -Level 'WARN'
    return
}

Write-Log 'Cleanup summary:'
foreach ($job in $jobs) {
    $result = $job.Result
    $sizeMB = if ($result.SizeBytes -gt 0) { [Math]::Round($result.SizeBytes / 1MB, 2) } else { 0 }
    $summary = "Server={0} Path={1} Deleted={2} SizeMB={3} Errors={4}" -f $job.Server, $result.Path, $result.Deleted, $sizeMB, $result.Errors
    Write-Log $summary
    foreach ($msg in $result.Messages) {
        Write-Log ("  -> {0}" -f $msg) -Level 'WARN'
    }
}
