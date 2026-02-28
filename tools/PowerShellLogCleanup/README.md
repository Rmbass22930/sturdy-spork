# PowerShell Log Cleanup

Automates deletion of stale log files across multiple Windows servers without using any external APIs. The script is authored for Windows 10 hosts running PowerShell 7 and is designed to run silently as a scheduled task.

## Files

- `Cleanup-Logs.ps1` – main script. Reads a JSON configuration file and performs the cleanup locally or via PowerShell remoting.
- `logcleanup.config.sample.json` – starter configuration showing how to define servers, paths, and retention settings.

## Configuration

The JSON file has two sections:

```jsonc
{
  "Global": {
    "RetentionDays": 30,
    "Recurse": true,
    "Extensions": [".log", ".txt"],
    "ExcludePatterns": ["*.keep.*"],
    "MinFileSizeMB": 0
  },
  "Targets": [
    {
      "Server": "APP-SVR01",
      "Paths": [
        {
          "Path": "C:\\Logs\\AppA",
          "RetentionDays": 14,
          "IncludeExtensions": [".log"],
          "ExcludePatterns": ["*-pinned.log"]
        }
      ]
    }
  ]
}
```

- `Global` defines defaults that every path inherits unless overridden. Set `Extensions` to the list of file extensions you want to delete; use `"[noext]"` to match files with no extension. `ExcludePatterns` uses the usual PowerShell wildcard syntax.
- Each `Target` lists a `Server` (use `localhost` or `.` for the local machine) and one or more `Paths`. Per-path options include `RetentionDays`, `Recurse`, `IncludeExtensions`, `ExcludePatterns`, and `MinFileSizeMB`. Omit a property to fall back to the global default.

## Running manually

```powershell
# Test run (WhatIf)
.	ools\PowerShellLogCleanup\Cleanup-Logs.ps1 \
    -ConfigPath .\tools\PowerShellLogCleanup\logcleanup.config.sample.json \
    -LogDirectory C:\Logs\CleanupReports \
    -WhatIf

# Actual cleanup
.	ools\PowerShellLogCleanup\Cleanup-Logs.ps1 \
    -ConfigPath .\config\logcleanup.json \
    -LogDirectory C:\Logs\CleanupReports \
    -RemoveEmptyDirectories
```

> **Note:** The standard `-WhatIf` and `-Verbose` switches are available because the script uses `SupportsShouldProcess`.

Ensure PowerShell remoting is enabled on every remote server (`Enable-PSRemoting -Force`) and that the scheduled-task identity has permission to access each path.

## Scheduling as a task

1. Copy your finalized JSON config somewhere accessible by the task account.
2. Register a task that runs under a service account with the necessary permissions. Example (run from an elevated PowerShell prompt):

```powershell
$action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"J:\\gdrive\\BallisticTarget\\src\\tools\\PowerShellLogCleanup\\Cleanup-Logs.ps1`" -ConfigPath `"J:\\configs\\logcleanup.json`" -LogDirectory `"D:\\OpsLogs\\Cleanup`" -RemoveEmptyDirectories"
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName "LogCleanup" -Action $action -Trigger $trigger -RunLevel Highest
```

3. Confirm the task’s history/log output in `-LogDirectory` and the Windows Event Log after the first run.

The scheduled task never calls external APIs; it only uses local/remote file system operations and PowerShell remoting to delete files.
