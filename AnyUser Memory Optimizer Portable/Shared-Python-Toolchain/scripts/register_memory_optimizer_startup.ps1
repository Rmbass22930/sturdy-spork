param(
    [string]$TaskName = "MemoryOptimizerHyperV",
    [string]$PythonPath = "python",
    [string]$WorkingDirectory = (Get-Location).Path,
    [double]$MinFreeMb = 1024,
    [double]$MaxReserveMb = -1,
    [double]$BlockSizeMb = 256,
    [double]$IdleSeconds = 180,
    [double]$SampleInterval = 5,
    [double]$VmWaitFreeMb = 2048,
    [double]$VmWaitTimeout = 600,
    [double]$VmStartDelay = 5,
    [switch]$NoRestartVm,
    [switch]$DisableControlPanel,
    [int]$ControlPanelPort = 8765,
    [string]$ControlPanelHost = "0.0.0.0",
    [Parameter(Mandatory = $true)][string]$HyperVVmName
)

function Join-Args {
    param([string[]]$Args)
    return ($Args | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"{0}"' -f ($_ -replace '"', '\"')
        } else {
            $_
        }
    }) -join ' '
}

$optimizerArgs = @(
    "-m", "memory_optimizer.cli", "autostart-run",
    "--hyperv-vm-name", $HyperVVmName,
    "--min-free-mb", $MinFreeMb,
    "--block-size-mb", $BlockSizeMb,
    "--idle-seconds", $IdleSeconds,
    "--sample-interval", $SampleInterval,
    "--vm-wait-free-mb", $VmWaitFreeMb,
    "--vm-wait-timeout", $VmWaitTimeout,
    "--vm-start-delay", $VmStartDelay,
    "--control-panel-host", $ControlPanelHost,
    "--control-panel-port", $ControlPanelPort
)

if ($MaxReserveMb -gt 0) {
    $optimizerArgs += @("--max-reserve-mb", $MaxReserveMb)
}

if ($NoRestartVm) {
    $optimizerArgs += "--no-restart-vm"
}

if ($DisableControlPanel) {
    $optimizerArgs += "--disable-control-panel"
}

$argString = Join-Args -Args $optimizerArgs
$action = New-ScheduledTaskAction -Execute $PythonPath -Argument $argString -WorkingDirectory $WorkingDirectory
$trigger = New-ScheduledTaskTrigger -AtLogOn
$task = Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Description "Memory optimizer + Hyper-V autostart" -Force

Write-Host "Registered scheduled task '$TaskName'."
Write-Host "Command:"
Write-Host "$PythonPath $argString"
