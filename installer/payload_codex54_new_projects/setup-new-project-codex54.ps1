param(
  [string]$SourceDir,
  [switch]$LoginNow = $true
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) {
  Write-Host "[new-project] $msg"
}

function Read-Choice {
  param(
    [string]$Prompt,
    [string[]]$Allowed
  )

  while ($true) {
    $value = (Read-Host $Prompt).Trim()
    if ($Allowed -contains $value) {
      return $value
    }
    Write-Host "Enter one of: $($Allowed -join ', ')"
  }
}

function Select-ProjectRoot {
  $desktopRoot = Join-Path $env:USERPROFILE "Desktop"

  Write-Host ""
  Write-Host "Where should the new project be stored?"
  Write-Host "  1) Desktop"
  Write-Host "  2) Jump drive (USB/removable)"
  Write-Host "  3) Custom path"
  $choice = Read-Choice -Prompt "Select 1, 2, or 3" -Allowed @("1", "2", "3")

  switch ($choice) {
    "1" {
      return $desktopRoot
    }
    "2" {
      $removable = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 2" | Sort-Object DeviceID)
      if ($removable.Count -gt 0) {
        Write-Host ""
        Write-Host "Detected jump drives:"
        for ($i = 0; $i -lt $removable.Count; $i++) {
          $label = $removable[$i].VolumeName
          if ([string]::IsNullOrWhiteSpace($label)) { $label = "(no label)" }
          Write-Host ("  {0}) {1}\  {2}" -f ($i + 1), $removable[$i].DeviceID, $label)
        }
        $max = $removable.Count.ToString()
        $pick = Read-Choice -Prompt "Pick drive number (1-$max)" -Allowed (1..$removable.Count | ForEach-Object { $_.ToString() })
        return ($removable[[int]$pick - 1].DeviceID + "\")
      }

      Write-Host "No removable drives detected."
      $manualDrive = (Read-Host "Enter jump-drive root (example: E:\\)").Trim()
      if ([string]::IsNullOrWhiteSpace($manualDrive)) {
        throw "Jump-drive path is required."
      }
      return $manualDrive
    }
    "3" {
      $custom = (Read-Host "Enter full base folder path").Trim()
      if ([string]::IsNullOrWhiteSpace($custom)) {
        throw "Custom path is required."
      }
      return $custom
    }
  }
}

function Resolve-TargetProjectDir {
  if (-not [string]::IsNullOrWhiteSpace($SourceDir)) {
    return $SourceDir
  }

  $root = Select-ProjectRoot
  if (-not (Test-Path -LiteralPath $root)) {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
  }

  $defaultName = "BallisticTargetProject"
  $name = (Read-Host "Project folder name [$defaultName]").Trim()
  if ([string]::IsNullOrWhiteSpace($name)) {
    $name = $defaultName
  }

  return (Join-Path $root $name)
}

$projectDir = Resolve-TargetProjectDir
if (-not (Test-Path -LiteralPath $projectDir)) {
  New-Item -ItemType Directory -Force -Path $projectDir | Out-Null
}

$resolvedProjectDir = (Resolve-Path -LiteralPath $projectDir).Path
Write-Info "Project directory: $resolvedProjectDir"

$setupScript = Join-Path $PSScriptRoot "setup-codex-chatgpt54.ps1"
if (-not (Test-Path -LiteralPath $setupScript)) {
  throw "Missing setup script: $setupScript"
}

$setupParams = @{
  SourceDir = $resolvedProjectDir
}
if ($LoginNow) {
  $setupParams["LoginNow"] = $true
}

& $setupScript @setupParams

