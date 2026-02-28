$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
  exit 0
}

$pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
if ($pwsh) {
  & $pwsh.Source -NoLogo -NoExit
} else {
  & powershell.exe -NoLogo -NoExit
}
