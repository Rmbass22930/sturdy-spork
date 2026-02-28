@echo off
setlocal
set "SCRIPT=%~dp0..\AnyUser Memory Optimizer\setup-memory-optimizer-wizard.ps1"
if not exist "%SCRIPT%" (
  echo ERROR: setup-memory-optimizer-wizard.ps1 not found at "%SCRIPT%".
  exit /b 1
)
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh -NoLogo -ExecutionPolicy Bypass -File "%SCRIPT%" %*
) else (
  powershell.exe -NoLogo -ExecutionPolicy Bypass -File "%SCRIPT%" %*
)
exit /b %ERRORLEVEL%
