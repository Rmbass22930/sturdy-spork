@echo off
setlocal
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh -NoLogo -ExecutionPolicy Bypass -File "%~dp0prepare-usb-payload.ps1" %*
) else (
  powershell.exe -NoLogo -ExecutionPolicy Bypass -File "%~dp0prepare-usb-payload.ps1" %*
)
exit /b %ERRORLEVEL%
