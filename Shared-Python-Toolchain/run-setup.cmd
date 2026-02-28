@echo off
setlocal
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-codex54.ps1" %*
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-codex54.ps1" %*
)
exit /b %ERRORLEVEL%
