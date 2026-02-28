@echo off
setlocal
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh -NoLogo -ExecutionPolicy Bypass -File "%~dp0install-anyuser-chatgpt53.ps1" %*
) else (
  powershell.exe -NoLogo -ExecutionPolicy Bypass -File "%~dp0install-anyuser-chatgpt53.ps1" %*
)
exit /b %ERRORLEVEL%
