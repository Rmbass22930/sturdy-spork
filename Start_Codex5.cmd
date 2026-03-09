@echo off
setlocal EnableExtensions
color 0F

if "%~1"=="" (
  where pwsh >nul 2>nul
  if %ERRORLEVEL% EQU 0 (
    pwsh -NoLogo -NoExit -ExecutionPolicy Bypass -File "%~dp0Start_Codex5.ps1"
  ) else (
    powershell.exe -NoLogo -NoExit -ExecutionPolicy Bypass -File "%~dp0Start_Codex5.ps1"
  )
  set "EC=%ERRORLEVEL%"
  goto :post
)

where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  pwsh -NoLogo -ExecutionPolicy Bypass -File "%~dp0Start_Codex5.ps1" %*
) else (
  powershell.exe -NoLogo -ExecutionPolicy Bypass -File "%~dp0Start_Codex5.ps1" %*
)
set "EC=%ERRORLEVEL%"

:post
if not "%EC%"=="0" (
  echo.
  echo Start_Codex5 failed with exit code %EC%.
  echo Press any key to close...
  pause >nul
)
exit /b %EC%