@echo off
setlocal EnableExtensions

echo Checking PowerShell 7+ for Codex 5.3...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-latest-powershell.ps1"
if errorlevel 1 (
  echo.
  echo PowerShell 7+ is required before continuing Codex 5.3 setup.
  echo Follow the install steps shown above, then re-run this script.
  exit /b 1
)

echo Checking Python 3 for Codex 5.3...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-latest-python.ps1"
if errorlevel 1 (
  echo.
  echo Python 3 is required before continuing Codex 5.3 setup.
  echo Follow the install steps shown above, then re-run this script.
  exit /b 1
)

set "SRC_DIR="
if "%~1"=="" goto wizard

set "SRC_DIR=%*"
set "SRC_DIR=%SRC_DIR:\"=%"
goto directsetup

:wizard
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-new-project-codex53.ps1"
exit /b %ERRORLEVEL%

:directsetup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-codex-chatgpt53.ps1" -SourceDir "%SRC_DIR%" -LoginNow
exit /b %ERRORLEVEL%
