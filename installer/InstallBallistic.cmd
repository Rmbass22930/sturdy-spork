@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: Install runs in standard user context (no UAC prompt).

set "PAYLOAD_ZIP=%~dp0BallisticTargetInstaller.zip"
if not exist "%PAYLOAD_ZIP%" (
  echo Payload ZIP not found: %PAYLOAD_ZIP%
  exit /b 1
)

set "TEMP_ROOT=%TEMP%\ballistic_cmd_installer_%RANDOM%%RANDOM%"
set "EXTRACT_DIR=%TEMP_ROOT%\payload"

mkdir "%EXTRACT_DIR%" >nul 2>nul
if errorlevel 1 (
  echo Failed to create temporary folder: %EXTRACT_DIR%
  exit /b 1
)

powershell -NoProfile -Command "Expand-Archive -LiteralPath '%PAYLOAD_ZIP%' -DestinationPath '%EXTRACT_DIR%' -Force" >nul 2>nul
if errorlevel 1 (
  echo Failed to extract payload.
  rd /s /q "%TEMP_ROOT%" >nul 2>nul
  exit /b 1
)

pushd "%EXTRACT_DIR%"
cmd /c call Install.cmd
set "ERR=%ERRORLEVEL%"
if not "%ERR%"=="0" (
  echo Installer exited with code %ERR%.
)
popd

rd /s /q "%TEMP_ROOT%" >nul 2>nul
exit /b %ERR%
