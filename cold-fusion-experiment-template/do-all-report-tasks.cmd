@echo off
setlocal
set ROOT=%~dp0
set REPORT=%ROOT%printable-report.md

if not exist "%REPORT%" (
  echo ERROR: Report not found: %REPORT%
  exit /b 1
)

start "" "%ROOT%"
start "" notepad "%REPORT%"
notepad /p "%REPORT%"

echo DONE: Opened folder, opened report in Notepad, and sent report to default printer.
endlocal
