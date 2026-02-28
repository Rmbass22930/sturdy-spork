@echo off
setlocal
set ROOT=%~dp0

set PY_CMD=
py -3 --version >nul 2>nul
if %errorlevel%==0 set PY_CMD=py -3
if not defined PY_CMD (
  python --version >nul 2>nul
  if %errorlevel%==0 set PY_CMD=python
)

if not defined PY_CMD (
  echo ERROR: Python 3 not found. Install Python 3 and ensure 'py' or 'python' is on PATH.
  exit /b 1
)

%PY_CMD% "%ROOT%dist\scenario-runner.pyz" --scenarios "%ROOT%dist\scenarios.json" --output "%ROOT%dist\scenario-results.md"
if not %errorlevel%==0 exit /b %errorlevel%

echo WROTE: %ROOT%dist\scenario-results.md
endlocal
