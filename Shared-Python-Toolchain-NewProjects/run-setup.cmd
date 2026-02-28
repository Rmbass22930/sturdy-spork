@echo off`r`nsetlocal`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-codex54.ps1" %*`r`nexit /b %ERRORLEVEL%`r`n
