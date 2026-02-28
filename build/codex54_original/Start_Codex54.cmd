@echo off
setlocal EnableExtensions`r`ncolor 0F`r`npowershell.exe -NoLogo -ExecutionPolicy Bypass -File "%~dp0Start_Codex54.ps1" %*
exit /b %ERRORLEVEL%


