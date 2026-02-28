@echo off
setlocal
call "%~dp0run-setup.cmd" %*
exit /b %ERRORLEVEL%

