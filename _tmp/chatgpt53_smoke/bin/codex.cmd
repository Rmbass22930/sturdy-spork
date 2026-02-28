@echo off
if "%1"=="login" (
  if "%2"=="status" (
    echo Logged in
    exit /b 0
  )
  if "%2"=="--device-auth" (
    echo device auth ok
    exit /b 0
  )
)
echo codex stub %*
exit /b 0
