@echo off
setlocal EnableExtensions

set "APP_NAME=Ballistic Target Calculator"
set "INSTALL_ROOT=%~dp0"
if "%INSTALL_ROOT:~-1%"=="\" set "INSTALL_ROOT=%INSTALL_ROOT:~0,-1%"

set "DESKTOP_DIR="
for /f "usebackq delims=" %%D in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "[Environment]::GetFolderPath('Desktop')"`) do set "DESKTOP_DIR=%%D"
if not defined DESKTOP_DIR set "DESKTOP_DIR=%USERPROFILE%\Desktop"
if not exist "%DESKTOP_DIR%" if exist "%USERPROFILE%\OneDrive\Desktop" set "DESKTOP_DIR=%USERPROFILE%\OneDrive\Desktop"

set "DESKTOP_LINK=%DESKTOP_DIR%\%APP_NAME%.lnk"
set "DESKTOP_LINK_FALLBACK=%USERPROFILE%\Desktop\%APP_NAME%.lnk"
set "DESKTOP_LINK_ONEDRIVE=%USERPROFILE%\OneDrive\Desktop\%APP_NAME%.lnk"
set "START_MENU_ROOT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\%APP_NAME%"
set "START_MENU_LINK=%START_MENU_ROOT%\%APP_NAME%.lnk"
set "ENV_LINK=%START_MENU_ROOT%\Environmentals + Geo.lnk"
set "UNINSTALL_LINK=%START_MENU_ROOT%\Uninstall %APP_NAME%.lnk"

taskkill /IM "BallisticTargetGUI.exe" /F >nul 2>nul
taskkill /IM "EnvironmentalsGeoGUI.exe" /F >nul 2>nul

del /F /Q "%DESKTOP_LINK%" >nul 2>nul
del /F /Q "%DESKTOP_LINK_FALLBACK%" >nul 2>nul
del /F /Q "%DESKTOP_LINK_ONEDRIVE%" >nul 2>nul
del /F /Q "%START_MENU_LINK%" >nul 2>nul
del /F /Q "%ENV_LINK%" >nul 2>nul
del /F /Q "%UNINSTALL_LINK%" >nul 2>nul

for %%F in ("%INSTALL_ROOT%\*.exe") do del /F /Q "%%~fF" >nul 2>nul
del /F /Q "%INSTALL_ROOT%\README.txt" >nul 2>nul
del /F /Q "%INSTALL_ROOT%\config.template.json" >nul 2>nul
del /F /Q "%INSTALL_ROOT%\install.log" >nul 2>nul

if exist "%START_MENU_ROOT%" rd "%START_MENU_ROOT%" >nul 2>nul

echo %APP_NAME% executable and shortcuts removed.
echo User data was kept:
echo   %INSTALL_ROOT%\config.json
echo   %INSTALL_ROOT%\output
echo   %INSTALL_ROOT%\logs
echo.
echo Delete the folder below manually if you also want to remove data:
echo   %INSTALL_ROOT%
pause
exit /b 0
