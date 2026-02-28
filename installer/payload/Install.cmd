@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: Install runs in standard user context (no UAC prompt).

set "APP_NAME=Ballistic Target Calculator"
set "MAIN_EXE=BallisticTargetGUI.exe"
set "ENV_EXE=EnvironmentalsGeoGUI.exe"
set "SRC_DIR=%~dp0"
if not "%SRC_DIR:~-1%"=="\" set "SRC_DIR=%SRC_DIR%\"

set "DESKTOP_DIR="
for /f "usebackq delims=" %%D in (`powershell -NoProfile -Command "$p=[Environment]::GetFolderPath('Desktop'); if([string]::IsNullOrWhiteSpace($p)){'NULL'} else {$p}"`) do (
  if /I not "%%D"=="NULL" set "DESKTOP_DIR=%%D"
)
if not defined DESKTOP_DIR set "DESKTOP_DIR=%USERPROFILE%\Desktop"
if not exist "%DESKTOP_DIR%" (
  for %%P in ("%USERPROFILE%\OneDrive\Desktop" "%USERPROFILE%\OneDrive - %USERNAME%\Desktop") do (
    if exist "%%~P" (
      set "DESKTOP_DIR=%%~P"
      goto :after_desktop_probe
    )
  )
  echo WARNING: Could not auto-detect Desktop folder. Falling back to %USERPROFILE%\Desktop
  set "DESKTOP_DIR=%USERPROFILE%\Desktop"
)
:after_desktop_probe

set "LOCAL_DESKTOP=%USERPROFILE%\Desktop"
if not exist "%LOCAL_DESKTOP%" (
  mkdir "%LOCAL_DESKTOP%" >nul 2>nul
)
set "INSTALL_BASE=%DESKTOP_DIR%"
set "VISIBLE_DESKTOP=%DESKTOP_DIR%"
if not exist "%INSTALL_BASE%" (
  mkdir "%INSTALL_BASE%" >nul 2>nul
)
set "INSTALL_FOLDER=ballilstic target calulator"
set "INSTALL_ROOT=%INSTALL_BASE%\%INSTALL_FOLDER%"
set "VISIBLE_INSTALL_ROOT=%VISIBLE_DESKTOP%\%INSTALL_FOLDER%"
set "OUTPUT_DIR=%INSTALL_ROOT%\output"
set "TARGETS_DIR=%OUTPUT_DIR%\targets"
set "LOG_DIR=%INSTALL_ROOT%\logs"
set "CONFIG_PATH=%INSTALL_ROOT%\config.json"
set "INSTALL_LOG=%INSTALL_ROOT%\install.log"
set "TARGETS_BACKUP="
set "RESTORE_TARGETS=0"

set "DESKTOP_LINK=%VISIBLE_DESKTOP%\%APP_NAME%.lnk"
set "START_MENU_ROOT=%APPDATA%\Microsoft\Windows\Start Menu\Programs\%APP_NAME%"
set "START_MENU_LINK=%START_MENU_ROOT%\%APP_NAME%.lnk"
set "ENV_LINK=%START_MENU_ROOT%\Environmentals + Geo.lnk"
set "UNINSTALL_LINK=%START_MENU_ROOT%\Uninstall %APP_NAME%.lnk"
set "IOS_ENV_HTML=EnvironmentalsGeo_iOS.html"
set "IOS_ENV_LINK=%START_MENU_ROOT%\Environmentals (iOS Web Companion).lnk"
set "IOS_MAIN_HTML=BallisticTarget_iOS.html"
set "IOS_MAIN_LINK=%START_MENU_ROOT%\Ballistic Target (iOS Web).lnk"
set "INSTALL_WINDOWS=1"
set "INSTALL_IOS=0"
set "PROCS_TO_CLOSE=BallisticTargetGUI.exe EnvironmentalsGeoGUI.exe"

if "%INSTALL_WINDOWS%"=="1" (
  if not exist "%SRC_DIR%%MAIN_EXE%" (
    echo ERROR: Missing required payload executable: %MAIN_EXE%
    exit /b 1
  )
)

if not exist "%VISIBLE_DESKTOP%" mkdir "%VISIBLE_DESKTOP%"
set "CURRENT_INSTALL="
if exist "%INSTALL_ROOT%" set "CURRENT_INSTALL=%INSTALL_ROOT%"
set "INSTALL_MODE=fresh"
if defined CURRENT_INSTALL (
  echo.
  echo Checking for running Ballistic Target processes...
  call :ensure_processes_closed
  echo.
  echo Existing installation detected at:
  echo   %CURRENT_INSTALL%
  set "CAN_WIPE=1"
  set "CURRENT_TARGETS=%CURRENT_INSTALL%\output\targets"
  if exist "%CURRENT_TARGETS%" (
    echo Backing up saved targets ^(best effort^)... 
    set "TARGETS_BACKUP=%TEMP%\bt_targets_%RANDOM%%RANDOM%"
    set "RESTORE_TARGETS=1"
    mkdir "%TARGETS_BACKUP%" >nul 2>nul
    if errorlevel 1 (
      echo WARNING: Could not stage temporary backup. Targets will remain in place.
      set "TARGETS_BACKUP="
      set "CAN_WIPE=0"
      set "RESTORE_TARGETS=0"
    ) else (
      robocopy "%CURRENT_TARGETS%" "%TARGETS_BACKUP%" /E /NFL /NDL /NJH /NJS /NP >nul
      set "RC=!errorlevel!"
      if !RC! GEQ 8 (
        echo WARNING: Target backup hit an error ^(!RC!^). Leaving originals untouched.
        rd /s /q "%TARGETS_BACKUP%" >nul 2>nul
        set "TARGETS_BACKUP="
        set "CAN_WIPE=0"
        set "RESTORE_TARGETS=0"
      )
    )
  )
  if "!CAN_WIPE!"=="1" (
    echo Removing old files...
    rd /s /q "%CURRENT_INSTALL%"
    if errorlevel 1 (
      echo WARNING: Could not remove previous install. Files will be updated in place instead.
      set "INSTALL_MODE=overlay"
      set "CAN_WIPE=0"
    )
  )
  if "!CAN_WIPE!"=="0" (
    echo Performing in-place update so existing targets stay where they are.
    set "INSTALL_MODE=overlay"
    set "RESTORE_TARGETS=0"
  )
)
if not exist "%INSTALL_ROOT%" (
  mkdir "%INSTALL_ROOT%" >nul 2>nul
  if errorlevel 1 (
    echo ERROR: Could not create install folder.
    echo        %INSTALL_ROOT%
    exit /b 1
  )
)

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%TARGETS_DIR%" mkdir "%TARGETS_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%START_MENU_ROOT%" mkdir "%START_MENU_ROOT%"

set "COPIED_EXE=0"
if "%INSTALL_WINDOWS%"=="1" (
  for %%F in ("%SRC_DIR%*.exe") do (
    copy /Y "%%~fF" "%INSTALL_ROOT%\%%~nxF" >nul
    if errorlevel 1 (
      echo ERROR: Failed to copy executable: %%~nxF
      exit /b 1
    )
    set "COPIED_EXE=1"
  )

  if "!COPIED_EXE!"=="0" (
    echo ERROR: No executables found in installer payload.
    exit /b 1
  )

  copy /Y "%SRC_DIR%Uninstall.cmd" "%INSTALL_ROOT%\Uninstall.cmd" >nul
  if errorlevel 1 (
    echo ERROR: Failed to copy uninstaller.
    exit /b 1
  )
  powershell -NoProfile -Command "Get-ChildItem -LiteralPath '%INSTALL_ROOT%' -Filter *.exe | Unblock-File" >nul 2>nul
) else (
  echo Skipping Windows desktop binaries per selection.
)

copy /Y "%SRC_DIR%README.txt" "%INSTALL_ROOT%\README.txt" >nul 2>nul
copy /Y "%SRC_DIR%config.template.json" "%INSTALL_ROOT%\config.template.json" >nul 2>nul

if not exist "%CONFIG_PATH%" (
  if exist "%SRC_DIR%config.template.json" (
    copy /Y "%SRC_DIR%config.template.json" "%CONFIG_PATH%" >nul
  )
)

if "%INSTALL_IOS%"=="1" (
  if exist "%SRC_DIR%%IOS_ENV_HTML%" (
    copy /Y "%SRC_DIR%%IOS_ENV_HTML%" "%INSTALL_ROOT%\%IOS_ENV_HTML%" >nul
  )
  if exist "%SRC_DIR%%IOS_MAIN_HTML%" (
    copy /Y "%SRC_DIR%%IOS_MAIN_HTML%" "%INSTALL_ROOT%\%IOS_MAIN_HTML%" >nul
  )
) else (
  echo Skipping iOS web companions per selection.
)

if "%RESTORE_TARGETS%"=="1" (
  if defined TARGETS_BACKUP (
    echo Restoring saved targets...
    if not exist "%TARGETS_DIR%" mkdir "%TARGETS_DIR%" >nul 2>nul
    robocopy "%TARGETS_BACKUP%" "%TARGETS_DIR%" /E /NFL /NDL /NJH /NJS >nul
    if errorlevel 8 (
      echo WARNING: Failed to restore some target files from backup.
    )
    rd /s /q "%TARGETS_BACKUP%" >nul 2>nul
    set "TARGETS_BACKUP="
  )
) else (
  if defined TARGETS_BACKUP (
    rd /s /q "%TARGETS_BACKUP%" >nul 2>nul
    set "TARGETS_BACKUP="
  )
)

if "%INSTALL_WINDOWS%"=="1" (
  set "ENV_TARGET=%INSTALL_ROOT%\%ENV_EXE%"
  if not exist "%ENV_TARGET%" set "ENV_TARGET=%INSTALL_ROOT%\%MAIN_EXE%"
) else (
  set "ENV_TARGET="
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"$createWin = '%INSTALL_WINDOWS%' -eq '1'; ^
$createIos = '%INSTALL_IOS%' -eq '1'; ^
$ws=New-Object -ComObject WScript.Shell; ^
if($createWin){ ^
  $desktop='%DESKTOP_LINK%'; ^
  $target='%INSTALL_ROOT%\%MAIN_EXE%'; ^
  if(Test-Path $target){ ^
    $s=$ws.CreateShortcut($desktop); ^
    $s.TargetPath=$target; ^
    $s.WorkingDirectory='%INSTALL_ROOT%'; ^
    $s.IconLocation=$target + ',0'; ^
    $s.Description='Ballistic Target Calculator'; ^
    $s.Save(); ^
    $s2=$ws.CreateShortcut('%START_MENU_LINK%'); ^
    $s2.TargetPath=$target; ^
    $s2.WorkingDirectory='%INSTALL_ROOT%'; ^
    $s2.IconLocation=$target + ',0'; ^
    $s2.Description='Ballistic Target Calculator'; ^
    $s2.Save(); ^
  } ^
  if('%ENV_TARGET%' -ne ''){ ^
    $envTarget='%ENV_TARGET%'; ^
    if(Test-Path $envTarget){ ^
      $s3=$ws.CreateShortcut('%ENV_LINK%'); ^
      $s3.TargetPath=$envTarget; ^
      $s3.WorkingDirectory='%INSTALL_ROOT%'; ^
      $s3.IconLocation=$envTarget + ',0'; ^
      $s3.Description='Environmentals + Geo'; ^
      $s3.Save(); ^
    } ^
  } ^
  if(Test-Path '%INSTALL_ROOT%\Uninstall.cmd'){ ^
    $s4=$ws.CreateShortcut('%UNINSTALL_LINK%'); ^
    $s4.TargetPath='%INSTALL_ROOT%\Uninstall.cmd'; ^
    $s4.WorkingDirectory='%INSTALL_ROOT%'; ^
    $s4.IconLocation='%SystemRoot%\System32\shell32.dll,131'; ^
    $s4.Description='Uninstall Ballistic Target Calculator'; ^
    $s4.Save(); ^
  } ^
} ^
if($createIos){ ^
  if(Test-Path '%INSTALL_ROOT%\%IOS_ENV_HTML%'){ ^
    $s_ios=$ws.CreateShortcut('%IOS_ENV_LINK%'); ^
    $s_ios.TargetPath='%INSTALL_ROOT%\%IOS_ENV_HTML%'; ^
    $s_ios.WorkingDirectory='%INSTALL_ROOT%'; ^
    $s_ios.IconLocation='%SystemRoot%\System32\shell32.dll,14'; ^
    $s_ios.Description='Open Environmentals companion (iOS web)'; ^
    $s_ios.Save(); ^
  } ^
  if(Test-Path '%INSTALL_ROOT%\%IOS_MAIN_HTML%'){ ^
    $s_ios2=$ws.CreateShortcut('%IOS_MAIN_LINK%'); ^
    $s_ios2.TargetPath='%INSTALL_ROOT%\%IOS_MAIN_HTML%'; ^
    $s_ios2.WorkingDirectory='%INSTALL_ROOT%'; ^
    $s_ios2.IconLocation='%SystemRoot%\System32\shell32.dll,14'; ^
    $s_ios2.Description='Open BallisticTarget calculator (iOS web)'; ^
    $s_ios2.Save(); ^
  } ^
}"

if errorlevel 1 (
  echo WARNING: Installed app, but shortcut creation failed.
)

(
  echo %APP_NAME% installed to:
  echo   %INSTALL_ROOT%
  echo.
  echo Install mode: %INSTALL_MODE%
  echo.
  if "%INSTALL_WINDOWS%"=="1" (
    echo Target output folder:
    echo   %OUTPUT_DIR%
    echo.
  ) else (
    echo Windows desktop EXE: skipped
    echo.
  )
  if "%INSTALL_IOS%"=="1" (
    echo iOS companions deployed:
    if exist "%INSTALL_ROOT%\%IOS_MAIN_HTML%" echo   %IOS_MAIN_HTML%
    if exist "%INSTALL_ROOT%\%IOS_ENV_HTML%" echo   %IOS_ENV_HTML%
    echo.
  ) else (
    echo iOS companions: skipped
    echo.
  )
  echo Optional target archive folder:
  echo   %TARGETS_DIR%
) > "%INSTALL_LOG%"

echo.
echo %APP_NAME% installed to:
echo   %INSTALL_ROOT%
if /I "%INSTALL_MODE%"=="overlay" (
  echo   (In-place update: existing targets stayed put.)
)
echo.
if "%INSTALL_WINDOWS%"=="1" (
  echo Target output folder:
  echo   %OUTPUT_DIR%
  echo.
  if /I "%BT_NO_AUTO_LAUNCH%"=="1" exit /b 0
  start "" "%INSTALL_ROOT%\%MAIN_EXE%"
  exit /b 0
) else (
  echo Windows desktop binaries not installed; use the Start Menu shortcut for the iOS web companion.
  exit /b 0
)

goto :EOF

:ensure_processes_closed
set "STILL_RUNNING="
for %%P in (%PROCS_TO_CLOSE%) do (
  tasklist /FI "IMAGENAME eq %%P" | find /I "%%P" >nul
  if not errorlevel 1 (
    echo   Attempting to close %%P ...
    taskkill /F /IM %%P >nul 2>nul
  )
)
for %%P in (%PROCS_TO_CLOSE%) do (
  tasklist /FI "IMAGENAME eq %%P" | find /I "%%P" >nul
    if not errorlevel 1 (
      set "STILL_RUNNING=1"
      echo   %%P is still running. Close it ^(or let us close it^) then press Enter.
    )
)
if defined STILL_RUNNING (
  pause
  goto ensure_processes_closed
)
exit /b 0
