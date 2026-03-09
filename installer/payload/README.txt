BallisticTarget Installer Package
=================================

Install
1. Extract this package to any folder.
2. Double-click `Install.cmd` (Run as administrator is optional).
3. App installs to:
   %USERPROFILE%\Desktop\ballilstic target calulator
4. Shortcuts are created on Desktop and Start Menu.
5. If an older install exists, the script backs up your `output` folder, wipes every other file, and leaves `output` in place so saved targets stay on disk during the clean reinstall.

What is included
- BallisticTarget GUI executable.
- Environmentals + Geo desktop tool.
- **EnvironmentalsGeo_iOS.html** (environment inputs from iPhone/iPad Safari).
- **BallisticTarget_iOS.html** (full ballistic calculator + printable target for iPhone/iPad Safari).
- **TargetUsage.txt** (step-by-step instructions for dialing/holding on the MOA dots at 50–400 yd).
- Any additional payload `.exe` files are copied during install.
- Default config file template for first run.
- Output and logs folders created at install time.
- Desktop output folder:
  %USERPROFILE%\Desktop\ballilstic target calulator\output
- Saved targets now live directly under the `output` folder. The installer migrates any legacy files from `output\targets` automatically.
- Optional compatibility folder:
  %USERPROFILE%\Desktop\ballilstic target calulator\output\targets

Uninstall
- Run `%USERPROFILE%\Desktop\ballilstic target calulator\Uninstall.exe`
  or the "Uninstall Ballistic Target Calculator" Start Menu shortcut.
- Uninstall keeps `config.json`, `output`, and `logs` by default.
