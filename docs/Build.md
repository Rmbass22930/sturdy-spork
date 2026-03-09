# Building BallisticTarget Installers

## Prerequisites
- Windows host with PowerShell 7+, PyInstaller, and IExpress (built into Windows).
- Python 3.14 environment that matches what the app uses (already configured in this repo).
- `G:\` and `H:\` mapped (or override the output roots when running the scripts).

## One-step CI/local build
Run the combined pipeline script. It builds the EXEs, packages the payload, creates both self-extracting installers, copies artifacts + checksums to every configured output root (default: `G:\` and `H:\`), and performs a smoke test that extracts each installer into a temp folder to ensure `Install.cmd` is present.

```powershell
pwsh -NoProfile -File scripts/ci-build.ps1            # default outputs G:\ and H:\
# or specify one or more output locations:
pwsh -NoProfile -File scripts/ci-build.ps1 -OutputRoot 'D:\drops\bt'
pwsh -NoProfile -File scripts/ci-build.ps1 -OutputRoot 'D:\drops\bt','E:\mirror'
```

## Individual stages
1. `scripts/build-installer.ps1 [-OutputRoot ...]`  
   - PyInstaller for `BallisticTargetGUI` and `Uninstall.exe`  
   - Zips `installer\payload` -> `installer\BallisticTargetInstaller.zip`  
   - Runs IExpress inside `installer\` to create `BallisticTargetSetup.exe` and `InstallBallistic.exe`  
   - Regenerates `CHECKSUMS.txt` and copies artifacts to each output root (skipping any drive that is offline)
2. `scripts/smoke-test-installers.ps1`  
   - Expands `installer\BallisticTargetInstaller.zip` into a temp folder  
   - Verifies that core files (`Install.cmd`, `BallisticTargetGUI.exe`, `Uninstall.exe`, `README.txt`) exist  
   - Cleans up the temp directory afterward  
   - Because both IExpress packages are built directly from this ZIP, validating its contents verifies the installers’ payload

## Scheduled task automation
To rebuild automatically every night on the workstation:
1. Ensure PowerShell 7, Python/PyInstaller, and access to `J:\gdrive\BallisticTarget\src` + `G:\` exist for the account that will run the task.
2. Run (once) from an elevated PowerShell prompt if you want the task to run even when logged off, otherwise a normal prompt creates an “Interactive only” task:
   ```powershell
   $taskCommand = '"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File "J:\gdrive\BallisticTarget\src\scripts\ci-build.ps1"'
   schtasks.exe /Create /TN BallisticTargetCIBuild /SC DAILY /ST 02:00 /TR $taskCommand
   ```
3. Adjust `/ST` or `/SC` as desired. The task executes `ci-build.ps1`, so it inherits the build + copy + smoke-test behavior described above.

If you later need the task to run when nobody is logged in, recreate it with `/RU SYSTEM /RL HIGHEST` from an elevated prompt to grant the necessary rights.

These scripts are intended for CI use, but you can also run them manually before sharing a build drop. Adjust the output root or add additional verification steps (code signing, etc.) as needed.

## QA harness
Run the targeted pytest suite before publishing to either desktop deployment:

```powershell
cd J:\gdrive\BallisticTarget\src
pytest tests/test_geo_projection.py tests/test_packaging.py
```

- `test_geo_projection.py` exercises the compass-to-bearing math and verifies that `project_path()` produces evenly spaced waypoints that match the between-pins projection helper.
- `test_packaging.py` compares the MD5 of `BallisticTargetGUI.exe` in the repo root with the copy staged inside `installer/payload`. Any mismatch means the installer payload is stale relative to the freshly built GUI and should block release until re-packed.
