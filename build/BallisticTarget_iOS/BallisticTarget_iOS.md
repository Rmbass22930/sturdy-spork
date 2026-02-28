# BallisticTarget on iPad/iPhone

Use `BallisticTarget_iOS.html` to generate the same MOA target and ballistic table directly in Safari on mobile devices.

## Quick Steps
1. Copy `BallisticTarget_iOS.html` to iCloud Drive (or host on an internal HTTPS server) and open it in Safari on your iPad/iPhone.  
   - Works fully offline once loaded because all scripts are embedded.
2. Fill in rifle/ammo/environment inputs or leave the defaults. Edits auto-save to `localStorage` so you can switch apps without losing data.
3. Tap **Generate Target** to redraw the target preview and ballistic table.
4. Export your work:
   - **Print / Share Target** – opens a print dialog or share sheet for PDF/air print.
   - **Download PNG** – saves the rendered target image; AirDrop/email it to the desktop and place it in `output/`.
   - **Copy Table Text** – copies the ballistic rows (yards, drop, MOA, velocity, TOF, angle) for pasting into notes or Slack.
5. (Optional) Tap **Reset Inputs** to revert to the desktop defaults.

## Tips
- The canvas renders at 816×1056 so it prints true-to-scale on Letter/A4 when set to 100%.
- You can use **Add to Home Screen** in Safari for a pseudo-native icon and full-screen view.
- If you need the desktop app to use the same environmentals, copy the temp/alt/wind numbers into `EnvironmentalsGeo_iOS.html`, export `config.json`, and drop it next to `BallisticTargetGUI.exe` before generating targets on Windows.

## Optional PWA Install
If you host the HTML + `ballistictarget-manifest.json` + `bt-service-worker.js` on HTTPS (or serve them from the Files app), Safari lets you tap **Share → Add to Home Screen** for an app-like icon. The service worker caches everything (`BallisticTarget_iOS.html`, `EnvironmentalsGeo_iOS.html`, icons), so after one load you can launch it offline straight from the home screen.
