BallisticTarget iPad – Step-by-Step (USB Drive)
=============================================

1. **Plug in the USB/SSD**
   - Connect the jump drive to the iPad (USB‑C cable or Lightning adapter).

2. **Open Files → Browse**
   - Under “Locations” tap the drive name (example: USBDrive).

3. **Launch the apps**
   - Tap `BallisticTarget_iOS.html` → Share → **Open in Safari**.
   - Do the same for `EnvironmentalsGeo_iOS.html` when you need to update config.json.

4. **Add to Home Screen (optional)**
   - In Safari tap Share → **Add to Home Screen** so the icon behaves like an app.

5. **Use the tools offline**
   - BallisticTarget generates targets and ballistic tables in the browser.
   - EnvironmentalsGeo captures weather/GPS and exports `config.json`.

6. **Save targets/configs back to the drive**
   - After tapping **Download PNG** (or downloading config.json), tap the download icon → the file → Share → **Save to Files** → choose the jump drive (or On My iPad > BallisticTargetOutput).

7. **Transfer to desktop**
   - Eject the drive (Files → tap eject icon) → plug into your PC → copy PNG/config.json into the BallisticTarget folders.

Notes
-----
- The HTML + manifest + service worker files already live in the drive root, so Safari can run them offline.
- If you want an online copy, host the entire folder on HTTPS—Safari will install it as a PWA.
