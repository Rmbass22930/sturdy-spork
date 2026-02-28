# Environmentals + Geo on iPad/iPhone

Use the `EnvironmentalsGeo_iOS.html` companion to capture weather/geo data on mobile Safari and export the same `config.json` the desktop GUI expects.

## Steps
1. Copy `EnvironmentalsGeo_iOS.html` to iCloud Drive (or host it on an internal web server) and open it in Safari on the iPad/iPhone.
2. Fill in the fields or tap **Use Phone GPS** to capture coordinates.
3. Paste a Google/Apple Maps link and tap **Extract Lat/Lon** if you prefer sharing.
4. Tap **Fetch Weather + Altitude** to pull current temperature, wind, gust, direction, and elevation from Open‑Meteo (falls back to OpenTopoData when needed).
5. Review the JSON preview, then either:
   - **Copy JSON** (paste into `BallisticTarget/config.json`),
   - **Share/Save…** (AirDrop or email `config.json`),
   - **Download config.json** and transfer it back to the desktop folder.
6. Launch (or reload) BallisticTarget on the desktop so it picks up the new values.

Notes:
- Data is cached in `localStorage`, so values persist between sessions on the same device.
- Safari will prompt for permission when using GPS or the Share sheet.
- Disable VPN on the phone when extracting map links for best accuracy.
