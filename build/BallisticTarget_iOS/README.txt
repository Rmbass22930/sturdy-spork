BallisticTarget iOS Companion Package
====================================

Included files:
- BallisticTarget_iOS.html (target builder)
- EnvironmentalsGeo_iOS.html (environment capture)
- ballistictarget-manifest.json + bt-service-worker.js + icons/ (PWA support)
- docs/*.md instructions

Usage (Files/Safari):
1. Copy these files to iCloud Drive or a portable SSD.
2. On iPad, open Files → locate the HTML → Share → Open in Safari. Tap “Add to Home Screen” for an app icon.
3. If hosting on HTTPS, upload the entire folder (including manifest, service worker, icons). Safari will cache the app for offline use.
4. Use the Environmentals tool to export config.json; drop it next to BallisticTargetGUI.exe on desktop before generating new targets.
