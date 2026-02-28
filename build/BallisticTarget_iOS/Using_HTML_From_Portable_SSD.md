Using BallisticTarget HTML From a Portable SSD on iPad
====================================================

What you need
-------------
1. A portable SSD/USB drive formatted as exFAT or APFS (iPadOS can read those).
2. A USB‑C cable or the Apple USB‑C to USB adapter (Lightning iPads need the camera connection kit + power).
3. The BallisticTarget companion HTML files (e.g., BallisticTarget_iOS.html, EnvironmentalsGeo_iOS.html) copied onto the drive.

Steps
-----
1. Connect the SSD to the iPad.
2. Open the **Files** app → tap **Browse** → under **Locations** choose the SSD (it appears with its volume name).
3. Navigate to the folder containing the HTML files.
4. Tap an HTML file (ex: BallisticTarget_iOS.html). Files will show a quick preview; to run it in Safari:
   - Tap the **Share** icon (square with arrow).
   - Choose **Open in Safari**. Safari will load the file directly from the SSD.
5. Once in Safari, the BallisticTarget tool runs offline. Tap the Share icon → **Add to Home Screen** if you want an app-like icon.
6. Any PNG/JSON you export can be saved back to the SSD:
   - After tapping **Download** inside Safari, open **Downloads** (top-right icon) → choose **Save to Files** → pick the SSD as the destination.
   - For config.json emailed/AirDropped back to desktop, place it in the SSD’s BallisticTarget folder for easy transfer later.

Tips
----
- Keep the SSD plugged in while using the HTML in Safari; if you disconnect, Safari may lose access to the file. If you want to run it without the drive, copy the HTML into iCloud Drive or “On My iPad” first.
- If you frequently run from the SSD, create a dedicated folder (e.g., /BallisticTargetMobile) so you know where to save the generated PNG/config files.
- Remember to safely eject the drive (tap the eject icon next to it in Files) before unplugging.

Security
--------
- The HTML/JS files run entirely locally—no network access unless you fetch weather data.
- Because you’re opening static files in Safari, iPadOS treats them like any other document; there’s no “installation” prompt or security warning.

