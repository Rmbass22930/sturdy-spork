# BallisticTarget Information Sheet

## What the colored dots mean
- Each dot on the generated target is drawn true-to-scale for its labeled distance. The 50 yd zero dot is a bold 1.5" circle for easy zeroing, while the farther yardages are smaller reference markers because you’ll simply dial to their printed MOA/click value while still aiming at the 50 yd column. Printing at 100% preserves those subtensions so your turret adjustments line up with the physical page.
- The caption under every dot shows the computed **hold/dial value in MOA** (and clicks) that keeps your point of impact centered while you keep aiming at the big 50-yard dot.
- MOA conversion: `hold (MOA) = drop (inches) ÷ [1.047 × (distance_yards ÷ 100)]`. BallisticTarget applies this automatically and lists the results on page 2 of the PDF and in the in-app table.

## Sight-in workflow
1. Zero the rifle at your chosen range (50 yd by default) before using the extended-distance dots.
2. Generate a new target with up-to-date velocity, BC, sight height, zero range, temperature, and altitude. Reprint anytime those inputs change.
3. Print on US Letter/A4 at **“actual size/100%”**. Disable any “fit to page” scaling in the print dialog.
4. After zeroing, keep aiming at the large 50 yd dot and simply dial/hold the MOA or click value listed under the distance you are checking. The vertically stacked dots are reminders of the order of yardages.
5. Record the observed impact versus the predicted MOA. If there is a consistent offset, update your ballistic profile (velocity, BC, zero) and regenerate the target before the next range trip.

## Manual input checklist
When you can’t or don’t want to use the web lookups, gather the following data so every field in the GUI has a trustworthy value:
- **Rifle make/model + barrel length:** note the exact model designation plus the real barrel length in inches (measure from bolt face to muzzle). If you have a spare upper or different contour, log each one separately.
- **Twist rate:** record it as a ratio (e.g., `1:8`). If the barrel stamp is unreadable, run a cleaning rod down the barrel and mark a full rotation to calculate the twist manually.
- **Ammunition description:** include manufacturer, product line, cartridge, bullet weight, and any lot-specific notes (e.g., “Hornady Precision Hunter 6.5 CM 143gr ELD-X, Lot 321045”).
- **Muzzle velocity:** chronograph at least a 10-shot string and average the result. Enter the value in feet per second; if you swap lots, re-measure instead of copying the box flap.
- **Ballistic coefficient (G1):** pull it from the projectile maker’s data sheet or the ammo manufacturer’s published spec. If both G1 and G7 are provided, convert or pick G1 for the current app.
- **Sight height:** measure from the center of the bore to the center of the optic. Calipers across the objective bell or mount plus tube radius work well; the Estimate Sight Height wizard can still fetch catalog numbers, but you can now overwrite it with your measured total.
- **Zero range:** confirm the distance you used to zero, even if it’s not 50 yards. Enter the exact yardage (e.g., `36`, `100`, `200`).
- **Environmentals:** capture temperature (°F), station pressure or altitude (ft), and wind (speed, direction, gust). If you’re shooting a different day than you measured, log the expected values before printing.
- **Wind inputs:** note steady wind, gust, and the direction **from which** it blows (degrees). Use 0° = due north, 90° = east, etc.

### Estimating sight height
- Click **Estimate Sight Height** in the desktop app to launch the guided wizard.  
- Pick your scope manufacturer/model to pull the latest rail-to-center numbers directly from the maker’s catalog.  
- If the scope is uncommon, enter a custom description and the wizard will estimate center height from the objective diameter or let you type an exact number.  
- Combine that with a preset rifle platform (flat-top AR, bolt gun, etc.) or type your measured base offset—no need to remember tape measurements between sessions.

Once you know the true rail-to-optic center height of your setup, save it as a preset so every new target reflects the rifle you brought to the line. If you already run a Burris AR-P.E.P.R. quick-detach mount (the 30 mm model sits about 1.50" over the rail and uses dual throw levers), enter that value so your drops stay tied to the mount you leave on the gun.citeturn4search0

#### Base, ring, and quick-detach options
Use the catalog drop-downs or type these published data points when you need to hand-enter a sight height for similar hardware:
- **American Defense MFG, LLC** – AD-RECON mounts pair the Auto-Lock lever with a 1.47" rail-to-centerline, while the taller AD-RECON-M stretches that to about 1.64" for heads-up AR work.citeturn1search0turn2search0
- **Burris** – AR-P.E.P.R. QD variants provide 1" and 30 mm rings, a 2" forward offset, and tool-free throw levers while holding a 1.50" rail-to-center height.citeturn3search0
- **Contessa USA** – Picatinny quick-release bases are machined in steel/Ergal and publish a 29 mm (1.14") center height on the 34 mm medium mount so you can log the exact number.citeturn3search0
- **Warne Scope Mounts** – QD X-SKEL cantilever mounts use dual throw levers, steel cross bolts, and a 1.43" centerline (with super-high 1.90" variants) for repeatable LPVO swaps.citeturn5search0
- **Alaska Arms LLC** – The CZ-series quick-detach rings show a 0.450" saddle height, making it easy to calculate total center height once you add the tube radius, and both cam levers flip free without tools.citeturn6search0
- **ATN Corp** – The 30 mm quick-detach cantilever mount lets X-Sight/ThOR users swap rifles without re-zeroing, and the Bobro-built dual-lever version sits roughly 1.50" over the rail.citeturn7search0turn10search0
- **Leupold** – Mark IMS cantilever bases clamp to Picatinny rails, push the scope forward, and set the optic centerline at 1.5" to match AR sight towers.citeturn8search0
- **Vortex Optics** – The Precision Quick-Release Extended Cantilever mount uses dual locking levers, a 2" offset, and a 1.45" center height for AR-pattern rifles.citeturn9search0
- **Bobro Engineering** – BLAC dual-lever mounts self-adjust to any in-spec rail and keep a 1.5" centerline, so recon optics return to zero even after frequent swaps.citeturn10search0
- **Midwest Industries** – One-piece QD mounts cover both 1.50" standard and 1.93" high centerline options with Elite Defense throw levers and titanium cross bolts for repeatability.citeturn11search0
- **EGW (Evolution Gun Works)** – Serialized HD/Keystone ring sets list a 1.275" center height in the 30 mm size and use oversized crossbolts to lock down on your rail.citeturn12search0
- **Weaver** – The Tactical 6-Hole XX-High 1" rings show a 0.64" base-to-bottom dimension, which pencils out to ≈1.14" to the bore center once you add the tube radius, perfect for traditional hunting rifles you still want to index.citeturn13search0

## Mission Planner + Geo automation
- **Save missions right from Environmentals + Geo.** After pasting your Point A/B pins and sampling weather, click **Save Mission Preset…** to capture the lat/lon, yardage, bearing, and averaged environmentals in `missions.json`. No more overwriting `config.json` just to keep a second firing position.
- **Launch Tools → Mission Planner** in the main GUI to review every preset, double-click to apply it, or delete stale entries before a range trip. Applying a mission updates the USB-friendly `config.json` *and* pushes the stored temperature/altitude/wind back into the main inputs in one click.
- **API health appears on the right rail.** The new “Data Feeds + Telemetry” panel polls Open-Meteo, MET Norway, the elevation endpoint, and the mapping service every five minutes. You’ll see `[OK]`/`[!!]` badges plus latency so you know when cached weather will be used.
- **Offline-friendly weather sampling.** When those feeds fail, the GUI now falls back to the last known samples (timestamped in minutes) instead of leaving the fields blank, so you can keep printing targets on a disconnected laptop.
- **Telemetry opt-in is transparent.** Check the box in the same panel to write anonymized shot contexts (hashed geo buckets, zero distance, slope, etc.) to `logs/telemetry.jsonl`. Leave it unchecked if you prefer purely local runs; the preference is stored in `preferences.json`.

## Extension sheets for large holds
- If additional yardages extend beyond the first page, BallisticTarget offers an **Extension Alignment Sheet**. Print it, slide it under the main target, and line up the gray **ALIGN** hashes (bottom of page one, top of the extension) before taping.
- Keep every intermediate extension sheet in the stack even if it does not contain a dot; it maintains the physical spacing for any further add-on sheets.
- Use the **Second Page Info** button to see which distances require the alignment sheet and where the PDF was saved. It updates after every Generate run and reflects whether you skipped the extra sheet or printed it.

## Using the ballistic table (PDF page 2 / iOS table)
- Columns now list **Drop (in)** and **Drop (MOA)** side by side so you can translate between linear inches and angular adjustments quickly.
- The table also includes muzzle velocity at range, time of flight, and launch angle so you can cross-check with other ballistic solvers.
- The “Per-distance quick reference” list restates the required MOA for each dot, making it easy to copy into a dope card or turret tape.

## Tips for stretching to longer ranges
- After confirming 100 and 200 yd dots, move to 300 and 400 yd lines. Their larger MOA footprints make small groups easier to center even when mirage or wind increases.
- If you run a different scope unit (MRAD), convert the MOA values shown on page 2: `MRAD = MOA ÷ 3.437`.
- Reconfirm every time you change ammunition lots, suppressor setups, or environmental conditions outside roughly ±15 °F or ±2,000 ft from the printed data.
