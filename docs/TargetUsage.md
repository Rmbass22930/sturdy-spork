# BallisticTarget Information Sheet

## What the colored dots mean
- Each dot on the generated target is drawn to a **true 1.00 MOA diameter** for its labeled distance (e.g., the 400 yd dot is 4.19 in across, the 50 yd dot is 0.52 in). Printing at 100% scale keeps those subtensions accurate.
- The caption under every dot shows the computed **hold/dial value in MOA** that keeps your point of impact centered when you aim at that dot from the matching distance.
- MOA conversion: `hold (MOA) = drop (inches) ÷ [1.047 × (distance_yards ÷ 100)]`. BallisticTarget applies this automatically and lists the results on page 2 of the PDF and in the in-app table.

## Sight-in workflow
1. Zero the rifle at your chosen range (50 yd by default) before using the extended-distance dots.
2. Generate a new target with up-to-date velocity, BC, sight height, zero range, temperature, and altitude. Reprint anytime those inputs change.
3. Print on US Letter/A4 at **“actual size/100%”**. Disable any “fit to page” scaling in the print dialog.
4. At the longer range you want to confirm (100–400 yd), dial or hold the MOA displayed under that color-coded dot, aim at the dot, and fire a group. Your impacts should land in the center crosshair if the ballistic inputs match reality.
5. Record the observed impact versus the predicted MOA. If there is a consistent offset, update your ballistic profile (velocity, BC, zero) and regenerate the target.

## Using the ballistic table (PDF page 2 / iOS table)
- Columns now list **Drop (in)** and **Drop (MOA)** side by side so you can translate between linear inches and angular adjustments quickly.
- The table also includes muzzle velocity at range, time of flight, and launch angle so you can cross-check with other ballistic solvers.
- The “Per-distance quick reference” list restates the required MOA for each dot, making it easy to copy into a dope card or turret tape.

## Tips for stretching to longer ranges
- After confirming 100 and 200 yd dots, move to 300 and 400 yd lines. Their larger MOA footprints make small groups easier to center even when mirage or wind increases.
- If you run a different scope unit (MRAD), convert the MOA values shown on page 2: `MRAD = MOA ÷ 3.437`.
- Reconfirm every time you change ammunition lots, suppressor setups, or environmental conditions outside roughly ±15 °F or ±2,000 ft from the printed data.
