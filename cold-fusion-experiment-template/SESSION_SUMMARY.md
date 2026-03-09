# Session Summary

- **Date:** 2026-02-27  **Workspace:** `J:\gdrive\BallisticTarget\src`

## Highlights
- Stood up `cold-fusion-experiment-template` with docs (README, templates, first run logs) plus integrity tracking via `SHA256SUMS.txt`.
- Delivered full simulation toolchain (scenario runner sources, JSON packs, build script, runnable `pyz`, and reporting notebooks).
- Added advanced analysis sweeps (`theory_*`, `threshold_*`, `advanced_tests`, `survivor_analysis`) with paired result write-ups.
- Created one-click helper scripts for printing/sharing reports.
- Tidied Python environment for the session (PATH cleanup, confirmed `python`/`py` both map to 3.14.3).

## Scenario Evaluator Policy (current)
1. Only “Net energy gain” scenarios can pass.
2. Signal-to-noise ratio must be ≥ 50.
3. Observed output must exceed `min_margin * 4` and be ≥ 12 W.
4. Nuclear evidence plus independent replication are both mandatory.
5. Public-claim gate remains tied to replication clearance.

## Test Outcomes
- 15-scenario fixed pack: all rejected under the strict policy.
- 720-scenario sweep: 0 positives.
- Additional conservative variants: 0 positives.

## Practical Energy Guidance
- Residential-scale nuclear (~27 kW) remains non-viable legally and technically.
- Recommended path: solar PV + battery + load management sized roughly at 15‑30 kW PV, 40‑80 kWh storage, 15‑20 kW inverter for a home running a 5-ton heat pump (fine-tune with actual usage data).

## Data Needed Next
1. Monthly utility kWh history.
2. Whether full-home or critical-load backup is required.
3. Desired outage runtime in hours.
4. Project location/state for solar insolation and permitting context.
