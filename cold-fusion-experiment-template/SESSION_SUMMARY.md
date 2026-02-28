# Session Summary

Date: 2026-02-27
Workspace: J:\gdrive\BallisticTarget\src

## What was done

1. Created project folder:
- `J:\gdrive\BallisticTarget\src\cold-fusion-experiment-template`

2. Added core documentation/templates:
- `README.md`
- `experiment-template.md`
- `run-001.md`
- `comparison.md`
- `printable-report.md`

3. Added integrity file:
- `SHA256SUMS.txt`

4. Added scenario tooling and builds:
- `scenario_runner.py`
- `scenarios.json`
- `scenario-results.md`
- `build.ps1`
- `run-built.cmd`
- `app\__main__.py`
- `app\scenario_runner.py`
- `dist\scenario-runner.pyz`

5. Added deeper theory testing scripts/reports:
- `theory_sweep.py`
- `theory-sweep-results.md`
- `threshold_sweep.py`
- `threshold-sweep-results.md`
- `advanced_tests.py`
- `advanced-tests-results.md`
- `survivor_analysis.py`
- `survivor-analysis-results.md`

6. Added one-click report helpers:
- `open-report-in-notepad.cmd`
- `print-report-notepad.cmd`
- `do-all-report-tasks.cmd`

7. Python/PATH maintenance performed:
- Verified `python` and `py` resolution.
- Cleaned stale/duplicate User PATH entries.
- Refreshed PATH in-session and validated:
  - `python --version` -> `Python 3.14.3`
  - `py -3 --version` -> `Python 3.14.3`

## Final strict policy state (scenario evaluator)

Current `scenario_runner.py` policy is ultra-hard and fail-closed:

1. Eligible class for positive outcome: `Net energy gain` only.
2. `SNR >= 50`.
3. `observed >= min_margin * 4`.
4. `observed >= 12.0 W` minimum excess.
5. Nuclear evidence required.
6. Independent replication required.
7. Public-claim gate tied to replication.

## Final test outcome snapshot

- Fixed 15-scenario pack: all negative under ultra-hard policy.
- Advanced 720-scenario sweep: `0` positives under ultra-hard baseline.
- Conservative stricter variants: also `0` positives.

## Practical energy conclusion discussed

- Home nuclear generator (~27 kW) is not practical/legal for residential deployment.
- Best non-nuclear, non-fuel path: solar PV + battery + load management.
- Given your 5-ton heat pump, likely planning envelope mentioned:
  - Inverter: ~15-20 kW class
  - Battery: ~40-80 kWh
  - Solar: ~15-30 kW (depends on usage/location)

## Next suggested step

Provide these to size a real home system precisely:
1. Monthly kWh usage from bill.
2. Full-home vs critical-load backup target.
3. Desired outage runtime.
4. Location/state.
