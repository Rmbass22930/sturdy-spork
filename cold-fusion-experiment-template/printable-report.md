# Cold Fusion Theory Evaluation Report

Date: 2026-02-27  
Project: `cold-fusion-experiment-template`

## Executive Summary

This report documents a fail-closed theory evaluation framework designed to reject weak or ambiguous results.

Final outcome under ultra-hard criteria: **0 passing positive scenarios**.

## Final Acceptance Policy (Ultra-Hard)

A scenario is allowed to end as `Replicated positive` only if all conditions are true:

1. Claim class is `Net energy gain`.
2. Signal-to-noise ratio (SNR) is at least `50`.
3. Observed excess is at least `min_margin * 4`.
4. Observed excess is at least `12.0 W` absolute minimum.
5. Nuclear evidence gate passes.
6. Independent replication gate passes.
7. Public claim gate passes (locked to independent replication).

If any gate fails, status is `Negative` (or `Inconclusive` only where explicitly allowed by logic).

## Scenario Set and Method

- Scenario universe: `720` generated combinations.
- Core dimensions swept:
1. Claim class (`Artifact check`, `Rate enhancement`, `Excess heat`, `Net energy gain`)
2. Excess power levels
3. Measurement uncertainty levels
4. Margin thresholds
5. Nuclear evidence present/absent
6. Independent replication true/false
- Additional analyses:
1. Perturbation robustness (small measurement shifts)
2. Gate ablation (effect of removing individual gates)
3. Strictness ladder and survivor analysis

## Key Results

### Fixed Scenario Pack (15 scenarios)

- Result: `15/15 Negative`
- File: `scenario-results.md`

### Advanced Sweep (720 scenarios)

- Strict baseline (`SNR >= 50`, margin `x4`, min excess `12 W`):
1. Negative: `720`
2. Inconclusive: `0`
3. Replicated positive: `0`

- Conservative mode (`SNR >= 60`, margin `x5`):
1. Negative: `720`
2. Inconclusive: `0`
3. Replicated positive: `0`

- Positive strictness ladder:
1. `SNR 50, margin x4`: `0`
2. `SNR 60, margin x5`: `0`
3. `SNR 70, margin x5`: `0`
4. `SNR 80, margin x6`: `0`
5. `SNR 100, margin x8`: `0`

## Interpretation

The current framework is intentionally conservative and behaves as designed:

1. It blocks weak and borderline cases.
2. It prevents claim classes outside `Net energy gain` from passing.
3. It produces zero positive outcomes across all tested synthetic scenarios under ultra-hard gates.

## Files Included in Evidence Package

1. `scenario_runner.py` (final gate logic)
2. `scenarios.json` (fixed scenario pack)
3. `scenario-results.md`
4. `advanced_tests.py`
5. `advanced-tests-results.md`
6. `theory_sweep.py`
7. `theory-sweep-results.md`
8. `threshold_sweep.py`
9. `threshold-sweep-results.md`
10. `survivor_analysis.py`
11. `survivor-analysis-results.md`

## Sign-off

Analyst: ____________________  
Reviewer: ____________________  
Date: ____________________
