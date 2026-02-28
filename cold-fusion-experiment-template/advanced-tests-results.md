# Advanced Theory Tests

- Scenario universe: 720
- Baseline strict mode: margin x4 + SNR >= 50 + nuclear + replication + claim eligibility

## Perturbation Robustness

| Perturbation | Negative | Inconclusive | Replicated positive | Positive rate |
|---|---:|---:|---:|---:|
| obs x0.90, unc x1.00 | 720 | 0 | 0 | 0.000 |
| obs x0.95, unc x1.00 | 720 | 0 | 0 | 0.000 |
| obs x1.00, unc x1.00 | 720 | 0 | 0 | 0.000 |
| obs x1.05, unc x1.00 | 720 | 0 | 0 | 0.000 |
| obs x1.10, unc x1.00 | 720 | 0 | 0 | 0.000 |
| obs x1.00, unc x1.10 | 720 | 0 | 0 | 0.000 |
| obs x1.00, unc x1.20 | 720 | 0 | 0 | 0.000 |

## Gate Ablation

| Configuration | Negative | Inconclusive | Replicated positive |
|---|---:|---:|---:|
| All gates on | 720 | 0 | 0 |
| No SNR gate | 702 | 9 | 9 |
| No replication gate | 720 | 0 | 0 |
| No nuclear gate | 720 | 0 | 0 |
| No margin gate | 720 | 0 | 0 |

## Conservative Mode Comparison

- Conservative mode: SNR >= 60 and margin multiplied by 5

| Mode | Negative | Inconclusive | Replicated positive |
|---|---:|---:|---:|
| Strict baseline (SNR >= 50) | 720 | 0 | 0 |
| Worst-case conservative | 720 | 0 | 0 |

## Positive Strictness Sweep

| SNR Threshold | Margin Scale | Replicated positive |
|---:|---:|---:|
| 50.0 | 4.0 | 0 |
| 60.0 | 5.0 | 0 |
| 70.0 | 5.0 | 0 |
| 80.0 | 6.0 | 0 |
| 100.0 | 8.0 | 0 |

## Readout

- Perturbation table shows sensitivity to modest measurement shifts.
- Ablation table shows which gates are most constraining in your current logic.
