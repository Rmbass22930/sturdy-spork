# Theory Sweep Results

- Total scenarios: 720
- Baseline Negative: 396
- Baseline Inconclusive: 162
- Baseline Replicated positive: 162
- Strict (SNR >= 5) Negative: 504
- Strict (SNR >= 5) Inconclusive: 108
- Strict (SNR >= 5) Replicated positive: 108

## Baseline vs Strict

| Mode | Negative | Inconclusive | Replicated positive |
|---|---:|---:|---:|
| Baseline | 396 | 162 | 162 |
| Strict (SNR >= 5) | 504 | 108 | 108 |

## By Claim Class

| Claim Class | Total | Baseline Negative | Baseline Inconclusive | Baseline Replicated positive | Strict Negative | Strict Inconclusive | Strict Replicated positive |
|---|---:|---:|---:|---:|
| Artifact check | 180 | 72 | 54 | 54 | 108 | 36 | 36 |
| Rate enhancement | 180 | 72 | 54 | 54 | 108 | 36 | 36 |
| Excess heat | 180 | 126 | 27 | 27 | 144 | 18 | 18 |
| Net energy gain | 180 | 126 | 27 | 27 | 144 | 18 | 18 |

## Top Positive Scenarios by SNR

| Scenario | Claim Class | Excess W | Uncertainty W | Margin W | SNR |
|---|---|---:|---:|---:|---:|
| T0146 | Artifact check | 8.00 | 0.20 | 0.70 | 40.00 |
| T0148 | Artifact check | 8.00 | 0.20 | 0.70 | 40.00 |
| T0150 | Artifact check | 8.00 | 0.20 | 1.50 | 40.00 |
| T0152 | Artifact check | 8.00 | 0.20 | 1.50 | 40.00 |
| T0154 | Artifact check | 8.00 | 0.20 | 3.00 | 40.00 |
| T0156 | Artifact check | 8.00 | 0.20 | 3.00 | 40.00 |
| T0326 | Rate enhancement | 8.00 | 0.20 | 0.70 | 40.00 |
| T0328 | Rate enhancement | 8.00 | 0.20 | 0.70 | 40.00 |
| T0330 | Rate enhancement | 8.00 | 0.20 | 1.50 | 40.00 |
| T0332 | Rate enhancement | 8.00 | 0.20 | 1.50 | 40.00 |
| T0334 | Rate enhancement | 8.00 | 0.20 | 3.00 | 40.00 |
| T0336 | Rate enhancement | 8.00 | 0.20 | 3.00 | 40.00 |
| T0508 | Excess heat | 8.00 | 0.20 | 0.70 | 40.00 |
| T0512 | Excess heat | 8.00 | 0.20 | 1.50 | 40.00 |
| T0516 | Excess heat | 8.00 | 0.20 | 3.00 | 40.00 |
| T0688 | Net energy gain | 8.00 | 0.20 | 0.70 | 40.00 |
| T0692 | Net energy gain | 8.00 | 0.20 | 1.50 | 40.00 |
| T0696 | Net energy gain | 8.00 | 0.20 | 3.00 | 40.00 |
| T0110 | Artifact check | 4.00 | 0.20 | 0.70 | 20.00 |
| T0112 | Artifact check | 4.00 | 0.20 | 0.70 | 20.00 |

## Gate Behavior

- `Public Claim Gate` only passes when independent replication is true.
- `Excess heat` and `Net energy gain` require nuclear evidence.
- `Replicated positive` requires signal margin pass + required nuclear evidence + replication.
- Strict mode additionally requires SNR >= 5.
