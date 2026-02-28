# Scenario Results

| Scenario | Claim Class | Excess W | Uncertainty W | SNR | Margin Gate | SNR Gate | Nuclear Evidence | Replication | Claim Eligible | Public Claim Gate | Final Status |
|---|---|---:|---:|---:|---|---|---|---|---|---|---|
| S1_Baseline_Noise | Artifact check | 0.08 | 0.22 | 0.36 | Fail | Fail | Pass | Fail | Fail | Fail | Negative |
| S2_Small_Heat_No_Replication | Excess heat | 1.30 | 0.35 | 3.71 | Fail | Fail | Pass | Fail | Fail | Fail | Negative |
| S3_Heat_No_Nuclear | Excess heat | 2.20 | 0.40 | 5.50 | Fail | Fail | Pass | Fail | Fail | Fail | Negative |
| S4_Rate_Enhancement_Replicated | Rate enhancement | 0.90 | 0.25 | 3.60 | Fail | Fail | Pass | Pass | Fail | Pass | Negative |
| S5_Net_Energy_Claim_Replicated | Net energy gain | 5.00 | 0.80 | 6.25 | Fail | Fail | Pass | Pass | Pass | Pass | Negative |
| S6_Net_Energy_No_Replication | Net energy gain | 4.20 | 0.90 | 4.67 | Fail | Fail | Pass | Fail | Pass | Fail | Negative |
| S7_Rate_Enhancement_Weak_Margin | Rate enhancement | 0.40 | 0.20 | 2.00 | Fail | Fail | Pass | Pass | Fail | Pass | Negative |
| S8_Artifact_Replicated_Noise | Artifact check | 0.15 | 0.15 | 1.00 | Fail | Fail | Pass | Pass | Fail | Pass | Negative |
| S9_Excess_Heat_High_SNR_Replicated | Excess heat | 3.10 | 0.45 | 6.89 | Fail | Fail | Pass | Pass | Fail | Pass | Negative |
| S10_Excess_Heat_Borderline | Excess heat | 1.01 | 0.50 | 2.02 | Fail | Fail | Pass | Fail | Fail | Fail | Negative |
| S11_Net_Energy_Missing_Nuclear | Net energy gain | 6.00 | 1.00 | 6.00 | Fail | Fail | Fail | Pass | Pass | Pass | Negative |
| S12_Rate_Enhancement_Not_Replicated | Rate enhancement | 1.20 | 0.30 | 4.00 | Fail | Fail | Pass | Fail | Fail | Fail | Negative |
| S13_Artifact_False_Positive_Check | Artifact check | 0.65 | 0.25 | 2.60 | Fail | Fail | Pass | Fail | Fail | Fail | Negative |
| S14_Excess_Heat_Replicated_Low_SNR | Excess heat | 1.60 | 0.90 | 1.78 | Fail | Fail | Pass | Pass | Fail | Pass | Negative |
| S15_Net_Energy_Strong_All_Gates | Net energy gain | 8.00 | 0.70 | 11.43 | Fail | Fail | Pass | Pass | Pass | Pass | Negative |

## Notes

- Fail-closed policy: positives require margin gate, SNR gate, nuclear evidence, replication, and eligible claim class.
- Margin gate uses `observed >= min_margin * 4`.
- SNR gate uses `SNR >= 50`.
- Minimum excess gate uses `observed >= 12`.
- Only `Net energy gain` is eligible for `Replicated positive`.
