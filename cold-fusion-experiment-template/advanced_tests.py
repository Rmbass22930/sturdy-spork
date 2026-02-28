import itertools
from pathlib import Path

from scenario_runner import evaluate_scenario

BASELINE_SNR = 50.0
BASELINE_MARGIN_SCALE = 4.0
CONSERVATIVE_SNR = 60.0
CONSERVATIVE_MARGIN_SCALE = 5.0


def build_scenarios() -> list[dict]:
    claim_classes = ["Artifact check", "Rate enhancement", "Excess heat", "Net energy gain"]
    observed_values = [0.4, 1.0, 2.0, 4.0, 8.0]
    uncertainty_values = [0.2, 0.5, 1.0]
    margin_values = [0.7, 1.5, 3.0]
    nuclear_flags = [False, True]
    replication_flags = [False, True]

    scenarios = []
    idx = 1
    for claim_class, observed, uncertainty, margin, nuclear, replication in itertools.product(
        claim_classes,
        observed_values,
        uncertainty_values,
        margin_values,
        nuclear_flags,
        replication_flags,
    ):
        scenarios.append(
            {
                "name": f"T{idx:04d}",
                "claim_class": claim_class,
                "observed_excess_w": observed,
                "combined_uncertainty_w": uncertainty,
                "min_margin_w": margin,
                "nuclear_evidence_present": nuclear,
                "independent_replication": replication,
            }
        )
        idx += 1
    return scenarios


def baseline_status(s: dict, snr_threshold: float = BASELINE_SNR) -> str:
    p = dict(s)
    p["min_margin_w"] = float(s["min_margin_w"]) * BASELINE_MARGIN_SCALE
    r = evaluate_scenario(p)
    if not (r.gate_signal_margin and r.gate_nuclear_evidence and r.gate_claim_eligible and r.snr >= snr_threshold):
        return "Negative"
    if r.gate_replication:
        return "Replicated positive"
    return "Inconclusive"


def conservative_status(s: dict, snr_threshold: float = CONSERVATIVE_SNR, margin_scale: float = CONSERVATIVE_MARGIN_SCALE) -> str:
    p = dict(s)
    p["min_margin_w"] = float(s["min_margin_w"]) * margin_scale
    r = evaluate_scenario(p)
    if not (r.gate_signal_margin and r.gate_nuclear_evidence and r.gate_claim_eligible and r.snr >= snr_threshold):
        return "Negative"
    if r.gate_replication:
        return "Replicated positive"
    return "Inconclusive"


def perturbation_robustness(scenarios: list[dict]) -> list[tuple[str, int, int, int, float]]:
    # Deterministic perturbations to test stability without randomness.
    perturbations = [
        (0.90, 1.00),  # lower observed by 10%
        (0.95, 1.00),
        (1.00, 1.00),
        (1.05, 1.00),
        (1.10, 1.00),  # higher observed by 10%
        (1.00, 1.10),  # uncertainty +10%
        (1.00, 1.20),  # uncertainty +20%
    ]
    rows = []
    for obs_scale, unc_scale in perturbations:
        neg = inc = pos = 0
        for s in scenarios:
            p = dict(s)
            p["observed_excess_w"] = round(float(s["observed_excess_w"]) * obs_scale, 6)
            p["combined_uncertainty_w"] = round(float(s["combined_uncertainty_w"]) * unc_scale, 6)
            status = baseline_status(p, snr_threshold=BASELINE_SNR)
            if status == "Negative":
                neg += 1
            elif status == "Inconclusive":
                inc += 1
            else:
                pos += 1
        pos_rate = pos / len(scenarios)
        label = f"obs x{obs_scale:.2f}, unc x{unc_scale:.2f}"
        rows.append((label, neg, inc, pos, pos_rate))
    return rows


def gate_ablation(scenarios: list[dict]) -> list[tuple[str, int, int, int]]:
    def classify(s: dict, use_margin: bool, use_nuclear: bool, use_replication: bool, use_snr: bool) -> str:
        r = evaluate_scenario(s)
        pass_margin = r.gate_signal_margin if use_margin else True
        pass_nuclear = r.gate_nuclear_evidence if use_nuclear else True
        pass_snr = r.snr >= BASELINE_SNR if use_snr else True
        pass_claim = r.gate_claim_eligible
        pass_repl = r.gate_replication if use_replication else True
        if not (pass_margin and pass_nuclear and pass_snr and pass_claim):
            return "Negative"
        if pass_repl:
            return "Replicated positive"
        return "Inconclusive"

    configs = [
        ("All gates on", True, True, True, True),
        ("No SNR gate", True, True, True, False),
        ("No replication gate", True, True, False, True),
        ("No nuclear gate", True, False, True, True),
        ("No margin gate", False, True, True, True),
    ]

    rows = []
    for label, g_margin, g_nuclear, g_repl, g_snr in configs:
        neg = inc = pos = 0
        for s in scenarios:
            status = classify(s, g_margin, g_nuclear, g_repl, g_snr)
            if status == "Negative":
                neg += 1
            elif status == "Inconclusive":
                inc += 1
            else:
                pos += 1
        rows.append((label, neg, inc, pos))
    return rows


def conservative_vs_strict(scenarios: list[dict]) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
    strict_counts = [0, 0, 0]  # neg, inc, pos
    conservative_counts = [0, 0, 0]

    for s in scenarios:
        strict = baseline_status(s, snr_threshold=BASELINE_SNR)
        cons = conservative_status(s, snr_threshold=CONSERVATIVE_SNR, margin_scale=CONSERVATIVE_MARGIN_SCALE)

        if strict == "Negative":
            strict_counts[0] += 1
        elif strict == "Inconclusive":
            strict_counts[1] += 1
        else:
            strict_counts[2] += 1

        if cons == "Negative":
            conservative_counts[0] += 1
        elif cons == "Inconclusive":
            conservative_counts[1] += 1
        else:
            conservative_counts[2] += 1

    return (strict_counts[0], strict_counts[1], strict_counts[2]), (
        conservative_counts[0],
        conservative_counts[1],
        conservative_counts[2],
    )


def positive_strictness_sweep(scenarios: list[dict]) -> list[tuple[float, float, int]]:
    configs = [
        (50.0, 4.0),
        (60.0, 5.0),
        (70.0, 5.0),
        (80.0, 6.0),
        (100.0, 8.0),
    ]
    rows = []
    for snr_t, margin_scale in configs:
        positives = 0
        for s in scenarios:
            status = conservative_status(s, snr_threshold=snr_t, margin_scale=margin_scale)
            if status == "Replicated positive":
                positives += 1
        rows.append((snr_t, margin_scale, positives))
    return rows


def main() -> None:
    root = Path(__file__).resolve().parent
    out_path = root / "advanced-tests-results.md"
    scenarios = build_scenarios()

    robust_rows = perturbation_robustness(scenarios)
    ablation_rows = gate_ablation(scenarios)
    strict_counts, conservative_counts = conservative_vs_strict(scenarios)
    strictness_rows = positive_strictness_sweep(scenarios)

    lines = []
    lines.append("# Advanced Theory Tests")
    lines.append("")
    lines.append(f"- Scenario universe: {len(scenarios)}")
    lines.append(
        f"- Baseline strict mode: margin x{BASELINE_MARGIN_SCALE:g} + SNR >= {BASELINE_SNR:g} + nuclear + replication + claim eligibility"
    )
    lines.append("")
    lines.append("## Perturbation Robustness")
    lines.append("")
    lines.append("| Perturbation | Negative | Inconclusive | Replicated positive | Positive rate |")
    lines.append("|---|---:|---:|---:|---:|")
    for label, neg, inc, pos, pos_rate in robust_rows:
        lines.append(f"| {label} | {neg} | {inc} | {pos} | {pos_rate:.3f} |")

    lines.append("")
    lines.append("## Gate Ablation")
    lines.append("")
    lines.append("| Configuration | Negative | Inconclusive | Replicated positive |")
    lines.append("|---|---:|---:|---:|")
    for label, neg, inc, pos in ablation_rows:
        lines.append(f"| {label} | {neg} | {inc} | {pos} |")

    lines.append("")
    lines.append("## Conservative Mode Comparison")
    lines.append("")
    lines.append(f"- Conservative mode: SNR >= {CONSERVATIVE_SNR:g} and margin multiplied by {CONSERVATIVE_MARGIN_SCALE:g}")
    lines.append("")
    lines.append("| Mode | Negative | Inconclusive | Replicated positive |")
    lines.append("|---|---:|---:|---:|")
    lines.append(f"| Strict baseline (SNR >= {BASELINE_SNR:g}) | {strict_counts[0]} | {strict_counts[1]} | {strict_counts[2]} |")
    lines.append(f"| Worst-case conservative | {conservative_counts[0]} | {conservative_counts[1]} | {conservative_counts[2]} |")

    lines.append("")
    lines.append("## Positive Strictness Sweep")
    lines.append("")
    lines.append("| SNR Threshold | Margin Scale | Replicated positive |")
    lines.append("|---:|---:|---:|")
    for snr_t, margin_scale, positives in strictness_rows:
        lines.append(f"| {snr_t:.1f} | {margin_scale:.1f} | {positives} |")

    lines.append("")
    lines.append("## Readout")
    lines.append("")
    lines.append("- Perturbation table shows sensitivity to modest measurement shifts.")
    lines.append("- Ablation table shows which gates are most constraining in your current logic.")

    out_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
