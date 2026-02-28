import itertools
from pathlib import Path

from scenario_runner import evaluate_scenario


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


def classify(result, snr_threshold: float) -> str:
    if not (result.gate_signal_margin and result.gate_nuclear_evidence and result.snr >= snr_threshold):
        return "Negative"
    if result.gate_replication:
        return "Replicated positive"
    return "Inconclusive"


def main() -> None:
    root = Path(__file__).resolve().parent
    out_path = root / "threshold-sweep-results.md"
    scenarios = build_scenarios()
    results = [evaluate_scenario(s) for s in scenarios]
    thresholds = [2.0, 3.0, 5.0, 8.0, 10.0]
    classes = ["Artifact check", "Rate enhancement", "Excess heat", "Net energy gain"]

    lines = []
    lines.append("# Threshold Sweep Results")
    lines.append("")
    lines.append(f"- Scenario universe: {len(results)}")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append("| SNR Threshold | Negative | Inconclusive | Replicated positive |")
    lines.append("|---:|---:|---:|---:|")

    for t in thresholds:
        statuses = [classify(r, t) for r in results]
        neg = sum(1 for s in statuses if s == "Negative")
        inc = sum(1 for s in statuses if s == "Inconclusive")
        pos = sum(1 for s in statuses if s == "Replicated positive")
        lines.append(f"| {t:.1f} | {neg} | {inc} | {pos} |")

    lines.append("")
    lines.append("## By Claim Class")
    lines.append("")

    for cls in classes:
        cls_results = [r for r in results if r.claim_class == cls]
        lines.append(f"### {cls}")
        lines.append("")
        lines.append("| SNR Threshold | Negative | Inconclusive | Replicated positive |")
        lines.append("|---:|---:|---:|---:|")
        for t in thresholds:
            statuses = [classify(r, t) for r in cls_results]
            neg = sum(1 for s in statuses if s == "Negative")
            inc = sum(1 for s in statuses if s == "Inconclusive")
            pos = sum(1 for s in statuses if s == "Replicated positive")
            lines.append(f"| {t:.1f} | {neg} | {inc} | {pos} |")
        lines.append("")

    lines.append("## Interpretation")
    lines.append("")
    lines.append("- Higher SNR thresholds shift cases from `Inconclusive`/`Replicated positive` to `Negative`.")
    lines.append("- `Excess heat` and `Net energy gain` remain harder to pass due to nuclear-evidence requirement.")

    out_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
