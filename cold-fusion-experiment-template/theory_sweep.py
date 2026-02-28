import itertools
from pathlib import Path

from scenario_runner import evaluate_scenario

SNR_THRESHOLD = 5.0


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


def main() -> None:
    root = Path(__file__).resolve().parent
    out_path = root / "theory-sweep-results.md"
    scenarios = build_scenarios()
    results = [evaluate_scenario(s) for s in scenarios]

    def classify_strict(r) -> str:
        gate_snr = r.snr >= SNR_THRESHOLD
        if r.gate_signal_margin and r.gate_nuclear_evidence and gate_snr and r.gate_replication:
            return "Replicated positive"
        if r.gate_signal_margin and r.gate_nuclear_evidence and gate_snr:
            return "Inconclusive"
        return "Negative"

    strict_status = {r.name: classify_strict(r) for r in results}

    total = len(results)
    negative = sum(1 for r in results if r.final_status == "Negative")
    inconclusive = sum(1 for r in results if r.final_status == "Inconclusive")
    positive = sum(1 for r in results if r.final_status == "Replicated positive")
    strict_negative = sum(1 for r in results if strict_status[r.name] == "Negative")
    strict_inconclusive = sum(1 for r in results if strict_status[r.name] == "Inconclusive")
    strict_positive = sum(1 for r in results if strict_status[r.name] == "Replicated positive")

    by_class = {}
    for cls in ["Artifact check", "Rate enhancement", "Excess heat", "Net energy gain"]:
        cls_results = [r for r in results if r.claim_class == cls]
        by_class[cls] = {
            "total": len(cls_results),
            "negative": sum(1 for r in cls_results if r.final_status == "Negative"),
            "inconclusive": sum(1 for r in cls_results if r.final_status == "Inconclusive"),
            "positive": sum(1 for r in cls_results if r.final_status == "Replicated positive"),
        }

    top_positive = sorted(
        (r for r in results if r.final_status == "Replicated positive"),
        key=lambda x: x.snr,
        reverse=True,
    )[:20]

    lines = []
    lines.append("# Theory Sweep Results")
    lines.append("")
    lines.append(f"- Total scenarios: {total}")
    lines.append(f"- Baseline Negative: {negative}")
    lines.append(f"- Baseline Inconclusive: {inconclusive}")
    lines.append(f"- Baseline Replicated positive: {positive}")
    lines.append(f"- Strict (SNR >= {SNR_THRESHOLD:g}) Negative: {strict_negative}")
    lines.append(f"- Strict (SNR >= {SNR_THRESHOLD:g}) Inconclusive: {strict_inconclusive}")
    lines.append(f"- Strict (SNR >= {SNR_THRESHOLD:g}) Replicated positive: {strict_positive}")
    lines.append("")
    lines.append("## Baseline vs Strict")
    lines.append("")
    lines.append("| Mode | Negative | Inconclusive | Replicated positive |")
    lines.append("|---|---:|---:|---:|")
    lines.append(f"| Baseline | {negative} | {inconclusive} | {positive} |")
    lines.append(f"| Strict (SNR >= {SNR_THRESHOLD:g}) | {strict_negative} | {strict_inconclusive} | {strict_positive} |")
    lines.append("")
    lines.append("## By Claim Class")
    lines.append("")
    lines.append("| Claim Class | Total | Baseline Negative | Baseline Inconclusive | Baseline Replicated positive | Strict Negative | Strict Inconclusive | Strict Replicated positive |")
    lines.append("|---|---:|---:|---:|---:|")
    for cls, v in by_class.items():
        strict_cls = [r for r in results if r.claim_class == cls]
        strict_v = {
            "negative": sum(1 for r in strict_cls if strict_status[r.name] == "Negative"),
            "inconclusive": sum(1 for r in strict_cls if strict_status[r.name] == "Inconclusive"),
            "positive": sum(1 for r in strict_cls if strict_status[r.name] == "Replicated positive"),
        }
        lines.append(
            f"| {cls} | {v['total']} | {v['negative']} | {v['inconclusive']} | {v['positive']} | "
            f"{strict_v['negative']} | {strict_v['inconclusive']} | {strict_v['positive']} |"
        )

    lines.append("")
    lines.append("## Top Positive Scenarios by SNR")
    lines.append("")
    lines.append("| Scenario | Claim Class | Excess W | Uncertainty W | Margin W | SNR |")
    lines.append("|---|---|---:|---:|---:|---:|")
    for r in top_positive:
        source = next(s for s in scenarios if s["name"] == r.name)
        lines.append(
            f"| {r.name} | {r.claim_class} | {r.observed_excess_w:.2f} | "
            f"{r.combined_uncertainty_w:.2f} | {source['min_margin_w']:.2f} | {r.snr:.2f} |"
        )

    lines.append("")
    lines.append("## Gate Behavior")
    lines.append("")
    lines.append("- `Public Claim Gate` only passes when independent replication is true.")
    lines.append("- `Excess heat` and `Net energy gain` require nuclear evidence.")
    lines.append("- `Replicated positive` requires signal margin pass + required nuclear evidence + replication.")
    lines.append(f"- Strict mode additionally requires SNR >= {SNR_THRESHOLD:g}.")

    out_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
