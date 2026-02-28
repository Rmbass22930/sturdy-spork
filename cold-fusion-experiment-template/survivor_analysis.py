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


def classify_conservative(s: dict, snr_threshold: float, margin_scale: float) -> str:
    p = dict(s)
    p["min_margin_w"] = float(s["min_margin_w"]) * margin_scale
    r = evaluate_scenario(p)
    if not (r.gate_signal_margin and r.gate_nuclear_evidence and r.snr >= snr_threshold):
        return "Negative"
    if r.gate_replication:
        return "Replicated positive"
    return "Inconclusive"


def main() -> None:
    root = Path(__file__).resolve().parent
    out_path = root / "survivor-analysis-results.md"
    scenarios = build_scenarios()

    ladder = [
        (10.0, 1.5),
        (12.0, 1.5),
        (15.0, 2.0),
        (20.0, 2.0),
        (25.0, 2.5),
    ]
    classes = ["Artifact check", "Rate enhancement", "Excess heat", "Net energy gain"]

    lines = []
    lines.append("# Survivor Analysis")
    lines.append("")
    lines.append(f"- Scenario universe: {len(scenarios)}")
    lines.append("")
    lines.append("## Ultra-Strict Ladder")
    lines.append("")
    lines.append("| SNR Threshold | Margin Scale | Replicated positive |")
    lines.append("|---:|---:|---:|")

    for snr_t, margin_scale in ladder:
        pos = sum(
            1
            for s in scenarios
            if classify_conservative(s, snr_threshold=snr_t, margin_scale=margin_scale)
            == "Replicated positive"
        )
        lines.append(f"| {snr_t:.1f} | {margin_scale:.1f} | {pos} |")

    lines.append("")
    lines.append("## Survivors by Claim Class")
    lines.append("")
    lines.append("| SNR Threshold | Margin Scale | Artifact check | Rate enhancement | Excess heat | Net energy gain |")
    lines.append("|---:|---:|---:|---:|---:|---:|")

    for snr_t, margin_scale in ladder:
        counts = []
        for cls in classes:
            c = sum(
                1
                for s in scenarios
                if s["claim_class"] == cls
                and classify_conservative(s, snr_threshold=snr_t, margin_scale=margin_scale)
                == "Replicated positive"
            )
            counts.append(c)
        lines.append(
            f"| {snr_t:.1f} | {margin_scale:.1f} | {counts[0]} | {counts[1]} | {counts[2]} | {counts[3]} |"
        )

    toughest_snr, toughest_margin = ladder[-1]
    toughest = []
    for s in scenarios:
        if classify_conservative(s, snr_threshold=toughest_snr, margin_scale=toughest_margin) == "Replicated positive":
            r = evaluate_scenario(
                {
                    **s,
                    "min_margin_w": float(s["min_margin_w"]) * toughest_margin,
                }
            )
            toughest.append((s, r.snr))
    toughest.sort(key=lambda x: x[1], reverse=True)

    lines.append("")
    lines.append(f"## Survivors at Toughest Level (SNR >= {toughest_snr:g}, margin x{toughest_margin:g})")
    lines.append("")
    lines.append("| Scenario | Claim Class | Excess W | Uncertainty W | Scaled Margin W | SNR |")
    lines.append("|---|---|---:|---:|---:|---:|")
    for s, snr in toughest[:20]:
        lines.append(
            f"| {s['name']} | {s['claim_class']} | {float(s['observed_excess_w']):.2f} | "
            f"{float(s['combined_uncertainty_w']):.2f} | {float(s['min_margin_w']) * toughest_margin:.2f} | {snr:.2f} |"
        )

    lines.append("")
    lines.append("## Readout")
    lines.append("")
    lines.append("- Surviving positives at high strictness are dominated by high excess and low uncertainty combinations.")
    lines.append("- `Excess heat` and `Net energy gain` still require nuclear evidence and replication to survive.")

    out_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"Wrote: {out_path}")


if __name__ == "__main__":
    main()
