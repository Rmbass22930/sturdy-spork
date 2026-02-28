import argparse
import json
from dataclasses import dataclass
from pathlib import Path

STRICT_SNR_THRESHOLD = 50.0
STRICT_MARGIN_SCALE = 4.0
STRICT_MIN_EXCESS_W = 12.0
POSITIVE_ELIGIBLE_CLASSES = {"Net energy gain"}


@dataclass
class ScenarioResult:
    name: str
    claim_class: str
    observed_excess_w: float
    combined_uncertainty_w: float
    snr: float
    gate_signal_margin: bool
    gate_snr: bool
    gate_nuclear_evidence: bool
    gate_replication: bool
    gate_public_claim: bool
    gate_claim_eligible: bool
    final_status: str


def evaluate_scenario(s: dict) -> ScenarioResult:
    observed = float(s["observed_excess_w"])
    uncertainty = float(s["combined_uncertainty_w"])
    min_margin = float(s["min_margin_w"])
    claim_class = s["claim_class"]

    snr = observed / uncertainty if uncertainty > 0 else 0.0
    gate_signal_margin = observed >= (min_margin * STRICT_MARGIN_SCALE)
    gate_snr = snr >= STRICT_SNR_THRESHOLD

    nuclear_required = claim_class in POSITIVE_ELIGIBLE_CLASSES
    if nuclear_required:
        gate_nuclear_evidence = bool(s["nuclear_evidence_present"])
    else:
        gate_nuclear_evidence = True

    gate_replication = bool(s["independent_replication"])
    gate_public_claim = gate_replication
    gate_claim_eligible = claim_class in POSITIVE_ELIGIBLE_CLASSES

    gate_min_excess = observed >= STRICT_MIN_EXCESS_W
    base_evidence = gate_signal_margin and gate_snr and gate_nuclear_evidence and gate_min_excess

    if gate_claim_eligible and base_evidence and gate_replication and gate_public_claim:
        final_status = "Replicated positive"
    elif gate_claim_eligible and base_evidence:
        final_status = "Inconclusive"
    else:
        final_status = "Negative"

    return ScenarioResult(
        name=s["name"],
        claim_class=claim_class,
        observed_excess_w=observed,
        combined_uncertainty_w=uncertainty,
        snr=snr,
        gate_signal_margin=gate_signal_margin,
        gate_snr=gate_snr,
        gate_nuclear_evidence=gate_nuclear_evidence,
        gate_replication=gate_replication,
        gate_public_claim=gate_public_claim,
        gate_claim_eligible=gate_claim_eligible,
        final_status=final_status,
    )


def run(scenarios_path: Path, results_path: Path) -> None:
    scenarios = json.loads(scenarios_path.read_text(encoding="ascii"))
    results = [evaluate_scenario(s) for s in scenarios]

    lines = []
    lines.append("# Scenario Results")
    lines.append("")
    lines.append("| Scenario | Claim Class | Excess W | Uncertainty W | SNR | Margin Gate | SNR Gate | Nuclear Evidence | Replication | Claim Eligible | Public Claim Gate | Final Status |")
    lines.append("|---|---|---:|---:|---:|---|---|---|---|---|---|---|")

    for r in results:
        lines.append(
            f"| {r.name} | {r.claim_class} | {r.observed_excess_w:.2f} | "
            f"{r.combined_uncertainty_w:.2f} | {r.snr:.2f} | "
            f"{'Pass' if r.gate_signal_margin else 'Fail'} | "
            f"{'Pass' if r.gate_snr else 'Fail'} | "
            f"{'Pass' if r.gate_nuclear_evidence else 'Fail'} | "
            f"{'Pass' if r.gate_replication else 'Fail'} | "
            f"{'Pass' if r.gate_claim_eligible else 'Fail'} | "
            f"{'Pass' if r.gate_public_claim else 'Fail'} | {r.final_status} |"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Fail-closed policy: positives require margin gate, SNR gate, nuclear evidence, replication, and eligible claim class.")
    lines.append(f"- Margin gate uses `observed >= min_margin * {STRICT_MARGIN_SCALE:g}`.")
    lines.append(f"- SNR gate uses `SNR >= {STRICT_SNR_THRESHOLD:g}`.")
    lines.append(f"- Minimum excess gate uses `observed >= {STRICT_MIN_EXCESS_W:g}`.")
    lines.append("- Only `Net energy gain` is eligible for `Replicated positive`.")

    results_path.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"Wrote results: {results_path}")


def main() -> None:
    base_dir = Path.cwd()
    parser = argparse.ArgumentParser(description="Run theory scenarios through template gates.")
    parser.add_argument(
        "--scenarios",
        default=str(base_dir / "scenarios.json"),
        help="Path to scenarios JSON file.",
    )
    parser.add_argument(
        "--output",
        default=str(base_dir / "scenario-results.md"),
        help="Output markdown file path.",
    )
    args = parser.parse_args()

    run(Path(args.scenarios), Path(args.output))


if __name__ == "__main__":
    main()

