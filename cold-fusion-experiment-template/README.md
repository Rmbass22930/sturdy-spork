# Cold Fusion Experiment Template

This project contains a one-page, pre-registered experiment template focused on rigorous measurement, controls, and reproducibility.

## Files

- `experiment-template.md`: Fill-in template for hypothesis, protocol, instrumentation, controls, analysis, and replication gate.
- `scenario_runner.py`: CLI scenario evaluator.
- `scenarios.json`: Theoretical scenario set.
- `build.ps1`: Builds executable-style `.pyz` artifact into `dist/`.
- `run-built.cmd`: Runs the built artifact.

## Usage

1. Copy `experiment-template.md` to a run-specific file (for example `run-001.md`).
2. Fill all pre-run sections before collecting data.
3. Lock analysis criteria before unblinding.
4. Record results and sign off.

## Build and run (executable-style)

1. `powershell -ExecutionPolicy Bypass -File .\build.ps1`
2. `.\run-built.cmd`
