from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT_SECONDS = 900
TIMEOUT_EXIT_CODE = 124


def build_pytest_command(pytest_args: list[str]) -> list[str]:
    args = list(pytest_args) if pytest_args else ["tests", "-q"]
    return [sys.executable, "-m", "pytest", *args]


def terminate_process_tree(process: subprocess.Popen[str] | subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return
    try:
        os.kill(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return


def run_pytest(
    pytest_args: list[str],
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    cwd: Path = REPO_ROOT,
) -> int:
    process = subprocess.Popen(build_pytest_command(pytest_args), cwd=cwd)
    try:
        return process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        print(
            f"pytest timed out after {timeout_seconds} seconds; terminating process tree.",
            file=sys.stderr,
        )
        terminate_process_tree(process)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            terminate_process_tree(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        return TIMEOUT_EXIT_CODE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run pytest with a hard timeout.")
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    pytest_args = list(args.pytest_args)
    if pytest_args[:1] == ["--"]:
        pytest_args = pytest_args[1:]
    return run_pytest(pytest_args, timeout_seconds=args.timeout_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
