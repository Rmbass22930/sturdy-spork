from __future__ import annotations

import os
import time
from pathlib import Path


def _has_basetemp(args: list[str]) -> bool:
    return any(arg == "--basetemp" or arg.startswith("--basetemp=") for arg in args)


def inject_unique_basetemp(
    args: list[str],
    *,
    cwd: str | Path | None = None,
    now_ns: int | None = None,
    pid: int | None = None,
) -> list[str]:
    if _has_basetemp(args):
        return list(args)
    root = Path(cwd) if cwd is not None else Path.cwd()
    stamp = now_ns if now_ns is not None else time.time_ns()
    process_id = pid if pid is not None else os.getpid()
    basetemp = root / ".pytest_tmp_runs" / f"run_{process_id}_{stamp}"
    return [*args, f"--basetemp={basetemp}"]


def pytest_load_initial_conftests(
    early_config: object,
    parser: object,
    args: list[str],
) -> None:
    args[:] = inject_unique_basetemp(args)
