from __future__ import annotations

from pathlib import Path

from pytest_local_tmp import inject_unique_basetemp, pytest_load_initial_conftests


def test_inject_unique_basetemp_appends_repo_local_directory() -> None:
    args = inject_unique_basetemp(["tests", "-q"], cwd=Path("J:/sturdy-spork/Shared-Python-Toolchain"), now_ns=123, pid=456)
    assert args[:-1] == ["tests", "-q"]
    assert args[-1] == "--basetemp=J:\\sturdy-spork\\Shared-Python-Toolchain\\.pytest_tmp_runs\\run_456_123"


def test_inject_unique_basetemp_preserves_explicit_override() -> None:
    args = inject_unique_basetemp(["tests", "-q", "--basetemp=custom"], cwd=Path("J:/sturdy-spork/Shared-Python-Toolchain"))
    assert args == ["tests", "-q", "--basetemp=custom"]


def test_pytest_load_initial_conftests_updates_args_in_place() -> None:
    args = ["tests", "-q"]
    pytest_load_initial_conftests(object(), object(), args)
    assert args[0:2] == ["tests", "-q"]
    assert args[2].startswith("--basetemp=")
