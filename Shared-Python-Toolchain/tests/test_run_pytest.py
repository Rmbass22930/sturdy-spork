from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import Any


def _load_run_pytest_module() -> Any:
    path = Path("J:/sturdy-spork/Shared-Python-Toolchain/scripts/run_pytest.py")
    spec = importlib.util.spec_from_file_location("security_gateway_run_pytest", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


run_pytest = _load_run_pytest_module()


def test_build_pytest_command_defaults_to_repo_suite() -> None:
    assert run_pytest.build_pytest_command([]) == [run_pytest.sys.executable, "-m", "pytest", "tests", "-q"]


def test_build_pytest_command_preserves_args() -> None:
    assert run_pytest.build_pytest_command(["tests/test_soc_dashboard.py", "-q"]) == [
        run_pytest.sys.executable,
        "-m",
        "pytest",
        "tests/test_soc_dashboard.py",
        "-q",
    ]


def test_run_pytest_returns_subprocess_exit_code(monkeypatch: Any) -> None:
    class Process:
        pid = 100

        def wait(self, timeout: int | None = None) -> int:
            assert timeout == 12
            return 0

        def poll(self) -> None:
            return None

    monkeypatch.setattr(run_pytest.subprocess, "Popen", lambda *args, **kwargs: Process())
    assert run_pytest.run_pytest(["tests"], timeout_seconds=12, cwd=Path("J:/repo")) == 0


def test_run_pytest_timeout_returns_timeout_code(monkeypatch: Any) -> None:
    class Process:
        pid = 101
        waits = 0

        def wait(self, timeout: int | None = None) -> int:
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired(cmd="pytest", timeout=timeout or 0)
            return 0

        def poll(self) -> None:
            return None

    process = Process()
    terminated: list[int] = []
    monkeypatch.setattr(run_pytest.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(run_pytest, "terminate_process_tree", lambda proc: terminated.append(proc.pid))
    assert run_pytest.run_pytest(["tests"], timeout_seconds=5, cwd=Path("J:/repo")) == run_pytest.TIMEOUT_EXIT_CODE
    assert terminated == [101]


def test_run_pytest_timeout_returns_timeout_code_if_wait_times_out_again(monkeypatch: Any) -> None:
    class Process:
        pid = 202

        def wait(self, timeout: int | None = None) -> int:
            raise subprocess.TimeoutExpired(cmd="pytest", timeout=timeout or 0)

        def poll(self) -> None:
            return None

    process = Process()
    terminated: list[int] = []
    monkeypatch.setattr(run_pytest.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(run_pytest, "terminate_process_tree", lambda proc: terminated.append(proc.pid))
    assert run_pytest.run_pytest(["tests"], timeout_seconds=5, cwd=Path("J:/repo")) == run_pytest.TIMEOUT_EXIT_CODE
    assert terminated == [202, 202]


def test_main_strips_double_dash(monkeypatch: Any) -> None:
    captured: dict[str, Any] = {}

    def _run(pytest_args: list[str], *, timeout_seconds: int, cwd: Path = Path(".")) -> int:
        captured["pytest_args"] = pytest_args
        captured["timeout_seconds"] = timeout_seconds
        return 0

    monkeypatch.setattr(run_pytest, "run_pytest", _run)
    assert run_pytest.main(["--timeout-seconds", "30", "--", "tests/test_soc_dashboard.py", "-q"]) == 0
    assert captured == {"pytest_args": ["tests/test_soc_dashboard.py", "-q"], "timeout_seconds": 30}
