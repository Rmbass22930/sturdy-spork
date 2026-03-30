from __future__ import annotations

from pathlib import Path

from security_gateway.host_monitor import HostMonitor


class DummyCompletedProcess:
    def __init__(self, stdout: str):
        self.stdout = stdout


def _make_runner(*, defender_running: bool = True, firewall_on: bool = True):
    def run(args: list[str]):
        if args[:3] == ["sc", "query", "WinDefend"]:
            state = "RUNNING" if defender_running else "STOPPED"
            return DummyCompletedProcess(f"STATE              : 4  {state}\n")
        if args[:4] == ["netsh", "advfirewall", "show", "allprofiles"]:
            profile_state = "ON" if firewall_on else "OFF"
            return DummyCompletedProcess(
                f"Domain Profile Settings:\nState {profile_state}\n\n"
                f"Private Profile Settings:\nState {profile_state}\n\n"
                f"Public Profile Settings:\nState {profile_state}\n"
            )
        raise AssertionError(f"Unexpected command: {args}")

    return run


def test_host_monitor_detects_defender_and_firewall_drift(tmp_path, monkeypatch) -> None:
    monitor = HostMonitor(
        state_path=tmp_path / "host_monitor_state.json",
        system_drive="C:",
        disk_free_percent_threshold=5.0,
        runner=_make_runner(defender_running=False, firewall_on=False),
    )
    monkeypatch.setattr("security_gateway.host_monitor.shutil.disk_usage", lambda _path: (100, 70, 30))

    result = monitor.run_check()

    emitted_keys = {item["key"] for item in result["emitted_findings"]}
    assert emitted_keys == {"firewall-disabled", "defender-stopped"}
    assert Path(tmp_path / "host_monitor_state.json").exists()


def test_host_monitor_emits_recovery_once(tmp_path, monkeypatch) -> None:
    state_path = tmp_path / "host_monitor_state.json"
    monitor = HostMonitor(
        state_path=state_path,
        system_drive="C:",
        disk_free_percent_threshold=5.0,
        runner=_make_runner(defender_running=False, firewall_on=True),
    )
    monkeypatch.setattr("security_gateway.host_monitor.shutil.disk_usage", lambda _path: (100, 70, 30))
    monitor.run_check()

    recovered_monitor = HostMonitor(
        state_path=state_path,
        system_drive="C:",
        disk_free_percent_threshold=5.0,
        runner=_make_runner(defender_running=True, firewall_on=True),
    )
    monkeypatch.setattr("security_gateway.host_monitor.shutil.disk_usage", lambda _path: (100, 70, 30))

    result = recovered_monitor.run_check()

    assert [item["key"] for item in result["resolved_findings"]] == ["defender-stopped"]
    assert result["emitted_findings"] == []
