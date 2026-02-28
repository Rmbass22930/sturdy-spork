from pathlib import Path

from memory_optimizer import setup


def test_build_optimizer_args_includes_proper_flags():
    args = setup.build_optimizer_args(
        "Lab",
        min_free_mb=512,
        max_reserve_mb=2048,
        block_size_mb=128,
        idle_seconds=60,
        sample_interval=5,
        vm_wait_free_mb=1024,
        vm_wait_timeout=100,
        vm_start_delay=3,
        restart_vm=False,
        control_panel_host="127.0.0.1",
        control_panel_port=9999,
        disable_control_panel=True,
        privacy_up_command=None,
        privacy_check_command=None,
        privacy_check_retries=5,
        privacy_check_interval=3.0,
        allow_unsafe_network_start=False,
    )
    assert "--hyperv-vm-name" in args
    assert "--max-reserve-mb" in args
    assert "--no-restart-vm" in args
    assert "--disable-control-panel" in args


def test_build_optimizer_args_includes_privacy_flags():
    args = setup.build_optimizer_args(
        "Lab",
        min_free_mb=512,
        max_reserve_mb=None,
        block_size_mb=128,
        idle_seconds=60,
        sample_interval=5,
        vm_wait_free_mb=1024,
        vm_wait_timeout=100,
        vm_start_delay=3,
        restart_vm=True,
        control_panel_host="127.0.0.1",
        control_panel_port=9999,
        disable_control_panel=False,
        privacy_up_command="& 'C:\\Program Files\\Mullvad VPN\\MullvadVPN.exe' connect",
        privacy_check_command="exit 0",
        privacy_check_retries=7,
        privacy_check_interval=2.5,
        allow_unsafe_network_start=True,
    )
    assert "--privacy-up-command" in args
    assert "--privacy-check-command" in args
    assert "--privacy-check-retries" in args
    assert "--privacy-check-interval" in args
    assert "--allow-unsafe-network-start" in args


def test_write_autostart_script_renders_ps_array(tmp_path: Path):
    script_path = tmp_path / "start.ps1"
    setup.write_autostart_script(
        script_path,
        python_path=Path(r"C:\Python\python.exe"),
        optimizer_args=["-m", "memory_optimizer.cli", "status"],
        working_directory=tmp_path,
    )
    content = script_path.read_text()
    assert "-m" in content
    assert "memory_optimizer.cli" in content
    assert "Set-Location" in content


def test_register_scheduled_task_builds_safe_arguments(monkeypatch, tmp_path: Path):
    captured = {}

    def fake_run(script: str):
        captured["script"] = script

    monkeypatch.setattr(setup, "_run_powershell", fake_run)
    setup.register_scheduled_task("MemoryOptimizerHyperV", tmp_path / "Start Memory Optimizer.ps1")

    script = captured["script"]
    assert "$psArgs" in script
    assert "-Argument $psArgs" in script
    assert "-RunLevel Limited" in script
    assert '`"$scriptFile`"' in script


def test_hyperv_setup_falls_back_to_run_key(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(setup, "register_scheduled_task", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("PowerShell failed: Access is denied.")))

    calls = {"run_key": 0}

    def fake_run_key(name: str, script_path: Path):
        calls["run_key"] += 1

    monkeypatch.setattr(setup, "register_startup_run_key", fake_run_key)
    result = setup.run_hyperv_setup(
        "Lab",
        skip_enable=True,
        script_path=tmp_path / "StartMemoryOptimizer.ps1",
        working_directory=tmp_path,
    )
    assert result["startup_mode"] == "run_key"
    assert calls["run_key"] == 1
