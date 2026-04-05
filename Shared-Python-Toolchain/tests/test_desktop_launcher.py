from security_gateway import desktop_launcher


def test_main_runs_background_monitor_for_automation(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(desktop_launcher, "_ensure_runtime_directories", lambda: calls.append("dirs"))
    monkeypatch.setattr(desktop_launcher, "_run_background_monitor", lambda: calls.append("automation"))
    monkeypatch.setattr(desktop_launcher.sys, "argv", ["SecurityGateway.exe", "automation-run"])

    result = desktop_launcher.main()

    assert result == 0
    assert calls == ["dirs", "automation"]


def test_main_runs_smoke_check_headlessly(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(desktop_launcher, "_ensure_runtime_directories", lambda: calls.append("dirs"))
    monkeypatch.setattr(desktop_launcher, "_run_smoke_check", lambda: calls.append("smoke"))
    monkeypatch.setattr(desktop_launcher, "_finalize_smoke_check_exit", lambda code: calls.append(f"exit:{code}"))
    monkeypatch.setattr(desktop_launcher.sys, "argv", ["SecurityGateway.exe", "smoke-check"])

    result = desktop_launcher.main()

    assert result == 0
    assert calls == ["dirs", "smoke", "exit:0"]


def test_main_exits_frozen_smoke_check_with_failure_code(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(desktop_launcher, "_ensure_runtime_directories", lambda: calls.append("dirs"))

    def fail() -> None:
        calls.append("smoke")
        raise RuntimeError("boom")

    monkeypatch.setattr(desktop_launcher, "_run_smoke_check", fail)
    monkeypatch.setattr(desktop_launcher, "_finalize_smoke_check_exit", lambda code: calls.append(f"exit:{code}"))
    monkeypatch.setattr(desktop_launcher.sys, "argv", ["SecurityGateway.exe", "smoke-check"])

    try:
        desktop_launcher.main()
    except RuntimeError as exc:
        assert str(exc) == "boom"
    else:  # pragma: no cover - defensive assertion path
        raise AssertionError("Expected smoke-check failure to propagate")

    assert calls == ["dirs", "smoke", "exit:1"]
