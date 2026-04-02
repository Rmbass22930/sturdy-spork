from typer.testing import CliRunner

from security_gateway import cli


runner = CliRunner()


def test_report_list_command_runs(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli.settings, "report_output_dir", str(tmp_path / "reports"))
    result = runner.invoke(cli.app, ["report-list"])

    assert result.exit_code == 0
    assert "'reports': []" in result.stdout


def test_report_pdf_command_accepts_filters(monkeypatch, tmp_path) -> None:
    calls = []

    def fake_write(output, **kwargs):
        calls.append((output, kwargs))
        target = tmp_path / "reports" / "filtered.pdf"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"%PDF-sample")
        return target

    monkeypatch.setattr(cli.report_builder, "write_summary_pdf", fake_write)
    result = runner.invoke(
        cli.app,
        [
            "report-pdf",
            "--max-events", "12",
            "--time-window-hours", "24",
            "--min-risk-score", "60",
            "--no-events",
        ],
    )

    assert result.exit_code == 0
    assert calls
    _, kwargs = calls[0]
    assert kwargs["max_events"] == 12
    assert kwargs["time_window_hours"] == 24.0
    assert kwargs["min_risk_score"] == 60.0
    assert kwargs["include_recent_events"] is False


def test_soc_dashboard_command_uses_local_dashboard_by_default(monkeypatch) -> None:
    calls: list[tuple[str, object]] = []
    monkeypatch.setattr(cli.settings, "platform_manager_url", None)
    monkeypatch.setattr(cli, "run_soc_dashboard", lambda manager=None: calls.append(("local", manager)))
    monkeypatch.setattr(
        cli,
        "run_remote_soc_dashboard",
        lambda **kwargs: calls.append(("remote", kwargs)),
    )

    result = runner.invoke(cli.app, ["soc-dashboard"])

    assert result.exit_code == 0
    assert calls == [("local", None)]


def test_soc_dashboard_command_uses_configured_remote_dashboard(monkeypatch) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(cli.settings, "platform_manager_url", "https://manager.local")
    monkeypatch.setattr(cli.settings, "platform_manager_bearer_token", "operator-token")
    monkeypatch.setattr(cli.settings, "platform_manager_timeout_seconds", 7.5)
    monkeypatch.setattr(cli, "run_soc_dashboard", lambda manager=None: (_ for _ in ()).throw(AssertionError("local dashboard should not be used")))
    monkeypatch.setattr(cli, "run_remote_soc_dashboard", lambda **kwargs: calls.append(kwargs))

    result = runner.invoke(cli.app, ["soc-dashboard"])

    assert result.exit_code == 0
    assert calls == [
        {
            "base_url": "https://manager.local",
            "bearer_token": "operator-token",
            "timeout_seconds": 7.5,
        }
    ]


def test_soc_dashboard_command_errors_when_remote_requested_without_url(monkeypatch) -> None:
    monkeypatch.setattr(cli.settings, "platform_manager_url", None)

    result = runner.invoke(cli.app, ["soc-dashboard", "--remote"])

    assert result.exit_code == 1
    assert "no manager url is configured" in result.stderr.lower()


def test_launch_uses_report_browser_when_frozen_without_args(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "_select_frozen_action", lambda: "report-browser")
    monkeypatch.setattr(cli, "run_report_browser", lambda builder=None: calls.append("browser"))
    monkeypatch.setattr(cli, "app", lambda *args, **kwargs: calls.append("app"))

    cli.launch()

    assert calls == ["browser"]


def test_launch_uses_soc_dashboard_when_selected(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "_select_frozen_action", lambda: "soc-dashboard")
    monkeypatch.setattr(cli, "_open_configured_soc_dashboard", lambda **kwargs: calls.append("dashboard"))
    monkeypatch.setattr(cli, "run_report_browser", lambda builder=None: calls.append("browser"))

    cli.launch()

    assert calls == ["dashboard"]


def test_launch_uses_cli_when_args_present(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe", "report-list"])
    monkeypatch.setattr(cli, "run_report_browser", lambda builder=None: calls.append("browser"))
    monkeypatch.setattr(cli, "app", lambda *args, **kwargs: calls.append("app"))

    cli.launch()

    assert calls == ["app"]


def test_launch_runs_uninstaller_when_selected(monkeypatch, tmp_path) -> None:
    calls = []
    uninstaller = tmp_path / "SecurityGateway-Uninstall.exe"
    uninstaller.write_text("stub")
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "_select_frozen_action", lambda: "uninstall")
    monkeypatch.setattr(cli, "_resolve_uninstaller_path", lambda: uninstaller)
    monkeypatch.setattr(cli, "_launch_uninstaller", lambda target: calls.append(target))

    cli.launch()

    assert calls == [uninstaller]


def test_launch_exits_when_uninstaller_is_missing(monkeypatch) -> None:
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "_select_frozen_action", lambda: "uninstall")
    monkeypatch.setattr(cli, "_resolve_uninstaller_path", lambda: None)

    try:
        cli.launch()
    except cli.typer.Exit as exc:
        assert exc.exit_code == 1
    else:  # pragma: no cover - defensive assertion path
        raise AssertionError("Expected launch() to raise typer.Exit when uninstaller is missing")
