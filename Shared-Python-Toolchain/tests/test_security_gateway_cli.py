from typer.testing import CliRunner

from security_gateway import cli


runner = CliRunner()


def test_report_list_command_runs(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(cli.settings, "report_output_dir", str(tmp_path / "reports"))
    result = runner.invoke(cli.app, ["report-list"])

    assert result.exit_code == 0
    assert "'reports': []" in result.stdout


def test_launch_uses_report_browser_when_frozen_without_args(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe"])
    monkeypatch.setattr(cli, "run_report_browser", lambda builder=None: calls.append("browser"))
    monkeypatch.setattr(cli, "app", lambda *args, **kwargs: calls.append("app"))

    cli.launch()

    assert calls == ["browser"]


def test_launch_uses_cli_when_args_present(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(cli.sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli.sys, "argv", ["SecurityGateway.exe", "report-list"])
    monkeypatch.setattr(cli, "run_report_browser", lambda builder=None: calls.append("browser"))
    monkeypatch.setattr(cli, "app", lambda *args, **kwargs: calls.append("app"))

    cli.launch()

    assert calls == ["app"]
