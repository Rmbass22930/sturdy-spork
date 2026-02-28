from security_gateway.alerts import AlertManager


def test_escape_powershell_single_quoted():
    escaped = AlertManager._escape_powershell_single_quoted("can't stop")
    assert escaped == "can''t stop"


def test_toast_escapes_title_and_message(monkeypatch):
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return None

    monkeypatch.setattr("security_gateway.alerts.subprocess.Popen", fake_popen)
    manager = AlertManager(webhook_url=None, enable_toast=True)

    manager._toast({"title": "O'Brien", "message": "you've got mail"})  # pylint: disable=protected-access

    ps_script = captured["args"][-1]
    assert "$toast.BalloonTipTitle = 'SecurityGateway: O''Brien';" in ps_script
    assert "$toast.BalloonTipText = 'you''ve got mail';" in ps_script
