from security_gateway.alerts import AlertEvent, AlertLevel, AlertManager


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


def test_webhook_alert_uses_https_client(monkeypatch):
    captured = {}

    class DummyResponse:
        def raise_for_status(self):
            return None

    class DummyClient:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs

        def post(self, url, json):
            captured["url"] = url
            captured["json"] = json
            return DummyResponse()

        def close(self):
            return None

    monkeypatch.setattr("security_gateway.alerts.httpx.Client", DummyClient)
    manager = AlertManager(webhook_url="https://alerts.example.com/hook", enable_toast=False)

    manager.emit(AlertEvent(level=AlertLevel.warning, title="Test", message="Webhook", context={"source": "test"}))

    assert captured["url"] == "https://alerts.example.com/hook"
    assert captured["json"]["title"] == "Test"
    assert captured["client_kwargs"]["follow_redirects"] is False


def test_webhook_alert_rejects_localhost_destinations():
    manager = AlertManager(webhook_url="https://127.0.0.1/hook", enable_toast=False)

    assert manager.webhook_url is None
    assert manager._http_client is None  # pylint: disable=protected-access
    assert "blocked address" in manager._webhook_error  # pylint: disable=protected-access


def test_invalid_webhook_configuration_fails_closed(monkeypatch):
    captured = {}

    def fake_print(*args, **kwargs):
        captured["args"] = args

    monkeypatch.setattr("builtins.print", fake_print)
    manager = AlertManager(webhook_url="http://alerts.example.com/hook", enable_toast=False)

    manager.emit(AlertEvent(level=AlertLevel.info, title="Test", message="No webhook", context={}))

    assert manager._http_client is None  # pylint: disable=protected-access
    assert "disabled" in captured["args"][0].lower()
