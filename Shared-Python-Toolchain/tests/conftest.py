from pathlib import Path

import pytest

from security_gateway.alerts import alert_manager
from security_gateway.traceroute import TraceRouteRunner


@pytest.fixture(autouse=True)
def disable_live_alert_side_effects():
    previous_toast = alert_manager.enable_toast
    previous_webhook = alert_manager.webhook_url
    previous_http_client = alert_manager._http_client  # pylint: disable=protected-access
    previous_preference_path = alert_manager._preference_path  # pylint: disable=protected-access
    alert_manager.enable_toast = False
    alert_manager.webhook_url = None
    alert_manager._http_client = None  # pylint: disable=protected-access
    alert_manager._preference_path = Path("__test_alert_preferences__.json")  # pylint: disable=protected-access
    try:
        yield
    finally:
        alert_manager.enable_toast = previous_toast
        alert_manager.webhook_url = previous_webhook
        alert_manager._http_client = previous_http_client  # pylint: disable=protected-access
        alert_manager._preference_path = previous_preference_path  # pylint: disable=protected-access


@pytest.fixture(autouse=True)
def disable_interactive_traceroute_prompts(monkeypatch):
    monkeypatch.setattr(TraceRouteRunner, "_message_box", lambda self, message, title, flags: 7)
