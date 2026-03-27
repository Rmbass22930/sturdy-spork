import pytest

from security_gateway.alerts import alert_manager


@pytest.fixture(autouse=True)
def disable_live_alert_side_effects():
    previous_toast = alert_manager.enable_toast
    previous_webhook = alert_manager.webhook_url
    previous_http_client = alert_manager._http_client  # pylint: disable=protected-access
    alert_manager.enable_toast = False
    alert_manager.webhook_url = None
    alert_manager._http_client = None  # pylint: disable=protected-access
    try:
        yield
    finally:
        alert_manager.enable_toast = previous_toast
        alert_manager.webhook_url = previous_webhook
        alert_manager._http_client = previous_http_client  # pylint: disable=protected-access
