import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from security_gateway import service


def _websocket_headers(monkeypatch, token="test-operator-token"):
    monkeypatch.setattr(service.settings, "operator_bearer_token", token)
    monkeypatch.setattr(service.settings, "operator_allow_loopback_without_token", False)
    return {"Authorization": f"Bearer {token}"}


def test_websocket_ping_and_health_only_mode(monkeypatch):
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)
    headers = _websocket_headers(monkeypatch)

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws", headers=headers) as websocket:
            ready = websocket.receive_json()
            assert ready["type"] == "ready"
            assert ready["message"] == "connected"
            assert ready["mode"] == "health_only"

            websocket.send_text("ping")
            assert websocket.receive_text() == "pong"

            websocket.send_text("hello")
            unsupported = websocket.receive_json()
            assert unsupported["type"] == "unsupported"
            assert "health-only websocket" in unsupported["message"]


def test_websocket_requires_operator_auth(monkeypatch):
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)
    monkeypatch.setattr(service.settings, "operator_bearer_token", "expected-token")
    monkeypatch.setattr(service.settings, "operator_allow_loopback_without_token", False)

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws") as websocket:
            error = websocket.receive_json()
            assert error["type"] == "error"
            assert error["message"] == "Operator authentication required."
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_text()
