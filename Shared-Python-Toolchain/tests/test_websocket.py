from fastapi.testclient import TestClient

from security_gateway import service


def test_websocket_ping_and_echo(monkeypatch):
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws") as websocket:
            ready = websocket.receive_json()
            assert ready["type"] == "ready"
            assert ready["message"] == "connected"

            websocket.send_text("ping")
            assert websocket.receive_text() == "pong"

            websocket.send_text("hello")
            assert websocket.receive_text() == "echo:hello"
