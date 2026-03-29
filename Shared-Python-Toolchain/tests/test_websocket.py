import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from security_gateway import service
from security_gateway.pam import VaultClient


def _websocket_headers(monkeypatch, token="test-operator-token"):
    monkeypatch.setattr(service.settings, "operator_bearer_token", token)
    monkeypatch.setattr(service.settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(service.settings, "operator_allow_loopback_without_token", False)
    return {"Authorization": f"Bearer {token}"}


def _websocket_secret_headers(monkeypatch, token="test-operator-token", secret_name="operator-bearer-token"):
    monkeypatch.setattr(service.settings, "operator_bearer_token", "stale-fallback-token")
    monkeypatch.setattr(service.settings, "operator_bearer_secret_name", secret_name)
    monkeypatch.setattr(service.settings, "operator_allow_loopback_without_token", False)
    operator_vault = VaultClient(audit_logger=service.audit_logger, master_key="test-master-key")
    operator_vault.store_secret(secret_name, token)
    monkeypatch.setattr(service, "vault", operator_vault)
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
    monkeypatch.setattr(service.settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(service.settings, "operator_allow_loopback_without_token", False)

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws") as websocket:
            error = websocket.receive_json()
            assert error["type"] == "error"
            assert error["message"] == "Operator authentication required."
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_text()


def test_websocket_rejects_disallowed_origin(monkeypatch):
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)
    monkeypatch.setattr(service.settings, "websocket_allowed_origins", ["https://app.example"])
    headers = _websocket_headers(monkeypatch)
    headers["Origin"] = "https://evil.example"

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws", headers=headers) as websocket:
            error = websocket.receive_json()
            assert error["type"] == "error"
            assert error["message"] == "WebSocket origin is not allowed."
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_text()


def test_websocket_rejects_host_header_origin_spoof(monkeypatch):
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)
    monkeypatch.setattr(service.settings, "websocket_allowed_origins", ["https://app.example"])
    headers = _websocket_headers(monkeypatch)
    headers["Origin"] = "https://testserver"
    headers["Host"] = "testserver"

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws", headers=headers) as websocket:
            error = websocket.receive_json()
            assert error["type"] == "error"
            assert error["message"] == "WebSocket origin is not allowed."
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_text()


def test_websocket_rate_limits_abusive_message_volume(monkeypatch):
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)
    headers = _websocket_headers(monkeypatch)
    monkeypatch.setattr(service.settings, "websocket_max_messages_per_window", 2)
    monkeypatch.setattr(service.settings, "websocket_rate_window_seconds", 60.0)

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws", headers=headers) as websocket:
            websocket.receive_json()
            websocket.send_text("ping")
            assert websocket.receive_text() == "pong"
            websocket.send_text("health")
            assert websocket.receive_text() == "pong"
            websocket.send_text("ping")
            error = websocket.receive_json()
            assert error["type"] == "error"
            assert error["message"] == "WebSocket message rate limit exceeded."
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_text()


def test_websocket_accepts_pam_secret_backed_operator_token(monkeypatch):
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)
    headers = _websocket_secret_headers(monkeypatch, token="vault-backed-token")

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws", headers=headers) as websocket:
            ready = websocket.receive_json()
            assert ready["type"] == "ready"
            websocket.send_text("health")
            assert websocket.receive_text() == "pong"


def test_websocket_auth_rate_limits_repeated_failures(monkeypatch):
    monkeypatch.setattr(service.automation, "start", lambda: None)
    monkeypatch.setattr(service.automation, "stop", lambda: None)
    monkeypatch.setattr(service.resolver, "close", lambda: None)
    monkeypatch.setattr(service.settings, "operator_bearer_token", "expected-token")
    monkeypatch.setattr(service.settings, "operator_bearer_secret_name", None)
    monkeypatch.setattr(service.settings, "operator_allow_loopback_without_token", False)
    monkeypatch.setattr(service.settings, "operator_auth_max_failures_per_window", 1)
    monkeypatch.setattr(service.settings, "auth_failure_rate_limit_window_seconds", 60.0)
    service.auth_failure_rate_limiter.clear()

    with TestClient(service.app) as client:
        with client.websocket_connect("/ws") as websocket:
            error = websocket.receive_json()
            assert error["type"] == "error"
            assert error["message"] == "Operator authentication required."
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_text()

        with client.websocket_connect("/ws") as websocket:
            error = websocket.receive_json()
            assert error["type"] == "error"
            assert error["message"] == "Too many authentication failures; retry later."
            with pytest.raises(WebSocketDisconnect):
                websocket.receive_text()
