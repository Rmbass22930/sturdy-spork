import httpx
import pytest

from security_gateway.tor import OutboundProxy, ProxyRequestTimeoutError, ProxyResponseTooLargeError


class _FakeStreamResponse:
    def __init__(self, chunks, *, status_code=200, headers=None, encoding="utf-8"):
        self.status_code = status_code
        self.headers = headers or {}
        self.encoding = encoding
        self._chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def raise_for_status(self):
        return None

    def iter_bytes(self):
        yield from self._chunks


class _FakeClient:
    def __init__(self, response=None, error=None, **kwargs):
        self._response = response
        self._error = error

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def stream(self, method, url, headers=None, **kwargs):
        if self._error:
            raise self._error
        return self._response


def test_send_request_rejects_oversized_response(monkeypatch):
    response = _FakeStreamResponse([b"hello", b"world"], headers={"content-type": "text/plain"})
    monkeypatch.setattr("security_gateway.tor.httpx.Client", lambda **kwargs: _FakeClient(response=response))
    proxy = OutboundProxy(timeout=1.0, max_response_bytes=5)

    with pytest.raises(ProxyResponseTooLargeError):
        proxy._send_request("GET", "https://example.com")


def test_send_request_maps_timeout(monkeypatch):
    timeout_error = httpx.ReadTimeout("timed out")
    monkeypatch.setattr("security_gateway.tor.httpx.Client", lambda **kwargs: _FakeClient(error=timeout_error))
    proxy = OutboundProxy(timeout=1.5, max_response_bytes=1024)

    with pytest.raises(ProxyRequestTimeoutError):
        proxy._send_request("GET", "https://example.com")


def test_proxy_request_rejects_disallowed_methods():
    proxy = OutboundProxy(timeout=1.0, max_response_bytes=1024)

    with pytest.raises(ValueError, match="method must be one of"):
        proxy.request("POST", "https://example.com", via="direct")
