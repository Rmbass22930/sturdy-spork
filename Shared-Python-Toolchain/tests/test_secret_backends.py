import pytest

from security_gateway.secret_backends import HashicorpVaultBackend


class _DummyResponse:
    def __init__(self, *, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {"data": {"data": {"ciphertext": "secret"}}}

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _DummySession:
    def __init__(self):
        self.verify = True
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return _DummyResponse()

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        return _DummyResponse()


def test_hashicorp_vault_backend_rejects_insecure_urls():
    with pytest.raises(ValueError, match="HTTPS"):
        HashicorpVaultBackend("http://vault.example.com", "token")

    with pytest.raises(ValueError, match="embedded credentials"):
        HashicorpVaultBackend("https://user:pass@vault.example.com", "token")


def test_hashicorp_vault_backend_uses_timeout_and_tls_settings():
    session = _DummySession()
    backend = HashicorpVaultBackend(
        "https://vault.example.com",
        "token",
        timeout_seconds=7.5,
        verify_tls=False,
        session=session,
    )

    backend.write("db", "v1", "ciphertext")
    backend.read("db", "v1")

    assert session.verify is False
    assert session.calls[0][2]["timeout"] == 7.5
    assert session.calls[1][2]["timeout"] == 7.5
    assert session.calls[0][1].startswith("https://vault.example.com/v1/")
