import httpx
import pytest

from security_gateway.dns import SecureDNSResolver


def test_dns_resolver_parses_answers():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params.get("name") == "example.com"
        payload = {
            "Answer": [
                {"name": "example.com", "type": 1, "TTL": 60, "data": "93.184.216.34"}
            ],
            "AD": True,
        }
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    resolver = SecureDNSResolver(providers=["https://mock"], client=client)
    result = resolver.resolve("example.com")
    assert result.secure is True
    assert result.records[0].data == "93.184.216.34"


def test_dns_resolver_rejects_invalid_hostname_and_record_type():
    resolver = SecureDNSResolver(providers=["https://mock"], client=httpx.Client(transport=httpx.MockTransport(lambda r: None)))

    with pytest.raises(ValueError, match="hostname"):
        resolver.resolve("bad host", "A")

    with pytest.raises(ValueError, match="record_type"):
        resolver.resolve("example.com", "AXFR")


def test_dns_resolver_rejects_unsafe_provider_urls():
    with pytest.raises(ValueError, match="HTTPS"):
        SecureDNSResolver(providers=["http://dns.example.com/dns-query"])

    with pytest.raises(ValueError, match="embedded credentials"):
        SecureDNSResolver(providers=["https://user:pass@dns.example.com/dns-query"])

    with pytest.raises(ValueError, match="blocked"):
        SecureDNSResolver(providers=["https://127.0.0.1/dns-query"])
