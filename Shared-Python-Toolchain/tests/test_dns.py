import httpx

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
