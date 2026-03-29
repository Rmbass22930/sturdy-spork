import json
from datetime import UTC, datetime, timedelta

from security_gateway.endpoint import EndpointTelemetryService, MalwareScanner
from security_gateway.models import DeviceCompliance, DeviceContext


class _FakeResponse:
    def __init__(self, payload: str):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _device(device_id: str) -> DeviceContext:
    return DeviceContext(
        device_id=device_id,
        os="Windows",
        os_version="11",
        compliance=DeviceCompliance.compliant,
        is_encrypted=True,
        edr_active=True,
    )


def test_endpoint_telemetry_uses_stable_signing_key_across_instances():
    telemetry_a = EndpointTelemetryService(signing_key="stable-key")
    telemetry_b = EndpointTelemetryService(signing_key="stable-key")

    signature = telemetry_a.publish(_device("device-1"))
    telemetry_b._records["device-1"] = telemetry_a._records["device-1"]

    assert telemetry_b.verify("device-1") is True
    assert telemetry_b.get_payload("device-1")["device_id"] == "device-1"
    assert signature == telemetry_a._records["device-1"]["signature"]


def test_endpoint_telemetry_eviction_respects_max_records():
    telemetry = EndpointTelemetryService(signing_key="stable-key", max_records=2)

    telemetry.publish(_device("device-1"))
    telemetry.publish(_device("device-2"))
    telemetry.publish(_device("device-3"))

    assert telemetry.get_payload("device-1") is None
    assert telemetry.get_payload("device-2")["device_id"] == "device-2"
    assert telemetry.get_payload("device-3")["device_id"] == "device-3"


def test_endpoint_telemetry_prunes_expired_records():
    telemetry = EndpointTelemetryService(signing_key="stable-key", retention_hours=1)
    telemetry.publish(_device("fresh-device"))
    telemetry._records["expired-device"] = {
        "payload": {
            **_device("expired-device").model_dump(),
            "timestamp": (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
        },
        "signature": "invalid",
    }

    assert telemetry.get_payload("expired-device") is None
    assert "expired-device" not in telemetry._records
    assert telemetry.get_payload("fresh-device")["device_id"] == "fresh-device"


def test_malware_scanner_refreshes_feed_hashes_and_detects_match(monkeypatch, tmp_path):
    malicious_sample = b"security onion inspired sample"
    malicious_hash = "fd80cee809f15586897c7f84dc92e8cd94901cb14c945163c6d228562518a232"
    cache_path = tmp_path / "malware-feed-hashes.json"
    scanner = MalwareScanner(
        feed_cache_path=cache_path,
        feed_urls=["https://feed.local/malware.txt"],
        min_hashes_per_source=1,
        min_total_hashes=1,
    )

    monkeypatch.setattr(
        "security_gateway.endpoint.urlopen",
        lambda url, timeout=20.0, context=None: _FakeResponse(f"{malicious_hash}\n# comment\n"),
    )

    refreshed = scanner.refresh_feed_cache()

    assert refreshed["hash_count"] == 1
    assert refreshed["sources"] == [{"url": "https://feed.local/malware.txt", "hash_count": 1}]
    status = scanner.feed_status()
    assert status["hash_count"] == 1
    assert status["last_refresh_result"] == "success"

    malicious, verdict = scanner.scan_bytes(malicious_sample)

    assert malicious is True
    assert "flagged as malicious (feed)" in verdict


def test_malware_scanner_refuses_tiny_replacement_feed(monkeypatch, tmp_path):
    cache_path = tmp_path / "malware-feed-hashes.json"
    cache_path.write_text(
        """
{
  "hashes": [
    "1111111111111111111111111111111111111111111111111111111111111111",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "3333333333333333333333333333333333333333333333333333333333333333",
    "4444444444444444444444444444444444444444444444444444444444444444"
  ],
  "sources": [{"url": "https://feed.local/original", "hash_count": 4}],
  "updated_at": "2026-03-28T00:00:00+00:00"
}
""".strip(),
        encoding="utf-8",
    )
    scanner = MalwareScanner(
        feed_cache_path=cache_path,
        feed_urls=["https://feed.local/malware.txt"],
        min_hashes_per_source=1,
        min_total_hashes=1,
        replace_ratio_floor=0.5,
    )

    monkeypatch.setattr(
        "security_gateway.endpoint.urlopen",
        lambda url, timeout=20.0, context=None: _FakeResponse(
            "1111111111111111111111111111111111111111111111111111111111111111"
        ),
    )

    try:
        scanner.refresh_feed_cache()
    except ValueError as exc:
        assert "Refusing to replace malware feed cache" in str(exc)
    else:
        raise AssertionError("Expected refresh_feed_cache to reject undersized replacement")

    status = scanner.feed_status()
    assert status["hash_count"] == 4
    assert status["last_refresh_result"] == "failed"


def test_malware_rule_feed_refreshes_and_detects_match(monkeypatch, tmp_path):
    cache_path = tmp_path / "malware-rule-feed-rules.json"
    scanner = MalwareScanner(
        rule_feed_cache_path=cache_path,
        rule_feed_urls=["https://feed.local/rules.json"],
        min_rules_per_source=1,
        min_total_rules=1,
    )
    payload = json.dumps(
        {
            "rules": [
                {
                    "name": "suspicious-powershell",
                    "patterns": ["Invoke-WebRequest", "FromBase64String"],
                }
            ]
        }
    )

    monkeypatch.setattr(
        "security_gateway.endpoint.urlopen",
        lambda url, timeout=20.0, context=None: _FakeResponse(payload),
    )

    refreshed = scanner.refresh_rule_feed_cache()

    assert refreshed["rule_count"] == 1
    status = scanner.rule_feed_status()
    assert status["rule_count"] == 1
    assert status["last_refresh_result"] == "success"

    malicious, verdict = scanner.scan_bytes(b"powershell Invoke-WebRequest https://example.com")

    assert malicious is True
    assert "suspicious-powershell" in verdict


def test_malware_feed_import_and_health_status(tmp_path):
    hash_source = tmp_path / "hashes.txt"
    hash_source.write_text(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        encoding="utf-8",
    )
    rule_source = tmp_path / "rules.txt"
    rule_source.write_text("loader-rule: powershell.exe || certutil.exe\n", encoding="utf-8")
    scanner = MalwareScanner(
        feed_cache_path=tmp_path / "malware-feed-hashes.json",
        rule_feed_cache_path=tmp_path / "malware-rule-feed-rules.json",
        min_total_hashes=1,
        min_total_rules=1,
        verify_tls=False,
        rule_feed_verify_tls=False,
    )

    imported_hashes = scanner.import_feed_cache(hash_source)
    imported_rules = scanner.import_rule_feed_cache(rule_source)
    health = scanner.health_status()

    assert imported_hashes["last_refresh_result"] == "imported"
    assert imported_rules["last_refresh_result"] == "imported"
    assert health["healthy"] is False
    assert "malware hash feed TLS verification is disabled" in health["warnings"]
    assert "malware rule feed TLS verification is disabled" in health["warnings"]
