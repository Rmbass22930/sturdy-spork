import json
from pathlib import Path
from datetime import UTC, datetime, timedelta

from security_gateway.tracker_intel import TrackerIntel


def test_known_tracker_domain_is_blocked() -> None:
    intel = TrackerIntel()

    match = intel.is_tracker_hostname("www.google-analytics.com")

    assert match is not None
    assert match.source == "builtin"
    assert match.confidence == "high"


def test_heuristic_tracker_url_is_detected() -> None:
    intel = TrackerIntel()

    match = intel.is_tracker_url("https://metrics.example.com/collect?utm_source=email&gclid=abc123")

    assert match is not None
    assert match.source == "heuristic"
    assert "Tracker-style host labels" in match.reason
    assert "Tracking query keys" in match.reason


def test_normal_url_is_not_misclassified() -> None:
    intel = TrackerIntel()

    match = intel.is_tracker_url("https://api.example.com/orders?status=open")

    assert match is None


def test_first_party_cloaked_tracker_url_is_detected() -> None:
    intel = TrackerIntel()

    match = intel.is_tracker_url(
        "https://metrics.example.com/rum/collect?client_id=abc123&anonymous_id=user-1"
    )

    assert match is not None
    assert match.source == "heuristic"
    assert "First-party tracker cloaking pattern" in match.reason


def test_session_replay_and_fingerprint_patterns_are_detected() -> None:
    intel = TrackerIntel()

    match = intel.is_tracker_url(
        "https://telemetry.example.net/session-replay/ingest?fingerprint=device-42&_fbp=test"
    )

    assert match is not None
    assert match.source == "heuristic"
    assert "Tracker-style path tokens" in match.reason
    assert "Tracking query keys" in match.reason


def test_plain_ingest_endpoint_without_tracking_signals_is_not_flagged() -> None:
    intel = TrackerIntel()

    match = intel.is_tracker_url("https://api.example.com/ingest?job_id=42")

    assert match is None


class _FakeResponse:
    def __init__(self, payload: str):
        self.payload = payload

    def read(self) -> bytes:
        return self.payload.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


def test_refresh_feed_cache_parses_json_and_filter_lists(monkeypatch, tmp_path: Path) -> None:
    cache_path = tmp_path / "tracker-feeds.json"
    intel = TrackerIntel(feed_cache_path=cache_path, feed_urls=["https://feed.local/one", "https://feed.local/two"])

    payloads = {
        "https://feed.local/one": json.dumps(
            {
                "Advertising": {
                    "Example Tracker": {
                        "properties": ["track.example.com", "pixel.example.net"]
                    }
                }
            }
        ),
        "https://feed.local/two": "||metrics.example.org^\n0.0.0.0 beacon.example.io\n! comment\n",
    }

    monkeypatch.setattr(
        "security_gateway.tracker_intel.urlopen",
        lambda url, timeout=20.0: _FakeResponse(payloads[url]),
    )

    result = intel.refresh_feed_cache()

    assert result["domain_count"] == 4
    assert cache_path.exists()
    assert intel.is_tracker_hostname("www.metrics.example.org") is not None
    assert intel.is_tracker_hostname("track.example.com") is not None
    assert intel.feed_status()["domain_count"] == 4


def test_feed_cache_domains_report_feed_source(tmp_path: Path) -> None:
    cache_path = tmp_path / "tracker-feeds.json"
    cache_path.write_text(
        json.dumps(
            {
                "updated_at": "2026-03-27T12:00:00+00:00",
                "sources": [{"url": "https://feed.local/one", "domain_count": 1}],
                "domains": ["feedtracker.example"],
            }
        ),
        encoding="utf-8",
    )
    intel = TrackerIntel(feed_cache_path=cache_path)

    match = intel.is_tracker_hostname("cdn.feedtracker.example")

    assert match is not None
    assert match.source == "feed"


def test_feed_status_reports_stale_cache(tmp_path: Path) -> None:
    cache_path = tmp_path / "tracker-feeds.json"
    cache_path.write_text(
        json.dumps(
            {
                "updated_at": (datetime.now(UTC) - timedelta(hours=200)).isoformat(),
                "last_refresh_attempted_at": (datetime.now(UTC) - timedelta(hours=10)).isoformat(),
                "last_refresh_result": "success",
                "last_error": None,
                "failures": [],
                "sources": [{"url": "https://feed.local/one", "domain_count": 1}],
                "domains": ["feedtracker.example"],
            }
        ),
        encoding="utf-8",
    )
    intel = TrackerIntel(feed_cache_path=cache_path, stale_after_hours=168)

    status = intel.feed_status()

    assert status["is_stale"] is True
    assert status["age_hours"] is not None
    assert status["last_refresh_result"] == "success"


def test_failed_feed_refresh_records_failure_details(monkeypatch, tmp_path: Path) -> None:
    cache_path = tmp_path / "tracker-feeds.json"
    intel = TrackerIntel(feed_cache_path=cache_path, feed_urls=["https://feed.local/fail"])

    def _raise(url, timeout=20.0):
        raise OSError(f"down: {url}")

    monkeypatch.setattr("security_gateway.tracker_intel.urlopen", _raise)

    try:
        intel.refresh_feed_cache()
    except RuntimeError as exc:
        assert "down: https://feed.local/fail" in str(exc)
    else:
        raise AssertionError("Expected refresh_feed_cache to fail")

    status = intel.feed_status()
    assert status["last_refresh_result"] == "failed"
    assert status["failures"]
    assert "down: https://feed.local/fail" in status["last_error"]
