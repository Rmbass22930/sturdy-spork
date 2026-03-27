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
