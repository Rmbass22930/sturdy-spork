from security_gateway.report_browser import ReportBrowser


def test_feed_formatters_cover_sources_disabled_and_failures() -> None:
    browser = ReportBrowser.__new__(ReportBrowser)
    status = {
        "domain_count": 9357,
        "updated_at": "2026-03-27T22:25:36+00:00",
        "last_refresh_result": "partial",
        "last_refresh_attempted_at": "2026-03-27T22:25:36+00:00",
        "age_hours": 1.5,
        "is_stale": False,
        "active_feed_urls": ["https://feed.local/a", "https://feed.local/b"],
        "disabled_feed_urls": ["https://feed.local/c"],
        "sources": [
            {"url": "https://feed.local/a", "domain_count": 100},
            {"url": "https://feed.local/b", "domain_count": 200},
        ],
        "failures": [{"url": "https://feed.local/d", "error": "timeout"}],
    }

    status_line = browser._format_feed_status(status)
    detail_line = browser._format_feed_detail(status)
    sources_block = browser._format_feed_source_lines(status["sources"])
    disabled_block = browser._format_disabled_sources(status)
    failures_block = browser._format_feed_failures(status)

    assert "9357 domains" in status_line
    assert "last_result=partial" in status_line
    assert "active_sources=2" in detail_line
    assert "https://feed.local/a (100 domains)" in sources_block
    assert "https://feed.local/c" in disabled_block
    assert "timeout" in failures_block


def test_feed_formatters_handle_empty_values() -> None:
    browser = ReportBrowser.__new__(ReportBrowser)
    status = {
        "domain_count": 0,
        "updated_at": None,
        "last_refresh_result": None,
        "last_refresh_attempted_at": None,
        "age_hours": None,
        "is_stale": True,
        "active_feed_urls": [],
        "disabled_feed_urls": [],
        "sources": [],
        "failures": [],
    }

    assert "stale cache" in browser._format_feed_status(status)
    assert browser._format_feed_source_lines([]) == "No active source data recorded."
    assert browser._format_disabled_sources(status) == "No disabled sources."
    assert browser._format_feed_failures(status) == "No recent feed failures."
