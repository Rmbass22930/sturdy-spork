from security_gateway.automation import AutomationSupervisor
from security_gateway.alerts import AlertEvent, AlertLevel


class DummyVault:
    def __init__(self):
        self.rotations = 0

    def rotate_if_needed(self):
        self.rotations += 1

    def get_metrics(self):
        return {"rotation_count": self.rotations}


class DummyProxy:
    def health(self):
        return {"tor": {"status": "ok"}}


class DummyAudit:
    def __init__(self):
        self.events = []

    def log(self, event_type, data):
        self.events.append((event_type, data))


class DummyAlerts:
    def __init__(self):
        self.events = []

    def emit(self, event: AlertEvent):
        self.events.append(event)


class DummyTrackerIntel:
    def __init__(self):
        self.refresh_calls = 0

    def refresh_feed_cache(self):
        self.refresh_calls += 1
        return {
            "domain_count": 123,
            "last_refresh_result": "success",
            "last_error": None,
            "sources": [{"url": "https://feed.local/example", "domain_count": 123}],
        }


def test_perform_tasks_records_metrics():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        interval_seconds=0.1,
    )
    supervisor.perform_tasks()
    assert vault.rotations == 1
    assert any(event == "automation.tick" for event, _ in audit.events)
    status = supervisor.status()
    assert status["last_run"] is not None


def test_tracker_feed_refresh_is_disabled_by_default():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    tracker = DummyTrackerIntel()
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        tracker_intel=tracker,
        interval_seconds=0.1,
    )

    supervisor.perform_tasks()

    assert tracker.refresh_calls == 0
    assert supervisor.status()["tracker_feed_refresh"]["enabled"] is False


def test_tracker_feed_refresh_runs_on_configured_tick():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    tracker = DummyTrackerIntel()
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        tracker_intel=tracker,
        interval_seconds=0.1,
        tracker_feed_refresh_enabled=True,
        tracker_feed_refresh_every_ticks=2,
    )

    supervisor.perform_tasks()
    supervisor.perform_tasks()

    assert tracker.refresh_calls == 1
    status = supervisor.status()["tracker_feed_refresh"]
    assert status["enabled"] is True
    assert status["last_result"] == "success"
    assert any(event == "automation.tracker_feed_refresh" for event, _ in audit.events)
