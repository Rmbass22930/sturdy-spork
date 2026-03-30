from security_gateway.automation import AutomationSupervisor
from security_gateway.alerts import AlertEvent


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


class DummyMalwareScanner:
    def __init__(self):
        self.refresh_calls = 0
        self.rule_refresh_calls = 0

    def refresh_feed_cache(self):
        self.refresh_calls += 1
        return {
            "hash_count": 42,
            "last_refresh_result": "success",
            "last_error": None,
            "sources": [{"url": "https://feed.local/malware", "hash_count": 42}],
        }

    def refresh_rule_feed_cache(self):
        self.rule_refresh_calls += 1
        return {
            "rule_count": 5,
            "last_refresh_result": "success",
            "last_error": None,
            "sources": [{"url": "https://feed.local/malware-rules", "rule_count": 5}],
        }


class DummyHostMonitor:
    def __init__(self):
        self.run_calls = 0

    def run_check(self):
        self.run_calls += 1
        return {
            "active_findings": [{"key": "firewall-disabled"}],
            "emitted_findings": [
                {
                    "key": "firewall-disabled",
                    "severity": "critical",
                    "title": "Windows firewall profile disabled",
                    "summary": "One or more firewall profiles are disabled.",
                    "details": {"disabled_profiles": ["public"]},
                    "tags": ["host", "firewall"],
                    "resolved": False,
                }
            ],
            "resolved_findings": [],
        }


class DummyPacketMonitor:
    def __init__(self):
        self.run_calls = 0

    def run_check(self):
        self.run_calls += 1
        return {
            "snapshot": {"capture_status": "ok"},
            "active_findings": [],
            "emitted_findings": [],
            "resolved_findings": [],
        }


class DummyStreamMonitor:
    def __init__(self):
        self.run_calls = 0
        self.include_activity = False

    def run_check(self):
        self.run_calls += 1
        return {
            "snapshot": {
                "checked_at": "2026-03-30T00:00:00+00:00",
                "scanned_artifacts": [{"path": "C:/Temp/stream.tmp.js"}] if self.include_activity else [],
            },
            "active_findings": [],
            "emitted_findings": [],
            "resolved_findings": [],
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


def test_malware_feed_refresh_runs_on_configured_tick():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    scanner = DummyMalwareScanner()
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        malware_scanner=scanner,
        interval_seconds=0.1,
        malware_feed_refresh_enabled=True,
        malware_feed_refresh_every_ticks=2,
    )

    supervisor.perform_tasks()
    supervisor.perform_tasks()

    assert scanner.refresh_calls == 1
    status = supervisor.status()["malware_feed_refresh"]
    assert status["enabled"] is True
    assert status["last_result"] == "success"
    assert any(event == "automation.malware_feed_refresh" for event, _ in audit.events)


def test_malware_rule_feed_refresh_runs_on_configured_tick():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    scanner = DummyMalwareScanner()
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        malware_scanner=scanner,
        interval_seconds=0.1,
        malware_rule_feed_refresh_enabled=True,
        malware_rule_feed_refresh_every_ticks=2,
    )

    supervisor.perform_tasks()
    supervisor.perform_tasks()

    assert scanner.rule_refresh_calls == 1
    status = supervisor.status()["malware_rule_feed_refresh"]
    assert status["enabled"] is True
    assert status["last_result"] == "success"
    assert any(event == "automation.malware_rule_feed_refresh" for event, _ in audit.events)


def test_host_monitor_runs_and_dispatches_findings():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    host_monitor = DummyHostMonitor()
    forwarded_findings = []
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        host_monitor=host_monitor,
        host_monitor_enabled=True,
        host_monitor_callback=forwarded_findings.append,
        interval_seconds=0.1,
    )

    supervisor.perform_tasks()

    assert host_monitor.run_calls == 1
    assert forwarded_findings[0]["key"] == "firewall-disabled"
    assert alerts.events[0].title == "Windows firewall profile disabled"
    status = supervisor.status()["host_monitor"]
    assert status["enabled"] is True
    assert status["last_result"] == "success"


def test_packet_monitor_runs_on_first_tick_even_with_later_interval():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    packet_monitor = DummyPacketMonitor()
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        packet_monitor=packet_monitor,
        packet_monitor_enabled=True,
        packet_monitor_every_ticks=2,
        interval_seconds=0.1,
    )

    supervisor.perform_tasks()

    assert packet_monitor.run_calls == 1
    assert supervisor.status()["packet_monitor"]["last_result"] == "ok"


def test_stream_monitor_runs_on_first_tick_even_with_later_interval():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    stream_monitor = DummyStreamMonitor()
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        stream_monitor=stream_monitor,
        stream_monitor_enabled=True,
        stream_monitor_every_ticks=3,
        interval_seconds=0.1,
    )

    supervisor.perform_tasks()

    assert stream_monitor.run_calls == 1
    assert supervisor.status()["stream_monitor"]["last_result"] == "success"


def test_stream_activity_forces_packet_monitor_immediately():
    vault = DummyVault()
    proxy = DummyProxy()
    audit = DummyAudit()
    alerts = DummyAlerts()
    packet_monitor = DummyPacketMonitor()
    stream_monitor = DummyStreamMonitor()
    stream_monitor.include_activity = True
    supervisor = AutomationSupervisor(
        vault=vault,
        proxy=proxy,
        audit_logger=audit,
        alert_manager=alerts,
        packet_monitor=packet_monitor,
        packet_monitor_enabled=True,
        packet_monitor_every_ticks=5,
        stream_monitor=stream_monitor,
        stream_monitor_enabled=True,
        stream_monitor_every_ticks=3,
        interval_seconds=0.1,
    )

    supervisor.perform_tasks()

    assert stream_monitor.run_calls == 1
    assert packet_monitor.run_calls == 1
    assert supervisor.status()["packet_monitor"]["last_result"] == "ok"
