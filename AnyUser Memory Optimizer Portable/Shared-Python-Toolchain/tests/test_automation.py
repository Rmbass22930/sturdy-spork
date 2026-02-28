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
