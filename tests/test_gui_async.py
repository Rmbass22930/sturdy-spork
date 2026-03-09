from types import SimpleNamespace

import BallisticTargetGUI as bt_gui
from BallisticTargetGUI import App


class DummyVar:
    def __init__(self, value: str = ""):
        self.value = value

    def get(self) -> str:
        return self.value

    def set(self, value: str) -> None:
        self.value = value


class DummyThread:
    def __init__(self, alive: bool):
        self._alive = alive

    def is_alive(self) -> bool:
        return self._alive


def _make_stub(**overrides):
    stub = SimpleNamespace(
        vars={
            "rifle": DummyVar("Rifle"),
            "ammo": DummyVar("Ammo"),
            "velocity": DummyVar(""),
            "bc": DummyVar(""),
            "twist_rate": DummyVar("1:8"),
        },
        status=DummyVar(""),
        web_status=DummyVar(""),
        _web_fetch_thread=None,
        _extension_summary="",
        _clear_auto_fetch_job=lambda: None,
        update_idletasks=lambda: None,
        after=lambda delay, func: func(),
        _finish_web_fetch_async=lambda lookup, silent, rifle, ammo: None,
        _lookup_web_data=lambda rifle, ammo: {"errors": []},
        _start_web_fetch_async=lambda silent: True,
        _needs_web_data=lambda velocity_text, bc_text: True,
        _requires_auto_fill=lambda value: not str(value).strip(),
    )
    for key, value in overrides.items():
        setattr(stub, key, value)
    return stub


def test_start_web_fetch_async_reports_lookup_already_running(monkeypatch):
    messages = []
    monkeypatch.setattr(bt_gui.messagebox, "showinfo", lambda title, msg: messages.append((title, msg)))

    stub = _make_stub(_web_fetch_thread=DummyThread(alive=True))

    started = App._start_web_fetch_async(stub, silent=False)

    assert started is False
    assert messages == [("Web Data", "Lookup already running.")]
    assert stub.status.get() == ""


def test_on_generate_requests_async_refresh_when_web_data_missing(monkeypatch):
    errors = []
    monkeypatch.setattr(bt_gui.messagebox, "showerror", lambda title, msg: errors.append((title, msg)))

    starts = []
    stub = _make_stub(_start_web_fetch_async=lambda silent: starts.append(silent) or True)

    App.on_generate(stub)

    assert starts == [True]
    assert stub.web_status.get() == "Refreshing web data before generation..."
    assert stub.status.get() == "Error."
    assert stub._extension_summary == "Extension sheet status unavailable because target generation failed."
    assert len(errors) == 1
    assert errors[0][0] == "Error"
    assert "Missing muzzle velocity, G1 BC" in errors[0][1]
    assert "click Generate again after it finishes" in errors[0][1]
