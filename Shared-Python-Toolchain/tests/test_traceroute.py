from security_gateway.traceroute import TraceRouteRunner


def test_trace_skips_confirmation_when_disabled(monkeypatch) -> None:
    calls = []

    def fake_run(command, capture_output, text, timeout, check):
        calls.append(command)

        class Completed:
            returncode = 0
            stdout = "trace ok"
            stderr = ""

        return Completed()

    monkeypatch.setattr("security_gateway.traceroute.shutil.which", lambda name: "C:\\Windows\\System32\\tracert.exe")
    monkeypatch.setattr("security_gateway.traceroute.platform.system", lambda: "Windows")
    monkeypatch.setattr("security_gateway.traceroute.subprocess.run", fake_run)

    runner = TraceRouteRunner(confirm_before_trace=False, show_popup_results=False)
    result = runner.trace("8.8.8.8", context="resource=git, score=75.0")

    assert result is not None
    assert result.declined is False
    assert result.exit_code == 0
    assert calls


def test_trace_rejects_unsafe_target_without_running_subprocess(monkeypatch) -> None:
    calls = []

    def fake_run(command, capture_output, text, timeout, check):
        calls.append(command)
        raise AssertionError("subprocess.run should not be called for unsafe traceroute targets")

    monkeypatch.setattr("security_gateway.traceroute.subprocess.run", fake_run)

    runner = TraceRouteRunner(confirm_before_trace=False, show_popup_results=False)
    result = runner.trace("127.0.0.1", context="resource=git, score=75.0")

    assert result is not None
    assert result.exit_code is None
    assert "blocked address" in (result.error or "")
    assert calls == []


def test_trace_rejects_invalid_target_without_prompt(monkeypatch) -> None:
    prompts = []
    monkeypatch.setattr(
        "security_gateway.traceroute.TraceRouteRunner._message_box",
        lambda self, message, title, flags: prompts.append((message, title, flags)) or 6,
    )

    runner = TraceRouteRunner(confirm_before_trace=True, show_popup_results=False)
    result = runner.trace("bad host", context="resource=git, score=75.0")

    assert result is not None
    assert result.exit_code is None
    assert "whitespace" in (result.error or "")
    assert prompts == []
