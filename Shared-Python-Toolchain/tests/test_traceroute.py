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
    result = runner.trace("203.0.113.20", context="resource=git, score=75.0")

    assert result is not None
    assert result.declined is False
    assert result.exit_code == 0
    assert calls
