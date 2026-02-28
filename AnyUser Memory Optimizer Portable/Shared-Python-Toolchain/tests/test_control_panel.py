import time
import urllib.request

from memory_optimizer.control_panel import ControlPanelServer


def test_control_panel_stop_invokes_callback():
    called = []

    def _stop():
        called.append("stop")

    server = ControlPanelServer(on_stop=_stop, host="127.0.0.1", port=0)
    server.start()
    host, port = server.address
    urllib.request.urlopen(f"http://{host}:{port}/").read()
    req = urllib.request.Request(f"http://{host}:{port}/stop", method="POST")
    urllib.request.urlopen(req).read()
    time.sleep(0.2)
    server.stop()
    assert called == ["stop"]
