"""Simple HTTP control panel to stop VMs from inside the guest."""
from __future__ import annotations

import html
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional


class ControlPanelServer:
    def __init__(
        self,
        on_stop: Callable[[], None],
        host: str = "0.0.0.0",
        port: int = 8765,
        button_label: str = "Stop Virtual Machine",
    ) -> None:
        self._on_stop = on_stop
        self._host = host
        self._port = port
        self._button_label = button_label
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def address(self) -> tuple[str, int]:
        if not self._server:
            return (self._host, self._port)
        host, port = self._server.server_address
        return (host, port)

    def start(self) -> None:
        if self._server:
            return

        on_stop = self._on_stop
        button_label = self._button_label

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                content = f"""
                <html>
                    <head><title>VM Control Panel</title></head>
                    <body style="font-family: sans-serif; text-align: center; margin-top: 5em;">
                        <h1>Host Control</h1>
                        <p>Press the button below to safely stop the virtual machine.</p>
                        <form method="POST" action="/stop">
                            <button style="padding: 1em 2em; font-size: 1.2em;">{html.escape(button_label)}</button>
                        </form>
                    </body>
                </html>
                """
                self.wfile.write(content.encode("utf-8"))

            def do_POST(self):  # noqa: N802
                if self.path != "/stop":
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Stopping host VM...")
                try:
                    on_stop()
                except Exception:  # pragma: no cover
                    pass

            def log_message(self, format, *args):  # noqa: A003
                return

        self._server = ThreadingHTTPServer((self._host, self._port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
