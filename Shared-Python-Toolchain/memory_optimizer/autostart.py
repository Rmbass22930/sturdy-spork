"""Automation helpers that combine memory optimization with VM lifecycle."""
from __future__ import annotations

import subprocess
import threading
import time
from typing import Callable, Optional, Sequence

from .control_panel import ControlPanelServer
from .manager import MemoryManager
from .vm_launcher import BaseVMLauncher


class AutoStartOrchestrator:
    def __init__(
        self,
        vm_launcher: BaseVMLauncher,
        *,
        min_free_mb: float = 512.0,
        max_reserve_mb: Optional[float] = None,
        block_size_mb: float = 128.0,
        idle_seconds: float = 120.0,
        sample_interval: float = 5.0,
        vm_wait_free_mb: float = 1024.0,
        vm_wait_timeout: float = 300.0,
        vm_start_delay: float = 5.0,
        enable_control_panel: bool = True,
        control_panel_host: str = "0.0.0.0",
        control_panel_port: int = 8765,
        button_label: str = "Stop Virtual Machine",
        privacy_up_command: Optional[Sequence[str]] = None,
        privacy_check_command: Optional[Sequence[str]] = None,
        privacy_check_retries: int = 5,
        privacy_check_interval: float = 3.0,
        fail_closed: bool = True,
    ) -> None:
        self._manager = MemoryManager(
            min_free_mb=min_free_mb,
            max_reserve_mb=max_reserve_mb,
            block_size_mb=block_size_mb,
            idle_seconds=idle_seconds,
            sample_interval=sample_interval,
        )
        self._launcher = vm_launcher
        self._sample_interval = sample_interval
        self._vm_wait_free_mb = vm_wait_free_mb
        self._vm_wait_timeout = vm_wait_timeout
        self._vm_start_delay = vm_start_delay
        self._privacy_up_command = list(privacy_up_command) if privacy_up_command else None
        self._privacy_check_command = list(privacy_check_command) if privacy_check_command else None
        self._privacy_check_retries = max(1, privacy_check_retries)
        self._privacy_check_interval = max(0.1, privacy_check_interval)
        self._fail_closed = fail_closed
        self._stop = threading.Event()
        self._panel: Optional[ControlPanelServer] = None
        if enable_control_panel:
            self._panel = ControlPanelServer(
                on_stop=self._handle_stop_request,
                host=control_panel_host,
                port=control_panel_port,
                button_label=button_label,
            )

    def stop(self) -> None:
        self._stop.set()
        if self._panel:
            self._panel.stop()
        self._launcher.stop()
        self._manager.stop()

    def run(self, status_callback: Optional[Callable[[dict], None]] = None) -> None:
        if self._panel:
            self._panel.start()
        self._manager.start()
        try:
            self._ensure_privacy_path(status_callback)
            self._wait_for_capacity(status_callback)
            if self._vm_start_delay:
                time.sleep(self._vm_start_delay)
            self._launcher.ensure_running()
            while not self._stop.is_set():
                snapshot = self._manager.status()
                if status_callback:
                    status_callback(snapshot)
                if not self._launcher.running:
                    if getattr(self._launcher, "restart_on_exit", False):
                        self._launcher.ensure_running()
                    else:
                        break
                time.sleep(self._sample_interval)
        finally:
            self.stop()

    def _run_command(self, command: Sequence[str]) -> subprocess.CompletedProcess:
        return subprocess.run([str(part) for part in command], capture_output=True, text=True)

    def _status_message(self, status_callback: Optional[Callable[[dict], None]], message: str) -> None:
        if status_callback:
            status_callback({"message": message})

    def _ensure_privacy_path(self, status_callback: Optional[Callable[[dict], None]]) -> None:
        if self._privacy_up_command:
            self._status_message(status_callback, "Starting privacy route command...")
            up_result = self._run_command(self._privacy_up_command)
            if up_result.returncode != 0:
                details = up_result.stderr.strip() or up_result.stdout.strip() or "privacy up command failed"
                if self._fail_closed:
                    raise RuntimeError(f"Privacy route setup failed: {details}")
                self._status_message(status_callback, f"Privacy setup warning: {details}")

        if not self._privacy_check_command:
            return

        self._status_message(status_callback, "Verifying privacy route...")
        for attempt in range(1, self._privacy_check_retries + 1):
            result = self._run_command(self._privacy_check_command)
            if result.returncode == 0:
                self._status_message(status_callback, "Privacy route check passed.")
                return
            if attempt < self._privacy_check_retries:
                time.sleep(self._privacy_check_interval)

        details = result.stderr.strip() or result.stdout.strip() or "privacy check failed"
        if self._fail_closed:
            raise RuntimeError(f"Privacy route verification failed: {details}")
        self._status_message(status_callback, f"Privacy verification warning: {details}")

    def _handle_stop_request(self) -> None:
        self._stop.set()
        self._launcher.stop()

    def _wait_for_capacity(self, status_callback: Optional[Callable[[dict], None]]) -> None:
        waited = 0.0
        while waited < self._vm_wait_timeout and not self._stop.is_set():
            snapshot = self._manager.status()
            if status_callback:
                status_callback(snapshot)
            if snapshot["available_mb"] >= self._vm_wait_free_mb:
                return
            time.sleep(self._sample_interval)
            waited += self._sample_interval
        if status_callback:
            status_callback({"message": "Timeout waiting for VM capacity"})
