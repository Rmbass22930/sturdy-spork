"""Launchers for different VM providers."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional, Protocol, Sequence

from . import hyperv


class BaseVMLauncher(Protocol):
    @property
    def running(self) -> bool: ...

    def ensure_running(self) -> None: ...

    def stop(self) -> None: ...

    def poll(self) -> Optional[int]: ...


@dataclass
class CommandVMLauncher:
    command: Sequence[str]
    restart_on_exit: bool = True
    _process: Optional[subprocess.Popen] = None

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def ensure_running(self) -> None:
        if not self.command:
            raise ValueError("VM command cannot be empty")
        if self.running:
            return
        self._process = subprocess.Popen([str(arg) for arg in self.command])

    def stop(self) -> None:
        if not self._process:
            return
        if self.running:
            self._process.terminate()
            try:
                self._process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process = None

    def poll(self) -> Optional[int]:
        return self._process.poll() if self._process else None


@dataclass
class HyperVVMLauncher:
    vm_name: str
    restart_on_exit: bool = True

    @property
    def running(self) -> bool:
        state = hyperv.get_vm_state(self.vm_name)
        return state == "Running"

    def ensure_running(self) -> None:
        hyperv.start_vm(self.vm_name)

    def stop(self) -> None:
        hyperv.stop_vm(self.vm_name)

    def poll(self) -> Optional[int]:
        # Hyper-V doesn't expose process ID; return 0 if running else 1
        return 0 if self.running else 1
