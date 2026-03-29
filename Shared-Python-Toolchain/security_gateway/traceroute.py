"""Network back-trace helper for suspicious activity."""
from __future__ import annotations

import platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from .url_safety import validate_public_host_or_ip

try:  # pragma: no cover - Windows-only dependency
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None  # type: ignore[assignment]


@dataclass
class TraceRouteResult:
    target: str
    command: List[str]
    exit_code: Optional[int]
    output: str
    error: Optional[str] = None
    declined: bool = False


class TraceRouteRunner:
    """Runs traceroute/tracert with operator confirmation to avoid false positives."""

    def __init__(
        self,
        max_hops: int = 20,
        timeout_seconds: int = 30,
        confirm_before_trace: bool = True,
        show_popup_results: bool = True,
        preview_lines: int = 6,
    ):
        self.max_hops = max_hops
        self.timeout_seconds = timeout_seconds
        self.confirm_before_trace = confirm_before_trace
        self.show_popup_results = show_popup_results
        self.preview_lines = preview_lines

    def trace(self, target: str | None, context: Optional[str] = None) -> Optional[TraceRouteResult]:
        if not target:
            return None
        try:
            normalized_target = validate_public_host_or_ip(target, label="Traceroute target")
        except ValueError as exc:
            return TraceRouteResult(
                target=str(target),
                command=[],
                exit_code=None,
                output="",
                error=str(exc),
            )
        command = self._build_command(normalized_target)
        if not command:
            return TraceRouteResult(
                target=normalized_target,
                command=[],
                exit_code=None,
                output="",
                error="No traceroute executable available on this platform.",
            )
        if self.confirm_before_trace and not self._confirm_trace(normalized_target, context):
            return TraceRouteResult(
                target=normalized_target,
                command=command,
                exit_code=None,
                output="",
                error="Operator declined traceroute",
                declined=True,
            )
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            result = TraceRouteResult(
                target=normalized_target,
                command=command,
                exit_code=completed.returncode,
                output=completed.stdout.strip(),
                error=completed.stderr.strip() or None,
            )
            if self.show_popup_results:
                preview = self._preview_output(result)
                self._show_popup("SecurityGateway Traceroute", preview)
            return result
        except FileNotFoundError:
            return TraceRouteResult(
                target=normalized_target,
                command=command,
                exit_code=None,
                output="",
                error="Traceroute executable not found.",
            )
        except subprocess.TimeoutExpired as exc:
            return TraceRouteResult(
                target=normalized_target,
                command=command,
                exit_code=None,
                output=exc.stdout.strip() if exc.stdout else "",
                error=f"Traceroute timed out after {self.timeout_seconds}s",
            )

    def _build_command(self, target: str) -> List[str] | None:
        system = platform.system().lower()
        if "windows" in system:
            if shutil.which("tracert"):
                return ["tracert", "-d", "-h", str(self.max_hops), target]
        else:
            binary = shutil.which("traceroute") or shutil.which("tracepath")
            if binary:
                return [binary, "-m", str(self.max_hops), target]
        return None

    def _confirm_trace(self, target: str, context: Optional[str]) -> bool:
        if not self.confirm_before_trace:
            return True
        message = f"High-risk activity detected from {target}.\n"
        if context:
            message += f"Context: {context}\n"
        message += "Run traceroute now?"
        response = self._message_box(message, title="SecurityGateway - Confirm trace", flags=0x00000004)  # MB_YESNO
        if response == 6:  # IDYES
            return True
        if response == 7:  # IDNO
            return False
        return False

    def _preview_output(self, result: TraceRouteResult) -> str:
        if not result.output:
            return result.error or "Traceroute completed with no output."
        lines = result.output.splitlines()
        preview = "\n".join(lines[: self.preview_lines])
        if len(lines) > self.preview_lines:
            preview += "\n..."
        return preview

    def _show_popup(self, title: str, message: str) -> None:
        self._message_box(message, title=title, flags=0x00000040)  # MB_ICONINFORMATION

    def _message_box(self, message: str, title: str, flags: int) -> int:
        if ctypes and hasattr(ctypes, "windll"):
            try:
                return ctypes.windll.user32.MessageBoxW(0, message, title, flags)
            except Exception:  # pragma: no cover - fallback if user32 fails
                pass
        print(f"{title}: {message}")
        return 6  # Pretend "Yes" for non-Windows consoles
