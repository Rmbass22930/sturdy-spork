"""Low-level Windows memory management helpers."""
from __future__ import annotations

import ctypes
import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional, TypedDict

kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

# Constants from Win32 API.
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
MB = 1024 * 1024


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
kernel32.GlobalMemoryStatusEx.restype = ctypes.c_bool
kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
kernel32.VirtualFree.restype = ctypes.c_bool


class MemoryStats(TypedDict):
    total_mb: float
    available_mb: float
    load_percent: float


def get_memory_stats() -> MemoryStats:
    """Return physical memory stats in megabytes."""
    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError()
    total_mb = status.ullTotalPhys / MB
    available_mb = status.ullAvailPhys / MB
    load_percent = float(status.dwMemoryLoad)
    return {"total_mb": total_mb, "available_mb": available_mb, "load_percent": load_percent}


@dataclass
class MemorySegment:
    """Tracks an allocated virtual memory region."""

    id: str
    size_bytes: int
    address: int
    tag: Optional[str] = None
    created: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)

    def touch(self) -> None:
        self.last_used = time.time()


class MemoryManager:
    """Reserves and releases blocks of RAM while respecting system pressure."""

    def __init__(
        self,
        *,
        min_free_mb: float = 512.0,
        max_reserve_mb: Optional[float] = None,
        block_size_mb: float = 128.0,
        idle_seconds: float = 60.0,
        sample_interval: float = 5.0,
    ) -> None:
        if block_size_mb <= 0:
            raise ValueError("block_size_mb must be positive")
        self.min_free_mb = min_free_mb
        self.max_reserve_mb = max_reserve_mb
        self.block_size_mb = block_size_mb
        self.idle_seconds = idle_seconds
        self.sample_interval = sample_interval
        self._segments: Dict[str, MemorySegment] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_error: Optional[str] = None

    def __enter__(self) -> "MemoryManager":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._worker, name="memory-optimizer", daemon=True)
        self._thread.start()

    def stop(self, release_segments: bool = True) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.sample_interval * 2)
        if release_segments:
            self.release_all()

    def reserve(self, mb: float, *, tag: Optional[str] = None) -> list[MemorySegment]:
        """Reserve an explicit amount of RAM immediately."""
        if mb <= 0:
            raise ValueError("mb must be positive")
        blocks = math.ceil(mb / self.block_size_mb)
        segments: list[MemorySegment] = []
        for _ in range(blocks):
            segments.append(self._allocate_block(self.block_size_mb, tag=tag))
        return segments

    def release(self, segment_id: str) -> bool:
        with self._lock:
            segment = self._segments.pop(segment_id, None)
        if not segment:
            return False
        self._free(segment)
        return True

    def release_all(self) -> int:
        with self._lock:
            segments = list(self._segments.values())
            self._segments.clear()
        for segment in segments:
            self._free(segment)
        return len(segments)

    def status(self) -> Dict[str, float]:
        stats = get_memory_stats()
        with self._lock:
            reserved = sum(seg.size_bytes for seg in self._segments.values()) / MB
            segments = len(self._segments)
        return {
            "total_mb": stats["total_mb"],
            "available_mb": stats["available_mb"],
            "reserved_mb": reserved,
            "segments": segments,
            "load_percent": stats["load_percent"],
            "last_error": self._last_error or "",
        }

    def touch(self, segment_id: str) -> None:
        with self._lock:
            if segment_id in self._segments:
                self._segments[segment_id].touch()

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                self._rebalance()
            except Exception as exc:  # noqa: BLE001
                self._last_error = str(exc)
            self._stop.wait(self.sample_interval)

    def _rebalance(self) -> None:
        stats = get_memory_stats()
        desired_growth = stats["available_mb"] - self.min_free_mb
        with self._lock:
            reserved_mb = sum(seg.size_bytes for seg in self._segments.values()) / MB
        available_headroom = desired_growth
        if self.max_reserve_mb is not None:
            available_headroom = min(available_headroom, self.max_reserve_mb - reserved_mb)

        if available_headroom >= self.block_size_mb:
            blocks = int(available_headroom // self.block_size_mb)
            for _ in range(blocks):
                self._allocate_block(self.block_size_mb)
            return

        # Otherwise release idle blocks until the free floor is respected.
        self._release_until_safe(stats["available_mb"])

    def _release_until_safe(self, available_mb: float) -> None:
        deadline = time.time() - self.idle_seconds
        while available_mb < self.min_free_mb:
            segment = self._oldest_segment(deadline)
            if not segment:
                break
            self.release(segment.id)
            available_mb = get_memory_stats()["available_mb"]

    def _oldest_segment(self, cutoff: float) -> Optional[MemorySegment]:
        with self._lock:
            candidates = [seg for seg in self._segments.values() if seg.last_used <= cutoff]
            if not candidates and self._segments:
                candidates = list(self._segments.values())
            if not candidates:
                return None
            candidates.sort(key=lambda seg: seg.last_used)
            return candidates[0]

    def _allocate_block(self, mb: float, *, tag: Optional[str] = None) -> MemorySegment:
        size = int(mb * MB)
        ptr = kernel32.VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not ptr:
            raise ctypes.WinError()
        address = ctypes.cast(ptr, ctypes.c_void_p).value
        if address is None:
            raise ctypes.WinError()
        segment = MemorySegment(id=uuid.uuid4().hex, size_bytes=size, address=int(address), tag=tag)
        with self._lock:
            self._segments[segment.id] = segment
        return segment

    def _free(self, segment: MemorySegment) -> None:
        if segment.address:
            ptr = ctypes.c_void_p(segment.address)
            if not kernel32.VirtualFree(ptr, 0, MEM_RELEASE):
                raise ctypes.WinError()
