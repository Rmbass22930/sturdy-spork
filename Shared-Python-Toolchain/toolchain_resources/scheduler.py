"""Persisted scheduler for shared toolchain jobs."""
from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from security_gateway.models import ToolchainScheduleRecord, ToolchainSchedulerRuntimeRecord
from toolchain_resources.jobs import ToolchainJobRunner


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ToolchainScheduler:
    def __init__(self, state_path: str | Path, jobs: ToolchainJobRunner) -> None:
        self._state_path = Path(state_path)
        self.jobs = jobs
        self._runner_lock = threading.Lock()
        self._runner: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._poll_seconds = 60.0
        self._started_at: datetime | None = None
        self._last_tick_at: datetime | None = None
        self._last_run_count = 0

    def _read_state(self) -> dict[str, Any]:
        if not self._state_path.exists():
            return {"schedules": [], "recent_runs": []}
        try:
            return json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"schedules": [], "recent_runs": []}

    def _write_state(self, payload: dict[str, Any]) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def list_schedules(self) -> list[ToolchainScheduleRecord]:
        payload = self._read_state()
        schedules = payload.get("schedules") or []
        return [ToolchainScheduleRecord.model_validate(item) for item in schedules if isinstance(item, dict)]

    def list_recent_runs(self, *, limit: int = 10) -> list[dict[str, Any]]:
        payload = self._read_state()
        runs = payload.get("recent_runs") or []
        records = [item for item in runs if isinstance(item, dict)]
        return records[:limit]

    def get_schedule(self, schedule_id: str) -> ToolchainScheduleRecord | None:
        for schedule in self.list_schedules():
            if schedule.schedule_id == schedule_id:
                return schedule
        return None

    def upsert_schedule(
        self,
        job_id: str,
        *,
        interval_minutes: int,
        enabled: bool = True,
    ) -> ToolchainScheduleRecord:
        job = self.jobs.get_job(job_id)
        title = job.title if job is not None else job_id
        now = _utc_now()
        schedule = ToolchainScheduleRecord(
            schedule_id=job_id,
            job_id=job_id,
            title=title,
            status="active" if enabled else "paused",
            interval_minutes=interval_minutes,
            next_run_at=now + timedelta(minutes=interval_minutes),
            last_run_at=None,
            last_status="ready",
        )
        existing = [item for item in self.list_schedules() if item.schedule_id != job_id]
        existing.append(schedule)
        self._write_state({"schedules": [item.model_dump(mode="json") for item in existing]})
        return schedule

    def remove_schedule(self, schedule_id: str) -> bool:
        schedules = self.list_schedules()
        remaining = [item for item in schedules if item.schedule_id != schedule_id]
        if len(remaining) == len(schedules):
            return False
        self._write_state({"schedules": [item.model_dump(mode="json") for item in remaining]})
        return True

    def run_due_jobs(self, *, now: datetime | None = None) -> dict[str, Any]:
        effective_now = now or _utc_now()
        payload = self._read_state()
        schedules = [ToolchainScheduleRecord.model_validate(item) for item in (payload.get("schedules") or []) if isinstance(item, dict)]
        recent_runs = [item for item in (payload.get("recent_runs") or []) if isinstance(item, dict)]
        updated: list[ToolchainScheduleRecord] = []
        results: list[dict[str, Any]] = []
        for schedule in schedules:
            if schedule.status != "active":
                updated.append(schedule)
                continue
            if schedule.next_run_at and schedule.next_run_at > effective_now:
                updated.append(schedule)
                continue
            result = self.jobs.run_job(schedule.job_id)
            job_payload = result.get("job")
            last_status = str(job_payload.get("status") or "completed") if isinstance(job_payload, dict) else "completed"
            updated.append(
                schedule.model_copy(
                    update={
                        "last_run_at": effective_now,
                        "last_status": last_status,
                        "next_run_at": effective_now + timedelta(minutes=schedule.interval_minutes),
                    }
                )
            )
            results.append(result)
            job_payload = result.get("job") if isinstance(result, dict) else {}
            recent_runs.insert(
                0,
                {
                    "schedule_id": schedule.schedule_id,
                    "job_id": schedule.job_id,
                    "title": schedule.title,
                    "status": last_status,
                    "ran_at": effective_now.isoformat(),
                },
            )
        self._write_state(
            {
                "schedules": [item.model_dump(mode="json") for item in updated],
                "recent_runs": recent_runs[:25],
            }
        )
        self._last_tick_at = effective_now
        self._last_run_count = len(results)
        return {"ran": len(results), "results": results}

    def get_runtime_status(self) -> ToolchainSchedulerRuntimeRecord:
        running = self._runner is not None and self._runner.is_alive()
        return ToolchainSchedulerRuntimeRecord(
            enabled=running,
            running=running,
            poll_seconds=self._poll_seconds,
            started_at=self._started_at,
            last_tick_at=self._last_tick_at,
            last_run_count=self._last_run_count,
            summary=(
                f"Background scheduler is running every {self._poll_seconds:.0f} seconds."
                if running
                else "Background scheduler is stopped."
            ),
            metadata={"thread_name": self._runner.name if running and self._runner is not None else None},
        )

    def start_background_runner(self, *, poll_seconds: float = 60.0) -> ToolchainSchedulerRuntimeRecord:
        with self._runner_lock:
            if self._runner is not None and self._runner.is_alive():
                self._poll_seconds = poll_seconds
                return self.get_runtime_status()
            self._poll_seconds = max(0.01, poll_seconds)
            self._stop_event = threading.Event()
            self._started_at = _utc_now()
            self._runner = threading.Thread(target=self._run_forever, name="toolchain-scheduler", daemon=True)
            self._runner.start()
            return self.get_runtime_status()

    def stop_background_runner(self) -> ToolchainSchedulerRuntimeRecord:
        with self._runner_lock:
            runner = self._runner
            if runner is None or not runner.is_alive():
                self._runner = None
                return self.get_runtime_status()
            self._stop_event.set()
            runner.join(timeout=max(1.0, self._poll_seconds + 1.0))
            self._runner = None
            return self.get_runtime_status()

    def _run_forever(self) -> None:
        while not self._stop_event.wait(self._poll_seconds):
            self.run_due_jobs()
