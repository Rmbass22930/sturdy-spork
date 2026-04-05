"""Shared task runner for recurring toolchain work."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Callable

from security_gateway.models import ToolchainJobRecord

if TYPE_CHECKING:
    from toolchain_resources.runtime import ToolchainRuntime


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ToolchainJobRunner:
    def __init__(self, runtime: ToolchainRuntime) -> None:
        self.runtime = runtime

    def _jobs(self) -> dict[str, tuple[str, str, Callable[[], dict[str, Any]]]]:
        return {
            "sync_updates": (
                "Sync toolchain updates",
                "Refresh provider update feeds and apply safe catalog items.",
                lambda: self.runtime.updates.sync(apply_safe_only=True),
            ),
            "evaluate_policy": (
                "Evaluate toolchain policy",
                "Evaluate version policy and enforcement state.",
                lambda: {
                    "version_policy": [item.model_dump(mode="json") for item in self.runtime.version_policy.evaluate()],
                    "policy_enforcement": [
                        item.model_dump(mode="json") for item in self.runtime.policy_enforcement.evaluate()
                    ],
                },
            ),
            "resolve_secrets": (
                "Resolve shared secrets",
                "Resolve configured toolchain secrets and refresh cache metadata.",
                lambda: {
                    "resolutions": [item.model_dump(mode="json") for item in self.runtime.secret_resolver.list_resolutions()]
                },
            ),
            "snapshot_report": (
                "Snapshot toolchain report",
                "Generate a current shared toolchain report snapshot.",
                lambda: self.runtime.reporting.snapshot(),
            ),
        }

    def list_jobs(self) -> list[ToolchainJobRecord]:
        return [
            ToolchainJobRecord(job_id=job_id, title=title, status="ready", summary=summary)
            for job_id, (title, summary, _) in sorted(self._jobs().items())
        ]

    def get_job(self, job_id: str) -> ToolchainJobRecord | None:
        for record in self.list_jobs():
            if record.job_id == job_id:
                return record
        return None

    def run_job(self, job_id: str) -> dict[str, Any]:
        spec = self._jobs().get(job_id)
        if spec is None:
            return {"status": "not_found", "job_id": job_id}
        title, summary, runner = spec
        started_at = _utc_now()
        try:
            result = runner()
            status = "completed"
        except Exception as exc:  # noqa: BLE001
            result = {"error": str(exc)}
            status = "failed"
        return {
            "job": ToolchainJobRecord(
                job_id=job_id,
                title=title,
                status=status,
                summary=summary,
                last_run_at=started_at,
            ).model_dump(mode="json"),
            "result": result,
        }
