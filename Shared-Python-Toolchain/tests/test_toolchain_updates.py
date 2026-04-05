from __future__ import annotations

from pathlib import Path
from typing import cast

from security_gateway.models import LinearAsksFormUpsert
from toolchain_resources.linear_forms import LinearAsksFormRegistry
from toolchain_resources.updates import ToolchainUpdateRegistry


def test_toolchain_update_registry_syncs_docker_and_linear_sources(tmp_path: Path) -> None:
    forms_path = tmp_path / "linear_forms.json"
    updates_path = tmp_path / "toolchain_updates.json"
    forms = LinearAsksFormRegistry(forms_path)
    forms.upsert_form(
        LinearAsksFormUpsert(
            form_key="bug-report",
            title="Bug report",
            url="https://linear.app/example/forms/bug-report",
        )
    )
    registry = ToolchainUpdateRegistry(updates_path, linear_forms_path=forms_path)

    result = registry.sync(apply_safe_only=True)
    updates = registry.list_updates()

    assert cast(int, result["discovered"]) >= 2
    assert any(update.update_id == "docker:offload-ga-2026-04-02" for update in updates)
    assert any(update.update_id == "linear_form:bug-report" for update in updates)
    assert all(update.status == "applied" for update in updates)


def test_toolchain_update_registry_marks_new_update_seen(tmp_path: Path) -> None:
    registry = ToolchainUpdateRegistry(tmp_path / "toolchain_updates.json", linear_forms_path=tmp_path / "linear_forms.json")
    registry.sync(apply_safe_only=False)

    update = registry.mark_seen("docker:offload-ga-2026-04-02")

    assert update is not None
    assert update.status == "seen"
