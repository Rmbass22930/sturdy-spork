from __future__ import annotations

from pathlib import Path

from security_gateway.models import LinearAsksFormUpsert
from toolchain_resources.linear_forms import LinearAsksFormRegistry


def test_linear_asks_form_registry_persists_and_filters(tmp_path: Path) -> None:
    registry = LinearAsksFormRegistry(tmp_path / "linear_forms.json")

    enabled = registry.upsert_form(
        LinearAsksFormUpsert(
            form_key="bug-report",
            title="Bug report",
            url="https://linear.app/example/forms/bug-report",
            category="Engineering",
            team="Platform",
        )
    )
    disabled = registry.upsert_form(
        LinearAsksFormUpsert(
            form_key="it-help",
            title="IT help",
            url="https://linear.app/example/forms/it-help",
            enabled=False,
        )
    )

    visible = registry.list_forms()
    all_forms = registry.list_forms(include_disabled=True)

    assert enabled.form_key == "bug-report"
    assert disabled.form_key == "it-help"
    assert [form.form_key for form in visible] == ["bug-report"]
    assert sorted(form.form_key for form in all_forms) == ["bug-report", "it-help"]
