"""Provider scaffolding helpers for new shared toolchain integrations."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toolchain_resources.provider_templates import ToolchainProviderTemplateRegistry


class ToolchainProviderScaffolder:
    def __init__(self, templates: ToolchainProviderTemplateRegistry) -> None:
        self.templates = templates

    def scaffold(self, provider_id: str, target_dir: str | Path, *, write: bool = False) -> dict[str, Any] | None:
        rendered = self.templates.render_template(provider_id)
        if rendered is None:
            return None
        target = Path(target_dir)
        files = {
            "manifest.json": json.dumps(rendered["manifest"], indent=2, sort_keys=True),
            f"{provider_id}_provider.py": (
                '"""Scaffolded provider module."""\n'
                "from __future__ import annotations\n\n"
                f'PROVIDER_ID = "{provider_id}"\n'
            ),
            f"test_{provider_id}_provider.py": (
                '"""Scaffolded provider tests."""\n'
                "from __future__ import annotations\n\n"
                f"def test_{provider_id}_provider_placeholder() -> None:\n"
                "    assert True\n"
            ),
        }
        if write:
            target.mkdir(parents=True, exist_ok=True)
            for relative_path, content in files.items():
                (target / relative_path).write_text(content, encoding="utf-8")
        return {
            "provider_id": provider_id,
            "target_dir": str(target),
            "written": write,
            "files": sorted(files.keys()),
            "manifest": rendered["manifest"],
        }
