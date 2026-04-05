"""Project and dependency graph detection for the shared toolchain."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from security_gateway.models import ToolchainProjectRecord


_MANIFEST_PATTERNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("python", "pyproject.toml", ("uv", "poetry", "pip")),
    ("python", "requirements.txt", ("pip",)),
    ("nodejs", "package.json", ("npm", "pnpm", "yarn", "bun")),
    ("rust", "Cargo.toml", ("cargo",)),
    ("go", "go.mod", ("go",)),
    ("java", "pom.xml", ("mvn",)),
    ("java", "build.gradle", ("gradle",)),
    ("java", "build.gradle.kts", ("gradle",)),
    ("dotnet", "*.sln", ("dotnet",)),
    ("dotnet", "*.csproj", ("dotnet",)),
    ("php", "composer.json", ("composer",)),
    ("ruby", "Gemfile", ("bundle", "gem")),
)


class ToolchainProjectRegistry:
    def detect_projects(self, root_path: str | Path = ".") -> list[ToolchainProjectRecord]:
        root = Path(root_path).resolve()
        project_map: dict[Path, dict[str, Any]] = {}
        for ecosystem, pattern, managers in _MANIFEST_PATTERNS:
            for path in root.rglob(pattern):
                project_root = path.parent
                slot = project_map.setdefault(
                    project_root,
                    {
                        "ecosystems": set(),
                        "manifests": set(),
                        "package_manager_ids": set(),
                        "dependency_files": set(),
                    },
                )
                slot["ecosystems"].add(ecosystem)
                slot["manifests"].add(path.name)
                slot["package_manager_ids"].update(managers)
                slot["dependency_files"].add(str(path.relative_to(project_root)))
        records: list[ToolchainProjectRecord] = []
        for project_root, payload in sorted(project_map.items(), key=lambda item: str(item[0])):
            records.append(
                ToolchainProjectRecord(
                    project_id=str(project_root).replace("\\", "/"),
                    root_path=str(project_root),
                    title=project_root.name or str(project_root),
                    ecosystems=sorted(payload["ecosystems"]),
                    manifests=sorted(payload["manifests"]),
                    package_manager_ids=sorted(payload["package_manager_ids"]),
                    dependency_files=sorted(payload["dependency_files"]),
                    metadata={"relative_root": str(project_root.relative_to(root)) if project_root != root else "."},
                )
            )
        return records

    def get_project(self, project_id: str, root_path: str | Path = ".") -> ToolchainProjectRecord | None:
        for record in self.detect_projects(root_path):
            if record.project_id == project_id or record.root_path == project_id:
                return record
        return None
