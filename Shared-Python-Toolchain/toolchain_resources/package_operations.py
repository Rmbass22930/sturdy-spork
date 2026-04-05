"""Shared package-manager command planning and optional execution."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from security_gateway.models import ToolchainPackageOperationRecord
from toolchain_resources.package_managers import ToolchainPackageManagerRegistry


_OPERATION_TEMPLATES: dict[str, dict[str, list[str]]] = {
    "pip": {
        "install_deps": ["pip", "install", "-r", "requirements.txt"],
        "update_self": ["pip", "install", "--upgrade", "pip"],
        "audit": ["pip", "check"],
    },
    "uv": {
        "install_deps": ["uv", "sync"],
        "update_lock": ["uv", "lock"],
        "audit": ["uv", "pip", "check"],
    },
    "poetry": {
        "install_deps": ["poetry", "install"],
        "update_lock": ["poetry", "lock"],
        "audit": ["poetry", "check"],
    },
    "npm": {
        "install_deps": ["npm", "install"],
        "update_deps": ["npm", "update"],
        "audit": ["npm", "audit"],
    },
    "pnpm": {
        "install_deps": ["pnpm", "install"],
        "update_deps": ["pnpm", "update"],
        "audit": ["pnpm", "audit"],
    },
    "yarn": {
        "install_deps": ["yarn", "install"],
        "update_deps": ["yarn", "upgrade"],
        "audit": ["yarn", "audit"],
    },
    "cargo": {
        "install_deps": ["cargo", "fetch"],
        "build": ["cargo", "build"],
        "test": ["cargo", "test"],
    },
    "go": {
        "install_deps": ["go", "mod", "download"],
        "build": ["go", "build", "./..."],
        "test": ["go", "test", "./..."],
    },
    "dotnet": {
        "install_deps": ["dotnet", "restore"],
        "build": ["dotnet", "build"],
        "test": ["dotnet", "test"],
    },
    "mvn": {
        "install_deps": ["mvn", "dependency:resolve"],
        "build": ["mvn", "package"],
        "test": ["mvn", "test"],
    },
    "gradle": {
        "install_deps": ["gradle", "dependencies"],
        "build": ["gradle", "build"],
        "test": ["gradle", "test"],
    },
    "composer": {
        "install_deps": ["composer", "install"],
        "update_deps": ["composer", "update"],
        "audit": ["composer", "audit"],
    },
    "bundle": {
        "install_deps": ["bundle", "install"],
        "update_deps": ["bundle", "update"],
        "audit": ["bundle", "audit"],
    },
    "gem": {
        "update_self": ["gem", "update", "--system"],
        "audit": ["gem", "list"],
    },
}


class ToolchainPackageOperations:
    def __init__(self, package_managers: ToolchainPackageManagerRegistry) -> None:
        self.package_managers = package_managers

    def list_operations(self, manager_id: str | None = None) -> list[ToolchainPackageOperationRecord]:
        records: list[ToolchainPackageOperationRecord] = []
        managers = self.package_managers.list_package_managers()
        for manager in managers:
            if manager_id and manager.manager_id != manager_id:
                continue
            templates = _OPERATION_TEMPLATES.get(manager.manager_id, {})
            for operation, command in templates.items():
                records.append(
                    ToolchainPackageOperationRecord(
                        manager_id=manager.manager_id,
                        operation=operation,
                        title=f"{manager.title} {operation.replace('_', ' ')}",
                        command=command,
                        supported=manager.detected,
                        dry_run=True,
                        metadata={"detected": manager.detected, "version": manager.version},
                    )
                )
        return sorted(records, key=lambda item: (item.manager_id, item.operation))

    def build_operation(self, manager_id: str, operation: str) -> ToolchainPackageOperationRecord | None:
        for record in self.list_operations(manager_id):
            if record.operation == operation:
                return record
        return None

    def run_operation(
        self,
        manager_id: str,
        operation: str,
        *,
        project_path: str | Path = ".",
        execute: bool = False,
        timeout_seconds: float = 60.0,
    ) -> dict[str, Any]:
        record = self.build_operation(manager_id, operation)
        if record is None:
            return {"status": "not_found", "manager_id": manager_id, "operation": operation}
        result = {
            "operation": record.model_dump(mode="json"),
            "cwd": str(Path(project_path)),
            "executed": execute,
        }
        if not execute:
            return result
        completed = subprocess.run(
            record.command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            cwd=str(Path(project_path)),
        )
        result.update(
            {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        )
        return result
