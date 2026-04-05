"""Shared package-manager inventory for the toolchain."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from security_gateway.models import ToolchainPackageManagerRecord


@dataclass(frozen=True)
class _PackageManagerSpec:
    manager_id: str
    title: str
    command: str
    version_args: tuple[str, ...]
    related_languages: tuple[str, ...]


_PACKAGE_MANAGER_SPECS: tuple[_PackageManagerSpec, ...] = (
    _PackageManagerSpec("pip", "pip", "pip", ("--version",), ("python",)),
    _PackageManagerSpec("uv", "uv", "uv", ("--version",), ("python",)),
    _PackageManagerSpec("poetry", "Poetry", "poetry", ("--version",), ("python",)),
    _PackageManagerSpec("npm", "npm", "npm", ("--version",), ("nodejs",)),
    _PackageManagerSpec("pnpm", "pnpm", "pnpm", ("--version",), ("nodejs",)),
    _PackageManagerSpec("yarn", "Yarn", "yarn", ("--version",), ("nodejs",)),
    _PackageManagerSpec("bun", "Bun", "bun", ("--version",), ("nodejs",)),
    _PackageManagerSpec("cargo", "Cargo", "cargo", ("--version",), ("rust",)),
    _PackageManagerSpec("go", "Go", "go", ("version",), ("go",)),
    _PackageManagerSpec("mvn", "Maven", "mvn", ("--version",), ("java",)),
    _PackageManagerSpec("gradle", "Gradle", "gradle", ("--version",), ("java",)),
    _PackageManagerSpec("dotnet", ".NET CLI", "dotnet", ("--version",), ("dotnet",)),
    _PackageManagerSpec("gem", "RubyGems", "gem", ("--version",), ("ruby",)),
    _PackageManagerSpec("bundle", "Bundler", "bundle", ("--version",), ("ruby",)),
    _PackageManagerSpec("composer", "Composer", "composer", ("--version",), ("php",)),
    _PackageManagerSpec("vcpkg", "vcpkg", "vcpkg", ("version",), ("c_cpp",)),
    _PackageManagerSpec("conan", "Conan", "conan", ("--version",), ("c_cpp",)),
)


def _read_version(command: str, version_args: tuple[str, ...]) -> str | None:
    try:
        result = subprocess.run(
            [command, *version_args],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout or result.stderr or "").strip().splitlines()
    return output[0].strip() if output else None


class ToolchainPackageManagerRegistry:
    def list_package_managers(self) -> list[ToolchainPackageManagerRecord]:
        records: list[ToolchainPackageManagerRecord] = []
        for spec in _PACKAGE_MANAGER_SPECS:
            executable_path = shutil.which(spec.command)
            records.append(
                ToolchainPackageManagerRecord(
                    manager_id=spec.manager_id,
                    title=spec.title,
                    status="available" if executable_path else "missing",
                    detected=bool(executable_path),
                    executable_path=executable_path,
                    version=_read_version(spec.command, spec.version_args) if executable_path else None,
                    related_languages=list(spec.related_languages),
                )
            )
        return records

    def get_package_manager(self, manager_id: str) -> ToolchainPackageManagerRecord | None:
        for record in self.list_package_managers():
            if record.manager_id == manager_id:
                return record
        return None
