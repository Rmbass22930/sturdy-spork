"""Shared language toolchain inventory."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

from security_gateway.models import ToolchainLanguageRecord


@dataclass(frozen=True)
class _LanguageSpec:
    language_id: str
    title: str
    primary_candidates: tuple[str, ...]
    version_args: tuple[str, ...]
    package_managers: tuple[str, ...] = ()
    extra_tools: tuple[str, ...] = ()


_LANGUAGE_SPECS: tuple[_LanguageSpec, ...] = (
    _LanguageSpec(
        language_id="python",
        title="Python",
        primary_candidates=("python", "py"),
        version_args=("--version",),
        package_managers=("pip", "uv", "poetry"),
        extra_tools=("pytest", "mypy", "ruff"),
    ),
    _LanguageSpec(
        language_id="nodejs",
        title="Node.js",
        primary_candidates=("node",),
        version_args=("--version",),
        package_managers=("npm", "pnpm", "yarn", "bun"),
        extra_tools=("npx",),
    ),
    _LanguageSpec(
        language_id="rust",
        title="Rust",
        primary_candidates=("rustc",),
        version_args=("--version",),
        package_managers=("cargo", "rustup"),
    ),
    _LanguageSpec(
        language_id="go",
        title="Go",
        primary_candidates=("go",),
        version_args=("version",),
    ),
    _LanguageSpec(
        language_id="java",
        title="Java",
        primary_candidates=("java",),
        version_args=("-version",),
        package_managers=("mvn", "gradle"),
        extra_tools=("javac",),
    ),
    _LanguageSpec(
        language_id="dotnet",
        title=".NET",
        primary_candidates=("dotnet",),
        version_args=("--version",),
        extra_tools=("msbuild",),
    ),
    _LanguageSpec(
        language_id="ruby",
        title="Ruby",
        primary_candidates=("ruby",),
        version_args=("--version",),
        package_managers=("gem", "bundle"),
    ),
    _LanguageSpec(
        language_id="php",
        title="PHP",
        primary_candidates=("php",),
        version_args=("--version",),
        package_managers=("composer",),
    ),
    _LanguageSpec(
        language_id="c_cpp",
        title="C/C++",
        primary_candidates=("cl", "gcc", "clang"),
        version_args=("--version",),
        package_managers=("vcpkg", "conan"),
        extra_tools=("cmake", "ninja", "make"),
    ),
    _LanguageSpec(
        language_id="powershell",
        title="PowerShell",
        primary_candidates=("pwsh", "powershell"),
        version_args=("--version",),
    ),
)


def _resolve_command(candidates: tuple[str, ...]) -> tuple[str | None, str | None]:
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return candidate, resolved
    return None, None


def _command_available(command: str) -> bool:
    return shutil.which(command) is not None


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


class ToolchainLanguageRegistry:
    def list_languages(self) -> list[ToolchainLanguageRecord]:
        records: list[ToolchainLanguageRecord] = []
        for spec in _LANGUAGE_SPECS:
            primary_command, executable_path = _resolve_command(spec.primary_candidates)
            package_managers = [tool for tool in spec.package_managers if _command_available(tool)]
            extra_tools = {tool: shutil.which(tool) for tool in spec.extra_tools if _command_available(tool)}
            records.append(
                ToolchainLanguageRecord(
                    language_id=spec.language_id,
                    title=spec.title,
                    status="available" if executable_path else "missing",
                    detected=bool(executable_path),
                    primary_command=primary_command,
                    executable_path=executable_path,
                    version=_read_version(primary_command, spec.version_args) if primary_command else None,
                    package_managers=package_managers,
                    metadata={"extra_tools": extra_tools},
                )
            )
        return records

    def get_language(self, language_id: str) -> ToolchainLanguageRecord | None:
        for record in self.list_languages():
            if record.language_id == language_id:
                return record
        return None
