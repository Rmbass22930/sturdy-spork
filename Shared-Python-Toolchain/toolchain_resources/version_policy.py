"""Shared version-policy evaluation for languages and package managers."""
from __future__ import annotations

import re

from security_gateway.models import ToolchainVersionPolicyResultRecord
from toolchain_resources.languages import ToolchainLanguageRegistry
from toolchain_resources.package_managers import ToolchainPackageManagerRegistry


_MIN_LANGUAGE_VERSIONS: dict[str, str] = {
    "python": "3.11",
    "nodejs": "18.0",
    "rust": "1.75",
    "go": "1.21",
    "java": "17.0",
    "dotnet": "8.0",
    "ruby": "3.1",
    "php": "8.1",
    "powershell": "7.0",
}

_MIN_PACKAGE_MANAGER_VERSIONS: dict[str, str] = {
    "pip": "23.0",
    "uv": "0.4",
    "poetry": "1.7",
    "npm": "9.0",
    "pnpm": "8.0",
    "yarn": "1.22",
    "cargo": "1.75",
    "go": "1.21",
    "dotnet": "8.0",
    "mvn": "3.8",
    "gradle": "8.0",
    "composer": "2.0",
}


def _parse_version(value: str | None) -> tuple[int, ...] | None:
    if not value:
        return None
    match = re.search(r"(\d+(?:\.\d+)+)", value)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _compare_versions(current: str | None, minimum: str) -> str:
    parsed_current = _parse_version(current)
    parsed_minimum = _parse_version(minimum)
    if parsed_current is None or parsed_minimum is None:
        return "unknown"
    length = max(len(parsed_current), len(parsed_minimum))
    current_parts = parsed_current + (0,) * (length - len(parsed_current))
    minimum_parts = parsed_minimum + (0,) * (length - len(parsed_minimum))
    return "compliant" if current_parts >= minimum_parts else "noncompliant"


class ToolchainVersionPolicyRegistry:
    def __init__(self, languages: ToolchainLanguageRegistry, package_managers: ToolchainPackageManagerRegistry) -> None:
        self.languages = languages
        self.package_managers = package_managers

    def evaluate(self) -> list[ToolchainVersionPolicyResultRecord]:
        results: list[ToolchainVersionPolicyResultRecord] = []
        for language in self.languages.list_languages():
            minimum = _MIN_LANGUAGE_VERSIONS.get(language.language_id)
            if not minimum:
                continue
            status = _compare_versions(language.version, minimum)
            results.append(
                ToolchainVersionPolicyResultRecord(
                    target_id=language.language_id,
                    target_type="language",
                    title=language.title,
                    minimum_version=minimum,
                    current_version=language.version,
                    status=status,
                    summary=(
                        f"{language.title} meets the minimum version {minimum}."
                        if status == "compliant"
                        else f"{language.title} is below the minimum version {minimum}."
                        if status == "noncompliant"
                        else f"{language.title} version could not be evaluated against minimum {minimum}."
                    ),
                )
            )
        for manager in self.package_managers.list_package_managers():
            minimum = _MIN_PACKAGE_MANAGER_VERSIONS.get(manager.manager_id)
            if not minimum:
                continue
            status = _compare_versions(manager.version, minimum)
            results.append(
                ToolchainVersionPolicyResultRecord(
                    target_id=manager.manager_id,
                    target_type="package_manager",
                    title=manager.title,
                    minimum_version=minimum,
                    current_version=manager.version,
                    status=status,
                    summary=(
                        f"{manager.title} meets the minimum version {minimum}."
                        if status == "compliant"
                        else f"{manager.title} is below the minimum version {minimum}."
                        if status == "noncompliant"
                        else f"{manager.title} version could not be evaluated against minimum {minimum}."
                    ),
                )
            )
        return sorted(results, key=lambda item: (item.target_type, item.target_id))

    def get_result(self, target_id: str) -> ToolchainVersionPolicyResultRecord | None:
        for result in self.evaluate():
            if result.target_id == target_id:
                return result
        return None
