"""Health checks for shared language toolchains."""
from __future__ import annotations

from datetime import UTC, datetime

from security_gateway.models import ToolchainLanguageHealthRecord
from toolchain_resources.languages import ToolchainLanguageRegistry


class ToolchainLanguageHealthRegistry:
    def __init__(self, languages: ToolchainLanguageRegistry) -> None:
        self.languages = languages

    def list_checks(self) -> list[ToolchainLanguageHealthRecord]:
        checked_at = datetime.now(UTC)
        checks: list[ToolchainLanguageHealthRecord] = []
        for language in self.languages.list_languages():
            extra_tools = dict(language.metadata.get("extra_tools") or {})
            status = "ok" if language.detected else "warning"
            summary = (
                f"{language.title} is available via {language.primary_command}."
                if language.detected
                else f"{language.title} was not detected on PATH."
            )
            checks.append(
                ToolchainLanguageHealthRecord(
                    language_id=language.language_id,
                    title=language.title,
                    status=status,
                    summary=summary,
                    checked_at=checked_at,
                    metadata={
                        "primary_command": language.primary_command,
                        "version": language.version,
                        "package_managers": list(language.package_managers),
                        "extra_tools": extra_tools,
                    },
                )
            )
        return checks

    def get_check(self, language_id: str) -> ToolchainLanguageHealthRecord | None:
        for check in self.list_checks():
            if check.language_id == language_id:
                return check
        return None
