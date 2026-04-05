"""Provisioning guidance for missing toolchain components."""
from __future__ import annotations

from toolchain_resources.languages import ToolchainLanguageRegistry
from toolchain_resources.package_managers import ToolchainPackageManagerRegistry
from security_gateway.models import ToolchainProvisioningActionRecord


_LANGUAGE_INSTALL_HINTS: dict[str, list[str]] = {
    "python": ["winget install Python.Python.3.13"],
    "nodejs": ["winget install OpenJS.NodeJS.LTS"],
    "rust": ["winget install Rustlang.Rustup"],
    "go": ["winget install GoLang.Go"],
    "java": ["winget install Microsoft.OpenJDK.21"],
    "dotnet": ["winget install Microsoft.DotNet.SDK.8"],
    "ruby": ["winget install RubyInstallerTeam.RubyWithDevKit.3.2"],
    "php": ["winget install PHP.PHP"],
    "powershell": ["winget install Microsoft.PowerShell"],
}

_PACKAGE_MANAGER_INSTALL_HINTS: dict[str, list[str]] = {
    "uv": ["pip install uv"],
    "poetry": ["pip install poetry"],
    "pnpm": ["npm install -g pnpm"],
    "yarn": ["npm install -g yarn"],
    "bun": ["powershell -c \"irm bun.sh/install.ps1 | iex\""],
    "mvn": ["winget install Apache.Maven"],
    "gradle": ["winget install Gradle.Gradle"],
    "composer": ["winget install Composer.Composer"],
    "vcpkg": ["git clone https://github.com/microsoft/vcpkg && .\\vcpkg\\bootstrap-vcpkg.bat"],
    "conan": ["pip install conan"],
}


class ToolchainProvisioningRegistry:
    def __init__(self, languages: ToolchainLanguageRegistry, package_managers: ToolchainPackageManagerRegistry) -> None:
        self.languages = languages
        self.package_managers = package_managers

    def list_actions(self) -> list[ToolchainProvisioningActionRecord]:
        actions: list[ToolchainProvisioningActionRecord] = []
        for language in self.languages.list_languages():
            hints = _LANGUAGE_INSTALL_HINTS.get(language.language_id, [])
            verify_commands = [f"{language.primary_command} --version"] if language.primary_command else []
            actions.append(
                ToolchainProvisioningActionRecord(
                    target_id=language.language_id,
                    target_type="language",
                    title=language.title,
                    status="ready" if language.detected else "pending",
                    summary=(
                        f"{language.title} is installed."
                        if language.detected
                        else f"{language.title} is missing and should be installed."
                    ),
                    install_commands=[] if language.detected else hints,
                    repair_commands=hints,
                    verify_commands=verify_commands,
                    metadata={"current_version": language.version, "primary_command": language.primary_command},
                )
            )
        for manager in self.package_managers.list_package_managers():
            hints = _PACKAGE_MANAGER_INSTALL_HINTS.get(manager.manager_id, [])
            verify_commands = []
            primary_command = manager.metadata.get("primary_command") if isinstance(manager.metadata, dict) else None
            if isinstance(primary_command, str) and primary_command:
                version_flag = "--version"
                verify_commands = [f"{primary_command} {version_flag}"]
            actions.append(
                ToolchainProvisioningActionRecord(
                    target_id=manager.manager_id,
                    target_type="package_manager",
                    title=manager.title,
                    status="ready" if manager.detected else "pending",
                    summary=(
                        f"{manager.title} is installed."
                        if manager.detected
                        else f"{manager.title} is missing and should be installed."
                    ),
                    install_commands=[] if manager.detected else hints,
                    repair_commands=hints,
                    verify_commands=verify_commands,
                    metadata={"current_version": manager.version, "related_languages": list(manager.related_languages)},
                )
            )
        return sorted(actions, key=lambda item: (item.target_type, item.target_id))

    def get_action(self, target_id: str) -> ToolchainProvisioningActionRecord | None:
        for action in self.list_actions():
            if action.target_id == target_id:
                return action
        return None

    def can_repair(self, target_id: str) -> bool:
        action = self.get_action(target_id)
        return bool(action and (action.repair_commands or action.verify_commands))

    def resolve_command(self, target_id: str, *, mode: str = "install", command_index: int = 0) -> list[str]:
        action = self.get_action(target_id)
        if action is None:
            return []
        if mode == "repair":
            commands = list(action.repair_commands or action.install_commands or action.verify_commands)
        else:
            commands = list(action.install_commands or action.verify_commands)
        if not commands:
            return []
        if command_index >= len(commands):
            return []
        return commands[command_index].split()
