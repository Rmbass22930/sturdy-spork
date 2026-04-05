"""Bootstrap execution for provisioning actions."""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Any

from security_gateway.models import ToolchainBootstrapResultRecord
from toolchain_resources.provisioning import ToolchainProvisioningRegistry


def _tokenize_command(command: str) -> list[str]:
    return shlex.split(command, posix=False)


def _should_use_shell(command: str) -> bool:
    return any(token in command for token in ("|", "&&", "||", ">", "<"))


class ToolchainBootstrapExecutor:
    def __init__(self, provisioning: ToolchainProvisioningRegistry) -> None:
        self.provisioning = provisioning

    def list_targets(self, status: str | None = None) -> list[dict[str, Any]]:
        actions = self.provisioning.list_actions()
        if status:
            actions = [item for item in actions if item.status == status]
        return [item.model_dump(mode="json") for item in actions]

    def run(
        self,
        target_id: str,
        *,
        mode: str = "install",
        execute: bool = False,
        verify_after: bool = True,
        command_index: int = 0,
        project_path: str | Path = ".",
        timeout_seconds: float = 300.0,
    ) -> ToolchainBootstrapResultRecord:
        action = self.provisioning.get_action(target_id)
        if action is None:
            return ToolchainBootstrapResultRecord(
                target_id=target_id,
                title=target_id,
                status="not_found",
                mode=mode,
                summary="Provisioning target was not found.",
            )
        command_tokens = self.provisioning.resolve_command(target_id, mode=mode, command_index=command_index)
        available_commands = (
            list(action.repair_commands or action.install_commands or action.verify_commands)
            if mode == "repair"
            else list(action.install_commands or action.verify_commands)
        )
        summary = (
            f"{action.title} is already present; repair mode will verify the existing installation."
            if mode == "repair" and action.status == "ready"
            else f"{action.title} provisioning is planned."
        )
        verify_commands = list(action.verify_commands)
        if not execute:
            return ToolchainBootstrapResultRecord(
                target_id=action.target_id,
                title=action.title,
                status="planned",
                mode=mode,
                summary=summary,
                command=command_tokens,
                verify_command=_tokenize_command(verify_commands[0]) if verify_commands else [],
                project_path=str(Path(project_path)),
                metadata={
                    "available_commands": available_commands,
                    "verify_commands": verify_commands,
                    "target_type": action.target_type,
                },
            )
        if not command_tokens:
            return ToolchainBootstrapResultRecord(
                target_id=action.target_id,
                title=action.title,
                status="failed",
                mode=mode,
                summary=f"No {mode} command is available for {action.title}.",
                command=[],
                project_path=str(Path(project_path)),
                metadata={
                    "available_commands": available_commands,
                    "verify_commands": verify_commands,
                    "target_type": action.target_type,
                },
            )
        command_text = available_commands[command_index] if command_index < len(available_commands) else " ".join(command_tokens)
        completed = subprocess.run(
            command_text if _should_use_shell(command_text) else command_tokens,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(Path(project_path)),
            check=False,
            shell=_should_use_shell(command_text),
        )
        verify_command_text = verify_commands[0] if verify_commands else ""
        verify_completed: subprocess.CompletedProcess[str] | None = None
        verified: bool | None = None
        status = "executed" if completed.returncode == 0 else "failed"
        summary_text = (
            f"{action.title} {mode} command completed successfully."
            if completed.returncode == 0
            else f"{action.title} {mode} command failed."
        )
        if completed.returncode == 0 and verify_after and verify_command_text:
            verify_tokens = _tokenize_command(verify_command_text)
            verify_completed = subprocess.run(
                verify_command_text if _should_use_shell(verify_command_text) else verify_tokens,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                cwd=str(Path(project_path)),
                check=False,
                shell=_should_use_shell(verify_command_text),
            )
            verified = verify_completed.returncode == 0
            if not verified:
                status = "failed"
                summary_text = f"{action.title} {mode} command completed, but verification failed."
        return ToolchainBootstrapResultRecord(
            target_id=action.target_id,
            title=action.title,
            status=status,
            mode=mode,
            summary=summary_text,
            command=command_tokens,
            verify_command=_tokenize_command(verify_command_text) if verify_command_text else [],
            project_path=str(Path(project_path)),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            verify_returncode=verify_completed.returncode if verify_completed is not None else None,
            verify_stdout=verify_completed.stdout if verify_completed is not None else None,
            verify_stderr=verify_completed.stderr if verify_completed is not None else None,
            verified=verified,
            metadata={
                "available_commands": available_commands,
                "verify_commands": verify_commands,
                "target_type": action.target_type,
            },
        )
