"""Machine-level doctor checks for the shared toolchain."""
from __future__ import annotations

import importlib.util
import json
import os
import site
import subprocess
import sys
from pathlib import Path
from shutil import which
from typing import Any


class ToolchainDoctor:
    SCRIPT_NAMES = ("security-gateway", "toolchain-resources", "memory-optimizer")

    def __init__(
        self,
        *,
        toolchain_home: str | Path | None = None,
        manifest_path: str | Path | None = None,
    ) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        self.toolchain_home = Path(toolchain_home or os.environ.get("SECURITY_GATEWAY_TOOLCHAIN_HOME") or repo_root)
        default_manifest = self.toolchain_home / "toolchain_resources" / "global_manifest.json"
        self.manifest_path = Path(manifest_path or os.environ.get("SECURITY_GATEWAY_TOOLCHAIN_MANIFEST") or default_manifest)

    def _expected_env(self) -> dict[str, str]:
        return {
            "SECURITY_GATEWAY_TOOLCHAIN_HOME": str(self.toolchain_home),
            "SECURITY_GATEWAY_TOOLCHAIN_MANIFEST": str(self.manifest_path),
            "SECURITY_GATEWAY_TOOLCHAIN_CLI": "toolchain-resources",
            "SECURITY_GATEWAY_TOOLCHAIN_PYTHON_MODULE": "toolchain_resources.runtime",
            "SECURITY_GATEWAY_TOOLCHAIN_AUTOLOAD": "1",
        }

    def _default_manifest(self) -> dict[str, Any]:
        expected_env = self._expected_env()
        return {
            "toolchain_name": "Shared Python Toolchain",
            "toolchain_home": str(self.toolchain_home),
            "python_module": expected_env["SECURITY_GATEWAY_TOOLCHAIN_PYTHON_MODULE"],
            "python_autoload": {
                "mechanism": "sitecustomize",
                "loads_runtime": True,
            },
            "console_scripts": {
                "security_gateway": "security-gateway",
                "toolchain_resources": "toolchain-resources",
                "memory_optimizer": "memory-optimizer",
            },
            "environment_variables": {
                "SECURITY_GATEWAY_TOOLCHAIN_HOME": expected_env["SECURITY_GATEWAY_TOOLCHAIN_HOME"],
                "SECURITY_GATEWAY_TOOLCHAIN_MANIFEST": expected_env["SECURITY_GATEWAY_TOOLCHAIN_MANIFEST"],
                "SECURITY_GATEWAY_TOOLCHAIN_CLI": expected_env["SECURITY_GATEWAY_TOOLCHAIN_CLI"],
                "SECURITY_GATEWAY_TOOLCHAIN_PYTHON_MODULE": expected_env["SECURITY_GATEWAY_TOOLCHAIN_PYTHON_MODULE"],
                "SECURITY_GATEWAY_TOOLCHAIN_AUTOLOAD": expected_env["SECURITY_GATEWAY_TOOLCHAIN_AUTOLOAD"],
            },
        }

    def _sitecustomize_path(self) -> Path:
        return Path(site.getusersitepackages()) / "sitecustomize.py"

    def _sitecustomize_content(self) -> str:
        python_module = self._expected_env()["SECURITY_GATEWAY_TOOLCHAIN_PYTHON_MODULE"]
        return (
            '"""Auto-generated shared toolchain bootstrap."""\n'
            "from __future__ import annotations\n\n"
            "import importlib\n"
            "import os\n\n"
            'if os.environ.get("SECURITY_GATEWAY_TOOLCHAIN_AUTOLOAD", "1") == "1":\n'
            "    try:\n"
            "        importlib.import_module(\n"
            f'            os.environ.get("SECURITY_GATEWAY_TOOLCHAIN_PYTHON_MODULE", "{python_module}")\n'
            "        )\n"
            "    except Exception:\n"
            "        pass\n"
        )

    def _persisted_user_env(self) -> dict[str, str]:
        if os.name != "nt":
            return {}
        try:
            import winreg

            values: dict[str, str] = {}
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                index = 0
                while True:
                    try:
                        name, value, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    if isinstance(value, str):
                        values[name] = value
                    index += 1
            return values
        except Exception:
            return {}

    @staticmethod
    def _check(check_id: str, title: str, status: str, summary: str, **metadata: Any) -> dict[str, Any]:
        return {
            "check_id": check_id,
            "title": title,
            "status": status,
            "summary": summary,
            "metadata": metadata,
        }

    @staticmethod
    def _action(action_id: str, title: str, status: str, summary: str, **metadata: Any) -> dict[str, Any]:
        return {
            "action_id": action_id,
            "title": title,
            "status": status,
            "summary": summary,
            "metadata": metadata,
        }

    def _write_user_env(self, values: dict[str, str]) -> None:
        if os.name == "nt":
            import winreg

            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                for name, value in values.items():
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        for name, value in values.items():
            os.environ[name] = value

    def _broadcast_environment_change(self) -> bool:
        if os.name != "nt":
            return False
        try:
            import ctypes

            HWND_BROADCAST = 0xFFFF
            WM_SETTINGCHANGE = 0x001A
            SMTO_ABORTIFHUNG = 0x0002
            result = ctypes.c_void_p()
            ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                "Environment",
                SMTO_ABORTIFHUNG,
                5000,
                ctypes.byref(result),
            )
            return True
        except Exception:
            return False

    def _write_manifest(self) -> dict[str, Any]:
        try:
            self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
            self.manifest_path.write_text(
                json.dumps(self._default_manifest(), indent=2, sort_keys=True),
                encoding="utf-8",
            )
            return self._action(
                "manifest_write",
                "Write Global Manifest",
                "ok",
                f"Wrote toolchain manifest to {self.manifest_path}.",
                path=str(self.manifest_path),
            )
        except OSError as exc:
            return self._action(
                "manifest_write",
                "Write Global Manifest",
                "error",
                f"Failed to write toolchain manifest to {self.manifest_path}.",
                path=str(self.manifest_path),
                error=str(exc),
            )

    def _write_sitecustomize(self) -> dict[str, Any]:
        sitecustomize_path = self._sitecustomize_path()
        try:
            sitecustomize_path.parent.mkdir(parents=True, exist_ok=True)
            sitecustomize_path.write_text(self._sitecustomize_content(), encoding="utf-8")
            return self._action(
                "sitecustomize_write",
                "Write Python Autoload Hook",
                "ok",
                f"Wrote Python sitecustomize hook to {sitecustomize_path}.",
                path=str(sitecustomize_path),
            )
        except OSError as exc:
            return self._action(
                "sitecustomize_write",
                "Write Python Autoload Hook",
                "error",
                f"Failed to write Python sitecustomize hook to {sitecustomize_path}.",
                path=str(sitecustomize_path),
                error=str(exc),
            )

    def _repair_user_env(self) -> dict[str, Any]:
        expected_env = self._expected_env()
        try:
            self._write_user_env(expected_env)
            broadcasted = self._broadcast_environment_change()
            return self._action(
                "environment_write",
                "Persist User Environment",
                "ok",
                "Persisted toolchain environment variables for the current user.",
                values=expected_env,
                broadcasted=broadcasted,
            )
        except Exception as exc:
            return self._action(
                "environment_write",
                "Persist User Environment",
                "error",
                "Failed to persist toolchain environment variables for the current user.",
                values=expected_env,
                error=str(exc),
            )

    def _install_editable_package(self) -> dict[str, Any]:
        command = [sys.executable, "-m", "pip", "install", "--user", "-e", str(self.toolchain_home)]
        try:
            result = subprocess.run(
                command,
                cwd=self.toolchain_home,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
            )
            status = "ok" if result.returncode == 0 else "error"
            summary = (
                "Reinstalled the shared toolchain package in editable user mode."
                if result.returncode == 0
                else "Failed to reinstall the shared toolchain package in editable user mode."
            )
            return self._action(
                "editable_install",
                "Repair Editable Package Install",
                status,
                summary,
                command=command,
                returncode=result.returncode,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
            )
        except Exception as exc:
            return self._action(
                "editable_install",
                "Repair Editable Package Install",
                "error",
                "Failed to execute editable package repair.",
                command=command,
                error=str(exc),
            )

    def _needs_editable_install(self, report: dict[str, Any]) -> bool:
        for item in report.get("checks", []):
            check_id = str(item.get("check_id"))
            status = str(item.get("status"))
            if check_id == "python_module" and status != "ok":
                return True
            if check_id.startswith("script_") and status != "ok":
                return True
        return False

    def run(self) -> dict[str, Any]:
        persisted_env = self._persisted_user_env()
        checks: list[dict[str, Any]] = []

        manifest_exists = self.manifest_path.exists()
        if manifest_exists:
            try:
                json.loads(self.manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                manifest_exists = False
        checks.append(
            self._check(
                "manifest",
                "Global Manifest",
                "ok" if manifest_exists else "error",
                (
                    f"Toolchain manifest is available at {self.manifest_path}."
                    if manifest_exists
                    else f"Toolchain manifest is missing or unreadable at {self.manifest_path}."
                ),
                path=str(self.manifest_path),
            )
        )

        sitecustomize_path = Path(site.getusersitepackages()) / "sitecustomize.py"
        sitecustomize_exists = sitecustomize_path.exists()
        checks.append(
            self._check(
                "python_sitecustomize",
                "Python Autoload Hook",
                "ok" if sitecustomize_exists else "warning",
                (
                    f"Python sitecustomize hook is installed at {sitecustomize_path}."
                    if sitecustomize_exists
                    else "Python sitecustomize hook is not installed in the user site-packages directory."
                ),
                path=str(sitecustomize_path),
            )
        )

        autoload_active = os.environ.get("SECURITY_GATEWAY_TOOLCHAIN_LOADED") == "1"
        checks.append(
            self._check(
                "python_autoload_runtime",
                "Python Autoload Runtime",
                "ok" if autoload_active else "warning",
                (
                    "Python autoload is active in the current process."
                    if autoload_active
                    else "Python autoload did not mark the current process as loaded."
                ),
            )
        )

        required_env = self._expected_env()
        for env_name, expected in required_env.items():
            actual = persisted_env.get(env_name) or os.environ.get(env_name)
            checks.append(
                self._check(
                    f"env_{env_name.lower()}",
                    f"Environment Variable {env_name}",
                    "ok" if actual == expected else "warning",
                    (
                        f"{env_name} is set correctly."
                        if actual == expected
                        else f"{env_name} is not set to the expected value."
                    ),
                    expected=expected,
                    actual=actual,
                )
            )

        for script_name in self.SCRIPT_NAMES:
            resolved = which(script_name)
            checks.append(
                self._check(
                    f"script_{script_name.replace('-', '_')}",
                    f"Console Script {script_name}",
                    "ok" if resolved else "warning",
                    (
                        f"{script_name} is available on PATH."
                        if resolved
                        else f"{script_name} is not currently available on PATH."
                    ),
                    path=resolved,
                )
            )

        module_spec = importlib.util.find_spec("toolchain_resources.runtime")
        checks.append(
            self._check(
                "python_module",
                "Python Runtime Module",
                "ok" if module_spec is not None else "error",
                (
                    "toolchain_resources.runtime is importable."
                    if module_spec is not None
                    else "toolchain_resources.runtime is not importable."
                ),
                origin=getattr(module_spec, "origin", None),
            )
        )

        error_count = sum(1 for item in checks if item["status"] == "error")
        warning_count = sum(1 for item in checks if item["status"] == "warning")
        status = "error" if error_count else ("warning" if warning_count else "ok")
        summary = (
            "Toolchain machine registration is healthy."
            if status == "ok"
            else f"Toolchain machine registration has {error_count} errors and {warning_count} warnings."
        )
        return {
            "status": status,
            "summary": summary,
            "toolchain_home": str(self.toolchain_home),
            "manifest_path": str(self.manifest_path),
            "error_count": error_count,
            "warning_count": warning_count,
            "checks": checks,
        }

    def repair(self, *, force_reinstall: bool = False) -> dict[str, Any]:
        before = self.run()
        actions = [
            self._write_manifest(),
            self._write_sitecustomize(),
            self._repair_user_env(),
        ]
        if force_reinstall or self._needs_editable_install(before):
            actions.append(self._install_editable_package())
        else:
            actions.append(
                self._action(
                    "editable_install",
                    "Repair Editable Package Install",
                    "skipped",
                    "Editable package repair was not needed.",
                )
            )
        after = self.run()
        error_count = sum(1 for item in actions if item["status"] == "error") + int(after.get("error_count", 0))
        warning_count = int(after.get("warning_count", 0))
        status = "error" if error_count else ("warning" if warning_count else "ok")
        summary = (
            "Toolchain machine registration repair completed successfully."
            if status == "ok"
            else f"Toolchain machine registration repair completed with {error_count} errors and {warning_count} warnings."
        )
        return {
            "status": status,
            "summary": summary,
            "force_reinstall": force_reinstall,
            "actions": actions,
            "before": before,
            "after": after,
            "error_count": error_count,
            "warning_count": warning_count,
        }
