import sys
import importlib.util
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = PROJECT_ROOT / "installer" / "installer.py"

spec = importlib.util.spec_from_file_location("security_gateway_installer", INSTALLER_PATH)
installer = importlib.util.module_from_spec(spec)
assert spec is not None and spec.loader is not None
sys.modules[spec.name] = installer
spec.loader.exec_module(installer)


def test_rollback_install_cleans_created_artifacts(tmp_path: Path) -> None:
    install_dir = tmp_path / "SecurityGateway"
    install_dir.mkdir()
    installed_path = install_dir / "SecurityGateway.exe"
    backup_file = install_dir / "user_path_backup.txt"
    shortcut_path = tmp_path / "Desktop" / "SecurityGateway.lnk"
    shortcut_path.parent.mkdir()
    uninstall_script = install_dir / "Uninstall-SecurityGateway.ps1"

    for path in (installed_path, backup_file, shortcut_path, uninstall_script):
        path.write_text("x", encoding="utf-8")

    transaction = installer.InstallTransaction(
        installed_path=installed_path,
        previous_user_path="C:\\Existing\\Path",
        backup_file=backup_file,
        shortcut_paths=[shortcut_path],
        uninstall_script=uninstall_script,
        automation_task_registered=True,
    )

    with (
        mock.patch.object(installer, "restore_user_path") as restore_user_path,
        mock.patch.object(installer, "unregister_automation_task") as unregister_task,
    ):
        installer.rollback_install(transaction)

    restore_user_path.assert_called_once_with("C:\\Existing\\Path")
    unregister_task.assert_called_once()
    assert not installed_path.exists()
    assert not backup_file.exists()
    assert not shortcut_path.exists()
    assert not uninstall_script.exists()
    assert not install_dir.exists()


def test_create_shortcut_returns_created_paths(tmp_path: Path) -> None:
    exe_path = tmp_path / "SecurityGateway.exe"
    exe_path.write_text("binary", encoding="utf-8")

    with (
        mock.patch.dict(installer.os.environ, {"USERPROFILE": str(tmp_path)}),
        mock.patch.object(installer.subprocess, "run") as run,
    ):
        shortcut_paths = installer.create_shortcut(exe_path)

    assert shortcut_paths == [
        tmp_path / "Desktop" / "SecurityGateway.lnk",
        tmp_path / "OneDrive" / "Desktop" / "SecurityGateway.lnk",
    ]
    run.assert_called_once()
