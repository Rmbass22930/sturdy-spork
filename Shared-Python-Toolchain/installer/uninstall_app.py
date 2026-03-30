from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import winreg
from ctypes import wintypes
from pathlib import Path


APP_NAME = "Security Gateway"
APP_EXE_NAME = "SecurityGateway.exe"
UNINSTALL_EXE_NAME = "SecurityGateway-Uninstall.exe"
UNINSTALL_SCRIPT_NAME = "Uninstall-SecurityGateway.ps1"
PATH_BACKUP_NAME = "user_path_backup.txt"
DEFAULT_INSTALL_ROOT = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "SecurityGateway"
TASK_NAME = "SecurityGatewayMonitor"
LEGACY_TASK_NAMES = ("SecurityGatewayAutomation",)
SYSTEM_DATA_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SecurityGateway"
USER_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "SecurityGateway"
CSIDL_DESKTOPDIRECTORY = 0x0010
SHGFP_TYPE_CURRENT = 0
UNINSTALL_REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\SecurityGateway"
APP_REGISTRY_KEY = r"Software\SecurityGateway"


def ensure_admin() -> None:
    if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
        raise PermissionError("Please run this uninstaller as Administrator.")


def desktop_from_shell() -> Path | None:
    try:
        buffer = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
        result = ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DESKTOPDIRECTORY, None, SHGFP_TYPE_CURRENT, buffer)
        if result != 0:
            return None
        return Path(buffer.value)
    except Exception:
        return None


def desktop_candidates() -> list[Path]:
    candidates: list[Path] = []
    shell_desktop = desktop_from_shell()
    if shell_desktop is not None:
        candidates.append(shell_desktop)
    candidates.append(Path.home() / "Desktop")
    one_drive_desktop = Path.home() / "OneDrive" / "Desktop"
    if one_drive_desktop not in candidates:
        candidates.append(one_drive_desktop)
    return candidates


def desktop_shortcut_paths() -> list[Path]:
    return [desktop / "SecurityGateway.lnk" for desktop in desktop_candidates()]


def remove_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def remove_tree(path: Path) -> None:
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


def restore_user_path(previous: str) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_ALL_ACCESS) as key:
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, previous)


def remove_path_entry(dir_path: Path) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_ALL_ACCESS) as key:
        try:
            path_value, _ = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            return
        segments = [segment for segment in path_value.split(";") if segment and segment != str(dir_path)]
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join(segments))


def restore_path_from_backup(install_root: Path) -> None:
    backup_file = install_root / PATH_BACKUP_NAME
    if backup_file.exists():
        restore_user_path(backup_file.read_text(encoding="utf-8"))
        remove_file(backup_file)
    else:
        remove_path_entry(install_root)


def unregister_automation_task() -> None:
    for task_name in (TASK_NAME, *LEGACY_TASK_NAMES):
        subprocess.run(
            ["schtasks", "/Delete", "/TN", task_name, "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def _delete_registry_tree(root: int, subkey: str) -> None:
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
            child_count = winreg.QueryInfoKey(key)[0]
            children = [winreg.EnumKey(key, index) for index in range(child_count)]
        for child in children:
            _delete_registry_tree(root, f"{subkey}\\{child}")
        winreg.DeleteKey(root, subkey)
    except FileNotFoundError:
        return
    except OSError:
        return


def remove_registry_entries() -> None:
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        _delete_registry_tree(root, APP_REGISTRY_KEY)
        _delete_registry_tree(root, UNINSTALL_REGISTRY_KEY)


def schedule_self_delete(exe_path: Path, install_root: Path) -> None:
    script_path = Path(tempfile.gettempdir()) / "security_gateway_uninstall_cleanup.cmd"
    script_path.write_text(
        "@echo off\n"
        "ping 127.0.0.1 -n 3 > nul\n"
        f'del /f /q "{exe_path}"\n'
        f'if exist "{install_root}" rmdir /s /q "{install_root}"\n'
        f'del /f /q "{script_path}"\n',
        encoding="utf-8",
    )
    subprocess.Popen(["cmd.exe", "/c", str(script_path)], close_fds=True)


def remove_install_payload(install_root: Path, current_exe_path: Path | None = None) -> None:
    for name in (APP_EXE_NAME, UNINSTALL_EXE_NAME, UNINSTALL_SCRIPT_NAME, "README.txt"):
        target = install_root / name
        if current_exe_path is not None and target.resolve() == current_exe_path.resolve():
            continue
        remove_file(target)


def resolve_install_root(current_exe_path: Path) -> Path:
    if current_exe_path.parent == DEFAULT_INSTALL_ROOT:
        return DEFAULT_INSTALL_ROOT
    if DEFAULT_INSTALL_ROOT.exists():
        return DEFAULT_INSTALL_ROOT
    return current_exe_path.parent


def main() -> int:
    ensure_admin()
    exe_path = Path(sys.argv[0]).resolve()
    install_root = resolve_install_root(exe_path)

    print(f"Removing {APP_NAME} from {install_root}")

    for shortcut in desktop_shortcut_paths():
        remove_file(shortcut)

    unregister_automation_task()
    restore_path_from_backup(install_root)
    remove_registry_entries()
    remove_install_payload(install_root, current_exe_path=exe_path)
    remove_tree(SYSTEM_DATA_DIR)
    remove_tree(USER_DATA_DIR)
    schedule_self_delete(exe_path, install_root)

    print("Security Gateway uninstall scheduled.")
    print("Application files, shortcuts, PATH entry, scheduled task, and data directories were removed.")
    print("Close this window if it does not exit automatically.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
