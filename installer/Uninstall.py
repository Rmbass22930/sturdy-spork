from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
from pathlib import Path


APP_NAME = "Ballistic Target Calculator"
CSIDL_DESKTOPDIRECTORY = 0x0010
SHGFP_TYPE_CURRENT = 0


def _desktop_from_shell() -> Path | None:
    buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
    result = ctypes.windll.shell32.SHGetFolderPathW(
        0, CSIDL_DESKTOPDIRECTORY, 0, SHGFP_TYPE_CURRENT, buf
    )
    if result == 0:
        value = buf.value.strip()
        if value:
            return Path(value)
    return None


def _desktop_candidates() -> list[Path]:
    candidates: list[Path] = []
    shell_path = _desktop_from_shell()
    if shell_path:
        candidates.append(shell_path)
    env_desktop = os.environ.get("USERPROFILE")
    if env_desktop:
        candidates.append(Path(env_desktop) / "Desktop")
    onedrive = os.environ.get("OneDrive")
    if onedrive:
        candidates.append(Path(onedrive) / "Desktop")
    candidates.append(Path.home() / "Desktop")
    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def _kill_process(name: str) -> None:
    try:
        subprocess.run(
            ["taskkill", "/IM", name, "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def _remove_file(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def _remove_tree(path: Path) -> None:
    try:
        if path.exists():
            shutil.rmtree(path)
    except Exception:
        pass


def main() -> int:
    exe_path = Path(sys.argv[0]).resolve()
    install_root = exe_path.parent
    print(f"Uninstalling {APP_NAME} from {install_root}")

    for proc in ("BallisticTargetGUI.exe", "EnvironmentalsGeoGUI.exe"):
        _kill_process(proc)

    desktop_links = [desktop / f"{APP_NAME}.lnk" for desktop in _desktop_candidates()]
    start_menu_root = (
        Path(os.environ.get("APPDATA", str(Path.home())))
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / APP_NAME
    )
    uninstall_link = start_menu_root / f"Uninstall {APP_NAME}.lnk"
    env_link = start_menu_root / "Environmentals + Geo.lnk"
    for link in desktop_links + [uninstall_link, env_link]:
        _remove_file(link)

    for exe in install_root.glob("*.exe"):
        if exe.samefile(exe_path):
            continue
        _remove_file(exe)

    for extra in ("README.txt", "config.template.json", "install.log"):
        _remove_file(install_root / extra)

    _remove_tree(start_menu_root)

    print("\nRemoved application binaries and shortcuts.")
    print("User data kept:")
    print(f"  {install_root / 'config.json'}")
    print(f"  {install_root / 'output'}")
    print(f"  {install_root / 'logs'}")
    print("\nDelete the folder below manually if you also want to remove saved data:")
    print(f"  {install_root}")
    input("\nPress Enter to close...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
