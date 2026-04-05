from __future__ import annotations

import atexit
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT_TEXT = str(PROJECT_ROOT)
if PROJECT_ROOT_TEXT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT_TEXT)

from toolchain_resources.runtime import load_toolchain_runtime  # noqa: E402

load_toolchain_runtime(sync_updates=False)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def relaunch_as_admin() -> None:
    exe = Path(sys.executable).resolve()
    args = " ".join(f'"{arg}"' for arg in sys.argv[1:])
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        f'Start-Process -FilePath "{exe}" -ArgumentList {args!r} -Verb RunAs',
    ]
    subprocess.run(cmd, check=True)


def main() -> int:
    if os.name != "nt":
        print("This installer is only supported on Windows.")
        return 1

    if not is_admin():
        try:
            relaunch_as_admin()
        except Exception as exc:
            print(f"Failed to elevate privileges: {exc}")
            return 1
        return 0

    base_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    payload_src = base_dir / "payload"
    if not payload_src.exists():
        print(f"Embedded payload missing at {payload_src}")
        return 1

    temp_root = Path(tempfile.mkdtemp(prefix="ballistic_installer_"))
    payload_dst = temp_root / "payload"
    shutil.copytree(payload_src, payload_dst)

    def cleanup() -> None:
        try:
            shutil.rmtree(temp_root, ignore_errors=True)
        except Exception:
            pass

    atexit.register(cleanup)

    install_cmd = payload_dst / "Install.cmd"
    if not install_cmd.exists():
        print(f"Install script missing at {install_cmd}")
        return 1

    print("Launching Ballistic Target installer...")
    creation_flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    proc = subprocess.Popen(
        ["cmd.exe", "/k", str(install_cmd)],
        cwd=str(payload_dst),
        creationflags=creation_flags,
    )
    proc.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
