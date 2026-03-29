from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "installer"))

import uninstall_app


def test_remove_install_payload_removes_security_gateway_files(tmp_path):
    install_root = tmp_path / "SecurityGateway"
    install_root.mkdir()
    (install_root / uninstall_app.APP_EXE_NAME).write_text("app", encoding="utf-8")
    (install_root / uninstall_app.UNINSTALL_EXE_NAME).write_text("uninstall", encoding="utf-8")
    (install_root / uninstall_app.UNINSTALL_SCRIPT_NAME).write_text("script", encoding="utf-8")
    (install_root / "README.txt").write_text("readme", encoding="utf-8")

    uninstall_app.remove_install_payload(install_root)

    assert not (install_root / uninstall_app.APP_EXE_NAME).exists()
    assert not (install_root / uninstall_app.UNINSTALL_EXE_NAME).exists()
    assert not (install_root / uninstall_app.UNINSTALL_SCRIPT_NAME).exists()
    assert not (install_root / "README.txt").exists()


def test_remove_install_payload_preserves_running_uninstaller(tmp_path):
    install_root = tmp_path / "SecurityGateway"
    install_root.mkdir()
    current_exe = install_root / uninstall_app.UNINSTALL_EXE_NAME
    current_exe.write_text("uninstall", encoding="utf-8")

    uninstall_app.remove_install_payload(install_root, current_exe_path=current_exe)

    assert current_exe.exists()
