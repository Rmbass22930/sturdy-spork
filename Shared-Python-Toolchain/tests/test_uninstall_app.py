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


def test_remove_registry_entries_attempts_owned_keys(monkeypatch):
    deleted: list[tuple[int, str]] = []

    monkeypatch.setattr(uninstall_app, "_delete_registry_tree", lambda root, subkey: deleted.append((root, subkey)))

    uninstall_app.remove_registry_entries()

    assert deleted == [
        (uninstall_app.winreg.HKEY_CURRENT_USER, uninstall_app.APP_REGISTRY_KEY),
        (uninstall_app.winreg.HKEY_CURRENT_USER, uninstall_app.UNINSTALL_REGISTRY_KEY),
        (uninstall_app.winreg.HKEY_LOCAL_MACHINE, uninstall_app.APP_REGISTRY_KEY),
        (uninstall_app.winreg.HKEY_LOCAL_MACHINE, uninstall_app.UNINSTALL_REGISTRY_KEY),
    ]


def test_resolve_install_root_prefers_default_install_dir(tmp_path, monkeypatch):
    release_dir = tmp_path / "release"
    release_dir.mkdir()
    exe_path = release_dir / uninstall_app.UNINSTALL_EXE_NAME
    exe_path.write_text("stub", encoding="utf-8")
    install_root = tmp_path / "Program Files" / "SecurityGateway"
    install_root.mkdir(parents=True)

    monkeypatch.setattr(uninstall_app, "DEFAULT_INSTALL_ROOT", install_root)

    assert uninstall_app.resolve_install_root(exe_path) == install_root


def test_resolve_install_root_uses_current_dir_when_default_missing(tmp_path, monkeypatch):
    release_dir = tmp_path / "release"
    release_dir.mkdir()
    exe_path = release_dir / uninstall_app.UNINSTALL_EXE_NAME
    exe_path.write_text("stub", encoding="utf-8")
    install_root = tmp_path / "missing" / "SecurityGateway"

    monkeypatch.setattr(uninstall_app, "DEFAULT_INSTALL_ROOT", install_root)

    assert uninstall_app.resolve_install_root(exe_path) == release_dir
