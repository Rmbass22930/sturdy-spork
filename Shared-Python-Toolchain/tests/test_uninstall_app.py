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


def test_is_machine_install_matches_default_root(tmp_path, monkeypatch):
    install_root = tmp_path / "Program Files" / "SecurityGateway"
    install_root.mkdir(parents=True)

    monkeypatch.setattr(uninstall_app, "DEFAULT_INSTALL_ROOT", install_root)

    assert uninstall_app.is_machine_install(install_root) is True
    assert uninstall_app.is_machine_install(tmp_path / "smoke-install") is False


def test_resolve_local_data_roots_for_non_machine_install(tmp_path, monkeypatch):
    install_root = tmp_path / "smoke-install"
    install_root.mkdir()
    default_root = tmp_path / "Program Files" / "SecurityGateway"

    monkeypatch.setattr(uninstall_app, "DEFAULT_INSTALL_ROOT", default_root)

    assert uninstall_app.resolve_system_data_root(install_root) == install_root / "system-data"
    assert uninstall_app.resolve_user_data_root(install_root) == install_root / "user-data"


def test_main_skips_admin_and_machine_wide_cleanup_for_local_install(tmp_path, monkeypatch):
    install_root = tmp_path / "smoke-install"
    install_root.mkdir()
    exe_path = install_root / uninstall_app.UNINSTALL_EXE_NAME
    exe_path.write_text("stub", encoding="utf-8")
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(uninstall_app.sys, "argv", [str(exe_path)])
    monkeypatch.setattr(uninstall_app, "DEFAULT_INSTALL_ROOT", tmp_path / "Program Files" / "SecurityGateway")
    monkeypatch.setattr(
        uninstall_app,
        "ensure_admin",
        lambda: (_ for _ in ()).throw(AssertionError("admin should not be required")),
    )
    monkeypatch.setattr(uninstall_app, "shortcut_paths", lambda: [])
    monkeypatch.setattr(uninstall_app, "unregister_automation_task", lambda: calls.append(("task", None)))
    monkeypatch.setattr(uninstall_app, "restore_path_from_backup", lambda path: calls.append(("path", path)))
    monkeypatch.setattr(uninstall_app, "remove_registry_entries", lambda: calls.append(("registry", None)))
    monkeypatch.setattr(
        uninstall_app,
        "remove_install_payload",
        lambda path, current_exe_path=None: calls.append(("payload", path)),
    )
    monkeypatch.setattr(uninstall_app, "remove_tree", lambda path: calls.append(("tree", path)))
    monkeypatch.setattr(uninstall_app, "schedule_self_delete", lambda exe, root: calls.append(("delete", root)))

    result = uninstall_app.main()

    assert result == 0
    assert ("task", None) not in calls
    assert ("registry", None) not in calls
    assert ("path", install_root) not in calls
    assert ("payload", install_root) in calls
    assert ("tree", install_root / "system-data") in calls
    assert ("tree", install_root / "user-data") in calls
    assert ("delete", install_root) in calls


def test_shortcut_paths_include_dashboard_and_start_menu(monkeypatch, tmp_path):
    monkeypatch.setattr(uninstall_app, "desktop_candidates", lambda: [tmp_path / "Desktop"])
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
    monkeypatch.setenv("ProgramData", str(tmp_path / "ProgramData"))

    paths = uninstall_app.shortcut_paths()

    assert tmp_path / "Desktop" / "SecurityGateway.lnk" in paths
    assert tmp_path / "Desktop" / "SecurityGateway SOC Dashboard.lnk" in paths
    assert (
        tmp_path
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Security Gateway"
        / "SecurityGateway.lnk"
    ) in paths
    assert (
        tmp_path
        / "ProgramData"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Security Gateway"
        / "SecurityGateway SOC Dashboard.lnk"
    ) in paths


def test_schedule_self_delete_uses_secondary_cmd_for_script_cleanup(tmp_path, monkeypatch):
    script_path = tmp_path / "security_gateway_uninstall_cleanup.cmd"
    exe_path = tmp_path / uninstall_app.UNINSTALL_EXE_NAME
    install_root = tmp_path / "SecurityGateway"
    popen_calls: list[list[str]] = []

    monkeypatch.setattr(uninstall_app.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(
        uninstall_app.subprocess,
        "Popen",
        lambda args, close_fds=True: popen_calls.append(args),
    )

    uninstall_app.schedule_self_delete(exe_path, install_root)

    script_text = script_path.read_text(encoding="utf-8")
    assert 'start "" /b cmd /c "ping 127.0.0.1 -n 2 > nul & del /f /q ""' in script_text
    assert "exit /b 0" in script_text
    assert popen_calls == [["cmd.exe", "/c", str(script_path)]]
