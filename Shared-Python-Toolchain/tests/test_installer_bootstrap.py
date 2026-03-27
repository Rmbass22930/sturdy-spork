import sys
import importlib.util
from pathlib import Path
from unittest import mock
import pytest


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


def test_install_dependency_reports_winget_method(monkeypatch) -> None:
    dep = installer.ExternalDependency(name="Cloudflare WARP", winget_id="Cloudflare.WARP")
    monkeypatch.setattr(installer.shutil, "which", lambda name: "C:\\Windows\\System32\\winget.exe")
    calls = []

    def fake_run(args, check, timeout=None):
        calls.append((args, check, timeout))

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    result = installer.install_dependency(dep)

    assert result.name == "Cloudflare WARP"
    assert result.status == "installed"
    assert result.method == "winget"
    assert result.target == "Cloudflare.WARP"
    assert calls


def test_print_install_summary_lists_shortcuts_and_dependencies(capsys, tmp_path: Path) -> None:
    summary = installer.InstallSummary(
        installed_path=tmp_path / "SecurityGateway.exe",
        shortcut_paths=[
            tmp_path / "Desktop" / "SecurityGateway.lnk",
            tmp_path / "OneDrive" / "Desktop" / "SecurityGateway.lnk",
        ],
        uninstall_script=tmp_path / "Uninstall-SecurityGateway.ps1",
        dependency_results=[
            installer.DependencyInstallResult(
                name="Cloudflare WARP",
                status="installed",
                method="winget",
                target="Cloudflare.WARP",
            )
        ],
    )

    installer.print_install_summary(summary)
    output = capsys.readouterr().out

    assert "Install complete:" in output
    assert "Desktop shortcuts:" in output
    assert "Cloudflare WARP: installed via winget (Cloudflare.WARP)" in output


def test_main_wraps_rollback_failures(monkeypatch, tmp_path: Path) -> None:
    installed_path = tmp_path / "SecurityGateway.exe"
    installed_path.write_text("binary", encoding="utf-8")
    monkeypatch.setattr(installer, "ensure_admin", lambda: None)
    monkeypatch.setattr(installer, "show_install_guide", lambda url=None, reporter=None: None)
    monkeypatch.setattr(installer, "resolve_resource", lambda rel: installed_path)
    monkeypatch.setattr(installer, "resolve_manifest_reference", lambda ref: None)
    monkeypatch.setattr(installer, "load_dependency_manifest", lambda path: [])
    monkeypatch.setattr(installer, "install_external_dependencies", lambda deps, reporter=None: [])
    monkeypatch.setattr(installer, "copy_binary", lambda src, dest: installed_path)
    monkeypatch.setattr(installer, "update_user_path", lambda path: "C:\\Existing\\Path")
    monkeypatch.setattr(installer, "create_shortcut", lambda path: [tmp_path / "Desktop" / "SecurityGateway.lnk"])
    monkeypatch.setattr(installer, "register_automation_task", lambda path: (_ for _ in ()).throw(RuntimeError("task failed")))
    monkeypatch.setattr(installer, "rollback_install", lambda transaction: (_ for _ in ()).throw(RuntimeError("rollback failed")))

    with pytest.raises(RuntimeError, match="Rollback also failed"):
        installer.main([])


def test_show_install_guide_does_not_wait_for_input(monkeypatch, tmp_path: Path, capsys) -> None:
    guide_path = tmp_path / "INSTALL_GUIDE.pdf"
    guide_path.write_text("pdf", encoding="utf-8")
    monkeypatch.setattr(installer, "resolve_resource", lambda rel: guide_path)
    monkeypatch.setattr(installer.os, "startfile", lambda path: None, raising=False)

    installer.show_install_guide()
    output = capsys.readouterr().out

    assert "Setup will continue immediately." in output


def test_main_skips_dependencies_when_requested(monkeypatch, tmp_path: Path) -> None:
    installed_path = tmp_path / "SecurityGateway.exe"
    backup_file = tmp_path / "user_path_backup.txt"
    uninstall_script = tmp_path / "Uninstall-SecurityGateway.ps1"
    installed_path.write_text("binary", encoding="utf-8")
    uninstall_script.write_text("script", encoding="utf-8")
    dependency_calls = []

    monkeypatch.setattr(installer, "ensure_admin", lambda: None)
    monkeypatch.setattr(installer, "show_install_guide", lambda url=None, reporter=None: None)
    monkeypatch.setattr(installer, "resolve_resource", lambda rel: installed_path)
    monkeypatch.setattr(installer, "resolve_manifest_reference", lambda ref: (_ for _ in ()).throw(AssertionError("manifest should not be resolved")))
    monkeypatch.setattr(installer, "load_dependency_manifest", lambda path: (_ for _ in ()).throw(AssertionError("dependencies should not load")))
    monkeypatch.setattr(installer, "install_external_dependencies", lambda deps, reporter=None: dependency_calls.append(deps))
    monkeypatch.setattr(installer, "copy_binary", lambda src, dest: installed_path)
    monkeypatch.setattr(installer, "update_user_path", lambda path: "C:\\Existing\\Path")
    monkeypatch.setattr(installer, "create_shortcut", lambda path: [tmp_path / "Desktop" / "SecurityGateway.lnk"])
    monkeypatch.setattr(installer, "register_automation_task", lambda path: None)
    monkeypatch.setattr(installer, "write_uninstall_script", lambda path, backup: uninstall_script)

    result = installer.main(["--skip-dependencies"])

    assert result == 0
    assert dependency_calls == []


def test_uninstall_script_always_removes_path_entry(tmp_path: Path) -> None:
    installed_path = tmp_path / "SecurityGateway.exe"
    backup_file = tmp_path / "user_path_backup.txt"
    script_path = installer.write_uninstall_script(installed_path, backup_file)
    script = script_path.read_text(encoding="utf-8")

    assert "$restored = Restore-PathFromBackup -File $PathBackupFile" in script
    assert "Remove-PathEntry -Dir $InstallDir" in script


def test_install_external_dependencies_can_skip_on_failure(monkeypatch) -> None:
    dep = installer.ExternalDependency(name="Cloudflare WARP", winget_id="Cloudflare.WARP")
    monkeypatch.setattr(installer, "install_dependency", lambda dependency: (_ for _ in ()).throw(RuntimeError("winget timed out")))
    monkeypatch.setattr(installer, "prompt_dependency_failure", lambda dependency, message: "skip")

    results = installer.install_external_dependencies([dep])

    assert len(results) == 1
    assert results[0].status == "skipped"
    assert results[0].name == "Cloudflare WARP"
    assert "winget timed out" in (results[0].detail or "")


def test_install_external_dependencies_retries_before_success(monkeypatch) -> None:
    dep = installer.ExternalDependency(name="Cloudflare WARP", winget_id="Cloudflare.WARP")
    calls = {"count": 0}

    def fake_install(dependency):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("first failure")
        return installer.DependencyInstallResult(
            name=dependency.name,
            status="installed",
            method="winget",
            target=dependency.winget_id,
        )

    monkeypatch.setattr(installer, "install_dependency", fake_install)
    monkeypatch.setattr(installer, "prompt_dependency_failure", lambda dependency, message: "retry")

    results = installer.install_external_dependencies([dep])

    assert calls["count"] == 2
    assert len(results) == 1
    assert results[0].status == "installed"


def test_install_external_dependencies_can_abort(monkeypatch) -> None:
    dep = installer.ExternalDependency(name="Cloudflare WARP", winget_id="Cloudflare.WARP")
    monkeypatch.setattr(installer, "install_dependency", lambda dependency: (_ for _ in ()).throw(RuntimeError("winget timed out")))
    monkeypatch.setattr(installer, "prompt_dependency_failure", lambda dependency, message: "abort")

    with pytest.raises(RuntimeError, match="Dependency installation aborted"):
        installer.install_external_dependencies([dep])


def test_resolve_resource_uses_project_root_and_dist_fallback(monkeypatch, tmp_path: Path) -> None:
    project_root = tmp_path / "Shared-Python-Toolchain"
    installer_dir = project_root / "installer"
    docs_dir = project_root / "docs"
    dist_dir = project_root / "dist"
    installer_dir.mkdir(parents=True)
    docs_dir.mkdir()
    dist_dir.mkdir()
    (docs_dir / "INSTALL_GUIDE.pdf").write_text("pdf", encoding="utf-8")
    (dist_dir / "SecurityGateway.exe").write_text("binary", encoding="utf-8")

    fake_installer = installer_dir / "installer.py"
    fake_installer.write_text("# placeholder", encoding="utf-8")

    monkeypatch.delattr(installer.sys, "_MEIPASS", raising=False)
    monkeypatch.setattr(installer, "__file__", str(fake_installer))

    assert installer.resolve_resource(installer.GUIDE_RELATIVE) == docs_dir / "INSTALL_GUIDE.pdf"
    assert installer.resolve_resource(installer.RESOURCE_RELATIVE) == dist_dir / "SecurityGateway.exe"


def test_main_uses_console_flow_when_not_frozen(monkeypatch) -> None:
    args = installer.parse_args([])
    perform_calls = []

    monkeypatch.delattr(installer.sys, "frozen", raising=False)
    monkeypatch.setattr(installer, "parse_args", lambda argv=None: args)
    monkeypatch.setattr(installer, "perform_install", lambda parsed_args, reporter=None: perform_calls.append((parsed_args, reporter)) or 0)

    result = installer.main([])

    assert result == 0
    assert len(perform_calls) == 1
    assert perform_calls[0][0] is args
    assert isinstance(perform_calls[0][1], installer.InstallReporter)


def test_main_uses_tk_ui_when_frozen(monkeypatch) -> None:
    args = installer.parse_args([])

    monkeypatch.setattr(installer.sys, "frozen", True, raising=False)
    monkeypatch.setattr(installer, "parse_args", lambda argv=None: args)
    monkeypatch.setattr(installer, "run_installer_ui", lambda parsed_args: 17)

    result = installer.main([])

    assert result == 17


def test_main_console_flag_overrides_frozen_ui(monkeypatch) -> None:
    args = installer.parse_args(["--console"])
    perform_calls = []

    monkeypatch.setattr(installer.sys, "frozen", True, raising=False)
    monkeypatch.setattr(installer, "parse_args", lambda argv=None: args)
    monkeypatch.setattr(installer, "perform_install", lambda parsed_args, reporter=None: perform_calls.append((parsed_args, reporter)) or 0)

    result = installer.main(["--console"])

    assert result == 0
    assert len(perform_calls) == 1
    assert perform_calls[0][0] is args
