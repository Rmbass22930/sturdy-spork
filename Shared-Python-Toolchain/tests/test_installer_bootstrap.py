import os
import sys
import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest import mock
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INSTALLER_PATH = PROJECT_ROOT / "installer" / "installer.py"

spec = importlib.util.spec_from_file_location("security_gateway_installer", INSTALLER_PATH)
assert spec is not None and spec.loader is not None
installer = cast(Any, importlib.util.module_from_spec(spec))
sys.modules[spec.name] = installer
spec.loader.exec_module(installer)


def test_rollback_install_cleans_created_artifacts(tmp_path: Path) -> None:
    install_dir = tmp_path / "SecurityGateway"
    install_dir.mkdir()
    installed_path = install_dir / "SecurityGateway.exe"
    uninstall_executable = install_dir / "SecurityGateway-Uninstall.exe"
    backup_file = install_dir / "user_path_backup.txt"
    shortcut_path = tmp_path / "Desktop" / "SecurityGateway.lnk"
    shortcut_path.parent.mkdir()
    uninstall_script = install_dir / "Uninstall-SecurityGateway.ps1"

    for path in (installed_path, uninstall_executable, backup_file, shortcut_path, uninstall_script):
        path.write_text("x", encoding="utf-8")

    transaction = installer.InstallTransaction(
        installed_path=installed_path,
        uninstall_executable=uninstall_executable,
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
    assert not uninstall_executable.exists()
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
    command = run.call_args.args[0]
    assert "automation-run" not in command[-1]


def test_task_name_is_monitor_and_uninstall_script_uses_it(tmp_path: Path) -> None:
    installed_path = tmp_path / "SecurityGateway.exe"
    backup_file = tmp_path / "user_path_backup.txt"

    assert installer.TASK_NAME == "SecurityGatewayMonitor"

    script_path = installer.write_uninstall_script(installed_path, backup_file)
    script = script_path.read_text(encoding="utf-8")

    assert 'TaskName = "SecurityGatewayMonitor"' in script


def test_register_automation_task_uses_powershell_scheduled_task_api(monkeypatch, tmp_path: Path) -> None:
    exe_path = tmp_path / "SecurityGateway.exe"
    calls: list[list[str]] = []

    monkeypatch.setattr(installer, "unregister_automation_task", lambda: calls.append(["unregister"]))
    monkeypatch.setattr(installer, "_scheduled_task_exists", lambda name: True)

    def fake_run(args, check=False, capture_output=False, text=False):
        calls.append(args)
        return mock.Mock(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(installer.subprocess, "run", fake_run)

    installer.register_automation_task(exe_path)

    assert calls[0] == ["unregister"]
    assert calls[1][:6] == [
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
    ]
    script = calls[1][6]
    assert "New-ScheduledTaskAction" in script
    assert "New-ScheduledTaskTrigger -AtStartup" in script
    assert "New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest" in script
    assert "Register-ScheduledTask" in script
    assert str(exe_path) in script
    assert "automation-run" in script


def test_register_automation_task_falls_back_to_schtasks(monkeypatch, tmp_path: Path) -> None:
    exe_path = tmp_path / "SecurityGateway.exe"
    calls: list[list[str]] = []
    exists_checks: list[str] = []

    monkeypatch.setattr(installer, "unregister_automation_task", lambda: calls.append(["unregister"]))

    def fake_exists(name: str) -> bool:
        exists_checks.append(name)
        return True

    def fake_run(args, check=False, capture_output=False, text=False):
        calls.append(args)
        if args[0] == "powershell":
            return mock.Mock(returncode=1, stderr="Access is denied.", stdout="")
        return mock.Mock(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(installer, "_scheduled_task_exists", fake_exists)
    monkeypatch.setattr(installer.subprocess, "run", fake_run)

    installer.register_automation_task(exe_path)

    assert calls[0] == ["unregister"]
    assert calls[1][0] == "powershell"
    assert calls[2][:6] == [
        "schtasks",
        "/Create",
        "/TN",
        installer.TASK_NAME,
        "/SC",
        "ONSTART",
    ]
    assert exists_checks == [installer.TASK_NAME]


def test_register_automation_task_raises_when_no_task_is_created(monkeypatch, tmp_path: Path) -> None:
    exe_path = tmp_path / "SecurityGateway.exe"

    monkeypatch.setattr(installer, "unregister_automation_task", lambda: None)
    monkeypatch.setattr(installer, "_scheduled_task_exists", lambda name: False)
    monkeypatch.setattr(
        installer.subprocess,
        "run",
        lambda args, check=False, capture_output=False, text=False: mock.Mock(
            returncode=1,
            stderr="Access is denied.",
            stdout="",
        ),
    )

    with pytest.raises(RuntimeError, match="Failed to register automation startup task"):
        installer.register_automation_task(exe_path)


def test_copy_binary_retries_after_locked_file_error(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "SecurityGateway.exe"
    dest_dir = tmp_path / "install"
    src.write_text("binary", encoding="utf-8")
    attempts: list[str] = []
    terminated: list[Path] = []
    sleeps: list[float] = []

    locked = PermissionError(32, "file in use")
    locked.winerror = 32

    def fake_copy2(source, target):
        attempts.append(str(target))
        if len(attempts) == 1:
            raise locked
        Path(target).write_text(Path(source).read_text(encoding="utf-8"), encoding="utf-8")
        return target

    monkeypatch.setattr(installer.shutil, "copy2", fake_copy2)
    monkeypatch.setattr(installer, "_terminate_processes_for_binary", lambda target: terminated.append(target))
    monkeypatch.setattr(installer.time, "sleep", lambda seconds: sleeps.append(seconds))

    target = installer.copy_binary(src, dest_dir)

    assert target == dest_dir / "SecurityGateway.exe"
    assert terminated == [target]
    assert sleeps == [installer.LOCKED_FILE_RETRY_DELAY_SECONDS]
    assert target.read_text(encoding="utf-8") == "binary"


def test_copy_binary_reraises_non_locked_permission_error(tmp_path: Path, monkeypatch) -> None:
    src = tmp_path / "SecurityGateway.exe"
    dest_dir = tmp_path / "install"
    src.write_text("binary", encoding="utf-8")
    denied = PermissionError(5, "access denied")
    denied.winerror = 5

    monkeypatch.setattr(installer.shutil, "copy2", lambda source, target: (_ for _ in ()).throw(denied))
    monkeypatch.setattr(installer, "_terminate_processes_for_binary", lambda target: (_ for _ in ()).throw(AssertionError("should not terminate")))
    monkeypatch.setattr(installer.time, "sleep", lambda seconds: (_ for _ in ()).throw(AssertionError("should not sleep")))

    with pytest.raises(PermissionError) as excinfo:
        installer.copy_binary(src, dest_dir)

    assert excinfo.value is denied


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
        reports_dir=tmp_path / "LocalAppData" / "SecurityGateway" / "reports",
        shortcut_paths=[
            tmp_path / "Desktop" / "SecurityGateway.lnk",
            tmp_path / "OneDrive" / "Desktop" / "SecurityGateway.lnk",
        ],
        uninstall_executable=tmp_path / "SecurityGateway-Uninstall.exe",
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
    assert "Reports directory:" in output
    assert "Installed launcher tools: SOC Dashboard, Reports, Install Folder, Uninstaller" in output
    assert "Desktop shortcuts:" in output
    assert "Uninstall executable:" in output
    assert "Cloudflare WARP: installed via winget (Cloudflare.WARP)" in output


def test_create_reports_directory(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "LocalAppData" / "SecurityGateway" / "reports"
    monkeypatch.setattr(installer, "REPORTS_DIR", target)

    created = installer.create_reports_directory()

    assert created == target
    assert target.exists()
    assert target.is_dir()


def test_main_wraps_rollback_failures(monkeypatch, tmp_path: Path) -> None:
    installed_path = tmp_path / "SecurityGateway.exe"
    uninstall_executable = tmp_path / "SecurityGateway-Uninstall.exe"
    installed_path.write_text("binary", encoding="utf-8")
    uninstall_executable.write_text("binary", encoding="utf-8")
    monkeypatch.setattr(installer, "ensure_admin", lambda: None)
    monkeypatch.setattr(installer, "show_install_guide", lambda url=None, reporter=None: None)
    monkeypatch.setattr(
        installer,
        "resolve_resource",
        lambda rel: uninstall_executable if rel == installer.UNINSTALLER_RELATIVE else installed_path,
    )
    monkeypatch.setattr(installer, "resolve_manifest_reference", lambda ref: None)
    monkeypatch.setattr(installer, "load_dependency_manifest", lambda path: [])
    monkeypatch.setattr(installer, "install_external_dependencies", lambda deps, reporter=None: [])
    monkeypatch.setattr(installer, "copy_binary", lambda src, dest: uninstall_executable if src == uninstall_executable else installed_path)
    monkeypatch.setattr(installer, "update_user_path", lambda path: "C:\\Existing\\Path")
    monkeypatch.setattr(installer, "create_shortcut", lambda path: [tmp_path / "Desktop" / "SecurityGateway.lnk"])
    monkeypatch.setattr(installer, "register_automation_task", lambda path: (_ for _ in ()).throw(RuntimeError("task failed")))
    monkeypatch.setattr(installer, "rollback_install", lambda transaction: (_ for _ in ()).throw(RuntimeError("rollback failed")))

    with pytest.raises(RuntimeError, match="Rollback also failed"):
        installer.main([])


def test_show_install_guide_does_not_wait_for_input(monkeypatch, tmp_path: Path, capsys) -> None:
    guide_path = tmp_path / "INSTALL_GUIDE.pdf"
    guide_path.write_text("pdf", encoding="utf-8")
    scheduled: list[int | None] = []
    offered: list[Path] = []

    def fake_schedule(pid: int | None, reporter: object, timeout_seconds: int = 30) -> None:
        scheduled.append(pid)
        getattr(reporter, "info")(
            f"Installation guide will auto-close after {timeout_seconds} seconds unless you click into it to keep it open."
        )

    monkeypatch.setattr(installer, "resolve_resource", lambda rel: guide_path)
    monkeypatch.setattr(installer, "_launch_guide_process", lambda path: 1234)
    monkeypatch.setattr(installer, "_schedule_guide_auto_close", fake_schedule)
    monkeypatch.setattr(installer, "_offer_to_print_install_guide", lambda guide, reporter: offered.append(Path(guide)))

    installer.show_install_guide()
    output = capsys.readouterr().out

    assert scheduled == [1234]
    assert offered == [guide_path]
    assert "auto-close after 30 seconds unless you click into it to keep it open" in output
    assert "Setup will continue immediately." in output


def test_show_install_guide_materializes_frozen_resource(monkeypatch, tmp_path: Path, capsys) -> None:
    guide_path = tmp_path / "INSTALL_GUIDE.pdf"
    guide_path.write_text("pdf", encoding="utf-8")
    docs_dir = tmp_path / "stable-docs"
    opened: list[Path] = []
    scheduled: list[int | None] = []
    offered: list[Path] = []

    def fake_schedule(pid: int | None, reporter: object, timeout_seconds: int = 30) -> None:
        scheduled.append(pid)
        getattr(reporter, "info")(
            f"Installation guide will auto-close after {timeout_seconds} seconds unless you click into it to keep it open."
        )

    def fake_materialize(path: Path, target_dir: Path | None = None) -> Path:
        docs_dir.mkdir(parents=True, exist_ok=True)
        materialized = docs_dir / path.name
        materialized.write_text("pdf", encoding="utf-8")
        return materialized

    monkeypatch.setattr(installer, "resolve_resource", lambda rel: guide_path)
    monkeypatch.setattr(installer, "materialize_external_resource", fake_materialize)
    def fake_launch(path: Path) -> int:
        opened.append(Path(path))
        return 5678

    monkeypatch.setattr(installer, "_launch_guide_process", fake_launch)
    monkeypatch.setattr(installer, "_schedule_guide_auto_close", fake_schedule)
    monkeypatch.setattr(installer, "_offer_to_print_install_guide", lambda guide, reporter: offered.append(Path(guide)))
    monkeypatch.setattr(installer.sys, "_MEIPASS", str(tmp_path), raising=False)

    installer.show_install_guide()
    output = capsys.readouterr().out

    assert opened == [docs_dir / "INSTALL_GUIDE.pdf"]
    assert scheduled == [5678]
    assert offered == [docs_dir / "INSTALL_GUIDE.pdf"]
    assert "auto-close after 30 seconds unless you click into it to keep it open" in output
    assert "Setup will continue immediately." in output


def test_offer_to_print_install_guide_prints_when_confirmed(monkeypatch, tmp_path: Path, capsys) -> None:
    guide_path = tmp_path / "INSTALL_GUIDE.pdf"
    guide_path.write_text("pdf", encoding="utf-8")
    calls: list[tuple[str, str]] = []

    class FakeRoot:
        def withdraw(self) -> None:
            return None

        def destroy(self) -> None:
            return None

    monkeypatch.setattr(installer, "tk", type("TkModule", (), {"Tk": staticmethod(lambda: FakeRoot())})())
    monkeypatch.setattr(
        installer,
        "messagebox",
        type("MessageBox", (), {"askyesno": staticmethod(lambda *args, **kwargs: True)})(),
    )
    monkeypatch.setattr(installer.os, "startfile", lambda path, operation=None: calls.append((str(path), str(operation))), raising=False)

    installer._offer_to_print_install_guide(guide_path, installer.InstallReporter())
    output = capsys.readouterr().out

    assert calls == [(str(guide_path), "print")]
    assert "Sent the installation guide to the default printer." in output


def test_cleanup_stale_mei_directories_removes_only_stale_entries(tmp_path: Path) -> None:
    stale_dir = tmp_path / "_MEIold"
    recent_dir = tmp_path / "_MEIrecent"
    other_dir = tmp_path / "other"
    stale_dir.mkdir()
    recent_dir.mkdir()
    other_dir.mkdir()

    stale_time = (datetime.now(UTC) - timedelta(minutes=30)).timestamp()
    recent_time = (datetime.now(UTC) - timedelta(minutes=2)).timestamp()
    os.utime(stale_dir, (stale_time, stale_time))
    os.utime(recent_dir, (recent_time, recent_time))

    removed = installer.cleanup_stale_mei_directories(temp_root=tmp_path, stale_after_minutes=10)

    assert stale_dir in removed
    assert not stale_dir.exists()
    assert recent_dir.exists()
    assert other_dir.exists()


def test_cleanup_stale_mei_directories_skips_active_dir(tmp_path: Path) -> None:
    active_dir = tmp_path / "_MEIactive"
    stale_dir = tmp_path / "_MEIstale"
    active_dir.mkdir()
    stale_dir.mkdir()

    old_time = (datetime.now(UTC) - timedelta(minutes=30)).timestamp()
    os.utime(active_dir, (old_time, old_time))
    os.utime(stale_dir, (old_time, old_time))

    removed = installer.cleanup_stale_mei_directories(
        temp_root=tmp_path,
        active_dir=active_dir,
        stale_after_minutes=10,
    )

    assert stale_dir in removed
    assert active_dir not in removed
    assert active_dir.exists()


def test_main_skips_dependencies_when_requested(monkeypatch, tmp_path: Path) -> None:
    installed_path = tmp_path / "SecurityGateway.exe"
    uninstall_executable = tmp_path / "SecurityGateway-Uninstall.exe"
    uninstall_script = tmp_path / "Uninstall-SecurityGateway.ps1"
    installed_path.write_text("binary", encoding="utf-8")
    uninstall_executable.write_text("binary", encoding="utf-8")
    uninstall_script.write_text("script", encoding="utf-8")
    dependency_calls = []

    monkeypatch.setattr(installer, "ensure_admin", lambda: None)
    monkeypatch.setattr(installer, "show_install_guide", lambda url=None, reporter=None: None)
    monkeypatch.setattr(
        installer,
        "resolve_resource",
        lambda rel: uninstall_executable if rel == installer.UNINSTALLER_RELATIVE else installed_path,
    )
    monkeypatch.setattr(installer, "resolve_manifest_reference", lambda ref: (_ for _ in ()).throw(AssertionError("manifest should not be resolved")))
    monkeypatch.setattr(installer, "load_dependency_manifest", lambda path: (_ for _ in ()).throw(AssertionError("dependencies should not load")))
    monkeypatch.setattr(installer, "install_external_dependencies", lambda deps, reporter=None: dependency_calls.append(deps))
    monkeypatch.setattr(installer, "copy_binary", lambda src, dest: uninstall_executable if src == uninstall_executable else installed_path)
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


def test_install_external_dependencies_auto_skip_optional_failure(monkeypatch) -> None:
    dep = installer.ExternalDependency(name="Cloudflare WARP", optional=True, winget_id="Cloudflare.WARP")
    prompts: list[tuple[object, str]] = []

    def fake_prompt(dependency: object, message: str) -> str:
        prompts.append((dependency, message))
        return "abort"

    monkeypatch.setattr(
        installer,
        "install_dependency",
        lambda dependency: (_ for _ in ()).throw(RuntimeError("winget timed out")),
    )
    monkeypatch.setattr(installer, "prompt_dependency_failure", fake_prompt)

    results = installer.install_external_dependencies([dep])

    assert prompts == []
    assert len(results) == 1
    assert results[0].status == "skipped"
    assert results[0].method == "optional"
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


def test_resolve_resource_uses_dist_fallback_for_uninstaller(monkeypatch, tmp_path: Path) -> None:
    project_root = tmp_path / "Shared-Python-Toolchain"
    installer_dir = project_root / "installer"
    dist_dir = project_root / "dist"
    installer_dir.mkdir(parents=True)
    dist_dir.mkdir()
    (dist_dir / "SecurityGateway-Uninstall.exe").write_text("binary", encoding="utf-8")

    fake_installer = installer_dir / "installer.py"
    fake_installer.write_text("# placeholder", encoding="utf-8")

    monkeypatch.delattr(installer.sys, "_MEIPASS", raising=False)
    monkeypatch.setattr(installer, "__file__", str(fake_installer))

    assert installer.resolve_resource(installer.UNINSTALLER_RELATIVE) == dist_dir / "SecurityGateway-Uninstall.exe"


def test_main_summary_includes_uninstaller(monkeypatch, tmp_path: Path) -> None:
    installed_path = tmp_path / "SecurityGateway.exe"
    uninstall_executable = tmp_path / "SecurityGateway-Uninstall.exe"
    uninstall_script = tmp_path / "Uninstall-SecurityGateway.ps1"
    installed_path.write_text("binary", encoding="utf-8")
    uninstall_executable.write_text("binary", encoding="utf-8")
    uninstall_script.write_text("script", encoding="utf-8")
    summaries = []

    monkeypatch.setattr(installer, "ensure_admin", lambda: None)
    monkeypatch.setattr(installer, "show_install_guide", lambda url=None, reporter=None: None)
    monkeypatch.setattr(
        installer,
        "resolve_resource",
        lambda rel: uninstall_executable if rel == installer.UNINSTALLER_RELATIVE else installed_path,
    )
    monkeypatch.setattr(installer, "resolve_manifest_reference", lambda ref: None)
    monkeypatch.setattr(installer, "load_dependency_manifest", lambda path: [])
    monkeypatch.setattr(installer, "install_external_dependencies", lambda deps, reporter=None: [])
    monkeypatch.setattr(installer, "copy_binary", lambda src, dest: uninstall_executable if src == uninstall_executable else installed_path)
    monkeypatch.setattr(installer, "update_user_path", lambda path: "C:\\Existing\\Path")
    monkeypatch.setattr(installer, "create_shortcut", lambda path: [tmp_path / "Desktop" / "SecurityGateway.lnk"])
    monkeypatch.setattr(installer, "register_automation_task", lambda path: None)
    monkeypatch.setattr(installer, "write_uninstall_script", lambda path, backup: uninstall_script)

    class RecordingReporter:
        def stage(self, title: str) -> None:
            return None

        def info(self, message: str) -> None:
            return None

        def dependency_failure(self, dep, message: str) -> str:
            return "abort"

        def summary(self, summary):
            summaries.append(summary)

        def error(self, message: str) -> None:
            return None

    result = installer.perform_install(installer.parse_args(["--skip-dependencies"]), reporter=RecordingReporter())

    assert result == 0
    assert len(summaries) == 1
    assert summaries[0].uninstall_executable == uninstall_executable


def test_main_uses_console_flow_when_not_frozen(monkeypatch) -> None:
    args = installer.parse_args([])
    perform_calls = []

    def fake_perform_install(parsed_args, reporter=None):
        perform_calls.append((parsed_args, reporter))
        return 0

    monkeypatch.delattr(installer.sys, "frozen", raising=False)
    monkeypatch.setattr(installer, "ensure_frozen_installer_elevation", lambda argv=None: None)
    monkeypatch.setattr(installer, "parse_args", lambda argv=None: args)
    monkeypatch.setattr(installer, "perform_install", fake_perform_install)

    result = installer.main([])

    assert result == 0
    assert len(perform_calls) == 1
    assert perform_calls[0][0] is args
    assert isinstance(perform_calls[0][1], installer.InstallReporter)


def test_main_uses_tk_ui_when_frozen(monkeypatch) -> None:
    args = installer.parse_args([])

    monkeypatch.setattr(installer.sys, "frozen", True, raising=False)
    monkeypatch.setattr(installer, "ensure_frozen_installer_elevation", lambda argv=None: None)
    monkeypatch.setattr(installer, "parse_args", lambda argv=None: args)
    monkeypatch.setattr(installer, "run_installer_ui", lambda parsed_args: 17)

    result = installer.main([])

    assert result == 17


def test_main_console_flag_overrides_frozen_ui(monkeypatch) -> None:
    args = installer.parse_args(["--console"])
    perform_calls = []

    def fake_perform_install(parsed_args, reporter=None):
        perform_calls.append((parsed_args, reporter))
        return 0

    monkeypatch.setattr(installer.sys, "frozen", True, raising=False)
    monkeypatch.setattr(installer, "ensure_frozen_installer_elevation", lambda argv=None: None)
    monkeypatch.setattr(installer, "parse_args", lambda argv=None: args)
    monkeypatch.setattr(installer, "perform_install", fake_perform_install)

    result = installer.main(["--console"])

    assert result == 0
    assert len(perform_calls) == 1
    assert perform_calls[0][0] is args


def test_ensure_frozen_installer_elevation_relaunches_as_admin(monkeypatch) -> None:
    shell32 = mock.Mock()
    shell32.IsUserAnAdmin.return_value = False
    shell32.ShellExecuteW.return_value = 42

    monkeypatch.setattr(installer.sys, "frozen", True, raising=False)
    monkeypatch.setattr(installer.sys, "executable", r"C:\Temp\SecurityGatewayInstaller.exe")
    monkeypatch.setattr(installer.ctypes, "windll", mock.Mock(shell32=shell32))

    with pytest.raises(SystemExit, match="0"):
        installer.ensure_frozen_installer_elevation(["--console", "--skip-dependencies"])

    shell32.ShellExecuteW.assert_called_once()
    call = shell32.ShellExecuteW.call_args.args
    assert call[1] == "runas"
    assert call[2] == r"C:\Temp\SecurityGatewayInstaller.exe"
    assert "--console" in call[3]


def test_ensure_frozen_installer_elevation_raises_when_relaunch_fails(monkeypatch) -> None:
    shell32 = mock.Mock()
    shell32.IsUserAnAdmin.return_value = False
    shell32.ShellExecuteW.return_value = 31

    monkeypatch.setattr(installer.sys, "frozen", True, raising=False)
    monkeypatch.setattr(installer.sys, "executable", r"C:\Temp\SecurityGatewayInstaller.exe")
    monkeypatch.setattr(installer.ctypes, "windll", mock.Mock(shell32=shell32))

    with pytest.raises(PermissionError, match="Please run this installer as Administrator."):
        installer.ensure_frozen_installer_elevation([])
