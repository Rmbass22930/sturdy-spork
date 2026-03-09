import hashlib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_DIR = ROOT / "installer" / "payload"
CHECKSUMS = ROOT / "CHECKSUMS.txt"
PAYLOAD_ZIP = ROOT / "installer" / "BallisticTargetInstaller.zip"
SED_FILES = [
    ROOT / "installer" / "BallisticTargetInstaller.sed",
    ROOT / "installer" / "InstallBallistic.sed",
]
EXPECTED_BUILD_ARTIFACTS = [
    "BallisticTargetGUI.exe",
    "EnvironmentalsGeoGUI.exe",
    "BallisticTargetInstaller.zip",
    "BallisticTargetSetup.exe",
    "InstallBallistic.exe",
]


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sed_payload_files(path: Path) -> list[str]:
    files = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("FILE") and "=" in line:
            _name, value = line.split("=", 1)
            value = value.strip()
            if value:
                files.append(value)
    return files


def _checksums_entries(path: Path) -> dict[str, str]:
    entries = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        name, hash_value = line.rsplit(None, 1)
        entries[name] = hash_value
    return entries


@pytest.mark.parametrize(
    ("primary_exe", "installer_payload"),
    [
        (ROOT / "BallisticTargetGUI.exe", PAYLOAD_DIR / "BallisticTargetGUI.exe"),
        (ROOT / "EnvironmentalsGeoGUI.exe", PAYLOAD_DIR / "EnvironmentalsGeoGUI.exe"),
    ],
)
def test_installer_payload_in_sync_with_gui_binary(primary_exe: Path, installer_payload: Path):
    if not (primary_exe.exists() and installer_payload.exists()):
        pytest.skip("Build artifacts missing")
    assert primary_exe.stat().st_size > 0
    assert installer_payload.stat().st_size > 0
    assert _md5(primary_exe) == _md5(installer_payload)


@pytest.mark.parametrize("sed_path", SED_FILES)
def test_iexpress_manifest_files_exist_in_payload(sed_path: Path):
    expected_files = _sed_payload_files(sed_path)
    assert expected_files, f"No payload entries parsed from {sed_path.name}"
    missing = [name for name in expected_files if not (PAYLOAD_DIR / name).exists()]
    assert not missing, f"{sed_path.name} references missing payload files: {missing}"


def test_payload_zip_contains_every_manifest_file():
    if not PAYLOAD_ZIP.exists():
        pytest.skip("Payload ZIP missing")
    expected_files = set()
    for sed_path in SED_FILES:
        expected_files.update(_sed_payload_files(sed_path))
    with zipfile.ZipFile(PAYLOAD_ZIP) as archive:
        names = {Path(name).name for name in archive.namelist() if not name.endswith("/")}
    missing = sorted(expected_files - names)
    assert not missing, f"Payload ZIP missing files required by IExpress manifests: {missing}"


def test_checksums_cover_all_primary_build_artifacts():
    if not CHECKSUMS.exists():
        pytest.skip("CHECKSUMS.txt missing")
    entries = _checksums_entries(CHECKSUMS)
    missing = [name for name in EXPECTED_BUILD_ARTIFACTS if name not in entries]
    assert not missing, f"CHECKSUMS.txt missing build artifacts: {missing}"
