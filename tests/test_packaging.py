import hashlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.mark.parametrize(
    ("primary_exe", "installer_payload"),
    [
        (ROOT / "BallisticTargetGUI.exe", ROOT / "installer" / "payload" / "BallisticTargetGUI.exe"),
        (ROOT / "EnvironmentalsGeoGUI.exe", ROOT / "installer" / "payload" / "EnvironmentalsGeoGUI.exe"),
    ],
)
def test_installer_payload_in_sync_with_gui_binary(primary_exe: Path, installer_payload: Path):
    if not (primary_exe.exists() and installer_payload.exists()):
        pytest.skip("Build artifacts missing")
    assert primary_exe.stat().st_size > 0
    assert installer_payload.stat().st_size > 0
    assert _md5(primary_exe) == _md5(installer_payload)
