import hashlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PRIMARY_EXE = ROOT / "BallisticTargetGUI.exe"
INSTALLER_PAYLOAD = ROOT / "installer" / "payload" / "BallisticTargetGUI.exe"


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.mark.skipif(not (PRIMARY_EXE.exists() and INSTALLER_PAYLOAD.exists()), reason="Build artifacts missing")
def test_installer_payload_in_sync_with_gui_binary():
    assert PRIMARY_EXE.stat().st_size > 0
    assert INSTALLER_PAYLOAD.stat().st_size > 0
    assert _md5(PRIMARY_EXE) == _md5(INSTALLER_PAYLOAD)
