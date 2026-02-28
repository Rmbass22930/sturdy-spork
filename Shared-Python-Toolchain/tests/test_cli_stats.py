from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from common_crypto import AES256GCMCipher
from memory_optimizer import cli

runner = CliRunner()


def test_stats_decrypt_roundtrip(tmp_path: Path) -> None:
    stats = {"available_mb": 1024.0, "reserved_mb": 256.0}
    payload = AES256GCMCipher().encrypt_text(
        "passphrase",
        json.dumps(stats, indent=2),
        associated_data=cli._STATS_AAD,  # noqa: SLF001
    )
    enc_path = tmp_path / "stats.enc"
    enc_path.write_text(payload)

    result = runner.invoke(
        cli.app,
        ["stats-decrypt", str(enc_path), "--stats-key", "passphrase"],
    )

    assert result.exit_code == 0
    assert '"available_mb": 1024.0' in result.stdout
