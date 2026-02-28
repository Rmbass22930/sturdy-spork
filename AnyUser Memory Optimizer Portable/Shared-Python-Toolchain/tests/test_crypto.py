"""Tests for the shared AES-256-GCM helper."""
from __future__ import annotations

import pytest

from common_crypto import AES256GCMCipher


def test_encrypt_decrypt_roundtrip() -> None:
    cipher = AES256GCMCipher()
    secret = "correct horse battery staple"
    plaintext = "Sensitive payload that must stay secret."

    payload = cipher.encrypt_text(secret, plaintext)

    assert payload != plaintext
    recovered = cipher.decrypt_text(secret, payload)
    assert recovered == plaintext


def test_associated_data_enforced() -> None:
    cipher = AES256GCMCipher()
    secret = "passphrase"
    aad = b"memory-optimizer"

    payload = cipher.encrypt_text(secret, "stats snapshot", associated_data=aad)

    with pytest.raises(Exception):
        cipher.decrypt_text(secret, payload)

    result = cipher.decrypt_text(secret, payload, associated_data=aad)
    assert result == "stats snapshot"


def test_wrong_secret_fails() -> None:
    cipher = AES256GCMCipher()
    payload = cipher.encrypt_text("secret-a", "data")

    with pytest.raises(Exception):
        cipher.decrypt_text("secret-b", payload)
