"""Utility helpers."""
from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

from common_crypto import AES256GCMCipher

_cipher = AES256GCMCipher()


def encrypt_secret(master: str, plaintext: str) -> str:
    return _cipher.encrypt_text(master, plaintext)


def decrypt_secret(master: str, payload: str) -> str:
    return _cipher.decrypt_text(master, payload)


def generate_totp(secret: bytes, timestep: int, counter_override: int | None = None) -> str:
    if counter_override is not None:
        counter = counter_override
    else:
        counter = int(datetime.now(UTC).timestamp() // timestep)
    counter_bytes = counter.to_bytes(8, "big")
    h = hmac.new(secret, counter_bytes, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (int.from_bytes(h[offset:offset + 4], "big") & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"
