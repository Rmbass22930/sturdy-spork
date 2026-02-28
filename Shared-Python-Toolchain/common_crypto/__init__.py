"""Shared cryptographic helpers for all local projects."""
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Final, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants tuned for AES-256-GCM with PBKDF2-HMAC-SHA256 derivation.
_KEY_LEN: Final[int] = 32  # 256-bit keys
_DEFAULT_SALT_BYTES: Final[int] = 16
_DEFAULT_NONCE_BYTES: Final[int] = 12
_DEFAULT_ITERATIONS: Final[int] = 310_000


@dataclass
class AES256GCMCipher:
    """Convenience wrapper around AES-256-GCM with PBKDF2 key derivation."""

    iterations: int = _DEFAULT_ITERATIONS
    salt_bytes: int = _DEFAULT_SALT_BYTES
    nonce_bytes: int = _DEFAULT_NONCE_BYTES

    def __post_init__(self) -> None:
        if self.salt_bytes < 16:
            raise ValueError("salt_bytes must be at least 16 for PBKDF2 entropy")
        if self.nonce_bytes != 12:
            raise ValueError("nonce_bytes must be 12 for AESGCM interoperability")
        if self.iterations <= 0:
            raise ValueError("iterations must be positive")

    def _derive_key(self, master_secret: str, salt: bytes) -> bytes:
        if not master_secret:
            raise ValueError("master_secret must be non-empty")
        return hashlib.pbkdf2_hmac(
            "sha256",
            master_secret.encode("utf-8"),
            salt,
            self.iterations,
            dklen=_KEY_LEN,
        )

    def encrypt(
        self,
        master_secret: str,
        plaintext: bytes,
        *,
        associated_data: Optional[bytes] = None,
    ) -> str:
        salt = os.urandom(self.salt_bytes)
        nonce = os.urandom(self.nonce_bytes)
        key = self._derive_key(master_secret, salt)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, plaintext, associated_data)
        payload = salt + nonce + ciphertext
        return base64.urlsafe_b64encode(payload).decode("ascii")

    def decrypt(
        self,
        master_secret: str,
        payload: str,
        *,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        if len(decoded) <= self.salt_bytes + self.nonce_bytes:
            raise ValueError("payload is too short to include salt/nonce/ciphertext")
        salt = decoded[: self.salt_bytes]
        nonce = decoded[self.salt_bytes : self.salt_bytes + self.nonce_bytes]
        ciphertext = decoded[self.salt_bytes + self.nonce_bytes :]
        key = self._derive_key(master_secret, salt)
        aes = AESGCM(key)
        return aes.decrypt(nonce, ciphertext, associated_data)

    def encrypt_text(
        self,
        master_secret: str,
        plaintext: str,
        *,
        associated_data: Optional[bytes] = None,
    ) -> str:
        return self.encrypt(master_secret, plaintext.encode("utf-8"), associated_data=associated_data)

    def decrypt_text(
        self,
        master_secret: str,
        payload: str,
        *,
        associated_data: Optional[bytes] = None,
    ) -> str:
        data = self.decrypt(master_secret, payload, associated_data=associated_data)
        return data.decode("utf-8")


__all__ = ["AES256GCMCipher"]
