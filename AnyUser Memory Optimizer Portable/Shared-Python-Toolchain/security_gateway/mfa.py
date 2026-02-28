"""MFA helpers."""
from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Dict, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import settings
from .models import WebAuthnResponse
from .utils import generate_totp


@dataclass
class WebAuthnCredential:
    credential_id: str
    public_key: Ed25519PublicKey


class MFAChallenge:
    def __init__(self, user_id: str, challenge_id: str, expires_at: datetime, method: str = "totp"):
        self.user_id = user_id
        self.challenge_id = challenge_id
        self.expires_at = expires_at
        self.method = method

    def expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at


class MFAService:
    def __init__(self, timestep: int = 30):
        self._timestep = timestep
        self._totp_secrets: Dict[str, bytes] = {}
        self._challenges: Dict[str, MFAChallenge] = {}
        self._webauthn: Dict[str, Dict[str, WebAuthnCredential]] = {}

    def register_webauthn(self, user_id: str, credential_id: str, public_key_b64: str) -> None:
        public_key_bytes = base64.b64decode(public_key_b64)
        credential = WebAuthnCredential(credential_id=credential_id, public_key=Ed25519PublicKey.from_public_bytes(public_key_bytes))
        self._webauthn.setdefault(user_id, {})[credential_id] = credential

    def has_webauthn(self, user_id: str) -> bool:
        return bool(self._webauthn.get(user_id))

    def _get_secret(self, user_id: str) -> bytes:
        if user_id not in self._totp_secrets:
            self._totp_secrets[user_id] = os.urandom(20)
        return self._totp_secrets[user_id]

    def issue_challenge(self, user_id: str) -> MFAChallenge:
        method = "webauthn" if self.has_webauthn(user_id) else "totp"
        challenge_id = secrets.token_urlsafe(16)
        challenge = MFAChallenge(
            user_id=user_id,
            challenge_id=challenge_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            method=method,
        )
        self._challenges[challenge_id] = challenge
        return challenge

    def verify_totp(self, user_id: str, token: Optional[str]) -> bool:
        if not token:
            return False
        secret = self._get_secret(user_id)
        base_counter = int(datetime.now(UTC).timestamp() // self._timestep)
        for offset in range(-settings.totp_window, settings.totp_window + 1):
            counter = base_counter + offset
            expected = generate_totp(secret, self._timestep, counter_override=counter)
            if secrets.compare_digest(expected, token):
                return True
        return False

    def verify_webauthn(self, user_id: str, response: Optional[WebAuthnResponse]) -> bool:
        if not response:
            return False
        cred = self._webauthn.get(user_id, {}).get(response.credential_id)
        if not cred:
            return False
        challenge = self._challenges.get(response.challenge_id)
        if not challenge or challenge.user_id != user_id:
            return False
        try:
            signature = base64.b64decode(response.signature)
            cred.public_key.verify(signature, response.challenge_id.encode())
            self._challenges.pop(response.challenge_id, None)
            return True
        except Exception:  # noqa: BLE001
            return False

    def satisfy(self, user_id: str, token: Optional[str], webauthn: Optional[WebAuthnResponse]) -> bool:
        if webauthn and self.verify_webauthn(user_id, webauthn):
            return True
        return self.verify_totp(user_id, token)

    def validate_challenge(self, challenge_id: str, token: str) -> bool:
        challenge = self._challenges.get(challenge_id)
        if not challenge or challenge.expired():
            return False
        if challenge.method == "webauthn":
            # WebAuthn requires verify_webauthn via satisfy
            return False
        if self.verify_totp(challenge.user_id, token):
            self._challenges.pop(challenge_id, None)
            return True
        return False
