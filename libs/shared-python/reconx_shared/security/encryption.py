"""AES-256-GCM encryption for secrets management."""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import structlog

logger = structlog.get_logger(__name__)


class EncryptionManager:
    """AES-256-GCM encryption for storing sensitive data."""

    def __init__(self, key: bytes | None = None):
        if key is None:
            hex_key = os.getenv("RECONX_ENCRYPTION_KEY", "")
            if not hex_key or len(hex_key) < 64:
                raise ValueError("RECONX_ENCRYPTION_KEY must be 32 bytes (64 hex chars)")
            key = bytes.fromhex(hex_key)
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string and return base64-encoded ciphertext."""
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, ciphertext_b64: str) -> str:
        """Decrypt a base64-encoded ciphertext."""
        raw = base64.b64decode(ciphertext_b64)
        nonce, ct = raw[:12], raw[12:]
        return self._aesgcm.decrypt(nonce, ct, None).decode()


_manager: EncryptionManager | None = None


def _get_manager() -> EncryptionManager:
    global _manager
    if _manager is None:
        _manager = EncryptionManager()
    return _manager


def encrypt_secret(plaintext: str) -> str:
    return _get_manager().encrypt(plaintext)


def decrypt_secret(ciphertext: str) -> str:
    return _get_manager().decrypt(ciphertext)
