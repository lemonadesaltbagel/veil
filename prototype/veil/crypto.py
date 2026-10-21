"""At-rest encryption for real values (AES-256-GCM).

Each ciphertext is bound to its row via associated data (the token), so rows
can't be swapped; lookups use a keyed hash of (kind, value), never the value.
`NullCipher` keeps the same interface for in-memory/test vaults.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Cipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("vault key must be 32 bytes")
        self._aead = AESGCM(hmac.new(key, b"veil-aead-v1", hashlib.sha256).digest())
        self._mac = hmac.new(key, b"veil-lookup-v1", hashlib.sha256).digest()

    def lookup(self, kind: str, value: str) -> str:
        return hmac.new(self._mac, f"{kind}\0{value}".encode(), hashlib.sha256).hexdigest()

    def seal(self, plaintext: str, aad: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, plaintext.encode(), aad.encode())

    def open(self, blob: bytes, aad: str) -> str:
        return self._aead.decrypt(blob[:12], blob[12:], aad.encode()).decode()


class NullCipher:
    """Plaintext (in-memory vaults, tests)."""

    def lookup(self, kind: str, value: str) -> str:
        return f"{kind}\0{value}"

    def seal(self, plaintext: str, aad: str) -> bytes:
        return plaintext.encode()

    def open(self, blob: bytes, aad: str) -> str:
        return bytes(blob).decode()
