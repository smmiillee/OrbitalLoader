"""
loader/crypto_core.py
"""

import os
import base64
import hashlib
import hmac


class EnvVault:
    """Production: Secrets from environment variables."""

    def __init__(self, prefix: str = 'LOADER'):
        self._prefix = prefix

    def _get(self, name: str) -> bytes:
        full_name = f"{self._prefix}_{name}"
        value = os.environ.get(full_name)
        if not value:
            raise RuntimeError(f"Missing secret: {full_name}")
        # Add padding if needed for base64
        padding = 4 - (len(value) % 4)
        if padding != 4:
            value += '=' * padding
        return base64.b64decode(value)

    def get_master_secret(self) -> bytes:
        return self._get('MASTER_SECRET')


def derive_license_secret(master: bytes) -> bytes:
    return hmac.new(b'license-v1', master, hashlib.sha256).digest()


def derive_encryption_secret(master: bytes) -> bytes:
    return hmac.new(b'encrypt-v1', master, hashlib.sha256).digest()
