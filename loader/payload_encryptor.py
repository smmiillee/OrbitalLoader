"""
loader/payload_encryptor.py
"""

import os
import json
import base64
import hashlib
import zlib
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PayloadEncryptor:
    def __init__(self, encryption_secret: bytes):
        self._encryption_secret = encryption_secret

    def _get_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self._encryption_secret))

    def encrypt_payload(self, payload_path: Path, output_path: Path) -> dict:
        salt = os.urandom(16)
        key = self._get_key(salt)
        fernet = Fernet(key)

        with open(payload_path, 'rb') as f:
            original_data = f.read()

        compressed = zlib.compress(original_data, level=9)
        encrypted = fernet.encrypt(compressed)

        with open(output_path, 'wb') as f:
            f.write(encrypted)

        original_hash = hashlib.sha256(original_data).hexdigest()

        return {
            'salt': base64.b64encode(salt).decode(),
            'original_size': len(original_data),
            'compressed_size': len(compressed),
            'encrypted_size': len(encrypted),
            'original_hash': original_hash,
            'encrypted_path': str(output_path)
        }

    def decrypt_payload(self, encrypted_path: Path, metadata: dict) -> bytes:
        salt = base64.b64decode(metadata['salt'])
        key = self._get_key(salt)
        fernet = Fernet(key)

        with open(encrypted_path, 'rb') as f:
            encrypted = f.read()

        compressed = fernet.decrypt(encrypted)
        original = zlib.decompress(compressed)

        if hashlib.sha256(original).hexdigest() != metadata['original_hash']:
            raise RuntimeError("Payload integrity check failed")

        return original
