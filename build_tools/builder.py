"""
build_tools/builder.py
"""

import os
import sys
import json
import base64
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loader.crypto_core import EnvVault, derive_license_secret, derive_encryption_secret
from loader.license_manager import LicenseManager
from loader.payload_encryptor import PayloadEncryptor


class BuildOrchestrator:
    def __init__(self):
        vault = EnvVault()
        self._master = vault.get_master_secret()
        self._license_mgr = LicenseManager(derive_license_secret(self._master))
        self._encryptor = PayloadEncryptor(derive_encryption_secret(self._master))

    def protect_exe(self, exe_path: Path, output_dir: Path,
                    customer_id: str, expiry_days: int = 365,
                    features: list = None) -> dict:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[+] Generating license for {customer_id}...")
        license_info = self._license_mgr.generate_license(
            customer_id=customer_id,
            expiry_days=expiry_days,
            features=features or ['basic']
        )

        license_path = output_dir / 'license.key'
        with open(license_path, 'w') as f:
            f.write(license_info['license_key'])
        print(f"[+] License saved")

        print(f"[+] Encrypting {exe_path}...")
        payload_path = output_dir / 'payload.enc'
        meta = self._encryptor.encrypt_payload(exe_path, payload_path)

        meta_path = output_dir / 'payload.meta'
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)

        self._generate_loader(output_dir, license_info['license_key'])

        return {
            'customer_id': customer_id,
            'license_key': license_info['license_key'],
            'expires': license_info['expires'],
            'output_dir': str(output_dir),
        }

    def _generate_loader(self, output_dir: Path, license_key: str):
        template = '''#!/usr/bin/env python3
"""
Secure Loader - Auto-generated
"""

import os
import sys
import json
import base64
import subprocess
import tempfile
from pathlib import Path

# Embedded license
EMBEDDED_LICENSE = {embedded_license}

# Load license
license_path = Path(__file__).parent / 'license.key'
if license_path.exists():
    with open(license_path) as f:
        LICENSE_KEY = f.read().strip()
elif EMBEDDED_LICENSE:
    LICENSE_KEY = EMBEDDED_LICENSE
else:
    LICENSE_KEY = input("Enter license key: ").strip()

# Verify license
import zlib
import hashlib
import hmac

_SECRET_PIECES = {pieces}
_SECRET_ORDER = {order}

def _reconstruct_secret():
    ordered = [_SECRET_PIECES[i] for i in _SECRET_ORDER]
    cleaned = []
    for piece in ordered:
        cleaned.append(''.join(c for i, c in enumerate(piece) if i % 3 != 2))
    combined = ''.join(cleaned)
    # Fix base64 padding
    padding = 4 - (len(combined) % 4)
    if padding != 4:
        combined += '=' * padding
    return base64.b64decode(combined)

def _derive_keys(master):
    lic = hmac.new(b'license-v1', master, hashlib.sha256).digest()
    enc = hmac.new(b'encrypt-v1', master, hashlib.sha256).digest()
    return lic, enc

def validate_license(license_key, license_secret):
    padding = 4 - (len(license_key) % 4)
    if padding != 4:
        license_key += '=' * padding

    compressed = base64.urlsafe_b64decode(license_key)
    license_json = zlib.decompress(compressed)
    bundle = json.loads(license_json)

    payload = json.dumps(bundle['data'], sort_keys=True).encode()
    expected = hmac.new(license_secret, payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, bundle['signature']):
        raise ValueError("Invalid license")

    import time
    if time.time() > bundle['data']['expires_at']:
        raise ValueError("License expired")

    return bundle['data']

def decrypt_payload(enc_path, meta, enc_secret):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    salt = base64.b64decode(meta['salt'])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(enc_secret))

    fernet = Fernet(key)
    with open(enc_path, 'rb') as f:
        encrypted = f.read()

    compressed = fernet.decrypt(encrypted)
    import zlib
    original = zlib.decompress(compressed)

    if hashlib.sha256(original).hexdigest() != meta['original_hash']:
        raise ValueError("Integrity check failed")

    return original

def execute_exe(data):
    fd, path = tempfile.mkstemp(suffix='.exe' if sys.platform == 'win32' else '')
    try:
        os.fchmod(fd, 0o700)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        if sys.platform != 'win32':
            os.chmod(path, 0o700)
        result = subprocess.run([path] + sys.argv[1:])
        return result.returncode
    finally:
        try:
            os.unlink(path)
        except:
            pass

def main():
    master = _reconstruct_secret()
    lic_secret, enc_secret = _derive_keys(master)

    print("Validating license...")
    license_data = validate_license(LICENSE_KEY, lic_secret)
    print(f"Licensed to: {{license_data['customer_id']}}")

    base = Path(__file__).parent
    enc_path = base / 'payload.enc'
    with open(base / 'payload.meta') as f:
        meta = json.load(f)

    print("Decrypting payload...")
    payload = decrypt_payload(enc_path, meta, enc_secret)
    print(f"Payload: {{len(payload)}} bytes")

    print("Launching...")
    return execute_exe(payload)

if __name__ == '__main__':
    sys.exit(main())
'''

        import secrets as sec
        encoded = base64.b64encode(self._master).decode()
        chunks = [encoded[i:i+8] for i in range(0, len(encoded), 8)]
        pieces = []
        for chunk in chunks:
            noisy = ''.join(c + sec.choice('0123456789abcdef') for c in chunk)
            pieces.append(noisy)
        order = list(range(len(pieces)))
        sec.SystemRandom().shuffle(order)

        loader_code = template.format(
            embedded_license=repr(license_key),
            pieces=json.dumps(pieces),
            order=json.dumps(order)
        )

        loader_path = output_dir / 'loader.py'
        with open(loader_path, 'w') as f:
            f.write(loader_code)

        print(f"[+] Standalone loader: {loader_path}")


def main():
    parser = argparse.ArgumentParser(description='Secure Loader Builder')
    subparsers = parser.add_subparsers(dest='command', required=True)

    exe_parser = subparsers.add_parser('protect-exe', help='Protect executable')
    exe_parser.add_argument('exe', type=Path, help='Path to EXE/binary')
    exe_parser.add_argument('-o', '--output', type=Path, default=Path('protected'))
    exe_parser.add_argument('--customer', required=True)
    exe_parser.add_argument('--days', type=int, default=365)
    exe_parser.add_argument('--features', nargs='+', default=['basic'])

    args = parser.parse_args()

    if args.command == 'protect-exe':
        orch = BuildOrchestrator()
        result = orch.protect_exe(
            exe_path=args.exe,
            output_dir=args.output,
            customer_id=args.customer,
            expiry_days=args.days,
            features=args.features
        )
        print(json.dumps(result, indent=2))

    return 0


if __name__ == '__main__':
    sys.exit(main())
