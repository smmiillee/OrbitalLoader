"""
build_tools/builder.py
"""

import os
import sys
import json
import base64
import argparse
import tempfile
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
                    hardware_bound: bool = True) -> dict:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[+] Generating license for {customer_id}...")
        license_info = self._license_mgr.generate_license(
            customer_id=customer_id,
            expiry_days=expiry_days,
            features=['premium'],
            hardware_bound=hardware_bound
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
        embedded_license = repr(license_key)
        master_secret_b64 = repr(base64.b64encode(self._master).decode())

        template = r'''#!/usr/bin/env python3
"""
Secure Loader - Auto-generated
"""

import os
import sys
import json
import base64
import subprocess
import tempfile
import stat
import traceback
from pathlib import Path

# Embedded license
EMBEDDED_LICENSE = ''' + embedded_license + r'''

def _write_debug(content):
    try:
        loc = Path.home() / 'Desktop'
        loc.mkdir(exist_ok=True)
        with open(loc / 'debug.txt', 'w') as f:
            f.write(str(content))
    except:
        pass

# Load license - search multiple locations
LICENSE_KEY = None
license_sources = []
search_paths = [
    Path.cwd(),
    Path(sys.executable).parent,
    Path.home() / 'Desktop',
    Path(__file__).parent if '__file__' in dir() else None,
    Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else None,
]
for base in search_paths:
    if not base:
        continue
    test_path = base / 'license.key'
    if test_path.exists():
        try:
            with open(test_path, 'r', encoding='utf-8') as f:
                raw = f.read()
            cleaned = raw.encode('utf-8').decode('utf-8-sig')
            cleaned = ''.join(c for c in cleaned if not c.isspace())
            LICENSE_KEY = cleaned
            license_sources.append(f"Found at: {test_path} (len={len(cleaned)})")
            break
        except Exception as e:
            license_sources.append(f"Failed at {test_path}: {e}")

if not LICENSE_KEY and EMBEDDED_LICENSE:
    LICENSE_KEY = EMBEDDED_LICENSE
    license_sources.append("Using embedded")

if not LICENSE_KEY:
    license_sources.append("No license found")

_write_debug("License sources:\n" + '\n'.join(license_sources))

# Verify license
import zlib
import hashlib
import hmac

def _get_hardware_fingerprint():
    import struct
    import socket
    components = []
    for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
        try:
            with open(path, 'r') as f:
                components.append(f.read().strip())
            break
        except:
            pass
    try:
        components.append(socket.gethostname())
    except:
        pass
    components.append(sys.platform)
    components.append(struct.calcsize('P') * 8)
    combined = '|'.join(str(c) for c in components if c)
    return hashlib.sha256(combined.encode()).hexdigest()[:32]

def _get_write_dir():
    desktop = Path.home() / 'Desktop'
    desktop.mkdir(exist_ok=True)
    return desktop

def _reconstruct_secret():
    master_b64 = ''' + master_secret_b64 + r'''
    padding = 4 - (len(master_b64) % 4)
    if padding != 4:
        master_b64 += '=' * padding
    return base64.b64decode(master_b64)

def _derive_keys(master):
    lic = hmac.new(b'license-v1', master, hashlib.sha256).digest()
    enc = hmac.new(b'encrypt-v1', master, hashlib.sha256).digest()
    return lic, enc

def validate_license(license_key, license_secret):
    debug_info = []
    debug_info.append(f"Key length: {len(license_key)}")
    debug_info.append(f"Key first 20: {license_key[:20]}")
    
    if not license_key:
        raise ValueError("No license provided")
    padding = 4 - (len(license_key) % 4)
    if padding != 4:
        license_key += '=' * padding
    compressed = base64.urlsafe_b64decode(license_key)
    license_json = zlib.decompress(compressed)
    bundle = json.loads(license_json)
    
    lic_hw = bundle['data'].get('hardware_fingerprint', 'NONE')
    cur_hw = _get_hardware_fingerprint()
    
    debug_info.append(f"License customer: {bundle['data'].get('customer_id')}")
    debug_info.append(f"License HW: {lic_hw}")
    debug_info.append(f"Current HW: {cur_hw}")
    debug_info.append(f"Match: {lic_hw == cur_hw}")
    debug_info.append(f"HW bound: {bundle['data'].get('hardware_bound')}")
    
    _write_debug('\n'.join(debug_info))
    
    payload = json.dumps(bundle['data'], sort_keys=True).encode()
    expected = hmac.new(license_secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, bundle['signature']):
        raise ValueError("Invalid license signature")
    import time
    if time.time() > bundle['data']['expires_at']:
        raise ValueError("License expired")
    if bundle['data'].get('hardware_bound'):
        if lic_hw != cur_hw:
            raise ValueError("License bound to different hardware. Your hardware ID: " + cur_hw)
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

def _secure_write(path, data):
    with open(path, 'wb') as f:
        f.write(data)
    if sys.platform != 'win32':
        os.chmod(path, stat.S_IRWXU)

def execute_exe(data):
    fd, path = tempfile.mkstemp(suffix='.exe' if sys.platform == 'win32' else '')
    try:
        os.close(fd)
        _secure_write(path, data)
        result = subprocess.run([path] + sys.argv[1:])
        return result.returncode
    finally:
        try:
            os.unlink(path)
        except:
            pass

def _show_error(title, message):
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
        except:
            pass

def _show_info(title, message):
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
        except:
            pass

def main():
    if not LICENSE_KEY:
        hw_id = _get_hardware_fingerprint()
        write_dir = _get_write_dir()
        hw_file = write_dir / 'hardware_id.txt'
        with open(hw_file, 'w') as f:
            f.write(hw_id)
        msg = "Your hardware ID: " + hw_id + "\n\nhardware_id.txt saved to your Desktop.\nSend that file to get a new license."
        _show_info("LICENSE REQUIRED", msg)
        return 1

    try:
        master = _reconstruct_secret()
        lic_secret, enc_secret = _derive_keys(master)
        license_data = validate_license(LICENSE_KEY, lic_secret)
    except ValueError as e:
        err_str = str(e)
        if 'hardware ID:' in err_str:
            hw_id = err_str.split('hardware ID:')[-1].strip()
            write_dir = _get_write_dir()
            hw_file = write_dir / 'hardware_id.txt'
            with open(hw_file, 'w') as f:
                f.write(hw_id)
            err_str += '\n\nhardware_id.txt saved to your Desktop.\nSend that file to get a new license.'
        _show_error("License Error", err_str)
        return 1
    except Exception as e:
        _write_debug("Unexpected error:\n" + traceback.format_exc())
        _show_error("Error", f"Unexpected error: {e}")
        return 1

    enc_path = None
    meta_path = None
    for base in [
        Path(sys.executable).parent if getattr(sys, 'frozen', False) else None,
        Path(__file__).parent,
        Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else None,
    ]:
        if base:
            test_enc = base / 'payload.enc'
            test_meta = base / 'payload.meta'
            if test_enc.exists() and test_meta.exists():
                enc_path = test_enc
                meta_path = test_meta
                break

    if not enc_path:
        _show_error("Error", "Payload not found!")
        return 1

    with open(meta_path) as f:
        meta = json.load(f)

    payload = decrypt_payload(enc_path, meta, enc_secret)
    return execute_exe(payload)

if __name__ == '__main__':
    sys.exit(main())
'''

        loader_path = output_dir / 'loader.py'
        with open(loader_path, 'w') as f:
            f.write(template)

        print(f"[+] Standalone loader: {loader_path}")


def main():
    parser = argparse.ArgumentParser(description='Secure Loader Builder')
    subparsers = parser.add_subparsers(dest='command', required=True)

    exe_parser = subparsers.add_parser('protect-exe', help='Protect executable')
    exe_parser.add_argument('exe', type=Path, help='Path to EXE/binary')
    exe_parser.add_argument('-o', '--output', type=Path, default=Path('protected'))
    exe_parser.add_argument('--customer', required=True)
    exe_parser.add_argument('--days', type=int, default=365)
    exe_parser.add_argument('--no-hardware', action='store_true', help='Disable hardware binding')

    hw_parser = subparsers.add_parser('generate-license', help='Generate license for hardware ID')
    hw_parser.add_argument('--customer', required=True)
    hw_parser.add_argument('--days', type=int, default=365)
    hw_parser.add_argument('--hardware-id', required=True, help='Hardware ID from customer')

    args = parser.parse_args()

    if args.command == 'protect-exe':
        orch = BuildOrchestrator()
        result = orch.protect_exe(
            exe_path=args.exe,
            output_dir=args.output,
            customer_id=args.customer,
            expiry_days=args.days,
            hardware_bound=not args.no_hardware
        )
        print(json.dumps(result, indent=2))

    elif args.command == 'generate-license':
        orch = BuildOrchestrator()
        lic = orch._license_mgr.generate_license(
            customer_id=args.customer,
            expiry_days=args.days,
            features=['premium'],
            hardware_bound=True
        )
        import zlib
        padding = 4 - (len(lic['license_key']) % 4)
        compressed = base64.urlsafe_b64decode(lic['license_key'] + ('=' * padding if padding != 4 else ''))
        lic_json = zlib.decompress(compressed)
        lic_data = json.loads(lic_json)
        
        print(f"DEBUG: Original HW: {lic_data['data'].get('hardware_fingerprint')}")
        print(f"DEBUG: Target HW: {args.hardware_id}")
        
        lic_data['data']['hardware_fingerprint'] = args.hardware_id
        
        payload = json.dumps(lic_data['data'], sort_keys=True).encode()
        import hmac, hashlib
        lic_data['signature'] = hmac.new(derive_license_secret(orch._master), payload, hashlib.sha256).hexdigest()
        
        print(f"DEBUG: New HW in data: {lic_data['data'].get('hardware_fingerprint')}")
        print(f"DEBUG: Signature length: {len(lic_data['signature'])}")
        
        new_json = json.dumps(lic_data)
        lic_key = base64.urlsafe_b64encode(zlib.compress(new_json.encode())).decode().rstrip('=')
        print(f"License key for {args.customer}:")
        print(lic_key)

    return 0


if __name__ == '__main__':
    sys.exit(main())
