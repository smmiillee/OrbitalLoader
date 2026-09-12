"""
loader/license_manager.py
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import zlib
import secrets
from datetime import datetime, timezone


def generate_hardware_fingerprint() -> str:
    """
    Stable, cross-platform hardware fingerprint (32 hex chars).

    Windows : HKLM\\SOFTWARE\\Microsoft\\Cryptography -> MachineGuid
              + C: drive volume serial number
    Linux   : /etc/machine-id (fallback /var/lib/dbus/machine-id)
    macOS   : IOPlatformUUID

    The hostname is intentionally NOT part of the fingerprint, so renaming
    the PC does not invalidate licenses. Pointer size is also excluded so
    32/64-bit rebuilds don't break binding.
    """
    components = []

    if sys.platform == 'win32':
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography') as key:
                components.append(str(winreg.QueryValueEx(key, 'MachineGuid')[0]))
        except Exception:
            pass
        try:
            import ctypes
            volume_serial = ctypes.c_ulong(0)
            if ctypes.windll.kernel32.GetVolumeInformationW(
                'C:' + os.sep, None, 0, ctypes.byref(volume_serial), None, None, None, 0
            ):
                components.append(str(volume_serial.value))
        except Exception:
            pass
    else:
        for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
            try:
                with open(path, 'r') as f:
                    components.append(f.read().strip())
                break
            except Exception:
                continue
        if sys.platform == 'darwin':
            try:
                import subprocess
                result = subprocess.run(
                    ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
                    capture_output=True, text=True, timeout=5,
                )
                for line in result.stdout.splitlines():
                    if 'IOPlatformUUID' in line:
                        components.append(line.split('"')[-2])
                        break
            except Exception:
                pass

    components.append(sys.platform)
    combined = '|'.join(str(c) for c in components if c)
    return hashlib.sha256(combined.encode()).hexdigest()[:32]


class LicenseError(Exception):
    pass


class InvalidLicenseError(LicenseError):
    pass


class ExpiredLicenseError(LicenseError):
    pass


class LicenseManager:
    def __init__(self, license_secret: bytes):
        self._license_secret = license_secret

    def generate_license(
        self,
        customer_id: str,
        expiry_days: int = 365,
        hardware_bound: bool = True,
        features: list = None,
        hardware_fingerprint: str = None,
    ) -> dict:
        """
        Generate a signed license.

        hardware_fingerprint: the CUSTOMER's HWID (contents of their
        hardware_id.txt). If omitted while hardware_bound=True, this falls
        back to THIS machine's fingerprint - which is almost never what you
        want when building for a customer. Always pass it explicitly.
        """
        created_at = datetime.now(timezone.utc)
        expires_at = created_at.timestamp() + (expiry_days * 86400)

        hw_fp = None
        if hardware_bound:
            hw_fp = (hardware_fingerprint or '').strip() or generate_hardware_fingerprint()

        license_data = {
            'version': 2,
            'customer_id': customer_id,
            'created_at': created_at.isoformat(),
            'expires_at': expires_at,
            'hardware_bound': hardware_bound,
            'hardware_fingerprint': hw_fp,
            'features': features or ['premium'],
            'max_activations': 1,
            'activation_count': 0,
            'nonce': secrets.token_hex(16),
        }

        payload = json.dumps(license_data, sort_keys=True).encode()
        signature = hmac.new(self._license_secret, payload, hashlib.sha256).hexdigest()

        license_bundle = {
            'data': license_data,
            'signature': signature
        }

        license_json = json.dumps(license_bundle)
        license_key = base64.urlsafe_b64encode(
            zlib.compress(license_json.encode())
        ).decode().rstrip('=')

        return {
            'license_key': license_key,
            'customer_id': customer_id,
            'expires': datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
            'hardware_fingerprint': hw_fp,
        }

    def validate_license(self, license_key: str) -> dict:
        try:
            padding = 4 - (len(license_key) % 4)
            if padding != 4:
                license_key += '=' * padding

            compressed = base64.urlsafe_b64decode(license_key)
            license_json = zlib.decompress(compressed)
            bundle = json.loads(license_json)
        except Exception as e:
            raise InvalidLicenseError(f"Invalid license format: {e}")

        payload = json.dumps(bundle['data'], sort_keys=True).encode()
        expected_sig = hmac.new(
            self._license_secret,
            payload,
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected_sig, bundle['signature']):
            raise InvalidLicenseError("License signature verification failed")

        data = bundle['data']

        if datetime.now(timezone.utc).timestamp() > data['expires_at']:
            raise ExpiredLicenseError(
                f"License expired on {datetime.fromtimestamp(data['expires_at'], tz=timezone.utc).isoformat()}"
            )

        if data.get('hardware_bound'):
            current_hw = generate_hardware_fingerprint()
            stored_hw = data.get('hardware_fingerprint')
            if not stored_hw:
                raise LicenseError("License is hardware-bound but contains no fingerprint")
            if stored_hw != current_hw:
                raise LicenseError(
                    f"License bound to different hardware. "
                    f"Expected: {stored_hw}, Got: {current_hw}"
                )

        return data
