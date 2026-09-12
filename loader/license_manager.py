"""
loader/license_manager.py
"""

import json
import base64
import hashlib
import hmac
import zlib
import secrets
import struct
from datetime import datetime, timezone


class LicenseError(Exception):
    pass


class InvalidLicenseError(LicenseError):
    pass


class ExpiredLicenseError(LicenseError):
    pass


class LicenseManager:
    def __init__(self, license_secret: bytes):
        self._license_secret = license_secret

    @staticmethod
    def get_hardware_fingerprint() -> str:
        import sys
        import socket

        components = []

        for path in ['/etc/machine-id', '/var/lib/dbus/machine-id']:
            try:
                with open(path, 'r') as f:
                    components.append(f.read().strip())
                break
            except Exception:
                pass

        try:
            components.append(socket.gethostname())
        except Exception:
            pass

        components.append(sys.platform)
        components.append(struct.calcsize('P') * 8)

        combined = '|'.join(str(c) for c in components if c)
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    def generate_license(
        self,
        customer_id: str,
        expiry_days: int = 365,
        hardware_bound: bool = True,
        features: list = None,
    ) -> dict:
        created_at = datetime.now(timezone.utc)
        expires_at = created_at.timestamp() + (expiry_days * 86400)

        hw_fp = self.get_hardware_fingerprint() if hardware_bound else None

        license_data = {
            'version': 1,
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
        signature = hmac.new(
            self._license_secret,
            payload,
            hashlib.sha256
        ).hexdigest()

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
            'hardware_fingerprint': hw_fp
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

        now = datetime.now(timezone.utc).timestamp()
        if now > data['expires_at']:
            raise ExpiredLicenseError(
                f"License expired on {datetime.fromtimestamp(data['expires_at'], tz=timezone.utc).isoformat()}"
            )

        if data.get('hardware_bound'):
            current_hw = self.get_hardware_fingerprint()
            stored_hw = data.get('hardware_fingerprint')
            if stored_hw and stored_hw != current_hw:
                raise LicenseError(
                    f"License bound to different hardware. "
                    f"Expected: {stored_hw}, Got: {current_hw}"
                )

        return data
