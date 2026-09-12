"""
build_tools/builder.py
Builds protected, licensed launchers for one or more customer executables.
"""

import re
import sys
import json
import base64
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from loader.crypto_core import EnvVault, derive_license_secret, derive_encryption_secret
from loader.license_manager import LicenseManager
from loader.payload_encryptor import PayloadEncryptor


def _safe_stem(name: str) -> str:
    stem = Path(name).stem
    return re.sub(r'[^A-Za-z0-9_.\-]', '_', stem) or 'payload'


class BuildOrchestrator:
    def __init__(self):
        vault = EnvVault()
        self._master = vault.get_master_secret()
        # Only the DERIVED secrets get embedded into customer launchers.
        # The master secret never leaves this process.
        self._license_secret = derive_license_secret(self._master)
        self._encryption_secret = derive_encryption_secret(self._master)
        self._license_mgr = LicenseManager(self._license_secret)
        self._encryptor = PayloadEncryptor(self._encryption_secret)

    def protect_exe(self, exe_paths, output_dir, customer_id, expiry_days=365,
                    embed_license=True, hardware_bound=True,
                    hardware_fingerprint=None) -> dict:
        if embed_license and hardware_bound and not (hardware_fingerprint or '').strip():
            raise SystemExit(
                "[!] Refusing to build: embedding a hardware-bound license but no "
                "--hardware-id was supplied. The license would bind to this build\n"
                "    machine instead of the customer's PC.\n"
                "    Pass --hardware-id <customer HWID>, --no-hardware, or "
                "--no-embed-license."
            )

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        license_key = ''
        license_info = None

        if embed_license:
            print(f"[+] Generating license for {customer_id}...")
            license_info = self._license_mgr.generate_license(
                customer_id=customer_id,
                expiry_days=expiry_days,
                features=['premium'],
                hardware_bound=hardware_bound,
                hardware_fingerprint=hardware_fingerprint,
            )
            if hardware_bound:
                print(f"[+] License bound to HWID: {hardware_fingerprint}")

            license_path = output_dir / 'license.key'
            with open(license_path, 'w') as f:
                f.write(license_info['license_key'])
            print("[+] License saved")
            license_key = license_info['license_key']
        else:
            print("[+] No embedded license - the customer's first run will")
            print("    show their hardware ID and write hardware_id.txt.")
            print("    Generate their license with 'generate-license', then")
            print("    have them drop license.key next to the launcher.")

        encrypted = []
        for exe_path in exe_paths:
            exe_path = Path(exe_path)
            if not exe_path.exists():
                raise SystemExit(f"[!] EXE not found: {exe_path}")

            stem = _safe_stem(exe_path.name)
            print(f"[+] Encrypting {exe_path.name} -> payload_{stem}.enc")
            payload_path = output_dir / ('payload_' + stem + '.enc')
            meta = self._encryptor.encrypt_payload(exe_path, payload_path)
            meta['original_name'] = exe_path.name

            meta_path = output_dir / ('payload_' + stem + '.meta')
            with open(meta_path, 'w') as f:
                json.dump(meta, f, indent=2)

            encrypted.append({
                'source': str(exe_path),
                'payload': payload_path.name,
                'meta': meta_path.name,
            })

        self._generate_loader(output_dir, license_key)

        result = {
            'customer_id': customer_id,
            'embedded_license': bool(embed_license),
            'payloads': encrypted,
            'expires': license_info['expires'] if license_info else None,
            'hardware_fingerprint': license_info['hardware_fingerprint'] if license_info else None,
            'output_dir': str(output_dir),
        }
        if license_info:
            result['license_key'] = license_info['license_key']
        return result

    def generate_license(self, customer_id, expiry_days=365,
                         hardware_id=None, no_hardware=False) -> dict:
        if not no_hardware and not (hardware_id or '').strip():
            raise SystemExit(
                "[!] Refusing to generate a hardware-bound license without "
                "--hardware-id (it would bind to this machine instead of the "
                "customer's PC). Pass --hardware-id <customer HWID> or --no-hardware."
            )
        return self._license_mgr.generate_license(
            customer_id=customer_id,
            expiry_days=expiry_days,
            features=['premium'],
            hardware_bound=not no_hardware,
            hardware_fingerprint=hardware_id,
        )

    def _generate_loader(self, output_dir: Path, license_key: str):
        embedded_license = repr(license_key)
        license_secret_b64 = repr(base64.b64encode(self._license_secret).decode())
        encryption_secret_b64 = repr(base64.b64encode(self._encryption_secret).decode())

        template = r'''#!/usr/bin/env python3
"""
Secure Launcher - Auto-generated by OrbitalLoader.
Do not edit manually.
"""

import os
import sys
import json
import time
import base64
import hashlib
import hmac
import zlib
import stat
import subprocess
import tempfile
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

EMBEDDED_LICENSE = __EMBEDDED_LICENSE__
EMBEDDED_LICENSE_SECRET_B64 = __LICENSE_SECRET_B64__
EMBEDDED_ENCRYPT_SECRET_B64 = __ENCRYPT_SECRET_B64__

# Captured ONCE at module level, where '__file__' is always defined.
# (Using dir() inside a function only sees local names - do not change back.)
SCRIPT_FILE = globals().get('__file__')

CLI_ARGS = sys.argv[1:]
NO_GUI = '--nogui' in CLI_ARGS
PAYLOAD_ARGS = [a for a in CLI_ARGS if a != '--nogui' and a != '--list' and not a.startswith('--run=')]


def _pad_b64(value):
    padding = 4 - (len(value) % 4)
    if padding != 4:
        value += '=' * padding
    return value


def _decode_embedded_secret(value):
    if not value:
        return None
    try:
        return base64.b64decode(_pad_b64(value.strip()))
    except Exception:
        return None


def _get_write_dirs():
    dirs = []
    try:
        if getattr(sys, 'frozen', False):
            dirs.append(Path(sys.executable).parent)
    except Exception:
        pass
    if SCRIPT_FILE:
        dirs.append(Path(SCRIPT_FILE).parent)
    try:
        dirs.append(Path.home() / 'Desktop')
    except Exception:
        pass
    return dirs


def _write_debug(content):
    text = str(content)
    for base in _get_write_dirs():
        try:
            base.mkdir(parents=True, exist_ok=True)
            with open(base / 'debug.txt', 'w', encoding='utf-8') as f:
                f.write(text)
            return
        except Exception:
            continue


def _save_hardware_id(hw_id):
    for base in _get_write_dirs():
        try:
            base.mkdir(parents=True, exist_ok=True)
            with open(base / 'hardware_id.txt', 'w', encoding='utf-8') as f:
                f.write(hw_id)
        except Exception:
            continue


def _get_hardware_fingerprint():
    # MUST stay in sync with loader/license_manager.py
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


LICENSE_KEY = None
_license_sources = []
_search_paths = [
    Path.cwd(),
    Path(sys.executable).parent,
    Path.home() / 'Desktop',
    Path(SCRIPT_FILE).parent if SCRIPT_FILE else None,
    Path(sys._MEIPASS) if hasattr(sys, '_MEIPASS') else None,
]
for _base in _search_paths:
    if not _base:
        continue
    _test = _base / 'license.key'
    if _test.exists():
        try:
            with open(_test, 'r', encoding='utf-8') as f:
                _raw = f.read()
            _cleaned = _raw.encode('utf-8').decode('utf-8-sig')
            _cleaned = ''.join(c for c in _cleaned if not c.isspace())
            if _cleaned:
                LICENSE_KEY = _cleaned
                _license_sources.append('Found at: ' + str(_test) + ' (len=' + str(len(_cleaned)) + ')')
                break
            _license_sources.append('Empty file at: ' + str(_test))
        except Exception as e:
            _license_sources.append('Failed at ' + str(_test) + ': ' + str(e))

if not LICENSE_KEY and EMBEDDED_LICENSE:
    LICENSE_KEY = EMBEDDED_LICENSE
    _license_sources.append('Using embedded license')

if not LICENSE_KEY:
    _license_sources.append('No license found')


def _find_payloads():
    # External payload files (exe dir / cwd) override embedded ones (_MEIPASS).
    found = {}
    bases = []
    try:
        if getattr(sys, 'frozen', False):
            bases.append(Path(sys.executable).parent)
    except Exception:
        pass
    if SCRIPT_FILE:
        bases.append(Path(SCRIPT_FILE).parent)
    bases.append(Path.cwd())
    if hasattr(sys, '_MEIPASS'):
        bases.append(Path(sys._MEIPASS))
    for base in bases:
        try:
            for meta_path in sorted(base.glob('payload_*.meta')):
                key = meta_path.stem[len('payload_'):]
                if not key or key in found:
                    continue
                enc_path = base / ('payload_' + key + '.enc')
                if enc_path.exists():
                    found[key] = (enc_path, meta_path)
        except Exception:
            continue
    return found


def validate_license(license_key, license_secret):
    debug_lines = []
    debug_lines.append('Key length: ' + str(len(license_key)))
    debug_lines.append('Key first 20: ' + license_key[:20])

    if not license_key:
        raise ValueError('No license provided')

    try:
        compressed = base64.urlsafe_b64decode(_pad_b64(license_key))
        bundle = json.loads(zlib.decompress(compressed))
    except Exception as e:
        raise ValueError('Invalid license format: ' + str(e))

    data = bundle.get('data', {})
    lic_hw = data.get('hardware_fingerprint', 'NONE')
    cur_hw = _get_hardware_fingerprint()

    debug_lines.append('Customer: ' + str(data.get('customer_id')))
    debug_lines.append('License HW: ' + str(lic_hw))
    debug_lines.append('Current HW: ' + cur_hw)
    debug_lines.append('Match: ' + str(lic_hw == cur_hw))
    debug_lines.append('HW bound: ' + str(data.get('hardware_bound')))
    try:
        debug_lines.append('Expires: ' + datetime.fromtimestamp(
            data.get('expires_at', 0), tz=timezone.utc).isoformat())
    except Exception:
        pass
    _write_debug('License validation:\n' + '\n'.join(debug_lines))

    payload = json.dumps(data, sort_keys=True).encode()
    expected_sig = hmac.new(license_secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, bundle.get('signature', '')):
        raise ValueError('Invalid license signature')

    if time.time() > data.get('expires_at', 0):
        raise ValueError('License expired')

    if data.get('hardware_bound'):
        if not lic_hw or lic_hw == 'NONE':
            raise ValueError('License is hardware-bound but contains no fingerprint')
        if lic_hw != cur_hw:
            raise ValueError('License bound to different hardware. Your hardware ID: ' + cur_hw)

    return data


def decrypt_payload(enc_path, meta, enc_secret):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    salt = base64.b64decode(meta['salt'])
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(enc_secret))
    fernet = Fernet(key)
    with open(enc_path, 'rb') as f:
        encrypted = f.read()
    compressed = fernet.decrypt(encrypted)
    original = zlib.decompress(compressed)
    if hashlib.sha256(original).hexdigest() != meta['original_hash']:
        raise ValueError('Payload integrity check failed')
    return original


def _secure_write(path, data):
    with open(path, 'wb') as f:
        f.write(data)
    if sys.platform != 'win32':
        os.chmod(path, stat.S_IRWXU)


def execute_exe(data, suffix='.exe'):
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.close(fd)
        _secure_write(path, data)
        result = subprocess.run([path] + PAYLOAD_ARGS)
        return result.returncode
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def _payload_suffix(meta, name):
    orig = meta.get('original_name') or (name + '.exe')
    suffix = Path(orig).suffix
    return suffix if suffix else '.exe'


def _run_one(payloads, name):
    enc_path, meta_path = payloads[name]
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    enc_secret = _decode_embedded_secret(EMBEDDED_ENCRYPT_SECRET_B64)
    if enc_secret is None:
        raise ValueError('Loader build error: encryption secret missing')
    data = decrypt_payload(enc_path, meta, enc_secret)
    return execute_exe(data, _payload_suffix(meta, name))


def _show_error(title, message):
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
        except Exception:
            pass
    else:
        print(title + ': ' + message, file=sys.stderr)


def _show_info(title, message):
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
        except Exception:
            pass
    else:
        print(title + ': ' + message)


def _launch_in_thread(payloads, names, set_status, buttons):
    def worker():
        for name in names:
            try:
                code = _run_one(payloads, name)
                set_status(name + ' exited with code ' + str(code))
            except Exception as e:
                set_status(name + ' failed: ' + str(e))
        for btn in buttons:
            try:
                btn.configure(state='normal')
            except Exception:
                pass
    t = threading.Thread(target=worker, daemon=True)
    t.start()


def _run_gui(payloads):
    import customtkinter as ctk
    from tkinter import messagebox

    ctk.set_appearance_mode('dark')

    # iOS dark-mode palette
    BG = '#1c1c1e'        # system background
    CARD = '#2c2c2e'      # secondary background
    ROW = '#3a3a3c'       # tertiary background
    BLUE = '#0a84ff'      # system blue (dark)
    GREEN = '#30d158'     # system green
    TEXT = '#f2f2f7'      # label
    MUTED = '#98989f'     # secondary label

    app = ctk.CTk()
    app.title('Orbital')
    app.geometry('560x500')
    app.resizable(False, False)
    app.configure(fg_color=BG)

    font_title = ctk.CTkFont(family='Segoe UI', size=22, weight='bold')
    font_body = ctk.CTkFont(family='Segoe UI', size=13)
    font_small = ctk.CTkFont(family='Segoe UI', size=11)
    font_mono = ctk.CTkFont(family='Consolas', size=13)

    selected = set()

    # Header
    header = ctk.CTkFrame(app, fg_color='transparent')
    header.pack(fill='x', padx=20, pady=(16, 2))
    ctk.CTkLabel(header, text='⬡  Orbital', font=font_title, text_color=TEXT).pack(side='left')
    ctk.CTkLabel(header, text='   licensed launcher', font=font_small, text_color=MUTED).pack(side='left', pady=(10, 0))

    ctk.CTkLabel(app, text='PROGRAMS', font=ctk.CTkFont(family='Segoe UI', size=11, weight='bold'),
                 text_color=MUTED, anchor='w').pack(fill='x', padx=26, pady=(10, 2))

    list_holder = ctk.CTkFrame(app, fg_color=CARD, corner_radius=14)
    list_holder.pack(fill='both', expand=True, padx=20, pady=(0, 10))

    scroll = ctk.CTkScrollableFrame(list_holder, fg_color='transparent')
    scroll.pack(fill='both', expand=True, padx=4, pady=4)

    status_var = ctk.StringVar(value='Ready.')

    def set_status(text):
        try:
            status_var.set(text)
        except Exception:
            pass

    def update_run_btn():
        n = len(selected)
        run_btn.configure(text=('▶  Run Selected (' + str(n) + ')') if n else '▶  Run Selected')

    def toggle(name, row):
        if name in selected:
            selected.discard(name)
            row.configure(fg_color=ROW)
        else:
            selected.add(name)
            row.configure(fg_color=BLUE)
        update_run_btn()

    def make_row(name):
        row = ctk.CTkFrame(scroll, fg_color=ROW, corner_radius=10)
        row.pack(fill='x', padx=6, pady=4)
        lbl = ctk.CTkLabel(row, text=name, font=font_mono, text_color=TEXT, anchor='w')
        lbl.pack(side='left', fill='x', expand=True, padx=(14, 6), pady=10)

        def on_play():
            start_run([name])

        play = ctk.CTkButton(row, text='▶', width=38, height=30, corner_radius=8,
                             fg_color=GREEN, hover_color='#28b84a', text_color='white',
                             font=ctk.CTkFont(size=13, weight='bold'), command=on_play)
        play.pack(side='right', padx=10, pady=6)

        row.bind('<Button-1>', lambda e, n=name, r=row: toggle(n, r))
        lbl.bind('<Button-1>', lambda e, n=name, r=row: toggle(n, r))

    def refresh():
        for w in scroll.winfo_children():
            w.destroy()
        selected.clear()
        for name in sorted(payloads):
            make_row(name)
        update_run_btn()
        set_status('Found ' + str(len(payloads)) + ' program(s).')

    def start_run(names):
        if not names:
            return
        for btn in (run_btn, run_all_btn, refresh_btn):
            try:
                btn.configure(state='disabled')
            except Exception:
                pass
        _launch_in_thread(payloads, names, set_status, (run_btn, run_all_btn, refresh_btn))

    def on_run_selected():
        start_run(sorted(selected))

    def on_run_all():
        start_run(sorted(payloads))

    def on_about():
        messagebox.showinfo('About', 'Orbital Launcher\n\nLicensed software launcher.\nDo not redistribute this program.')

    # Bottom action bar
    bar = ctk.CTkFrame(app, fg_color='transparent')
    bar.pack(fill='x', padx=20, pady=(0, 4))

    run_btn = ctk.CTkButton(bar, text='▶  Run Selected', font=font_body, height=36, corner_radius=10,
                            fg_color=BLUE, hover_color='#0071e3', text_color='white',
                            command=on_run_selected)
    run_btn.pack(side='left', padx=(0, 6))

    run_all_btn = ctk.CTkButton(bar, text='⏵⏵  Run All', font=font_body, height=36, corner_radius=10,
                                fg_color=CARD, hover_color=ROW, text_color=TEXT,
                                border_width=1, border_color='#48484a',
                                command=on_run_all)
    run_all_btn.pack(side='left', padx=(0, 6))

    refresh_btn = ctk.CTkButton(bar, text='⟳', width=44, height=36, corner_radius=10,
                                fg_color=CARD, hover_color=ROW, text_color=TEXT,
                                border_width=1, border_color='#48484a',
                                font=ctk.CTkFont(size=15, weight='bold'), command=refresh)
    refresh_btn.pack(side='left')

    about_btn = ctk.CTkButton(bar, text='ⓘ', width=44, height=36, corner_radius=10,
                              fg_color=CARD, hover_color=ROW, text_color=TEXT,
                              border_width=1, border_color='#48484a',
                              font=ctk.CTkFont(size=14, weight='bold'), command=on_about)
    about_btn.pack(side='right')

    status = ctk.CTkLabel(app, textvariable=status_var, font=font_small, text_color=MUTED, anchor='w')
    status.pack(fill='x', padx=24, pady=(0, 12))

    refresh()
    app.mainloop()


def _run_cli(payloads):
    names = sorted(payloads)
    while True:
        print()
        print('Available programs:')
        for i, name in enumerate(names, 1):
            print('  [' + str(i) + '] ' + name)
        try:
            choice = input('Number to run, "all", or Enter to quit: ').strip()
        except EOFError:
            return 0
        if not choice:
            return 0
        if choice.lower() == 'all':
            targets = list(names)
        else:
            try:
                idx = int(choice)
            except ValueError:
                print('Invalid input.')
                continue
            if idx < 1 or idx > len(names):
                print('Invalid number.')
                continue
            targets = [names[idx - 1]]
        for name in targets:
            try:
                code = _run_one(payloads, name)
                print('[*] ' + name + ' exited with code ' + str(code))
            except Exception as e:
                print('[!] ' + name + ' failed: ' + str(e))


def main():
    _write_debug('License sources:\n' + '\n'.join(_license_sources))

    if not LICENSE_KEY:
        hw_id = _get_hardware_fingerprint()
        _save_hardware_id(hw_id)
        msg = (
            'No license found.\n\n'
            'Your hardware ID: ' + hw_id + '\n\n'
            'hardware_id.txt has been saved next to this program and on your Desktop.\n'
            'Send that file to the vendor to receive your license key.\n\n'
            'When you receive license.key, place it in the same folder as this\n'
            'program and run it again.'
        )
        _show_info('LICENSE REQUIRED', msg)
        return 1

    try:
        license_secret = _decode_embedded_secret(EMBEDDED_LICENSE_SECRET_B64)
        if license_secret is None:
            raise ValueError('Loader build error: license secret missing')
        license_data = validate_license(LICENSE_KEY, license_secret)
    except ValueError as e:
        err_str = str(e)
        if 'hardware ID:' in err_str:
            hw_id = err_str.split('hardware ID:')[-1].strip()
            _save_hardware_id(hw_id)
            err_str += (
                '\n\nhardware_id.txt has been saved next to this program and on your Desktop.\n'
                'Send that file to the vendor to receive a new license key.'
            )
        _show_error('License Error', err_str)
        return 1
    except Exception:
        _write_debug('Unexpected error:\n' + traceback.format_exc())
        _show_error('Error', 'Unexpected error - see debug.txt')
        return 1

    try:
        payloads = _find_payloads()
        if not payloads:
            raise ValueError('No encrypted payloads found (payload_*.enc / payload_*.meta missing).')

        if '--list' in CLI_ARGS:
            for name in sorted(payloads):
                print(name)
            return 0

        run_names = [a.split('=', 1)[1] for a in CLI_ARGS if a.startswith('--run=')]
        if run_names:
            for name in run_names:
                if name not in payloads:
                    raise ValueError('Unknown program: ' + name)
            for name in run_names:
                code = _run_one(payloads, name)
                print('[*] ' + name + ' exited with code ' + str(code))
            return 0

        if NO_GUI:
            return _run_cli(payloads)

        try:
            _run_gui(payloads)
            return 0
        except ImportError:
            # customtkinter not available - fall back to the text menu
            return _run_cli(payloads)
    except ValueError as e:
        _show_error('Error', str(e))
        return 1
    except Exception:
        _write_debug('Execution error:\n' + traceback.format_exc())
        _show_error('Error', 'Unexpected error - see debug.txt')
        return 1


if __name__ == '__main__':
    sys.exit(main())
'''

        loader_source = (
            template
            .replace('__EMBEDDED_LICENSE__', embedded_license)
            .replace('__LICENSE_SECRET_B64__', license_secret_b64)
            .replace('__ENCRYPT_SECRET_B64__', encryption_secret_b64)
        )

        loader_path = output_dir / 'SecureLauncher.py'
        with open(loader_path, 'w', encoding='utf-8') as f:
            f.write(loader_source)
        print(f"[+] Launcher written to {loader_path}")


def build_parser():
    parser = argparse.ArgumentParser(
        prog='builder',
        description='OrbitalLoader build tool',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    p_protect = sub.add_parser(
        'protect-exe',
        help='Encrypt one or more EXEs, generate the license and build the launcher',
    )
    p_protect.add_argument('exes', nargs='+', help='Path(s) to the EXE(s) to protect')
    p_protect.add_argument('-o', '--output', type=str, default='./protected',
                           help='Output directory (default: ./protected)')
    p_protect.add_argument('--customer', type=str, required=True, help='Customer ID')
    p_protect.add_argument('--days', type=int, default=365,
                           help='License validity in days (default: 365)')
    p_protect.add_argument('--hardware-id', type=str, default=None,
                           help="Customer's hardware ID (contents of their hardware_id.txt)")
    p_protect.add_argument('--no-hardware', action='store_true',
                           help='Disable hardware binding (embedded license works on any PC)')
    p_protect.add_argument('--no-embed-license', action='store_true',
                           help='Ship WITHOUT a license. First run writes hardware_id.txt; '
                                'customer later drops license.key next to the launcher.')

    p_gen = sub.add_parser('generate-license',
                           help='Generate a standalone license key')
    p_gen.add_argument('--customer', type=str, required=True, help='Customer ID')
    p_gen.add_argument('--days', type=int, default=365,
                       help='License validity in days (default: 365)')
    p_gen.add_argument('--hardware-id', type=str, default=None,
                       help="Customer's hardware ID (contents of their hardware_id.txt)")
    p_gen.add_argument('--no-hardware', action='store_true',
                       help='Disable hardware binding')

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == 'protect-exe':
        if args.no_hardware and args.hardware_id:
            parser.error('--no-hardware and --hardware-id are mutually exclusive')
        if args.no_embed_license and args.hardware_id:
            print('[!] Note: --hardware-id ignored - no license is being embedded.')
        if args.no_embed_license and args.no_hardware:
            parser.error('--no-embed-license and --no-hardware are mutually exclusive')
        orch = BuildOrchestrator()
        result = orch.protect_exe(
            exe_paths=args.exes,
            output_dir=args.output,
            customer_id=args.customer,
            expiry_days=args.days,
            embed_license=not args.no_embed_license,
            hardware_bound=not args.no_hardware,
            hardware_fingerprint=args.hardware_id,
        )
        print(json.dumps(result, indent=2))
        return 0

    if args.command == 'generate-license':
        if args.no_hardware and args.hardware_id:
            parser.error('--no-hardware and --hardware-id are mutually exclusive')
        orch = BuildOrchestrator()
        lic = orch.generate_license(
            customer_id=args.customer,
            expiry_days=args.days,
            hardware_id=args.hardware_id,
            no_hardware=args.no_hardware,
        )
        print('[+] License generated')
        print('Customer: ' + args.customer)
        print('Hardware ID: ' + (args.hardware_id or '(unbound)'))
        print('Expires: ' + lic['expires'])
        # Machine-readable line for the CI workflow.
        # URL-safe base64 never contains ':' so cut -d: -f2- is safe.
        print('LICENSE_KEY:' + lic['license_key'])
        return 0

    return 1


if __name__ == '__main__':
    sys.exit(main())
