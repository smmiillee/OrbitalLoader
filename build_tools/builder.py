"""
build_tools/builder.py
Builds protected, licensed launchers for one or more user executables.
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
        # Only the DERIVED secrets get embedded into user launchers.
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
                "    machine instead of the user's PC.\n"
                "    Pass --hardware-id <user HWID>, --no-hardware, or "
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
            print("[+] No embedded license - the user's first run will")
            print("    show their HWID and write hardware_id.txt.")
            print("    Generate their license with 'generate-license', then")
            print("    have them drop license.key next to the launcher.")

        # Optional display-name overrides, e.g. {"cs2_dashboard.exe": "Radar"}
        names_map = {}
        for candidate in (Path.cwd() / 'names.json', output_dir / 'names.json'):
            if candidate.exists():
                try:
                    with open(candidate, 'r', encoding='utf-8') as f:
                        names_map = json.load(f)
                    print(f"[+] Using display names from {candidate}")
                    break
                except Exception as e:
                    print(f"[!] Could not parse {candidate}: {e}")

        encrypted = []
        for exe_path in exe_paths:
            exe_path = Path(exe_path)
            if not exe_path.exists():
                raise SystemExit(f"[!] EXE not found: {exe_path}")

            raw_stem = exe_path.stem
            display = names_map.get(exe_path.name) or names_map.get(exe_path.stem) or raw_stem
            stem = _safe_stem(display)
            print(f"[+] Encrypting {exe_path.name} -> payload_{stem}.enc (shown as: {display})")
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

        self._generate_loader(output_dir, license_key, customer_id)

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
                "user's PC). Pass --hardware-id <user HWID> or --no-hardware."
            )
        return self._license_mgr.generate_license(
            customer_id=customer_id,
            expiry_days=expiry_days,
            features=['premium'],
            hardware_bound=not no_hardware,
            hardware_fingerprint=hardware_id,
        )

    def _generate_loader(self, output_dir: Path, license_key: str, customer_id: str):
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
CUSTOMER_ID = __CUSTOMER__

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
    # Append-mode with a timestamp header, so each entry survives later runs.
    text = str(content)
    for base in _get_write_dirs():
        try:
            base.mkdir(parents=True, exist_ok=True)
            with open(base / 'debug.txt', 'a', encoding='utf-8') as f:
                f.write('\n==== ' + datetime.now(timezone.utc).isoformat() + ' ====\n')
                f.write(text + '\n')
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

    debug_lines.append('User: ' + str(data.get('customer_id')))
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
            raise ValueError('License bound to different hardware. Your HWID: ' + cur_hw)

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
                set_status('Running ' + name + '...')
                code = _run_one(payloads, name)
                set_status(name + ' exited with code ' + str(code))
            except Exception as e:
                set_status(name + ' failed: ' + str(e))
        for btn in buttons:
            try:
                btn.configure(state='normal')
            except Exception:
                pass
    # Non-daemon: if the user closes the window while a program is still
    # running, the process lingers invisibly until the program exits, so the
    # PyInstaller onefile bootloader can delete its _MEIxxx temp folder
    # without the "Failed to remove temporary directory" warning.
    t = threading.Thread(target=worker, daemon=False)
    t.start()


def _run_gui(payloads):
    import tkinter as tk
    from tkinter import messagebox

    # Classic Win9x palette - real native widgets this time
    BG = '#c0c0c0'         # classic silver
    GOLD = '#c9a53a'
    GOLD_DARK = '#a8842c'
    BLACK = '#000000'
    WHITE = '#ffffff'

    app = tk.Tk()
    app.title('Orbital')
    app.geometry('620x540')
    app.resizable(False, False)
    app.configure(bg=BG)

    F_TITLE = ('Tahoma', 22, 'bold')
    F_GROUP = ('Tahoma', 10, 'bold')
    F_BODY = ('Tahoma', 10)
    F_BTN = ('Tahoma', 10, 'bold')
    F_STATUS = ('Tahoma', 9)

    selected = set()

    tk.Label(app, text='Orbital', font=F_TITLE, fg=GOLD_DARK, bg=BG).pack(pady=(6, 2))

    # Programs group box - LabelFrame naturally draws its label sitting
    # in the border line, exactly like the reference menus.
    group = tk.LabelFrame(app, text='Programs -', font=F_GROUP, fg=BLACK, bg=BG,
                          bd=0, highlightthickness=1, highlightbackground=GOLD)
    group.pack(fill='both', expand=True, padx=14, pady=(10, 6))

    canvas = tk.Canvas(group, bg=BG, highlightthickness=0, bd=0)
    vbar = tk.Scrollbar(group, orient='vertical', command=canvas.yview)
    inner = tk.Frame(canvas, bg=BG)
    inner.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
    canvas.create_window((0, 0), window=inner, anchor='nw')
    canvas.configure(yscrollcommand=vbar.set)

    def on_mousewheel(event):
        canvas.yview_scroll(int(-event.delta / 120), 'units')
    canvas.bind_all('<MouseWheel>', on_mousewheel)

    vbar.pack(side='right', fill='y')
    canvas.pack(side='left', fill='both', expand=True, padx=4, pady=4)

    status_var = tk.StringVar()

    def set_status(text):
        try:
            status_var.set('[ORBITAL v1.0] | PROFILE: [' + CUSTOMER_ID + '] | STATUS: [' + text + ']')
        except Exception:
            pass

    def make_row(name):
        row = tk.Frame(inner, bg=BG)
        row.pack(fill='x', padx=6, pady=2)
        var = tk.BooleanVar(value=(name in selected))

        def on_toggle(n=name, v=var):
            if v.get():
                selected.add(n)
            else:
                selected.discard(n)
            set_status(str(len(selected)) + ' selected')

        cb = tk.Checkbutton(row, text=name, variable=var, command=on_toggle,
                            font=F_BODY, bg=BG, fg=BLACK, activebackground=BG,
                            activeforeground=BLACK, anchor='w')
        cb.pack(side='left', fill='x', expand=True)

        def on_run_one(n=name):
            start_run([n])

        run1 = tk.Button(row, text='[Run]', font=('Tahoma', 9), bg=BG, fg=BLACK,
                         relief='raised', bd=2, activebackground='#d8d8d8',
                         activeforeground=BLACK, width=7, command=on_run_one)
        run1.pack(side='right', padx=4, pady=1)

    def refresh():
        for w in inner.winfo_children():
            w.destroy()
        for name in sorted(payloads):
            make_row(name)
        set_status(str(len(payloads)) + ' program(s) loaded')

    def start_run(names):
        if not names:
            set_status('Nothing selected')
            return
        for btn in (run_sel_btn, run_all_btn, refresh_btn):
            try:
                btn.configure(state='disabled')
            except Exception:
                pass
        _launch_in_thread(payloads, names, set_status, (run_sel_btn, run_all_btn, refresh_btn))

    def on_run_selected():
        start_run(sorted(selected))

    def on_run_all():
        start_run(sorted(payloads))

    def on_about():
        messagebox.showinfo('About', 'Orbital v1.0\nProfile: ' + CUSTOMER_ID +
                            '\n\nLicensed software launcher.\nDo not redistribute this program.')

    bar = tk.Frame(app, bg=BG)
    bar.pack(fill='x', padx=14, pady=(0, 6))

    def retro_btn(text, cmd, width):
        return tk.Button(bar, text=text, command=cmd, width=width, font=F_BTN,
                         bg=GOLD, fg=BLACK, relief='raised', bd=2,
                         activebackground=GOLD_DARK, activeforeground=BLACK)

    run_sel_btn = retro_btn('[Run Selected]', on_run_selected, 14)
    run_sel_btn.pack(side='left', padx=(0, 8))
    run_all_btn = retro_btn('[Run All]', on_run_all, 11)
    run_all_btn.pack(side='left', padx=(0, 8))
    refresh_btn = retro_btn('[Refresh]', refresh, 10)
    refresh_btn.pack(side='left', padx=(0, 8))
    about_btn = retro_btn('[About]', on_about, 9)
    about_btn.pack(side='right')

    # Sunken white status bar
    status = tk.Label(app, textvariable=status_var, font=F_STATUS, bg=WHITE, fg=BLACK,
                      relief='sunken', bd=2, anchor='w')
    status.pack(fill='x', padx=10, pady=(0, 10))

    # Watermark (top-right, next to the title). Loads watermark.png from the
    # exe folder, script folder, cwd, or the bundled _MEIPASS. tk.PhotoImage
    # handles PNG (and GIF) natively - a JPEG renamed to .png will NOT load,
    # and the reason gets recorded in debug.txt.
    wm_path = None
    for base in _search_paths:
        if base and (base / 'watermark.png').exists():
            wm_path = base / 'watermark.png'
            break
    if wm_path:
        try:
            wm = tk.PhotoImage(file=str(wm_path))
            if wm.width() > 240:
                factor = max(1, wm.width() // 240)
                wm = wm.subsample(factor, factor)
            wm_label = tk.Label(app, image=wm, bg=BG, bd=0, highlightthickness=0)
            wm_label.image = wm  # keep a reference so it is not garbage-collected
            wm_label.place(relx=1.0, rely=0.0, x=-10, y=6, anchor='ne')
            _write_debug('Watermark: loaded from ' + str(wm_path) +
                         ' (' + str(wm.width()) + 'x' + str(wm.height()) + ')')
        except Exception as e:
            _write_debug('Watermark: FAILED to load ' + str(wm_path) + ' - ' + repr(e) +
                         ' (is it a real PNG? A JPEG renamed to .png will not load)')
    else:
        _write_debug('Watermark: watermark.png not found next to the launcher or in the bundle')

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
            'Your HWID: ' + hw_id + '\n\n'
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
        if 'Your HWID:' in err_str:
            hw_id = err_str.split('Your HWID:')[-1].strip()
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
            # GUI unavailable - fall back to the text menu
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
            .replace('__CUSTOMER__', repr(customer_id))
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
    p_protect.add_argument('--customer', type=str, required=True, help='User ID')
    p_protect.add_argument('--days', type=int, default=365,
                           help='Sub time in days (default: 365)')
    p_protect.add_argument('--hardware-id', type=str, default=None,
                           help="User's HWID (contents of their hardware_id.txt)")
    p_protect.add_argument('--no-hardware', action='store_true',
                           help='Disable hardware binding (embedded license works on any PC)')
    p_protect.add_argument('--no-embed-license', action='store_true',
                           help='Ship WITHOUT a license. First run writes hardware_id.txt; '
                                'user later drops license.key next to the launcher.')

    p_gen = sub.add_parser('generate-license',
                           help='Generate a standalone license key')
    p_gen.add_argument('--customer', type=str, required=True, help='User ID')
    p_gen.add_argument('--days', type=int, default=365,
                       help='Sub time in days (default: 365)')
    p_gen.add_argument('--hardware-id', type=str, default=None,
                       help="User's HWID (contents of their hardware_id.txt)")
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
        print('User: ' + args.customer)
        print('HWID: ' + (args.hardware_id or '(unbound)'))
        print('Sub expires: ' + lic['expires'])
        # Machine-readable line for the CI workflow.
        # URL-safe base64 never contains ':' so cut -d: -f2- is safe.
        print('LICENSE_KEY:' + lic['license_key'])
        return 0

    return 1


if __name__ == '__main__':
    sys.exit(main())
