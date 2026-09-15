"""
loader/radar_launcher.py -- starts the Orbital radar server and opens it.

Drop into OrbitalLoader/loader/.

WHY THIS IS A SEPARATE PROCESS
The radar (cs2_dashboard.exe from smmiillee/orbitalweb) reads CS2 memory itself
and serves the dashboard on port 3000. It is NOT compiled into this Python
loader -- the loader's job is to start it and open a browser, same as it does
for the external.

*** WHY THIS TAKES AN EXPLICIT PATH ***
Your CI workflow encrypts EVERYTHING in incoming/, including
cs2_dashboard.exe. So at runtime there is no file called cs2_dashboard.exe on
disk -- there is whatever the loader decrypted. Hunting for it by name would
fail. The loader knows where it wrote the decrypted payload, so it passes that
path in.

USAGE -- in your loader, where you decrypt payloads:

    from loader.radar_launcher import RadarLauncher

    # After you have decrypted the dashboard payload to a real file:
    radar = RadarLauncher(exe_path=decrypted_dashboard_path)
    radar.start()      # launches it, waits for the port, opens the browser

    # ...and on exit:
    radar.stop()

If you would rather run the dashboard UNENCRYPTED (it is not the licensed
payload, so encrypting it is optional), keep the raw exe next to the loader and
just call RadarLauncher() with no argument -- the search below will find it.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

DASHBOARD_NAME = "cs2_dashboard.exe"
RADAR_PORT = 3000

# ── CLOUD READINESS ──────────────────────────────────────────────────────
# Leave this EMPTY for now -- the browser is on this machine, so loopback is
# correct and always works.
#
# When you have hosting, set this to the public URL and nothing else changes.
# e.g. os.environ.setdefault("ORBITAL_RADAR_PUBLIC_URL",
#                           "https://radar.yourdomain.gg")
#
# The dashboard's JS already picks ws:// or wss:// from the page's own
# protocol, so an HTTPS URL through a tunnel or proxy works with no code change
# on either side. That was the point of the radar.js protocol fix.
PUBLIC_URL_ENV = "ORBITAL_RADAR_PUBLIC_URL"


def _find_on_disk() -> Path | None:
    """Only used when no explicit path is given (unencrypted workflow)."""
    roots: list[Path] = []

    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    roots.append(Path(__file__).resolve().parent.parent)

    # incoming/ is where the raw exe lives in the repo, so it is the right
    # place to look during development.
    for sub in ("incoming", "radar", "bin", "assets"):
        roots.append(roots[0] / sub)

    # An explicit override, for pointing at a build dir without moving files.
    env = os.environ.get("ORBITAL_RADAR_DIR")
    if env:
        roots.insert(0, Path(env))

    for r in roots:
        p = r / DASHBOARD_NAME
        if p.is_file():
            return p
    return None


def lan_ipv4() -> str:
    """
    Best-effort LAN address, for DISPLAY only.

    Deliberately not used for the browser URL: the browser is on this machine,
    so loopback is right. This is only what you would hand to someone else.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))   # no packets sent; just picks a route
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.25) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


class RadarLauncher:
    def __init__(self, exe_path: str | os.PathLike | None = None,
                 port: int = RADAR_PORT, auto_open: bool = True):
        self.port = port
        self.auto_open = auto_open
        self.exe_path = Path(exe_path) if exe_path else None
        self._proc: subprocess.Popen | None = None
        self._we_started_it = False

    # ---- lifecycle -------------------------------------------------------

    def start(self) -> bool:
        # Already serving? Attach rather than starting a second copy, which
        # would fail to bind the port anyway.
        if port_open(self.port):
            print(f"[radar] already running on port {self.port}")
            if self.auto_open:
                self.open_browser()
            return True

        exe = self.exe_path if (self.exe_path and self.exe_path.is_file()) else None

        if exe is None:
            if self.exe_path is not None:
                print(f"[radar] given path does not exist: {self.exe_path}")
            exe = _find_on_disk()

        if exe is None:
            print(
                f"[radar] {DASHBOARD_NAME} not found.\n"
                f"        Pass exe_path=<decrypted payload>, or set\n"
                f"        ORBITAL_RADAR_DIR to the folder holding it."
            )
            return False

        print(f"[radar] launching {exe}")
        try:
            # CREATE_NEW_CONSOLE so you can read the server's own output -- it
            # prints the addresses to use.
            flags = subprocess.CREATE_NEW_CONSOLE if os.name == "nt" else 0
            self._proc = subprocess.Popen(
                [str(exe)],
                cwd=str(exe.parent),
                creationflags=flags,
            )
            self._we_started_it = True
        except OSError as e:
            print(f"[radar] failed to launch: {e}")
            return False

        # Wait for the port, so the browser does not race it and land on a
        # "can't reach this page" error.
        for _ in range(40):              # up to ~8 s
            if port_open(self.port):
                break
            if self._proc.poll() is not None:
                print("[radar] server exited immediately -- check its console")
                return False
            time.sleep(0.2)
        else:
            print("[radar] port did not open in time; opening the browser anyway")

        self._report_addresses()

        if self.auto_open:
            self.open_browser()
        return True

    def stop(self) -> None:
        """Only terminates the server if THIS loader started it."""
        if not (self._proc and self._we_started_it):
            return
        if self._proc.poll() is not None:
            self._proc = None
            return
        print("[radar] stopping server")
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        except OSError:
            pass
        self._proc = None

    # ---- helpers ---------------------------------------------------------

    def public_url(self) -> str | None:
        """Set ORBITAL_RADAR_PUBLIC_URL and this becomes the browser target."""
        v = os.environ.get(PUBLIC_URL_ENV, "").strip()
        return v or None

    def url(self) -> str:
        # Loopback on purpose: the browser opening this is on the same machine
        # as the server, and it is immune to the VPN / WSL / Hyper-V adapters
        # that make a "LAN" address ambiguous.
        pub = self.public_url()
        if pub:
            return pub
        return f"http://127.0.0.1:{self.port}"

    def _report_addresses(self) -> None:
        pub = self.public_url()
        if pub:
            print(f"[radar] public: {pub}   (from {PUBLIC_URL_ENV})")
            print(f"[radar] local:  http://127.0.0.1:{self.port}")
            return

        ip = lan_ipv4()
        print(f"[radar] local:  http://127.0.0.1:{self.port}")
        print(f"[radar] LAN:    http://{ip}:{self.port}")
        print( "[radar] no public URL set -- sharing is LAN-only for now.")

    def open_browser(self) -> None:
        url = self.url()
        print(f"[radar] opening {url}")
        try:
            webbrowser.open(url, new=2)
        except Exception as e:                       # noqa: BLE001
            print(f"[radar] could not open a browser ({e}); open {url} manually")
