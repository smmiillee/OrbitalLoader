"""
radar_launcher.py -- starts the Orbital radar server and opens the dashboard.

Drop into OrbitalLoader/loader/.

WHY THIS IS A SEPARATE PROCESS
The radar (cs2_dashboard.exe from smmiillee/orbitalweb) reads CS2 memory itself
and serves the dashboard on port 3000. It is NOT part of the external and cannot
be "compiled into" the Python loader -- so the loader's job is to start it and
open a browser, exactly like it launches cs2external.exe.

WIRING IT UP
In your loader's startup path, next to wherever cs2external.exe is launched:

    from loader.radar_launcher import RadarLauncher

    radar = RadarLauncher()          # finds the exe next to the loader
    radar.start()                    # launches it + opens the browser

And in your shutdown path:

    radar.stop()

If you have a GUI toggle, call start()/stop() from it.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

# The radar server, and the port its WebSocket + HTTP share. Both are what the
# orbitalweb README documents.
DASHBOARD_EXE = "cs2_dashboard.exe"
RADAR_PORT = 3000


def _candidate_dirs() -> list[Path]:
    """Places the dashboard exe might live, most likely first."""
    dirs: list[Path] = []

    # Next to the loader itself -- the normal layout once you bundle it.
    if getattr(sys, "frozen", False):
        dirs.append(Path(sys.executable).resolve().parent)
    dirs.append(Path(__file__).resolve().parent.parent)

    # An explicit override, so you can point it at a build directory while
    # developing without moving files around.
    env = os.environ.get("ORBITAL_RADAR_DIR")
    if env:
        dirs.insert(0, Path(env))

    # Subfolders people actually use.
    for sub in ("radar", "orbitalweb", "bin", "dist", "build", "build/Release"):
        dirs.append(dirs[0] / sub)

    return dirs


def find_dashboard() -> Path | None:
    for d in _candidate_dirs():
        exe = d / DASHBOARD_EXE
        if exe.is_file():
            return exe
    return None


def lan_ipv4() -> str:
    """
    Best-effort LAN address for display.

    Deliberately NOT used to build the browser URL: we open 127.0.0.1 because
    the browser is on this machine. The LAN address is only what you would send
    to someone else.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packets are actually sent; this just picks the route.
        s.connect(("8.8.8.8", 80))
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
    def __init__(self, port: int = RADAR_PORT, auto_open: bool = True):
        self.port = port
        self.auto_open = auto_open
        self._proc: subprocess.Popen | None = None
        self._we_started_it = False

    # ---- lifecycle -------------------------------------------------------

    def start(self) -> bool:
        """
        Start the radar server if it is not already up, then open the dashboard.

        Returns True if a dashboard should be reachable at the end of this call.
        """
        # Already serving? Then it is running from a previous session or a
        # manual launch -- attach to it rather than starting a second copy,
        # which would fail to bind the port anyway.
        if port_open(self.port):
            print(f"[radar] already running on port {self.port}")
            if self.auto_open:
                self.open_browser()
            return True

        exe = find_dashboard()
        if exe is None:
            print(
                f"[radar] {DASHBOARD_EXE} not found.\n"
                f"        Build it from smmiillee/orbitalweb and put it next to\n"
                f"        the loader, or set ORBITAL_RADAR_DIR."
            )
            return False

        print(f"[radar] launching {exe}")
        try:
            # The server prints its own IP to its console, so let it have one.
            flags = 0
            if os.name == "nt":
                flags = subprocess.CREATE_NEW_CONSOLE
            self._proc = subprocess.Popen(
                [str(exe)],
                cwd=str(exe.parent),
                creationflags=flags,
            )
            self._we_started_it = True
        except OSError as e:
            print(f"[radar] failed to launch: {e}")
            return False

        # Wait for the port to come up, so the browser does not race it and
        # land on "can't reach this page".
        for _ in range(40):            # up to ~8 s
            if port_open(self.port):
                break
            if self._proc.poll() is not None:
                print("[radar] server exited immediately -- check its console")
                return False
            time.sleep(0.2)
        else:
            print("[radar] server did not open the port in time; opening anyway")

        ip = lan_ipv4()
        print(f"[radar] local:  http://127.0.0.1:{self.port}")
        print(f"[radar] LAN:    http://{ip}:{self.port}")
        print(f"[radar] others on your network open the LAN address")

        if self.auto_open:
            self.open_browser()
        return True

    def stop(self) -> None:
        """Only terminates the server if THIS loader started it."""
        if not (self._proc and self._we_started_it):
            return
        if self._proc.poll() is not None:
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

    def url(self) -> str:
        # Loopback on purpose: the browser opening this is on the same machine
        # as the server. This always works, including when the machine has
        # VPN / WSL / Hyper-V adapters that make the "LAN" address ambiguous.
        return f"http://127.0.0.1:{self.port}"

    def open_browser(self) -> None:
        url = self.url()
        print(f"[radar] opening {url}")
        try:
            webbrowser.open(url, new=2)
        except Exception as e:                      # noqa: BLE001
            print(f"[radar] could not open a browser ({e}); open {url} manually")
