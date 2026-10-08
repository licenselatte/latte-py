"""The machine ID ``Sdk`` sends as ``machine_id`` and checks against a
token's ``mid`` claim.

The value is always ``protected_id(raw, app_id)``: lowercase hex
HMAC-SHA256 keyed on the raw machine ID, over ``"licenselatte_" + app_id``.
That is denisbrodbeck/machineid's ``ProtectedID``, which latte-go uses, so
every SDK derives the same ID on the same machine. A raw ID never leaves
the machine.

``read_platform_id`` reads the raw ID the way that package does:

- Linux: ``/var/lib/dbus/machine-id``, then ``/etc/machine-id``.
- macOS: ``IOPlatformUUID`` from ``ioreg -rd1 -c IOPlatformExpertDevice``.
- Windows: ``HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid`` from the
  64-bit registry view.
- BSD and Solaris: ``/etc/hostid``, then ``kenv -q smbios.system.uuid``.
"""

from __future__ import annotations

import hashlib
import hmac
import subprocess
import sys

from .errors import MachineIdError

_MESSAGE_PREFIX = "licenselatte_"

_LINUX_PATHS = ("/var/lib/dbus/machine-id", "/etc/machine-id")
_HOSTID_PATH = "/etc/hostid"
_BSD_PLATFORMS = ("freebsd", "netbsd", "openbsd", "dragonfly", "sunos")


def protected_id(raw: str, app_id: str) -> str:
    """The derived machine ID for ``raw`` under ``app_id``. ``raw`` is used
    byte for byte as UTF-8, with no trimming."""
    msg = (_MESSAGE_PREFIX + app_id).encode("utf-8")
    return hmac.new(raw.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def read_platform_id() -> str:
    """The raw machine ID of this host. Raises ``MachineIdError`` when it
    cannot be read or is empty."""
    try:
        raw = _read_raw()
    except (OSError, subprocess.SubprocessError) as e:
        raise MachineIdError(f"cannot read the platform machine ID: {e}") from e
    if not raw:
        raise MachineIdError("the platform machine ID is empty")
    return raw


def _trim(s: str) -> str:
    return s.strip()


def _read_raw() -> str:
    if sys.platform == "darwin":
        return _trim(_extract_ioreg_uuid(_run("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")))
    if sys.platform == "win32":
        return _read_windows()
    if sys.platform.startswith("linux"):
        return _read_first_file(_LINUX_PATHS)
    if sys.platform.startswith(_BSD_PLATFORMS):
        try:
            return _read_first_file((_HOSTID_PATH,))
        except OSError:
            return _trim(_run("/bin/kenv", "-q", "smbios.system.uuid"))
    raise MachineIdError(f"no platform machine ID on {sys.platform}")


def _read_first_file(paths: tuple[str, ...]) -> str:
    err: OSError | None = None
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                value = _trim(f.read())
        except OSError as e:
            err = e
            continue
        if value:
            return value
    if err is not None:
        raise err
    return ""


def _run(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout


def _extract_ioreg_uuid(output: str) -> str:
    """The ``IOPlatformUUID`` value from ``ioreg`` output: the first line
    naming it that splits on ``" = "`` into exactly two parts, with trailing
    quotes removed."""
    for line in output.split("\n"):
        if "IOPlatformUUID" in line:
            parts = line.split('" = "')
            if len(parts) == 2:
                return parts[1].rstrip('"')
    raise MachineIdError("no IOPlatformUUID in ioreg output")


def _read_windows() -> str:
    import winreg  # type: ignore[import-not-found,unused-ignore]

    with winreg.OpenKey(  # type: ignore[attr-defined,unused-ignore]
        winreg.HKEY_LOCAL_MACHINE,  # type: ignore[attr-defined,unused-ignore]
        r"SOFTWARE\Microsoft\Cryptography",
        0,
        winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY,  # type: ignore[attr-defined,unused-ignore]
    ) as key:
        value, _ = winreg.QueryValueEx(key, "MachineGuid")  # type: ignore[attr-defined,unused-ignore]
    if not isinstance(value, str):
        raise MachineIdError("MachineGuid is not a string")
    return value
