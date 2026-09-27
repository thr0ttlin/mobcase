"""mbc.transport: device-I/O abstraction (adb vs iOS scatter).

Typical use in a command:

    from mbc import transport as tp

    dev = tp.connect(serial=args.serial)     # auto-detects platform
    dev.run("id", check=True)
    dev.pull("/data/local/tmp/x", "./x")

`mbcinfo` never imports this module - it works on files only.
"""

from __future__ import annotations

from .base import (
    Device, Platform, RunResult, Transport,
    TransportError, UnsupportedOperation, ToolNotFound,
)
from .adb import AdbTransport
from .ios import IosTransport

__all__ = [
    "Device", "Platform", "RunResult", "Transport",
    "TransportError", "UnsupportedOperation", "ToolNotFound",
    "AdbTransport", "IosTransport",
    "list_devices", "connect",
]


def list_devices() -> list[Device]:
    """Every connected device across both platforms."""
    return AdbTransport.list_devices() + IosTransport.list_devices()


def _make(device: Device, ssh: dict | None = None, **kw) -> Transport:
    if device.platform == Platform.ANDROID:
        return AdbTransport(serial=device.serial, **kw)
    return IosTransport(serial=device.serial, **(ssh or {}), **kw)


def connect(serial: str | None = None,
            platform: str | Platform | None = None,
            ssh: dict | None = None, **kw) -> Transport:
    """Pick a transport.

    - one device connected            -> use it (platform auto-detected)
    - `serial` given                  -> that device
    - `platform` given                -> narrows the choice
    - ambiguous (several match)        -> TransportError asking for -s
    - `serial`+`platform` but not seen -> construct anyway (adb-network / ssh-only)

    `ssh` (dict) carries iOS SSH options (host/port/user/password); it is applied
    only when the chosen device is iOS.
    """
    if platform is not None:
        platform = Platform(platform)

    candidates = [
        d for d in list_devices()
        if (serial is None or d.serial == serial)
        and (platform is None or d.platform == platform)
    ]

    if not candidates:
        if serial is not None and platform is not None:
            return _make(Device(serial=serial, platform=platform), ssh=ssh, **kw)
        if serial is not None:
            raise TransportError(
                f"device {serial!r} not found; add platform=android|ios to force it"
            )
        raise TransportError("no devices connected")

    if len(candidates) > 1:
        listing = ", ".join(f"{d.serial} ({d.platform.value})" for d in candidates)
        raise TransportError(f"multiple devices - select one with -s: {listing}")

    return _make(candidates[0], ssh=ssh, **kw)