"""mbc.target: resolve *what* a command acts on, and *which* device.

Two halves, deliberately kept apart:

  1. Artifact resolution (resolve_artifact / require_file)
     Classifies a positional argument: a file, an unpacked directory, or a
     package/bundle identifier: WITHOUT touching any device. This is the clean
     replacement for appquick's check_and_init_vars: it does not silently go to
     the device when the arg isn't a file.

  2. Device selection (select_device / list_devices / is_installed)
     Thin wrappers over the transport layer, which is imported LAZILY inside
     these functions. Consequence: `import mbc.target` does not import
     mbc.transport, so a file-only command (mbcinfo) has no path to a device.

Direction of dependencies: this is core, so it never imports the android/ios
platform layers. Turning a *file* into its package id is parsing: that lives
in the platform layer and is orchestrated by the command, not here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class Platform(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class Kind(str, Enum):
    APK = "apk"                # single base .apk
    SPLIT = "split"            # .xapk/.apkm/.apks bundle (android split set)
    IPA = "ipa"
    DIR = "dir"                # unpacked artifact directory
    IDENTIFIER = "identifier"  # package name / bundle id - not a path


class TargetError(Exception):
    """The positional target could not be resolved."""


_ANDROID_SPLIT_EXT = {".xapk", ".apkm", ".apks"}
# reverse-DNS-ish: com.example.app / net.whatsapp.WhatsApp (hyphens allowed for iOS)
_IDENT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$")


@dataclass
class Target:
    raw: str
    kind: Kind
    platform: Platform
    path: Optional[Path] = None
    identifier: Optional[str] = None

    @property
    def is_file(self) -> bool:
        return self.kind in (Kind.APK, Kind.SPLIT, Kind.IPA, Kind.DIR)

    @property
    def is_identifier(self) -> bool:
        return self.kind is Kind.IDENTIFIER


# --------------------------------------------------------------------------- #
# 1. Artifact resolution  (no device access)
# --------------------------------------------------------------------------- #

def _platform_of_dir(d: Path) -> Platform:
    """Infer platform from an unpacked directory's contents."""
    try:
        children = list(d.iterdir())
    except OSError:
        return Platform.UNKNOWN
    # iOS: an IPA payload, or an extracted .app bundle
    if (d / "Payload").is_dir() or any(
        c.is_dir() and c.suffix.lower() == ".app" for c in children
    ):
        return Platform.IOS
    # Android: apktool output, or a set of split apks
    if (d / "AndroidManifest.xml").exists() or any(
        c.is_file() and c.suffix.lower() == ".apk" for c in children
    ):
        return Platform.ANDROID
    return Platform.UNKNOWN


def resolve_artifact(arg: str) -> Target:
    """Classify a positional target without touching any device.

    On-disk file/dir  -> its kind + inferred platform.
    Reverse-DNS string not on disk -> IDENTIFIER (platform UNKNOWN; a device
                                      command resolves it against the device).
    Otherwise -> TargetError.
    """
    p = Path(arg).expanduser()
    if p.exists():
        if p.is_dir():
            return Target(arg, Kind.DIR, _platform_of_dir(p), path=p)
        ext = p.suffix.lower()
        if ext == ".apk":
            return Target(arg, Kind.APK, Platform.ANDROID, path=p)
        if ext in _ANDROID_SPLIT_EXT:
            return Target(arg, Kind.SPLIT, Platform.ANDROID, path=p)
        if ext == ".ipa":
            return Target(arg, Kind.IPA, Platform.IOS, path=p)
        raise TargetError(
            f"unsupported file type: {p.name} "
            f"(expected .apk / .xapk / .apkm / .apks / .ipa, or a directory)"
        )
    if _IDENT_RE.match(arg):
        return Target(arg, Kind.IDENTIFIER, Platform.UNKNOWN, identifier=arg)
    raise TargetError(f"no such file, and not a package/bundle id: {arg!r}")


def require_file(target: Target) -> Target:
    """Guard for file-only commands (mbcinfo).

    Rejects an identifier by pointing at the device boundary instead of quietly
    pulling: mbcinfo never touches the device.
    """
    if target.is_identifier:
        raise TargetError(
            f"{target.raw!r} is a package/bundle id, not a file. "
            f"mbcinfo analyses artifacts only.\n"
            f"To analyse an installed app, pull it first:\n"
            f"    mbcdev pull {target.raw}\n"
            f"    mbcinfo <pulled-file>"
        )
    return target


# --------------------------------------------------------------------------- #
# 2. Device selection  (lazy transport import - the only device dependency)
# --------------------------------------------------------------------------- #

def select_device(serial: str | None = None, platform: str | None = None,
                  ssh: dict | None = None):
    """Pick a device transport (auto-detects platform when unambiguous).

    The lazy import keeps `import mbc.target` free of the device layer. `ssh`
    carries iOS SSH options (host/port/user/password), applied only for iOS.
    """
    from . import transport as tp
    return tp.connect(serial=serial, platform=platform, ssh=ssh)


def list_devices():
    from . import transport as tp
    return tp.list_devices()


def is_installed(dev, identifier: str) -> bool:
    """Exact match against installed packages / bundle ids."""
    return identifier in set(dev.list_installed())


def find_installed(dev, needle: str) -> list[str]:
    """Substring search over installed ids (appquick's grep convenience)."""
    return sorted(p for p in dev.list_installed() if needle in p)