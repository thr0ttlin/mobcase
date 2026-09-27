"""mbc.ios.pack: unpack / repack / sign an iOS package.

Uses zip/unzip binaries (they preserve exec bits and symlinks, which matter for
a working .app) and ldid for (pseudo-)signing. `repack --sign` signs the app's
binaries and rebuilds the .ipa in one step.
"""

from __future__ import annotations

import plistlib
import shutil
from pathlib import Path

from ..transport.base import locate_tool, run_argv


def extract(ipa: str, out: str | None = None) -> str:
    unzip = locate_tool("unzip")
    out = out or f"{Path(ipa).with_suffix('')}.src"
    run_argv([unzip, "-q", "-o", str(ipa), "-d", out]).check()
    return out


def _app_dir(target: Path) -> Path | None:
    if target.suffix.lower() == ".app" and target.is_dir():
        return target
    payload = target / "Payload"
    search = payload if payload.is_dir() else target
    apps = sorted(p for p in search.iterdir() if p.suffix.lower() == ".app" and p.is_dir())
    return apps[0] if apps else None


def _binaries(app: Path) -> list[Path]:
    """Main executable + frameworks + plugin executables to sign."""
    out: list[Path] = []
    try:
        info = plistlib.load(open(app / "Info.plist", "rb"))
    except Exception:
        info = {}
    exe = info.get("CFBundleExecutable")
    if exe and (app / exe).exists():
        out.append(app / exe)

    fw = app / "Frameworks"
    if fw.is_dir():
        out += list(fw.glob("*.dylib"))
        for f in fw.glob("*.framework"):
            if (f / f.stem).exists():
                out.append(f / f.stem)

    plugins = app / "PlugIns"
    if plugins.is_dir():
        for ax in plugins.glob("*.appex"):
            try:
                i = plistlib.load(open(ax / "Info.plist", "rb"))
            except Exception:
                continue
            e = i.get("CFBundleExecutable")
            if e and (ax / e).exists():
                out.append(ax / e)
    return out


def sign(target: str, entitlements: str | None = None) -> int:
    ldid = locate_tool("ldid")
    t = Path(target)
    app = _app_dir(t) if t.is_dir() else t
    bins = _binaries(app) if (app and app.is_dir()) else [t]
    flag = f"-S{entitlements}" if entitlements else "-S"
    for b in bins:
        run_argv([ldid, flag, str(b)]).check()
    return len(bins)


def build(src_dir: str, out: str | None = None, sign_pkg: bool = False,
           entitlements: str | None = None) -> str:
    zip_ = locate_tool("zip")
    src = Path(src_dir).resolve()

    # Accept either a directory containing Payload/ (as from unpack) or a bare
    # .app (as from `mbcdev pull`); wrap a lone .app into a temp Payload/ tree.
    app = _app_dir(src)
    if (src / "Payload").is_dir():
        root = src
    elif app is not None and app.suffix.lower() == ".app":
        import tempfile
        root = Path(tempfile.mkdtemp(prefix="mbc-ipa-"))
        (root / "Payload").mkdir()
        shutil.copytree(app, root / "Payload" / app.name, symlinks=True)
    else:
        raise ValueError("repack expects a .app or a directory containing Payload/")

    if sign_pkg:
        sign(str(root), entitlements=entitlements)

    # name the .ipa after the app, not after how the path was typed ('.', './', …)
    if out:
        outp = Path(out).resolve()
    else:
        stem = (app.stem if app is not None else src.name) or "app"
        outp = src.parent / f"{stem}.ipa" if src.suffix.lower() == ".app" \
            else src / f"{stem}.ipa"
    if outp.exists():
        outp.unlink()
    run_argv([zip_, "-qry", str(outp), "Payload"], cwd=str(root)).check()
    return str(outp)