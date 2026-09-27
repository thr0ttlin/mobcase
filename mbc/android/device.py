"""mbc.android.device: installed-app inspection AND active operations (Android).

`analyze` reads `dumpsys package` / `pm path` (read-only). Actions
(install/start/stop/remove/setproxy/logcat) mutate device/app state or
stream. Component parsing is deliberately absent: to inspect components of an
installed app, pull it and run mbcinfo on the file.
"""

from __future__ import annotations

import re
import tempfile
import zipfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

from .. import ui
from ..transport import Transport, TransportError

_SPLIT_EXT = {".xapk", ".apkm", ".apks"}


@dataclass
class InstalledApp:
    package: str
    installed: bool
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    uid: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    code_path: Optional[str] = None
    data_dir: Optional[str] = None
    cache_path: Optional[str] = None
    code_cache_path: Optional[str] = None
    files_path: Optional[str] = None
    ext_data_path: Optional[str] = None
    ext_obb_path: Optional[str] = None
    apk_paths: list[str] = field(default_factory=list)
    installer: Optional[str] = None
    first_install: Optional[str] = None
    last_update: Optional[str] = None
    granted_permissions: list[str] = field(default_factory=list)


def _first(pattern: str, text: str) -> Optional[str]:
    m = re.search(pattern, text)
    return m.group(1).strip() if m else None


def _int(pattern: str, text: str) -> Optional[int]:
    v = _first(pattern, text)
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def _uid(dev: Transport, package: str, dumpsys_text: str) -> Optional[str]:
    """UID via `pm list packages -U` (stable across ROMs); dumpsys as fallback."""
    out = dev.run(f"pm list packages -U {package}").stdout
    for line in out.splitlines():
        if not line.startswith("package:"):
            continue
        name = line.split(":", 1)[1].split()[0]
        if name == package:
            m = re.search(r"uid:(\d+)", line)
            if m:
                return m.group(1)
    return _first(r"userId=(\d+)", dumpsys_text)


def analyze(dev: Transport, package: str, via: str = "afc2") -> InstalledApp:
    # via is an iOS channel selector; Android already reports paths inline
    apk_paths = [
        line[len("package:"):].strip()
        for line in dev.run(f"pm path {package}").stdout.splitlines()
        if line.startswith("package:")
    ]
    if not apk_paths:
        return InstalledApp(package=package, installed=False)

    ext = dev.run("echo $EXTERNAL_STORAGE").stdout.strip()
    real_ext = dev.run(f"realpath {ext}").stdout.strip() if ext else ""

    d = dev.run(f"dumpsys package {package}").stdout

    granted = sorted({
        m.group(1) for m in re.finditer(r"^\s*([\w.]+): granted=true", d, re.MULTILINE)
    })

    base = _first(r"dataDir=(\S+)", d)
    return InstalledApp(
        package=package,
        installed=True,
        version_name=_first(r"versionName=(\S+)", d),
        version_code=_int(r"versionCode=(\d+)", d),
        uid=_uid(dev, package, d),
        min_sdk=_int(r"minSdk=(\d+)", d),
        target_sdk=_int(r"targetSdk=(\d+)", d),

        code_path=_first(r"codePath=(\S+)", d),
        data_dir=base,
        cache_path=f"{base}/cache" if base else None,
        code_cache_path=f"{base}/code_cache" if base else None,
        files_path=f"{base}/files" if base else None,
        ext_data_path=f"{real_ext}/Android/data/{package}" if real_ext else None,
        ext_obb_path=f"{real_ext}/Android/obb/{package}" if real_ext else None,

        apk_paths=apk_paths,
        installer=_first(r"installerPackageName=(\S+)", d),
        first_install=_first(r"firstInstallTime=(.+)", d),
        last_update=_first(r"lastUpdateTime=(.+)", d),
        granted_permissions=granted,
    )


def to_report(app: InstalledApp) -> ui.Report:
    rep = ui.Report(title=app.package)
    if not app.installed:
        rep.section("Installed app").text(f"{app.package} is not installed")
        return rep

    kv = rep.section("Installed app").kv()
    kv.add("Package", app.package)
    kv.add("Version", f"{app.version_name} ({app.version_code})")
    kv.add("UID", app.uid)
    kv.add("Min SDK", app.min_sdk)
    kv.add("Target SDK", app.target_sdk)
    kv.add("Installer", app.installer)
    kv.add("First install", app.first_install)
    kv.add("Last update", app.last_update)

    kv = rep.section("Paths").kv()
    kv.add("Code path", app.code_path)
    kv.add("Data", app.data_dir)
    kv.add("Cache", app.cache_path)
    kv.add("Code cache", app.code_cache_path)
    kv.add("Files", app.files_path)
    kv.add("Ext data", app.ext_data_path)
    kv.add("Ext obb", app.ext_obb_path)

    rep.section("APK paths", hide_if_empty=True).listing().items.extend(
        (p, []) for p in app.apk_paths)
    rep.section("Granted runtime permissions", hide_if_empty=True).listing().items.extend(
        (p, []) for p in app.granted_permissions)
    return rep


# --------------------------------------------------------------------------- #
# pull  (fetch the package off the device -> file for mbcinfo)
# --------------------------------------------------------------------------- #

@dataclass
class PullResult:
    identifier: str
    installed: bool
    target: Optional[str] = None      # what to hand to mbcinfo (file or dir)
    files: list[str] = field(default_factory=list)
    kind: Optional[str] = None        # "apk" | "split-dir"


def pull(dev: Transport, package: str, dest: str = ".") -> PullResult:
    remote = [
        line[len("package:"):].strip()
        for line in dev.run(f"pm path {package}").stdout.splitlines()
        if line.startswith("package:")
    ]
    if not remote:
        return PullResult(identifier=package, installed=False)

    dest_dir = Path(dest)
    dest_dir.mkdir(parents=True, exist_ok=True)

    if len(remote) == 1:
        local = dest_dir / f"{package}.apk"
        dev.pull(remote[0], str(local))
        return PullResult(identifier=package, installed=True,
                          target=str(local), files=[str(local)], kind="apk")

    out = dest_dir / package
    out.mkdir(parents=True, exist_ok=True)
    files: list[str] = []
    for r in remote:
        local = out / r.rsplit("/", 1)[-1]
        dev.pull(r, str(local))
        files.append(str(local))
    return PullResult(identifier=package, installed=True,
                      target=str(out), files=files, kind="split-dir")


def pull_to_report(r: PullResult) -> ui.Report:
    rep = ui.Report(title=r.identifier)
    if not r.installed:
        rep.section("Pull").text(f"{r.identifier} is not installed")
        return rep
    kv = rep.section("Pulled").kv()
    kv.add("Target", r.target)
    kv.add("Kind", r.kind)
    kv.add("Files", len(r.files))
    rep.section("Files", hide_if_empty=True).listing().items.extend((f, []) for f in r.files)
    rep.section("Next").text(f"mbcinfo {r.target}")
    return rep


# --------------------------------------------------------------------------- #
# actions
# --------------------------------------------------------------------------- #

def _apks_from(path: Path) -> list[str]:
    """Resolve a target into the apk file(s) to install."""
    if path.is_dir():
        apks = sorted(str(p) for p in path.rglob("*.apk"))
        if not apks:
            raise TransportError(f"no .apk found in {path}")
        return apks
    ext = path.suffix.lower()
    if ext == ".apk":
        return [str(path)]
    if ext in _SPLIT_EXT:
        tmp = Path(tempfile.mkdtemp(prefix="mbc-inst-"))
        with zipfile.ZipFile(path) as z:
            z.extractall(tmp)
        apks = sorted(str(p) for p in tmp.rglob("*.apk"))
        if not apks:
            raise TransportError(f"no .apk inside bundle {path}")
        return apks
    raise TransportError(f"unsupported install target: {path.name}")


def install(dev: Transport, target: str, via: str = "usbmux",
            installer: str | None = None) -> str:
    # via/installer are iOS-only (adb has a single install path)
    apks = _apks_from(Path(target).expanduser())
    r = dev.install(apks if len(apks) > 1 else apks[0])
    if not r.ok:
        raise TransportError(r.stderr.strip() or r.stdout.strip() or "install failed")
    return f"installed {len(apks)} apk(s)"


def start(dev: Transport, package: str, launcher: str | None = None,
          via: str = "frida") -> str:
    # launcher/via are iOS concepts; ignored on Android (launches via am)
    if not dev.run(f"pm path {package}").stdout.strip():
        raise TransportError(f"{package} is not installed")

    r = dev.run(f"cmd package resolve-activity --brief {package}")
    comp = r.stdout.strip().splitlines()[-1].strip() if r.stdout.strip() else ""
    if "/" in comp and not comp.endswith("/"):
        res = dev.run(f"am start -n {comp}")
        blob = (res.stdout or "") + (res.stderr or "")
        if res.ok and "Error" not in blob:
            return f"started {comp}"
        raise TransportError(res.stderr.strip() or res.stdout.strip() or "am start failed")

    res = dev.run(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
    blob = (res.stdout or "") + (res.stderr or "")
    if res.ok and "No activities found" not in blob and "aborted" not in blob:
        return f"started {package} (launcher)"
    raise TransportError(f"{package}: no launchable activity found")


def stop(dev: Transport, package: str, via: str = "frida") -> str:
    # via is an iOS concept; Android always force-stops via am
    dev.run(f"am force-stop {package}", check=True)
    return f"force-stopped {package}"


def remove(dev: Transport, package: str) -> str:
    r = dev.uninstall(package)
    if not r.ok:
        raise TransportError(r.stderr.strip() or r.stdout.strip() or "uninstall failed")
    return f"removed {package}"


def setproxy(dev: Transport, value: str) -> str:
    dev.run(f"settings put global http_proxy {value}", check=True)
    return "proxy cleared" if value in (":0", ":", "0") else f"proxy set to {value}"


def logcat(dev: Transport, package: str) -> int:
    """Stream logcat filtered to the app. Prefer the app's UID (stable across
    process restarts, and catches multi-process apps); fall back to a live PID.
    No unfiltered fallback: a bogus id errors instead of dumping everything."""
    uid = _uid(dev, package, "")
    if uid:
        return dev.stream(["logcat", f"--uid={uid}", "-v", "color"])
    pid = dev.run(f"pidof -s {package}").stdout.strip()
    if pid:
        return dev.stream(["logcat", f"--pid={pid}", "-v", "color"])
    raise TransportError(
        f"{package}: not installed / not running - nothing to filter logcat on")