"""mbc.ios.device: installed-app inspection AND active operations (iOS).

`analyze` reads installation_proxy over usbmux (async, bridged to sync via
asyncio.run) and reports identity + containers. Actions mirror the transport
scatter:
    install / remove   -> ideviceinstaller (usbmux)
    stop               -> killall <exe> over SSH
    start              -> frida spawn (if available) else a launcher over SSH
    logcat             -> idevicesyslog, filtered by process name
"""

from __future__ import annotations

import asyncio
import shlex
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Optional

from .. import ui
from ..transport import Transport, TransportError, UnsupportedOperation
from ..transport.base import locate_tool, stream_argv


@dataclass
class ContainerRef:
    identifier: str
    path: str


@dataclass
class InstalledApp:
    bundle_id: str
    installed: bool
    name: Optional[str] = None
    version: Optional[str] = None
    build: Optional[str] = None
    app_type: Optional[str] = None            # User / System
    bundle_path: Optional[str] = None          # the .app
    bundle_container: Optional[str] = None     # Bundle/Application/<UUID>
    data_container: Optional[str] = None       # Data/Application/<UUID>
    signer: Optional[str] = None               # SignerIdentity
    file_sharing: Optional[bool] = None
    entitlements: dict[str, Any] = field(default_factory=dict)
    extensions: list[ContainerRef] = field(default_factory=list)   # PluginKit data
    app_groups: list[ContainerRef] = field(default_factory=list)   # shared AppGroup


async def _fetch(udid: str, bundle_id: str) -> dict[str, Any]:
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService

    lockdown = await create_using_usbmux(serial=udid)
    try:
        async with InstallationProxyService(lockdown) as ip:
            apps = await ip.get_apps(bundle_identifiers=[bundle_id])
    finally:
        close = getattr(lockdown, "aclose", None) or getattr(lockdown, "close", None)
        if close:
            try:
                r = close()
                if asyncio.iscoroutine(r):
                    await r
            except Exception:
                pass
    return apps.get(bundle_id) or {}


_AFC2_SERVICE = "com.apple.afc2"


def _match_container(path: str, ident: Optional[str], bundle_id: str, groups_set: set,
                     exts: list, groups: list, seen: list) -> None:
    if not ident:
        return
    seen.append(ident)
    if "/PluginKitPlugin/" in path and (ident == bundle_id
                                        or ident.startswith(bundle_id + ".")):
        exts.append(ContainerRef(ident, path))
    elif "/AppGroup/" in path and ident in groups_set:
        groups.append(ContainerRef(ident, path))


def _ident_from_plist(data: bytes) -> Optional[str]:
    import plistlib
    try:
        meta = plistlib.loads(data)
    except Exception:
        return None
    return (meta.get("MCMMetadataIdentifier") or meta.get("MCMetadataIdentifier")
            or next((v for k, v in meta.items() if k.endswith("MetadataIdentifier")), None))


async def _afc_containers_async(udid: str, bundle_id: str, group_ids: list[str]):
    """Enumerate containers over afc2 (unsandboxed AFC on jailbreak): full-FS
    read over usbmux, no SSH password. Raises if the afc2 service can't start."""
    import inspect
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.afc import AfcService

    async def _aw(x):
        return await x if inspect.isawaitable(x) else x

    lockdown = await create_using_usbmux(serial=udid)
    afc = AfcService(lockdown, service_name=_AFC2_SERVICE)
    await afc.connect()                             # raises if afc2 not installed
    try:
        groups_set = set(group_ids or [])
        exts: list[ContainerRef] = []
        groups: list[ContainerRef] = []
        seen: list[str] = []
        for base in (_PLUGINKIT, _APPGROUP):
            try:
                names = await _aw(afc.listdir(base))
            except Exception:
                names = []
            for name in names:
                path = f"{base}/{name}"
                try:
                    data = await _aw(afc.get_file_contents(f"{path}/{_META}"))
                except Exception:
                    continue
                _match_container(path, _ident_from_plist(data), bundle_id,
                                 groups_set, exts, groups, seen)
        return exts, groups, seen
    finally:
        try:
            await afc.close()
        except Exception:
            pass


def _deep_containers(dev: Transport, bundle_id: str, group_ids: list[str],
                     via: str = "afc2") -> tuple[list[ContainerRef], list[ContainerRef]]:
    """Enumerate extension/app-group containers. via='afc2' (default) prefers the
    passwordless afc2 channel and falls back to SSH; via='ssh' forces SSH."""
    if via == "afc2" and dev.serial:
        try:
            exts, groups, seen = asyncio.run(
                _afc_containers_async(dev.serial, bundle_id, group_ids))
            ui.console.verbose(f"containers via afc2: {len(seen)} identifier(s), "
                               f"{len(exts)} ext + {len(groups)} group")
            if seen:                               # afc2 reachable and read metadata
                if not exts and not groups:
                    ui.console.warn(f"read {len(seen)} container(s) via afc2 but none "
                                    f"matched {bundle_id}")
                return exts, groups
            ui.console.verbose("afc2 returned no metadata; falling back to SSH")
        except Exception as e:
            ui.console.verbose(f"afc2 unavailable ({e}); falling back to SSH")
    return _ssh_containers(dev, bundle_id, group_ids)


_PLUGINKIT = "/var/mobile/Containers/Data/PluginKitPlugin"
_APPGROUP = "/var/mobile/Containers/Shared/AppGroup"
_META = ".com.apple.mobile_container_manager.metadata.plist"

# Read each container's metadata over the SSH *shell* (some jailbreak SFTP
# servers deny these files even to the owner; the shell reads them, as
# icontainers.sh does). PATH is set explicitly (rootless jailbreak tools live
# in /var/jb/usr/bin). Content is piped through base64 via STDIN so both GNU and
# BSD base64 work; xxd hex is a fallback if base64 is unavailable.
_CONTAINERS_SNIPPET = r"""
export PATH=/var/jb/usr/bin:/var/jb/bin:/var/jb/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH
for base in %s %s; do
  [ -d "$base" ] || continue
  for d in "$base"/*; do
    m="$d/%s"
    [ -r "$m" ] || continue
    enc=$(cat "$m" 2>/dev/null | base64 2>/dev/null) \
      || enc=$(openssl base64 -in "$m" 2>/dev/null) \
      || enc="HEX:$(xxd -p "$m" 2>/dev/null | tr -d '\n')"
    printf '===MBC===%%s\t%%s\n' "$d" "$enc"
  done
done
"""% (_PLUGINKIT, _APPGROUP, _META)


def _decode_meta(payload: str) -> Optional[bytes]:
    import base64 as _b64
    payload = payload.strip()
    if not payload:
        return None
    try:
        if payload.startswith("HEX:"):
            return bytes.fromhex(payload[4:])
        return _b64.b64decode(payload)
    except Exception:
        return None


def _ssh_containers(dev: Transport, bundle_id: str,
                    group_ids: list[str]) -> tuple[list[ContainerRef], list[ContainerRef]]:
    """Enumerate the app's PluginKit (extension) and AppGroup containers by
    matching each container metadata's MCMMetadataIdentifier. Runs over the SSH
    shell (connection errors propagate). Verbose mode traces every step."""
    import plistlib

    out = dev.run(_CONTAINERS_SNIPPET).stdout      # TransportError propagates if no tunnel
    ui.console.verbose(f"containers: raw ssh output {len(out)} bytes; "
                       f"head={out[:200]!r}")

    groups_set = set(group_ids or [])
    exts: list[ContainerRef] = []
    groups: list[ContainerRef] = []
    seen: list[str] = []
    blocks = 0

    for block in out.split("===MBC===")[1:]:
        blocks += 1
        head, _, payload = block.partition("\t")   # path <TAB> encoded-metadata
        path = head.strip()
        if payload == "" and "\n" in block:        # tolerate a stray newline layout
            first, _, rest = block.partition("\n")
            path, payload = first.strip(), rest
        data = _decode_meta(payload)
        if blocks <= 3:
            ui.console.verbose(f"  block {blocks}: path={path} payload_len={len(payload)} "
                               f"decoded={'None' if data is None else len(data)}")
        if not data:
            continue
        try:
            meta = plistlib.loads(data)
        except Exception as e:
            if blocks <= 3:
                ui.console.verbose(f"  block {blocks}: plist parse failed: {e}; "
                                   f"raw head={data[:16]!r}")
            continue
        if blocks <= 3:
            ui.console.verbose(f"  block {blocks}: keys={sorted(meta.keys())}")
        ident = (meta.get("MCMMetadataIdentifier") or meta.get("MCMetadataIdentifier")
                 or next((v for k, v in meta.items()
                          if k.endswith("MetadataIdentifier")), None))
        if not ident:
            continue
        seen.append(ident)
        if "/PluginKitPlugin/" in path and (ident == bundle_id
                                            or ident.startswith(bundle_id + ".")):
            exts.append(ContainerRef(ident, path))
        elif "/AppGroup/" in path and ident in groups_set:
            groups.append(ContainerRef(ident, path))

    ui.console.verbose(
        f"containers: {blocks} block(s), {len(seen)} identifier(s) parsed; "
        f"matched {len(exts)} ext + {len(groups)} group")
    if not exts and not groups:
        if blocks == 0:
            ui.console.warn("no readable container metadata over SSH: check the tunnel; "
                            "try --ssh-user root")
        elif not seen:
            ui.console.warn("read container dirs but couldn't decode metadata "
                            "(no base64/xxd on device?): run with -v for details")
        else:
            ui.console.warn(f"read {blocks} container(s) but none matched {bundle_id} "
                            f"(run with -v to see identifiers)")
    return exts, groups


def analyze(dev: Transport, bundle_id: str, via: str = "afc2") -> InstalledApp:
    if not dev.serial:
        raise TransportError("no device UDID for iOS lookup")
    try:
        info = asyncio.run(_fetch(dev.serial, bundle_id))
    except Exception as e:
        raise TransportError(f"installation_proxy query failed: {e}") from e

    if not info:
        return InstalledApp(bundle_id=bundle_id, installed=False)

    ent = info.get("Entitlements", {})
    ent = ent if isinstance(ent, dict) else {}
    bundle_path = info.get("Path")
    bundle_container = bundle_path.rsplit("/", 1)[0] if bundle_path else None

    gids = ent.get("com.apple.security.application-groups", []) or []
    try:
        exts, groups = _deep_containers(dev, bundle_id, gids, via=via)
    except Exception as e:
        ui.console.warn(f"container enumeration failed: {e}")
        exts, groups = [], []

    return InstalledApp(
        bundle_id=bundle_id,
        installed=True,
        name=info.get("CFBundleDisplayName") or info.get("CFBundleName"),
        version=info.get("CFBundleShortVersionString"),
        build=info.get("CFBundleVersion"),
        app_type=info.get("ApplicationType"),
        bundle_path=bundle_path,
        bundle_container=bundle_container,
        data_container=info.get("Container"),
        signer=info.get("SignerIdentity"),
        file_sharing=info.get("UIFileSharingEnabled"),
        entitlements=ent,
        extensions=exts,
        app_groups=groups,
    )


def to_report(app: InstalledApp) -> ui.Report:
    rep = ui.Report(title=app.bundle_id)
    if not app.installed:
        rep.section("Installed app").text(f"{app.bundle_id} is not installed")
        return rep

    kv = rep.section("Installed app").kv()
    kv.add("Bundle ID", app.bundle_id)
    kv.add("Name", app.name)
    kv.add("Version", f"{app.version} ({app.build})")
    kv.add("Type", app.app_type)
    kv.add("Signer", app.signer)
    kv.add("File sharing", app.file_sharing)

    kv = rep.section("Containers").kv()
    kv.add("Bundle path", app.bundle_path)
    kv.add("Bundle container", app.bundle_container)
    kv.add("Data container", app.data_container)

    if app.extensions:
        t = rep.section("Extension containers", hide_if_empty=True).table(["extension", "container"])
        for c in app.extensions:
            t.rows.append({"extension": c.identifier, "container": c.path})
    if app.app_groups:
        t = rep.section("App group containers", hide_if_empty=True).table(["group", "container"])
        for c in app.app_groups:
            t.rows.append({"group": c.identifier, "container": c.path})

    ent = rep.section("Entitlements", hide_if_empty=True)
    if app.entitlements:
        e = ent.kv()
        for k in sorted(app.entitlements):
            e.add(k, app.entitlements[k])
    return rep


# --------------------------------------------------------------------------- #
# pull  (copy the .app bundle off the device -> Payload/ dir for mbcinfo/mbcpack)
# --------------------------------------------------------------------------- #

@dataclass
class PullResult:
    identifier: str
    installed: bool
    target: Optional[str] = None
    files: list[str] = field(default_factory=list)
    kind: Optional[str] = None        # "app-bundle"


def pull(dev: Transport, bundle_id: str, dest: str = ".") -> PullResult:
    """Copy the installed .app bundle to the host over SSH (jailbreak required).

    App Store binaries stay FairPlay-encrypted (only __TEXT), but Info.plist,
    embedded plists and the code signature (entitlements + signer) sit outside
    the encrypted region, so mbcinfo can still analyse the pulled bundle.
    """
    if not dev.serial:
        raise TransportError("no device UDID for iOS lookup")
    try:
        info = asyncio.run(_fetch(dev.serial, bundle_id))
    except Exception as e:
        raise TransportError(f"installation_proxy query failed: {e}") from e
    if not info:
        return PullResult(identifier=bundle_id, installed=False)

    bundle_path = info.get("Path")
    if not bundle_path:
        raise TransportError(f"no bundle path reported for {bundle_id}")

    dest_dir = Path(dest)
    payload = dest_dir / "Payload"
    payload.mkdir(parents=True, exist_ok=True)
    dev.pull(bundle_path, str(payload), recursive=True)   # scp -r <.app> dest/Payload/
    app_name = bundle_path.rsplit("/", 1)[-1]
    local = payload / app_name
    return PullResult(identifier=bundle_id, installed=True,
                      target=str(dest_dir), files=[str(local)], kind="app-bundle")


def pull_to_report(r: PullResult) -> ui.Report:
    rep = ui.Report(title=r.identifier)
    if not r.installed:
        rep.section("Pull").text(f"{r.identifier} is not installed")
        return rep
    kv = rep.section("Pulled").kv()
    kv.add("Target", r.target)
    kv.add("Kind", r.kind)
    rep.section("Next").text(f"mbcinfo {r.target}")
    return rep


# --------------------------------------------------------------------------- #
# actions
# --------------------------------------------------------------------------- #

def _app_info(dev: Transport, bundle_id: str) -> dict:
    if not dev.serial:
        raise TransportError("no device UDID for iOS lookup")
    try:
        return asyncio.run(_fetch(dev.serial, bundle_id)) or {}
    except Exception as e:
        raise TransportError(f"installation_proxy query failed: {e}") from e


def install(dev: Transport, target: str, via: str = "usbmux",
            installer: str | None = None) -> str:
    p = Path(target).expanduser()
    if p.suffix.lower() != ".ipa":
        raise TransportError("iOS install takes a single .ipa")

    if via == "ssh":
        remote = f"/var/mobile/Media/{p.name}"     # writable by the mobile user
        dev.push(str(p), remote)
        if installer:
            cmd = (installer.replace("{ipa}", shlex.quote(remote))
                   if "{ipa}" in installer else f"{installer} {shlex.quote(remote)}")
            r = dev.run(cmd)
            if r.ok:
                return f"installed {p.name} via custom installer"
            raise TransportError(
                f"installer failed: {r.stderr.strip() or r.stdout.strip() or 'no output'}")
        tried: list[str] = []
        for tool in ("appinst", "installipa"):
            r = dev.run(f"{tool} {shlex.quote(remote)}")
            if r.ok:
                return f"installed {p.name} via {tool}"
            tried.append(tool)
        raise TransportError(
            f"no on-device installer worked (tried {', '.join(tried)}); "
            f"pass --installer '<cmd>' (use {{ipa}} for the uploaded path: {remote})")

    r = dev.install(str(p))                          # usbmux / ideviceinstaller
    if not r.ok:
        raise TransportError(r.stderr.strip() or r.stdout.strip() or "install failed")
    return f"installed {p.name}"


def remove(dev: Transport, bundle_id: str) -> str:
    r = dev.uninstall(bundle_id)
    if not r.ok:
        raise TransportError(r.stderr.strip() or r.stdout.strip() or "uninstall failed")
    return f"removed {bundle_id}"


def _frida_kill(dev: Transport, bundle_id: str) -> tuple[bool, str]:
    """Kill the app's process via frida (usbmux, no SSH password). Returns
    (killed, err). killed is True if a running process was found and killed."""
    def _do(frida_dev) -> tuple[bool, str]:
        try:
            apps = frida_dev.enumerate_applications()
        except Exception as e:
            return False, f"enumerate failed: {e}"
        pid = next((a.pid for a in apps if a.identifier == bundle_id and a.pid), 0)
        if not pid:
            return False, "not running"
        frida_dev.kill(pid)
        return True, ""

    try:
        import frida
    except ImportError:
        pass
    else:
        try:
            fd = frida.get_device(dev.serial) if dev.serial else frida.get_usb_device()
            return _do(fd)
        except Exception as e:
            return False, f"frida module: {e}"

    import shutil
    import subprocess
    cli = shutil.which("frida-kill")
    if cli:
        argv = [cli] + (["-D", dev.serial] if dev.serial else ["-U"]) + [bundle_id]
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=30)
            if p.returncode == 0:
                return True, ""
            return False, (p.stderr.strip() or p.stdout.strip() or f"exit {p.returncode}")
        except Exception as e:
            return False, str(e)
    return False, "frida unavailable (no module, no frida-kill CLI)"


def stop(dev: Transport, bundle_id: str, via: str = "frida") -> str:
    if via == "frida":
        killed, err = _frida_kill(dev, bundle_id)
        if killed:
            return f"killed {bundle_id} via frida"
        if err == "not running":
            return f"{bundle_id} is not running"
        ui.console.verbose(f"frida kill unavailable ({err}); falling back to SSH killall")

    exe = _app_info(dev, bundle_id).get("CFBundleExecutable")
    if not exe:
        raise TransportError(f"{bundle_id} is not installed")
    dev.run(f"killall -9 {shlex.quote(exe)}")     # non-zero if not running; that's fine
    return f"killed {exe}"


_LAUNCH_PATH = ("export PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:"
                "/usr/sbin:/sbin:$PATH; ")

# on-device launchers tried for --via ssh (correct syntax per tool); PATH covers
# rootful (/usr/bin) and rootless (/var/jb/usr/bin)
_SSH_LAUNCHERS = ("uiopen --bundleid {b}", "open {b}")


def _frida_launch(dev: Transport, bundle_id: str) -> tuple[str | None, str, str]:
    """Return (success_msg, module_err, cli_err)."""
    module_err = cli_err = ""
    try:
        import frida
    except ImportError:
        module_err = "python module not in this venv (pip install frida==<device-major>.x)"
    else:
        try:
            d = frida.get_device(dev.serial) if dev.serial else frida.get_usb_device()
            pid = d.spawn([bundle_id])
            d.resume(pid)
            return f"spawned {bundle_id} (pid {pid}) via frida", module_err, cli_err
        except Exception as e:
            module_err = f"spawn failed: {e}"

    import shutil
    import subprocess
    frida_cli = shutil.which("frida")
    if not frida_cli:
        cli_err = "frida CLI not on PATH"
    else:
        argv = [frida_cli] + (["-D", dev.serial] if dev.serial else ["-U"]) + \
            ["-f", bundle_id, "--no-pause", "-q"]
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=30)
            if p.returncode == 0:
                return f"spawned {bundle_id} via frida CLI", module_err, cli_err
            cli_err = p.stderr.strip() or p.stdout.strip() or f"exit {p.returncode}"
        except subprocess.TimeoutExpired:
            cli_err = "frida CLI timed out"
        except Exception as e:
            cli_err = str(e)
    return None, module_err, cli_err


def _ssh_launch(dev: Transport, bundle_id: str) -> tuple[str | None, list[str]]:
    tried: list[str] = []
    for tmpl in _SSH_LAUNCHERS:
        cmd = tmpl.format(b=shlex.quote(bundle_id))
        r = dev.run(_LAUNCH_PATH + cmd)
        if r.ok:
            return f"launched {bundle_id} via {cmd.split()[0]}", tried
        tried.append(cmd.split()[0])
    return None, tried


def start(dev: Transport, bundle_id: str, launcher: str | None = None,
          via: str = "frida") -> str:
    # explicit custom launcher wins ({bundle} substituted, else appended); PATH-aware
    if launcher:
        cmd = (launcher.replace("{bundle}", shlex.quote(bundle_id))
               if "{bundle}" in launcher else f"{launcher} {shlex.quote(bundle_id)}")
        r = dev.run(_LAUNCH_PATH + cmd)
        if r.ok:
            return f"launched {bundle_id} via custom launcher"
        raise TransportError(
            f"custom launcher failed: {r.stderr.strip() or r.stdout.strip() or 'no output'}")

    module_err = cli_err = ""
    if via == "frida":
        msg, module_err, cli_err = _frida_launch(dev, bundle_id)
        if msg:
            return msg
        # fall through to ssh launchers as a last resort

    msg, tried = _ssh_launch(dev, bundle_id)
    if msg:
        return msg

    raise TransportError(
        f"could not launch {bundle_id}.\n"
        + (f"  frida module: {module_err}\n  frida CLI:    {cli_err}\n"
           if via == "frida" else "")
        + f"  ssh launchers failed: {', '.join(tried)}\n"
        f"Fix one of:\n"
        f"  - --via frida with frida-tools on host (or the frida module in the venv) "
        f"matching the device's frida-server, or\n"
        f"  - --via ssh with uiopen/open present on the device, or\n"
        f"  - --launcher '<cmd>' (e.g. 'uiopen --bundleid {{bundle}}')"
    )


def setproxy(dev: Transport, value: str) -> str:
    raise UnsupportedOperation(
        "setproxy is Android-only; on iOS set a Wi-Fi proxy or install a .mobileconfig"
    )


def logcat(dev: Transport, bundle_id: str) -> int:
    exe = _app_info(dev, bundle_id).get("CFBundleExecutable")
    argv = [locate_tool("idevicesyslog")]
    if dev.serial:
        argv += ["-u", dev.serial]
    if exe:
        argv += ["--process", exe]
    else:
        ui.console.warn(f"{bundle_id}: no executable name: streaming full syslog")
    return stream_argv(argv)