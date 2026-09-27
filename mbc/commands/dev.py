"""mbcdev: devices, installed-app inspection, and active operations.

    list                 connected devices (both platforms)
    info     <id>        installed-app info (version, paths/containers, grants)
    pull     <id>        fetch the package off the device (split-aware) -> file
    install  <file>      install an apk / split bundle / ipa
    start    <id>        launch the app
    stop     <id>        force-stop / kill
    remove   <id>        uninstall
    log      <id>        stream logs filtered to the app (logcat / syslog)
    setproxy <val>       set/clear the global HTTP proxy (Android only; ":0" clears)
"""

from __future__ import annotations

import argparse
import sys

from .. import ui
from ..cliopts import add_ssh_args, ssh_opts
from ..transport import TransportError


def _device(args, need_ssh: bool = True):
    from .. import target as tgt
    return tgt.select_device(serial=args.serial, platform=args.platform,
                             ssh=ssh_opts(args) if need_ssh else None)


def _dispatch_backend(dev):
    if dev.platform.value == "android":
        from ..android import device as backend
    else:
        from ..ios import device as backend
    return backend


def _cmd_list(args) -> int:
    from .. import target as tgt
    devices = tgt.list_devices()

    if args._fmt == "json":
        ui.emit(data=[vars(d) | {"platform": d.platform.value} for d in devices],
                fmt="json")
        return 0

    rep = ui.Report()
    sec = rep.section("Devices", hide_if_empty=False)
    if devices:
        tbl = sec.table(["serial", "platform", "name"])
        for d in devices:
            tbl.rows.append({"serial": d.serial, "platform": d.platform.value,
                             "name": d.name or ""})
    else:
        sec.text("no devices connected")
    ui.emit(rep, fmt="text", color=args._color)
    return 0


def _cmd_info(args) -> int:
    # deep container enumeration always runs on iOS; afc2 is passwordless, ssh
    # (chosen or as afc2 fallback) prompts lazily only if actually used
    dev = _device(args, need_ssh=True)
    backend = _dispatch_backend(dev)
    app = backend.analyze(dev, args.identifier, via=getattr(args, "via", "afc2"))
    if args._fmt == "json":
        ui.emit(data=app, fmt="json")
    else:
        ui.emit(backend.to_report(app), fmt="text", color=args._color)
    return 0


def _cmd_pull(args) -> int:
    dev = _device(args)
    backend = _dispatch_backend(dev)
    with ui.console.spinner(f"pulling {args.identifier}"):
        res = backend.pull(dev, args.identifier, dest=args.output)
    if args._fmt == "json":
        ui.emit(data=res, fmt="json")
    else:
        ui.emit(backend.pull_to_report(res), fmt="text", color=args._color)
    return 0


def _cmd_action(args) -> int:
    """install/start/stop/remove/setproxy: one-shot, prints a status line."""
    dev = _device(args)
    backend = _dispatch_backend(dev)
    fn = getattr(backend, args.cmd)
    arg = args.file if args.cmd == "install" else args.identifier
    with ui.console.spinner(f"{args.cmd} {arg}"):
        if args.cmd == "install":
            msg = fn(dev, arg, via=getattr(args, "via", "usbmux"),
                     installer=getattr(args, "installer", None))
        elif args.cmd == "start":
            msg = fn(dev, arg, launcher=getattr(args, "launcher", None),
                     via=getattr(args, "via", "frida"))
        elif args.cmd == "stop":
            msg = fn(dev, arg, via=getattr(args, "via", "frida"))
        else:
            msg = fn(dev, arg)
    ui.console.success(msg)
    return 0


def _cmd_log(args) -> int:
    dev = _device(args)
    backend = _dispatch_backend(dev)
    return backend.logcat(dev, args.identifier)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mbcdev",
                                description="Devices, installed-app info, and actions.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-s", "--serial", help="target device (adb serial / iOS UDID)")
        sp.add_argument("--platform", choices=["android", "ios"])
        add_ssh_args(sp)
        ui.add_output_args(sp)

    pl = sub.add_parser("list", help="connected devices")
    ui.add_output_args(pl)
    pl.set_defaults(func=_cmd_list)

    pn = sub.add_parser("info", help="installed-app info")
    pn.add_argument("identifier", help="package name / bundle id")
    pn.add_argument("-s", "--serial", help="target device (adb serial / iOS UDID)")
    pn.add_argument("--platform", choices=["android", "ios"])
    pn.add_argument("--via", choices=["afc2", "ssh"], default="afc2",
                    help="iOS: channel for container enumeration (default: afc2, "
                         "passwordless; ssh needs a password)")
    add_ssh_args(pn)
    ui.add_output_args(pn)
    pn.set_defaults(func=_cmd_info)

    pu = sub.add_parser("pull", help="fetch the package off the device")
    pu.add_argument("identifier", help="package name / bundle id")
    pu.add_argument("-o", "--output", default=".", help="destination directory (default: .)")
    common(pu)
    pu.set_defaults(func=_cmd_pull)

    pi = sub.add_parser("install", help="install an apk / bundle / ipa")
    pi.add_argument("file", help="path to .apk/.xapk/.apkm/.apks/.ipa or apk dir")
    pi.add_argument("--via", choices=["usbmux", "ssh"], default="usbmux",
                    help="iOS install path: usbmux/ideviceinstaller (default) or "
                         "ssh on-device installer")
    pi.add_argument("--installer",
                    help="iOS --via ssh: on-device install command, e.g. 'appinst {ipa}' "
                         "(default: try appinst, then installipa)")
    common(pi)
    pi.set_defaults(func=_cmd_action)

    for name, help_ in (("start", "launch the app"),
                        ("stop", "force-stop / kill"),
                        ("remove", "uninstall")):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("identifier", help="package name / bundle id")
        if name == "start":
            sp.add_argument("--via", choices=["frida", "ssh"], default="frida",
                            help="iOS launch channel (default: frida; ssh uses "
                                 "uiopen/open on the device)")
            sp.add_argument("--launcher",
                            help="iOS: custom launch command, e.g. 'uiopen --bundleid {bundle}'")
        elif name == "stop":
            sp.add_argument("--via", choices=["frida", "ssh"], default="frida",
                            help="iOS kill channel (default: frida, passwordless; "
                                 "ssh uses killall)")
        common(sp)
        sp.set_defaults(func=_cmd_action)

    ps = sub.add_parser("setproxy", help="set/clear global HTTP proxy (Android)")
    ps.add_argument("identifier", metavar="value", help="host:port, or ':0' to clear")
    common(ps)
    ps.set_defaults(func=_cmd_action)

    pg = sub.add_parser("log", help="stream app logs (Android logcat / iOS syslog)")
    pg.add_argument("identifier", help="package name / bundle id")
    common(pg)
    pg.set_defaults(func=_cmd_log)

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    ui.configure(args)
    try:
        return args.func(args)
    except (TransportError, ValueError) as e:
        ui.die(str(e))
    except BrokenPipeError:
        import os
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 141
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())