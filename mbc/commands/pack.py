"""
extract / build / sign a package (no device needed)

Android: apktool + zipalign + apksigner
iOS: zip/unzip + ldid
Platform is inferred from the artifact (extension / directory contents) unless
--platform is given.

    extract <file>          extract to a source directory
    build   <dir> [--sign]  rebuild the package (and sign in one step)
    sign    <file|dir>      sign an existing package/app
"""

from __future__ import annotations

import argparse
import sys

from .. import ui
from ..target import Platform, TargetError, resolve_artifact
from ..transport.base import TransportError, ToolNotFound


def _platform(target, forced: str | None) -> Platform:
    if forced:
        return Platform(forced)
    if target.platform != Platform.UNKNOWN:
        return target.platform
    raise TargetError(f"can't tell the platform of {target.raw!r}; pass --platform android|ios")


def _backend(platform: Platform):
    if platform == Platform.ANDROID:
        from ..android import pack as p
    else:
        from ..ios import pack as p
    return p


def _cmd_extract(args) -> int:
    tgt = resolve_artifact(args.target)
    if tgt.is_identifier:
        ui.die("extract needs a package file, not an identifier")
    backend = _backend(_platform(tgt, args.force_platform))
    with ui.console.spinner(f"extracting {tgt.path.name}"):
        out = backend.extract(str(tgt.path), out=args.output)
    ui.console.success(f"extracted to {out}")
    return 0


def _cmd_build(args) -> int:
    tgt = resolve_artifact(args.target)
    platform = _platform(tgt, args.force_platform)
    backend = _backend(platform)
    kw = {}
    if platform == Platform.ANDROID:
        kw["keystore"] = args.keystore
    else:
        kw["entitlements"] = args.entitlements
    with ui.console.spinner("building"):
        out = backend.build(str(tgt.path), out=args.output, sign_pkg=not args.nosign, **kw)
    ui.console.success(f"{'built + signed' if not args.nosign else 'built'} -> {out}")
    return 0


def _cmd_sign(args) -> int:
    tgt = resolve_artifact(args.target)
    platform = _platform(tgt, args.force_platform)
    backend = _backend(platform)
    with ui.console.spinner("signing"):
        if platform == Platform.ANDROID:
            out = backend.sign(str(tgt.path), out=args.output, keystore=args.keystore)
            msg = f"signed -> {out}"
        else:
            n = backend.sign(str(tgt.path), entitlements=args.entitlements)
            msg = f"signed {n} binary(ies)"
    ui.console.success(msg)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mbcpack", description="Extract / build / sign a package.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("extract", aliases=["x"], help="extract to a source directory")
    pe.add_argument("target", help="path to .apk / .ipa")
    pe.add_argument("-o", "--output", help="output directory")
    pe.add_argument("--platform", choices=["android", "ios"], dest="force_platform")
    ui.add_output_args(pe)
    pe.set_defaults(func=_cmd_extract)

    pb = sub.add_parser("build", aliases=["b"], help="rebuild the package (optionally sign)")
    pb.add_argument("target", help="source directory (apktool dir / dir with Payload)")
    pb.add_argument("-o", "--output", help="output package path")
    pb.add_argument("--nosign", action="store_true", help="do not sign after building")
    pb.add_argument("--keystore", help="Android: keystore to sign with (default: debug)")
    pb.add_argument("--entitlements", help="iOS: entitlements plist for ldid")
    pb.add_argument("--platform", choices=["android", "ios"], dest="force_platform")
    ui.add_output_args(pb)
    pb.set_defaults(func=_cmd_build)

    ps = sub.add_parser("sign", help="sign an existing package/app")
    ps.add_argument("target", help="path to .apk / .ipa / .app")
    ps.add_argument("-o", "--output", help="Android: signed output path")
    ps.add_argument("--keystore", help="Android: keystore (default: debug)")
    ps.add_argument("--entitlements", help="iOS: entitlements plist for ldid")
    ps.add_argument("--platform", choices=["android", "ios"], dest="force_platform")
    ui.add_output_args(ps)
    ps.set_defaults(func=_cmd_sign)

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    ui.configure(args)
    try:
        return args.func(args)
    except ToolNotFound as e:
        ui.die(f"{e}\nInstall the missing tool and ensure it's on your PATH "
               f"(Android: apktool/zipalign/apksigner/keytool; iOS: zip/unzip/ldid).")
    except (TargetError, TransportError, ValueError) as e:
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