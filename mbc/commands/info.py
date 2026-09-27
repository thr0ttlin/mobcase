"""
Static analysis of a mobile app artifact
"""

from __future__ import annotations

import argparse
import sys

from .. import ui
from ..target import Platform, TargetError, require_file, resolve_artifact


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mbcinfo",
        description="Static analysis of an APK / split bundle / IPA / unpacked dir.",
    )
    p.add_argument("target",
                   help="path to .apk/.xapk/.apkm/.apks/.ipa or an unpacked directory")
    p.add_argument("-e", "--all", action="store_true", dest="show_all",
                   help="include non-exported components")
    p.add_argument("--platform", choices=["android", "ios"], dest="force_platform",
                   help="force platform for an ambiguous directory")
    ui.add_output_args(p)
    return p


def _resolve_platform(target, forced: str | None) -> Platform:
    if forced:
        return Platform(forced)
    if target.platform != Platform.UNKNOWN:
        return target.platform
    raise TargetError(
        f"can't tell the platform of {target.raw!r}; pass --platform android|ios"
    )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    con, fmt = ui.configure(args)

    try:
        target = require_file(resolve_artifact(args.target))
        platform = _resolve_platform(target, args.force_platform)

        con.verbose(f"target: {target.kind.value} ({platform.value}) -> {target.path}")

        if platform == Platform.ANDROID:
            from ..android import apk as backend
        elif platform == Platform.IOS:
            from ..ios import ipa as backend
        else:
            raise TargetError

        with con.spinner(f"analysing {target.path.name}"):
            app = backend.analyze(target)

        if fmt == "json":
            ui.emit(data=app, fmt="json")
        else:
            ui.emit(backend.to_report(app, show_all=args.show_all), fmt="text",
                    color=args._color)
        return 0

    except (TargetError, ValueError) as e:
        ui.die(str(e))
    except BrokenPipeError:
        # downstream closed the pipe (e.g. | head); exit quietly. Point stdout at
        # devnull so the interpreter's shutdown flush doesn't re-raise.
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