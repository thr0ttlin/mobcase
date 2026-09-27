"""mbcstore: store recon by package name / bundle id / App Store id.

No device needed: pure store lookups. Platform is inferred (numeric id -> App
Store; otherwise Play first, then App Store) unless --platform is given.
Language/country default to en/us and are switchable.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error

from .. import ui

_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$")


def _looks_like_id(s: str) -> bool:
    return s.isdigit() or bool(_ID_RE.match(s))


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mbcstore",
        description="Store recon: look up by id, or search by app name.",
    )
    p.add_argument("identifier",
                   help="package/bundle id, App Store id, or an app name to search")
    p.add_argument("--platform", choices=["android", "ios"],
                   help="force store (default: infer / search both)")
    p.add_argument("-l", "--lang", default="en", help="language (default: en)")
    p.add_argument("-c", "--country", default="us", help="storefront country (default: us)")
    p.add_argument("--search", action="store_true",
                   help="force search-by-name even for a dotted term")
    p.add_argument("-n", "--limit", type=int, default=5,
                   help="max search results per store (default: 5)")
    ui.add_output_args(p)
    return p


def _fetch(identifier: str, platform: str | None, lang: str, country: str):
    """Return a StoreApp or None, trying the inferred/explicit store(s)."""
    want_ios = platform == "ios" or (platform is None and identifier.isdigit())

    if platform == "android":
        from ..android import store as play
        return play.fetch(identifier, lang=lang, country=country)
    if want_ios:
        from ..ios import store as appstore
        return appstore.fetch(identifier, lang=lang, country=country)

    from ..android import store as play
    hit = play.fetch(identifier, lang=lang, country=country)
    if hit is not None:
        return hit
    from ..ios import store as appstore
    return appstore.fetch(identifier, lang=lang, country=country)


def _search(term: str, platform: str | None, lang: str, country: str, limit: int):
    """Search by name across the requested store(s); failures in one store when
    searching both are warned, not fatal."""
    results = []
    stores = ([platform] if platform else ["android", "ios"])
    for st in stores:
        try:
            if st == "android":
                from ..android import store as play
                results += play.search(term, lang=lang, country=country, limit=limit)
            else:
                from ..ios import store as appstore
                results += appstore.search(term, lang=lang, country=country, limit=limit)
        except Exception as e:
            if platform:            # explicit store -> surface the error
                raise
            ui.console.warn(f"{st} search failed: {e}")
    if any(r.store == "play" and not r.identifier for r in results):
        ui.console.warn("Play omitted the package id for its top result "
                        "-")
    return results


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    con, fmt = ui.configure(args)

    do_search = args.search or not _looks_like_id(args.identifier)

    try:
        from .. import store as store_model
        if do_search:
            with con.spinner(f'searching "{args.identifier}"'):
                results = _search(args.identifier, args.platform,
                                  args.lang, args.country, args.limit)
            if fmt == "json":
                ui.emit(data=results, fmt="json")
            else:
                ui.emit(store_model.to_search_report(results, args.identifier),
                        fmt="text", color=args._color)
            return 0

        with con.spinner(f"looking up {args.identifier}"):
            app = _fetch(args.identifier, args.platform, args.lang, args.country)
        if app is None:
            ui.die(f"not found in store(s): {args.identifier}")
        if fmt == "json":
            ui.emit(data=app, fmt="json")
        else:
            ui.emit(store_model.to_report(app), fmt="text", color=args._color)
        return 0
    except (urllib.error.URLError, OSError, ValueError) as e:
        ui.die(f"store lookup failed: {e}")
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