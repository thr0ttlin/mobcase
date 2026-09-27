"""mbc.android.store: Google Play listing via google-play-scraper."""

from __future__ import annotations

import re
from typing import Optional

from .. import ui
from ..store import StoreApp


def fetch(app_id: str, lang: str = "en", country: str = "us") -> Optional[StoreApp]:
    from google_play_scraper import app as _play_app
    from google_play_scraper.exceptions import NotFoundError

    try:
        d = _play_app(app_id, lang=lang, country=country)
    except NotFoundError:
        return None

    if d.get("free") is True:
        price = "Free"
    elif d.get("price"):
        price = f"{d.get('price')} {d.get('currency') or ''}".strip()
    else:
        price = None

    return StoreApp(
        store="play",
        identifier=app_id,
        title=d.get("title"),
        developer=d.get("developer"),
        version=d.get("version"),
        released=d.get("released"),
        updated=d.get("lastUpdatedOn") or _as_str(d.get("updated")),
        size=d.get("size"),
        score=d.get("score"),
        ratings=d.get("ratings"),
        installs=d.get("installs"),
        price=price,
        genre=d.get("genre"),
        content_rating=d.get("contentRating"),
        min_os=d.get("androidVersion"),
        privacy_policy=d.get("privacyPolicy"),
        summary=d.get("summary"),
        description=d.get("description"),
        url=d.get("url") or f"https://play.google.com/store/apps/details?id={app_id}",
    )


def _as_str(v) -> Optional[str]:
    return str(v) if v is not None else None


def search(term: str, lang: str = "en", country: str = "us",
           limit: int = 5) -> list[StoreApp]:
    """Play search. Works around google-play-scraper's top-result quirk (its
    appId path is stale) by content-scanning the raw top node for a package id
    and confirming it via an app() title match: correct id or none, never wrong.
    Falls back to the stock scraper on any unexpected error."""
    try:
        hits = _search_hits(term, lang, country, limit)
    except Exception as e:
        ui.console.verbose(f"play: custom search failed ({e}); using stock scraper")
        from google_play_scraper import search as _play_search
        hits = _play_search(term, n_hits=limit, lang=lang, country=country)

    out: list[StoreApp] = []
    for d in hits:
        if d.get("free") is True:
            price = "Free"
        elif d.get("price"):
            price = f"{d.get('price')} {d.get('currency') or ''}".strip()
        else:
            price = None
        app_id = d.get("appId")
        out.append(StoreApp(
            store="play",
            identifier=app_id,
            title=d.get("title"),
            developer=d.get("developer"),
            price=price,
            score=d.get("score"),
            url=(f"https://play.google.com/store/apps/details?id={app_id}"
                 if app_id else None),
        ))
    return out


_PKG_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,}$")


def _search_hits(term: str, lang: str, country: str, limit: int) -> list[dict]:
    """Reimplementation of google_play_scraper.search that recovers the
    top-result appId. Reuses the library's own fetch primitives, so it is no
    more coupled to Google's format than the library itself."""
    import json
    from urllib.parse import quote
    from google_play_scraper.constants.element import ElementSpecs
    from google_play_scraper.constants.regex import Regex
    from google_play_scraper.constants.request import Formats
    from google_play_scraper.exceptions import NotFoundError
    from google_play_scraper.utils.request import get

    q = quote(term)
    url = Formats.Searchresults.build(query=q, lang=lang, country=country)
    try:
        dom = get(url)
    except NotFoundError:
        dom = get(Formats.Searchresults.fallback_build(query=q, lang=lang))

    dataset = {}
    for match in Regex.SCRIPT.findall(dom):
        k = Regex.KEY.findall(match)
        v = Regex.VALUE.findall(match)
        if k and v:
            dataset[k[0]] = json.loads(v[0])

    try:
        top_entry = dataset["ds:4"][0][1][0]        # whole top-result record
        top_node = top_entry[23][16]                 # field subtree the specs use
    except (IndexError, KeyError, TypeError):
        top_entry = None
        top_node = None

    cluster = None
    for idx in range(len(dataset["ds:4"][0][1])):
        try:
            cluster = dataset["ds:4"][0][1][idx][22][0]
            break
        except (IndexError, KeyError, TypeError):
            continue
    if cluster is None:
        return []

    results: list[dict] = []

    if top_node:
        top = {k: spec.extract_content(top_node)
               for k, spec in ElementSpecs.SearchResultOnTop.items()}
        if not top.get("appId"):
            top["appId"] = _recover_top_appid(top_entry, top.get("title"), lang, country)
        results.append(top)

    for i in range(min(len(cluster), limit) - len(results)):
        results.append({k: spec.extract_content(cluster[i])
                        for k, spec in ElementSpecs.SearchResult.items()})
    return results


def _recover_top_appid(node, title: Optional[str], lang: str, country: str) -> Optional[str]:
    """Scan the raw top node for package-id-looking strings and accept the first
    that app() confirms matches `title`. Returns None if nothing validates.
    Validation makes it correct-or-nothing regardless of how broad the scan is."""
    from google_play_scraper import app as _play_app
    from google_play_scraper.exceptions import NotFoundError

    seen: list[str] = []

    def walk(x):
        if isinstance(x, str):
            if _PKG_RE.match(x) and x not in seen:
                seen.append(x)
        elif isinstance(x, (list, tuple)):
            for e in x:
                walk(e)
        elif isinstance(x, dict):
            for e in x.values():
                walk(e)

    walk(node)
    ui.console.verbose(f"play top-result id recovery: {len(seen)} candidate(s): "
                       f"{', '.join(seen[:12])}")

    want = (title or "").strip().lower()
    for cand in seen[:12]:                      # bounded probes; validation filters
        try:
            info = _play_app(cand, lang=lang, country=country)
        except NotFoundError:
            continue
        except Exception:
            continue
        got = (info.get("title") or "").strip().lower()
        if not want or got == want or want in got or got in want:
            ui.console.verbose(f"play top-result id recovered: {cand}")
            return cand

    if not seen:
        import reprlib
        r = reprlib.Repr(); r.maxstring = 120; r.maxlist = 30; r.maxlevel = 6
        ui.console.verbose("play top-result: no package-id candidates in node; "
                           "raw node (truncated): " + r.repr(node)[:1500])
    else:
        ui.console.verbose("play top-result: candidates found but none matched the title")
    return None