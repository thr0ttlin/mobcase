"""mbc.ios.store: App Store listing via the iTunes Lookup API (stdlib only).

Lookup accepts a numeric App Store id or a bundle id. `country` selects the
storefront; `lang` (e.g. fr_fr) localises the returned text: but it must be a
locale the storefront actually serves, so we fall back to the storefront
default if the combination is rejected.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from .. import ui
from ..store import StoreApp, human_size

_LOOKUP = "https://itunes.apple.com/lookup"
_SEARCH = "https://itunes.apple.com/search"


def _lookup(params: dict, timeout: float) -> dict:
    url = f"{_LOOKUP}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "mobcase/mbcstore"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def fetch(identifier: str, lang: str = "en", country: str = "us",
          timeout: float = 15.0) -> Optional[StoreApp]:
    key = "id" if identifier.isdigit() else "bundleId"
    base = {key: identifier, "country": country}

    # Try a locale-qualified lang first; if the storefront rejects the pair
    # (e.g. fr_us doesn't exist -> HTTP 400), retry with the storefront default.
    with_lang = {**base, "lang": f"{lang}_{country}".lower()}
    data = None
    for attempt, params in enumerate((with_lang, base)):
        try:
            data = _lookup(params, timeout)
            break
        except urllib.error.HTTPError as e:
            if e.code == 400 and attempt == 0:
                ui.console.warn(
                    f"lang '{lang}' not served by the '{country}' storefront  - "
                    f"showing its default language")
                continue
            raise
    if data is None:
        return None

    results = data.get("results") or []
    if not results:
        return None
    r = results[0]

    price = r.get("formattedPrice") or (
        "Free" if r.get("price") in (0, 0.0) else _as_str(r.get("price")))

    return StoreApp(
        store="appstore",
        identifier=r.get("bundleId") or identifier,
        title=r.get("trackName"),
        developer=r.get("sellerName") or r.get("artistName"),
        version=r.get("version"),
        released=r.get("releaseDate"),
        updated=r.get("currentVersionReleaseDate"),
        size=human_size(r.get("fileSizeBytes")),
        score=r.get("averageUserRating"),
        ratings=r.get("userRatingCount"),
        installs=None,                          # not exposed by the App Store
        price=price,
        genre=r.get("primaryGenreName"),
        content_rating=r.get("trackContentRating") or r.get("contentAdvisoryRating"),
        min_os=r.get("minimumOsVersion"),
        privacy_policy=None,
        summary=None,
        description=r.get("description"),
        url=r.get("trackViewUrl"),
    )


def _as_str(v) -> Optional[str]:
    return str(v) if v is not None else None


def search(term: str, lang: str = "en", country: str = "us",
           limit: int = 5, timeout: float = 15.0) -> list[StoreApp]:
    params = {"term": term, "entity": "software", "country": country, "limit": limit}
    url = f"{_SEARCH}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "mobcase/mbcstore"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))

    out: list[StoreApp] = []
    for r in data.get("results", []) or []:
        out.append(StoreApp(
            store="appstore",
            identifier=r.get("bundleId"),
            title=r.get("trackName"),
            developer=r.get("sellerName") or r.get("artistName"),
            version=r.get("version"),
            price=r.get("formattedPrice"),
            score=r.get("averageUserRating"),
            url=r.get("trackViewUrl"),
        ))
    return out