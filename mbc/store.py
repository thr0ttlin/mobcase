"""mbc.store: shared store-listing model and renderer.

Play (google-play-scraper) and the App Store (iTunes Lookup) return different
shapes; each fetcher maps into this one StoreApp so the --json contract and the
human view are identical across platforms.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import ui


@dataclass
class StoreApp:
    store: str                       # "play" | "appstore"
    identifier: str
    title: Optional[str] = None
    developer: Optional[str] = None
    version: Optional[str] = None
    released: Optional[str] = None
    updated: Optional[str] = None
    size: Optional[str] = None
    score: Optional[float] = None
    ratings: Optional[int] = None
    installs: Optional[str] = None   # Play only
    price: Optional[str] = None
    genre: Optional[str] = None
    content_rating: Optional[str] = None
    min_os: Optional[str] = None
    privacy_policy: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None


def human_size(num_bytes) -> Optional[str]:
    try:
        n = float(num_bytes)
    except (TypeError, ValueError):
        return None
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return None


def to_report(app: StoreApp) -> ui.Report:
    rep = ui.Report(title=app.title or app.identifier)

    def kv_add(block, label, value):
        if value is not None and value != "":
            block.add(label, value)

    basic = rep.section("Store").kv()
    kv_add(basic, "Store", "Google Play" if app.store == "play" else "App Store")
    kv_add(basic, "ID", app.identifier)
    kv_add(basic, "Title", app.title)
    kv_add(basic, "Developer", app.developer)
    kv_add(basic, "Version", app.version)
    kv_add(basic, "Price", app.price)

    stats = rep.section("Stats", hide_if_empty=True).kv()
    kv_add(stats, "Rating", f"{app.score} ({app.ratings} ratings)"
           if app.score is not None else None)
    kv_add(stats, "Installs", app.installs)
    kv_add(stats, "Size", app.size)
    kv_add(stats, "Released", app.released)
    kv_add(stats, "Updated", app.updated)

    meta = rep.section("Meta", hide_if_empty=True).kv()
    kv_add(meta, "Genre", app.genre)
    kv_add(meta, "Content rating", app.content_rating)
    kv_add(meta, "Min OS", app.min_os)
    kv_add(meta, "Privacy policy", app.privacy_policy)
    kv_add(meta, "URL", app.url)

    if app.summary:
        rep.section("Summary").text(app.summary)
    if app.description:
        desc = app.description.strip()
        if len(desc) > 500:
            desc = desc[:500].rstrip() + " …"
        rep.section("Description").text(desc)

    return rep


def to_search_report(results: "list[StoreApp]", term: str) -> ui.Report:
    """Compact list of matches: only the fields shown under the Store header."""
    rep = ui.Report(title=f'Search: "{term}"')
    sec = rep.section("Results")
    if not results:
        sec.text("no matches")
        return rep
    tbl = sec.table(["store", "title", "developer", "id", "version", "price"])
    for a in results:
        tbl.rows.append({
            "store": "Play" if a.store == "play" else "App Store",
            "title": a.title or "",
            "developer": a.developer or "",
            "id": a.identifier or "—",
            "version": a.version or "",
            "price": a.price or "",
        })
    return rep