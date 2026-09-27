"""mbc.ui: unified console output for the mobcase toolkit.

Design, in two rules:

1. Two channels, split by stream.
       feedback (steps, warn/error, verbose, spinner)  -> STDERR
       result   (the report / the data)                -> STDOUT
   Because feedback never touches stdout, machine use always sees a clean
   payload:  ``mbcinfo app.apk --json | jq``  ,  ``mbcdev list | grep ...``.

2. Data -> render, never print-in-place.
       A command builds a Report (ordered Sections of elements) for humans,
       and - preferably - a domain dataclass for --json. emit() dispatches:
       JSON dumps the dataclass (stable, semantic contract); text renders the
       Report in the appquick aesthetic. Human and machine views can't drift.

Zero third-party dependencies: this module is imported by every command, so
it must start instantly. Heavy renderers (rich trees, etc.) stay out of here
and are imported lazily by the few commands that actually need them.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, is_dataclass
from enum import IntEnum
from typing import Any, Iterator, Mapping

__all__ = [
    "Level", "Console", "console", "use",
    "Report", "Section", "KV", "Listing", "Table", "Text",
    "emit", "die",
    "add_output_args", "console_from_args", "fmt_from_args", "configure",
]


# --------------------------------------------------------------------------- #
# Colour / TTY
# --------------------------------------------------------------------------- #

class _C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"


def _color_for(stream: Any, override: bool | None) -> bool:
    """Resolve whether to colour *this* stream.

    override True/False forces it; None means auto: honour NO_COLOR /
    FORCE_COLOR, then fall back to whether the stream is a TTY.
    """
    if override is not None:
        return override
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", None) and stream.isatty())


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_C.RESET}" if enabled else text


# --------------------------------------------------------------------------- #
# Console  (feedback channel -> stderr)
# --------------------------------------------------------------------------- #

class Level(IntEnum):
    QUIET = 0    # errors only
    NORMAL = 1
    VERBOSE = 2


@dataclass
class Console:
    """The feedback channel. Everything here goes to stderr and is styled;
    errors are shown even in QUIET, verbose() only in VERBOSE."""

    stream: Any = None
    level: Level = Level.NORMAL
    color: bool | None = None  # tri-state; resolved against `stream`

    def __post_init__(self) -> None:
        if self.stream is None:
            self.stream = sys.stderr
        self._use_color = _color_for(self.stream, self.color)
        self._spin_pause = None

    # -- low level --------------------------------------------------------- #
    def _write(self, text: str) -> None:
        try:
            self.stream.write(text + "\n")
            self.stream.flush()
        except Exception:
            pass

    # -- feedback API ------------------------------------------------------ #
    def step(self, msg: str) -> None:
        if self.level >= Level.NORMAL:
            self._write(_paint(msg, _C.YELLOW, self._use_color))

    def info(self, msg: str) -> None:
        if self.level >= Level.NORMAL:
            self._write(msg)

    def success(self, msg: str) -> None:
        if self.level >= Level.NORMAL:
            self._write(_paint(msg, _C.GREEN, self._use_color))

    def warn(self, msg: str) -> None:
        if self.level >= Level.NORMAL:
            self._write(_paint("! " + msg, _C.YELLOW, self._use_color))

    def error(self, msg: str) -> None:
        # errors survive --quiet
        self._write(_paint("\u2717 " + msg, _C.RED, self._use_color))

    def verbose(self, msg: str) -> None:
        if self.level >= Level.VERBOSE:
            self._write(_paint(msg, _C.BLUE, self._use_color))

    # -- spinner ----------------------------------------------------------- #
    @contextmanager
    def spinner(self, label: str) -> Iterator[None]:
        """Wrap a long operation. Animates only on an interactive stderr;
        otherwise prints the label once (and nothing in --quiet)."""
        animate = (
            self.level >= Level.NORMAL
            and bool(getattr(self.stream, "isatty", None) and self.stream.isatty())
        )
        if not animate:
            if self.level >= Level.NORMAL:
                self._write(label)
            yield
            return

        stop = threading.Event()
        pause = threading.Event()
        self._spin_pause = pause

        def _run() -> None:
            frames = "-\\|/"
            i = 0
            while not stop.is_set():
                if pause.is_set():                       # yield the line to a prompt
                    self.stream.write("\r" + " " * (len(label) + 6) + "\r")
                    self.stream.flush()
                    while pause.is_set() and not stop.is_set():
                        time.sleep(0.05)
                    continue
                mark = _paint("[" + frames[i % 4] + "]", _C.YELLOW, self._use_color)
                self.stream.write(f"\r{mark} {label}")
                self.stream.flush()
                i += 1
                time.sleep(0.1)
            self.stream.write("\r" + " " * (len(label) + 6) + "\r")
            self.stream.flush()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        try:
            yield
        finally:
            stop.set()
            t.join()
            self._spin_pause = None

    def ask_password(self, prompt: str) -> str:
        """Prompt for a password without the spinner clobbering the line: pause
        any active spinner, read via getpass, then resume."""
        import getpass
        pause = getattr(self, "_spin_pause", None)
        if pause is not None:
            pause.set()
            time.sleep(0.12)          # let the spinner clear its line first
        try:
            return getpass.getpass(prompt)
        finally:
            if pause is not None:
                pause.clear()


# module-level default; commands swap it in via use()/configure()
console = Console()


def use(c: Console) -> Console:
    """Install `c` as the module-level console and return it."""
    global console
    console = c
    return c


# --------------------------------------------------------------------------- #
# Report model  (result channel -> stdout, human or json)
# --------------------------------------------------------------------------- #

@dataclass
class KV:
    """Aligned key/value block."""
    pairs: list[tuple[str, Any]] = field(default_factory=list)

    def add(self, key: str, value: Any) -> "KV":
        self.pairs.append((key, value))
        return self


@dataclass
class Listing:
    """Bulleted list; each item may carry indented detail lines."""
    items: list[tuple[str, list[str]]] = field(default_factory=list)

    def add(self, text: str, details: list[str] | None = None) -> "Listing":
        self.items.append((text, list(details or [])))
        return self


@dataclass
class Table:
    """Column-aligned rows (e.g. component | exported | permission)."""
    columns: list[str]
    rows: list[dict[str, Any]] = field(default_factory=list)

    def add(self, **row: Any) -> "Table":
        self.rows.append(row)
        return self


@dataclass
class Text:
    body: str


_Element = Any  # KV | Listing | Table | Text


@dataclass
class Section:
    title: str
    hide_if_empty: bool = False   # appquick's print_green_echo_if_not_empty
    elements: list[_Element] = field(default_factory=list)

    def kv(self) -> KV:
        el = KV(); self.elements.append(el); return el

    def listing(self) -> Listing:
        el = Listing(); self.elements.append(el); return el

    def table(self, columns: list[str]) -> Table:
        el = Table(list(columns)); self.elements.append(el); return el

    def text(self, body: str) -> "Section":
        self.elements.append(Text(body)); return self

    def is_empty(self) -> bool:
        for el in self.elements:
            if isinstance(el, KV) and el.pairs:
                return False
            if isinstance(el, Listing) and el.items:
                return False
            if isinstance(el, Table) and el.rows:
                return False
            if isinstance(el, Text) and el.body.strip():
                return False
        return True


@dataclass
class Report:
    title: str | None = None
    sections: list[Section] = field(default_factory=list)

    def section(self, title: str, hide_if_empty: bool = False) -> Section:
        s = Section(title, hide_if_empty)
        self.sections.append(s)
        return s


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def _fmt(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"   # manifest semantics: exported=true
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return str(v)


def _render_text(report: Report, out: Any, color: bool) -> None:
    def line(s: str = "") -> None:
        out.write(s + "\n")

    if report.title:
        line(_paint(report.title, _C.BOLD, color))

    first = True
    for sec in report.sections:
        if sec.hide_if_empty and sec.is_empty():
            continue
        if not first:
            line()
        first = False
        line(_paint(sec.title, _C.GREEN, color))
        for el in sec.elements:
            _render_element(el, line, color)


def _render_element(el: _Element, line: Any, color: bool) -> None:
    if isinstance(el, KV):
        width = max((len(k) for k, _ in el.pairs), default=0)
        for k, v in el.pairs:
            line(f"{(k + ':'):<{width + 1}} {_fmt(v)}")
    elif isinstance(el, Listing):
        for text, details in el.items:
            line(f"  - {text}")
            for d in details:
                line(f"      {d}")
    elif isinstance(el, Table):
        _render_table(el, line, color)
    elif isinstance(el, Text):
        for row in (el.body.splitlines() or [""]):
            line(row)


def _render_table(tbl: Table, line: Any, color: bool) -> None:
    widths = {c: len(c) for c in tbl.columns}
    cells: list[dict[str, str]] = []
    for row in tbl.rows:
        r = {c: _fmt(row.get(c, "")) for c in tbl.columns}
        cells.append(r)
        for c in tbl.columns:
            widths[c] = max(widths[c], len(r[c]))
    header = "  ".join(_paint(c.ljust(widths[c]), _C.DIM, color) for c in tbl.columns)
    line("  " + header)
    for r in cells:
        line("  " + "  ".join(r[c].ljust(widths[c]) for c in tbl.columns))


# -- JSON -------------------------------------------------------------------- #

def _jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)
    if isinstance(obj, Mapping):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return obj


def _slug(title: str) -> str:
    keep = [c.lower() if c.isalnum() else "_" for c in title.strip()]
    s = "".join(keep)
    while "__" in s:
        s = s.replace("__", "_")
    return s.strip("_") or "section"


def _report_to_dict(report: Report) -> dict[str, Any]:
    """Fallback JSON when a command hands us only a Report and no dataclass.
    Prefer passing data=<dataclass> to emit() for a stable, semantic schema."""
    out: dict[str, Any] = {}
    if report.title:
        out["title"] = report.title
    for sec in report.sections:
        block: dict[str, Any] = {}
        for el in sec.elements:
            if isinstance(el, KV):
                for k, v in el.pairs:
                    block[_slug(k)] = v
            elif isinstance(el, Listing):
                block.setdefault("items", []).extend(
                    ({"value": t, "details": d} if d else t) for t, d in el.items
                )
            elif isinstance(el, Table):
                block.setdefault("rows", []).extend(el.rows)
            elif isinstance(el, Text):
                block.setdefault("text", []).append(el.body)
        out[_slug(sec.title)] = block
    return out


# --------------------------------------------------------------------------- #
# emit : the single result sink
# --------------------------------------------------------------------------- #

def emit(
    report: Report | None = None,
    *,
    data: Any = None,
    fmt: str = "text",
    out: Any = None,
    color: bool | None = None,
) -> None:
    """Write the result to stdout.

    fmt="json": dumps `data` (a dataclass / dict: the stable contract) if
                given, else derives JSON from `report`.
    fmt="text": renders `report` in the human aesthetic.
    """
    out = out if out is not None else sys.stdout

    if fmt == "json":
        payload = data if data is not None else (
            _report_to_dict(report) if report is not None else {}
        )
        json.dump(_jsonable(payload), out, ensure_ascii=False, indent=2)
        out.write("\n")
        return

    if report is None:
        raise ValueError("text output requires a Report")
    resolved = _color_for(out, color if color is not None else console.color)
    _render_text(report, out, resolved)


def die(msg: str | None = None, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    """appquick's die(): optional red error to stderr, then exit."""
    if msg:
        console.error(msg)
    raise SystemExit(code)


# --------------------------------------------------------------------------- #
# argparse conventions  (every command gets identical output flags)
# --------------------------------------------------------------------------- #

def add_output_args(parser: Any) -> Any:
    """Attach the shared output flags: --json / -v / -q / --color / --no-color."""
    parser.add_argument(
        "--json", dest="_fmt", action="store_const", const="json", default="text",
        help="machine-readable JSON on stdout",
    )
    vq = parser.add_mutually_exclusive_group()
    vq.add_argument("-v", "--verbose", action="store_true",
                    help="verbose feedback on stderr")
    vq.add_argument("-q", "--quiet", action="store_true",
                    help="errors only on stderr")
    col = parser.add_mutually_exclusive_group()
    col.add_argument("--color", dest="_color", action="store_const", const=True,
                     default=None, help="force colour")
    col.add_argument("--no-color", dest="_color", action="store_const", const=False,
                     help="disable colour")
    return parser


def console_from_args(args: Any) -> Console:
    level = Level.NORMAL
    if getattr(args, "verbose", False):
        level = Level.VERBOSE
    if getattr(args, "quiet", False):
        level = Level.QUIET
    return Console(stream=sys.stderr, level=level, color=getattr(args, "_color", None))


def fmt_from_args(args: Any) -> str:
    return getattr(args, "_fmt", "text")


def _install_sigpipe() -> None:
    """Restore default SIGPIPE so `mbc... | head` exits quietly like a Unix tool
    instead of raising BrokenPipeError. No-op where SIGPIPE doesn't exist."""
    try:
        import signal
        if hasattr(signal, "SIGPIPE"):
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass


def configure(args: Any) -> tuple[Console, str]:
    """One-call setup: install the console from parsed args, return (console, fmt).

    Usage in a command:
        c, fmt = ui.configure(args)
        ...
        ui.emit(report, data=result, fmt=fmt)
    """
    _install_sigpipe()
    c = use(console_from_args(args))
    return c, fmt_from_args(args)


# --------------------------------------------------------------------------- #
# self-demo:  python -m mbc.ui   (add --json to see the machine view)
# --------------------------------------------------------------------------- #

def _demo() -> None:
    import argparse

    p = argparse.ArgumentParser(description="mbc.ui self-demo (mimics an mbcinfo run)")
    add_output_args(p)
    args = p.parse_args()
    c, fmt = configure(args)

    c.verbose("resolving target: com.example.app")
    with c.spinner("parsing manifest"):
        time.sleep(0.6)
    c.success("parsed 1 base.apk")

    rep = Report(title="com.example.app")

    basic = rep.section("Basic info")
    kv = basic.kv()
    kv.add("Package", "com.example.app")
    kv.add("MainActivity", ".ui.MainActivity")
    kv.add("Version", "3.14.1")
    kv.add("Min SDK", 24)
    kv.add("Target SDK", 34)

    perms = rep.section("Uses permissions")
    pl = perms.listing()
    for x in ("android.permission.INTERNET",
              "android.permission.CAMERA",
              "android.permission.READ_CONTACTS"):
        pl.add(x)

    comps = rep.section("Activities")
    t = comps.table(["name", "exported", "permission"])
    t.add(name=".ui.MainActivity", exported=True, permission="")
    t.add(name=".ui.DeepLinkActivity", exported=True,
          permission="com.example.permission.DEEP")
    t.add(name=".internal.WorkActivity", exported=False, permission="")

    schemes = rep.section("URL schemes", hide_if_empty=True)
    schemes.listing().add("myapp://open/")

    empty = rep.section("Activity-alias (exported)", hide_if_empty=True)  # stays hidden
    empty.listing()

    misconf = rep.section("Potential misconfiguration")
    misconf.listing().add('android:debuggable="true"').add('usesCleartextTraffic="true"')

    emit(rep, data=None, fmt=fmt)


if __name__ == "__main__":
    _demo()