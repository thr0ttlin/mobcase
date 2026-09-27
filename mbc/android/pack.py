"""mbc.android.pack: unpack / repack / sign an Android package.

Orchestrates apktool (decode/build), zipalign and apksigner. The value over
raw apktool: `repack --sign` builds, aligns and signs in one step (apktool
alone can't sign). A debug keystore is created on first use so signing is
zero-config; pass your own with --keystore.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ..transport.base import locate_tool, run_argv, ToolNotFound
from .. import ui

_BUILD_TOOLS = Path("~/Android/Sdk/build-tools").expanduser()


def _build_tool(name: str) -> str:
    """Find a build-tools binary (zipalign/apksigner) in PATH or the SDK."""
    try:
        return locate_tool(name)
    except ToolNotFound:
        cands = sorted(_BUILD_TOOLS.glob(f"*/{name}"))
        if cands:
            return str(cands[-1])
        raise ToolNotFound(f"{name} not found (install Android build-tools or add to PATH)")


def extract(path: str, out: str | None = None) -> str:
    apktool = locate_tool("apktool")
    out = out or f"{Path(path).with_suffix('')}.src"
    run_argv([apktool, "d", "-f", str(path), "-o", out]).check()
    return out


def _debug_keystore() -> tuple[str, str, str]:
    """Return (keystore, alias, password), creating a debug keystore if needed."""
    ks = Path("~/.mobcase/debug.keystore").expanduser()
    if not ks.exists():
        ks.parent.mkdir(parents=True, exist_ok=True)
        keytool = locate_tool("keytool")
        run_argv([
            keytool, "-genkeypair", "-v", "-keystore", str(ks),
            "-storepass", "android", "-keypass", "android", "-alias", "mobcase",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
            "-dname", "CN=mobcase,O=mobcase,C=US",
        ]).check()
    return str(ks), "mobcase", "android"


def sign(apk: str, out: str | None = None, keystore: str | None = None,
         alias: str = "mobcase", password: str = "android") -> str:
    apksigner = _build_tool("apksigner")
    if keystore:
        ks = keystore
    else:
        ks, alias, password = _debug_keystore()
    out = out or apk
    argv = [apksigner, "sign", "--ks", ks, "--ks-pass", f"pass:{password}",
            "--ks-key-alias", alias, "--key-pass", f"pass:{password}"]
    if str(out) != str(apk):
        argv += ["--out", str(out)]
    argv += [str(apk)]
    run_argv(argv).check()
    return str(out)


def _relax_private_resources(src_dir: str) -> int:
    """apktool-decoded resources often reference *private* framework resources,
    which aapt2 rejects at link time. Prefix every framework reference with `*`
    (@android: -> @*android:) across res/**.xml so aapt2 allows private ones;
    the star is harmless for public references. Returns the number of files
    changed."""
    res_root = Path(src_dir) / "res"
    changed = 0
    for xml in res_root.rglob("*.xml"):
        try:
            text = xml.read_text(encoding="utf-8")
        except Exception:
            continue
        if "@android:" in text:
            xml.write_text(text.replace("@android:", "@*android:"), encoding="utf-8")
            changed += 1
    return changed


def build(src_dir: str, out: str | None = None, sign_pkg: bool = False,
          keystore: str | None = None) -> str:
    apktool = locate_tool("apktool")
    zipalign = _build_tool("zipalign")
    out = out or f"{str(src_dir).rstrip('/')}.apk"

    built = str(Path(tempfile.mkdtemp(prefix="mbc-b-")) / "built.apk")

    # apktool build; if aapt2 rejects private framework resources, relax them
    # (@android: -> @*android:) once across res/ and rebuild
    relaxed = False
    while True:
        r = run_argv([apktool, "b", str(src_dir), "-o", built])
        if r.ok:
            break
        combined = (r.stdout or "") + (r.stderr or "")
        if "is private" in combined and not relaxed:
            n = _relax_private_resources(str(src_dir))
            relaxed = True
            if n:
                ui.console.verbose(f"relaxed private framework refs in {n} res file(s) "
                                   f"(@android: -> @*android:); rebuilding")
                continue
        _build_error(combined)

    aligned = str(Path(tempfile.mkdtemp(prefix="mbc-a-")) / "aligned.apk")
    run_argv([zipalign, "-f", "-p", "4", built, aligned]).check()  # align before signing

    if sign_pkg:
        return sign(aligned, out=out, keystore=keystore)
    shutil.copy(aligned, out)
    return out


def _build_error(output: str):
    from ..transport.base import TransportError
    # surface the meaningful apktool/aapt lines, not a Java stack trace
    lines = [ln for ln in output.splitlines()
             if ln.startswith(("W:", "E:", "error:", "brut.")) or "error:" in ln]
    msg = "\n".join(lines[-12:]) if lines else output.strip()[-800:]
    raise TransportError(f"apktool build failed:\n{msg}")