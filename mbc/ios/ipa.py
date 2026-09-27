"""mbc.ios.ipa: static analysis of an iOS artifact (mirror of android.apk).

Turns an .ipa / unpacked .app / Payload directory into an IosApp dataclass
(the --json contract) and a Report (human view). No device access.

Pure stdlib: .ipa is a zip (zipfile), Info.plist is a (binary) plist
(plistlib handles both encodings). Entitlements are read from the embedded
provisioning profile by extracting the plist inside it: good enough for recon;
a cryptography-based CMS parse can replace it later without changing the model.
"""

from __future__ import annotations

import plistlib
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .. import ui
from .. import certs
from ..target import Kind, Target


# --------------------------------------------------------------------------- #
# data model  (the --json contract)
# --------------------------------------------------------------------------- #

@dataclass
class Extension:
    bundle_id: Optional[str]
    point: Optional[str]              # NSExtensionPointIdentifier
    name: Optional[str] = None


@dataclass
class Signing:
    source: str                       # "provisioning" | "code-signature"
    profile_name: Optional[str] = None
    team_ids: list[str] = field(default_factory=list)
    creation: Optional[str] = None
    expiration: Optional[str] = None
    certificates: list[certs.Certificate] = field(default_factory=list)


@dataclass
class IosApp:
    bundle_id: Optional[str]
    name: Optional[str]
    display_name: Optional[str]
    version: Optional[str]            # CFBundleShortVersionString
    build: Optional[str]             # CFBundleVersion
    min_os: Optional[str]
    executable: Optional[str]
    platforms: list[str] = field(default_factory=list)
    url_schemes: list[str] = field(default_factory=list)
    usage_descriptions: list[tuple[str, str]] = field(default_factory=list)
    entitlements: dict[str, Any] = field(default_factory=dict)
    extensions: list[Extension] = field(default_factory=list)
    signing: Optional[Signing] = None
    misconfig: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# loading  (resolve ipa/app/dir -> the .app directory)
# --------------------------------------------------------------------------- #

def _find_app_dir(root: Path) -> Optional[Path]:
    if root.suffix.lower() == ".app" and root.is_dir():
        return root
    payload = root / "Payload"
    search = payload if payload.is_dir() else root
    apps = sorted(p for p in search.iterdir() if p.suffix.lower() == ".app" and p.is_dir())
    return apps[0] if apps else None


def _load(target: Target) -> Path:
    """Return the .app directory for `target` (extracting an .ipa to temp)."""
    if target.kind == Kind.IPA:
        tmp = Path(tempfile.mkdtemp(prefix="mbc-ipa-"))
        with zipfile.ZipFile(target.path) as z:
            z.extractall(tmp)
        app = _find_app_dir(tmp)
        if app is None:
            raise ValueError(f"no Payload/*.app inside {target.raw}")
        return app

    if target.kind == Kind.DIR:
        app = _find_app_dir(target.path)
        if app is None:
            raise ValueError(f"no *.app found in directory {target.raw}")
        return app

    raise ValueError(f"not an iOS artifact: {target.raw}")


def _read_plist(path: Path) -> dict:
    with open(path, "rb") as fh:
        return plistlib.load(fh)


def _read_profile(app_dir: Path) -> dict[str, Any]:
    """Extract the XML plist payload from embedded.mobileprovision (CMS/PKCS#7).

    Good enough for recon; a cryptography-based CMS verify can replace it later
    without changing the model. Returns {} if absent or unparseable.
    """
    prof = app_dir / "embedded.mobileprovision"
    if not prof.exists():
        return {}
    blob = prof.read_bytes()
    start = blob.find(b"<plist")
    end = blob.find(b"</plist>")
    if start == -1 or end == -1:
        return {}
    try:
        data = plistlib.loads(blob[start:end + len(b"</plist>")])
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _signing_from_profile(profile: dict) -> Optional[Signing]:
    if not profile:
        return None
    devcerts: list[certs.Certificate] = []
    for der in profile.get("DeveloperCertificates", []) or []:
        try:
            devcerts.append(certs.from_der(bytes(der)))
        except Exception:
            continue

    def iso(v):
        try:
            return v.isoformat()
        except Exception:
            return str(v) if v is not None else None

    return Signing(
        source="provisioning",
        profile_name=profile.get("Name"),
        team_ids=list(profile.get("TeamIdentifier", []) or []),
        creation=iso(profile.get("CreationDate")),
        expiration=iso(profile.get("ExpirationDate")),
        certificates=devcerts,
    )


def _certs_from_cms(der: bytes) -> list[certs.Certificate]:
    from asn1crypto import cms
    out: list[certs.Certificate] = []
    seen: set[str] = set()
    try:
        signed = cms.ContentInfo.load(der)["content"]
        for choice in signed["certificates"]:
            try:
                cert = certs.from_asn1(choice.chosen)
            except Exception:
                continue
            if cert.sha256 not in seen:
                seen.add(cert.sha256)
                out.append(cert)
    except Exception:
        pass
    return out


def _signing_from_macho(cms_der: Optional[bytes]) -> Optional[Signing]:
    if not cms_der:
        return None
    chain = _certs_from_cms(cms_der)
    if not chain:
        return None
    return Signing(source="code-signature", certificates=chain)


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #

def analyze(target: Target) -> IosApp:
    app_dir = _load(target)
    info = _read_plist(app_dir / "Info.plist")

    url_schemes: set[str] = set()
    for t in info.get("CFBundleURLTypes", []) or []:
        for s in t.get("CFBundleURLSchemes", []) or []:
            url_schemes.add(s)

    usage = sorted(
        (k, str(v)) for k, v in info.items()
        if k.endswith("UsageDescription")
    )

    profile = _read_profile(app_dir)
    ent = profile.get("Entitlements", {})
    entitlements = ent if isinstance(ent, dict) else {}

    # App Store apps have no embedded.mobileprovision - fall back to the Mach-O
    # code signature for entitlements (always) and signer certs (package only).
    macho_signing = None
    if not profile:
        exe = app_dir / (info.get("CFBundleExecutable") or "")
        if exe.is_file():
            from . import macho
            ent_bytes, cms_der = macho.code_signature(exe)
            if ent_bytes and not entitlements:
                try:
                    entitlements = plistlib.loads(ent_bytes)
                except Exception:
                    pass
            macho_signing = _signing_from_macho(cms_der)

    extensions = _collect_extensions(app_dir)
    misconfig = _collect_misconfig(info, entitlements)

    # signing section only for a whole package, matching the Android rule
    signing = None
    if target.kind == Kind.IPA:
        signing = _signing_from_profile(profile) or macho_signing

    return IosApp(
        bundle_id=info.get("CFBundleIdentifier"),
        name=info.get("CFBundleName"),
        display_name=info.get("CFBundleDisplayName"),
        version=info.get("CFBundleShortVersionString"),
        build=info.get("CFBundleVersion"),
        min_os=info.get("MinimumOSVersion"),
        executable=info.get("CFBundleExecutable"),
        platforms=list(info.get("CFBundleSupportedPlatforms", []) or []),
        url_schemes=sorted(url_schemes),
        usage_descriptions=usage,
        entitlements=entitlements,
        extensions=extensions,
        signing=signing,
        misconfig=misconfig,
    )


def _collect_extensions(app_dir: Path) -> list[Extension]:
    plugins = app_dir / "PlugIns"
    if not plugins.is_dir():
        return []
    out: list[Extension] = []
    for appex in sorted(plugins.glob("*.appex")):
        info_path = appex / "Info.plist"
        if not info_path.exists():
            continue
        try:
            info = _read_plist(info_path)
        except Exception:
            continue
        point = (info.get("NSExtension", {}) or {}).get("NSExtensionPointIdentifier")
        out.append(Extension(
            bundle_id=info.get("CFBundleIdentifier"),
            point=point,
            name=info.get("CFBundleDisplayName") or info.get("CFBundleName"),
        ))
    return out


def _collect_misconfig(info: dict, entitlements: dict) -> list[str]:
    out: list[str] = []
    ats = info.get("NSAppTransportSecurity", {}) or {}
    if ats.get("NSAllowsArbitraryLoads") is True:
        out.append("NSAppTransportSecurity.NSAllowsArbitraryLoads = true")
    if entitlements.get("get-task-allow") is True:
        out.append("get-task-allow = true (debuggable)")
    return out


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def to_report(app: IosApp, *, show_all: bool = False) -> ui.Report:
    rep = ui.Report(title=app.bundle_id or "iOS app")

    basic = rep.section("Basic info").kv()
    basic.add("Bundle ID", app.bundle_id)
    basic.add("Name", app.display_name or app.name)
    basic.add("Version", f"{app.version} ({app.build})")
    basic.add("Min iOS", app.min_os)
    basic.add("Executable", app.executable)
    if app.platforms:
        basic.add("Platforms", app.platforms)

    rep.section("URL schemes", hide_if_empty=True).listing().items.extend(
        (u, []) for u in app.url_schemes
    )

    priv = rep.section("Privacy usage strings", hide_if_empty=True).listing()
    for key, purpose in app.usage_descriptions:
        priv.add(key, [purpose] if purpose else [])

    ent = rep.section("Entitlements", hide_if_empty=True)
    if app.entitlements:
        kv = ent.kv()
        for k in sorted(app.entitlements):
            kv.add(k, app.entitlements[k])

    if app.extensions:
        ext = rep.section("App extensions", hide_if_empty=True).table(
            ["bundle_id", "point", "name"])
        for e in app.extensions:
            ext.rows.append({"bundle_id": e.bundle_id or "",
                             "point": e.point or "",
                             "name": e.name or ""})

    if app.signing is not None:
        s = app.signing
        title = ("Signing (provisioning)" if s.source == "provisioning"
                 else "Signing (code signature)")
        sec = rep.section(title)
        if s.source == "provisioning":
            kv = sec.kv()
            kv.add("Profile", s.profile_name)
            kv.add("Team", ", ".join(s.team_ids))
            kv.add("Expires", s.expiration)
        lst = sec.listing()
        for c in s.certificates:
            lst.add(c.subject, [f"SHA-256: {certs.fingerprint(c.sha256)}"])

    mis = rep.section("Potential misconfiguration")
    if app.misconfig:
        mis.listing().items.extend((m, []) for m in app.misconfig)
    else:
        mis.text("none")

    return rep