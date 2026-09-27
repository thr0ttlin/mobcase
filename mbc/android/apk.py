"""mbc.android.apk: static analysis of an Android artifact.

Accepts .apk, split bundles (.xapk/.apkm/.apks), and unpacked directories -
a raw `unzip` of an apk, or an `apktool d` decode - and produces the SAME
AndroidApp regardless of how it arrived (directory parity).

  * .apk / split / raw-unzipped dir  -> androguard (a raw unzip is re-zipped to
                                        a temp apk; its binary manifest is intact,
                                        so results match the original 1:1)
  * apktool-decoded dir              -> the text AndroidManifest.xml is parsed
                                        directly, versions/SDK from apktool.yml

Component inspector: every component carries its full intent-filter breakdown
(actions, categories, data specs) and app-level deep links are derived. PoC
`adb am` generation is intentionally NOT here - that's an active action (mbcrun).
"""

from __future__ import annotations

import re
import shlex
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:  # androguard is chatty via loguru; silence it.
    from loguru import logger as _loguru
    _loguru.disable("androguard")
except Exception:  # pragma: no cover
    pass

from androguard.core.apk import APK

try:  # androguard's import wraps stdout via colorama; undo it.
    import colorama
    colorama.deinit()
except Exception:  # pragma: no cover
    pass

from lxml import etree

from .. import ui
from .. import certs
from ..target import Kind, Target

_NS = "http://schemas.android.com/apk/res/android"
_AXML_MAGIC = b"\x03\x00\x08\x00"     # binary AndroidManifest.xml (raw unzip)
_COMPONENT_TAGS = [
    ("activity", "activity"),
    ("activity-alias", "activity-alias"),
    ("service", "service"),
    ("receiver", "receiver"),
    ("provider", "provider"),
]
_VIEW = "android.intent.action.VIEW"


# --------------------------------------------------------------------------- #
# data model  (the --json contract)
# --------------------------------------------------------------------------- #

@dataclass
class DataSpec:
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[str] = None
    path: Optional[str] = None
    path_prefix: Optional[str] = None
    path_pattern: Optional[str] = None
    mime_type: Optional[str] = None


@dataclass
class IntentFilter:
    actions: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    data: list[DataSpec] = field(default_factory=list)


@dataclass
class Component:
    kind: str
    name: str
    exported: Optional[bool]          # explicit android:exported (None = absent)
    exported_effective: bool          # what Android actually treats it as
    permission: Optional[str] = None
    authorities: Optional[str] = None
    target_activity: Optional[str] = None
    intent_filters: list[IntentFilter] = field(default_factory=list)


@dataclass
class DeepLink:
    uri: str
    component: str


@dataclass
class Signing:
    schemes: list[str] = field(default_factory=list)     # v1 / v2 / v3
    certificates: list[certs.Certificate] = field(default_factory=list)


@dataclass
class DomainConfig:
    domains: list[str] = field(default_factory=list)
    include_subdomains: bool = False
    cleartext_permitted: Optional[bool] = None
    trusts_user_ca: bool = False
    pinned: bool = False


@dataclass
class NetworkSecurity:
    source_file: Optional[str] = None
    base_cleartext_permitted: Optional[bool] = None
    base_trusts_user_ca: bool = False
    debug_overrides_trusts_user_ca: bool = False
    domains: list[DomainConfig] = field(default_factory=list)


@dataclass
class Invocation:
    """A potential invocation of an exported component, derived statically.

    `command` is the on-device part (e.g. "am start -n pkg/.Comp"): mbcrun can
    run it verbatim through the transport; mbcinfo prints it with an "adb shell"
    prefix for copy-paste. Generating this is static; running it is not.
    """
    component: str
    kind: str
    method: str          # start-explicit / deeplink / action / broadcast / provider-query
    command: str


@dataclass
class AndroidApp:
    package: str
    main_activity: Optional[str]
    version_name: Optional[str]
    version_code: Optional[int]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    permissions_used: list[str] = field(default_factory=list)
    permissions_declared: list[str] = field(default_factory=list)
    url_schemes: list[str] = field(default_factory=list)
    deep_links: list[DeepLink] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    invocations: list[Invocation] = field(default_factory=list)
    signing: Optional[Signing] = None
    network_security: Optional[NetworkSecurity] = None
    misconfig: list[str] = field(default_factory=list)

    def of_kind(self, kind: str) -> list[Component]:
        return [c for c in self.components if c.kind == kind]

    def exported(self) -> list[Component]:
        return [c for c in self.components if c.exported_effective]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _fqcn(name: Optional[str], package: str) -> Optional[str]:
    if not name:
        return name
    if name.startswith("."):
        return package + name
    if "." not in name:
        return f"{package}.{name}"
    return name


def _attr(el, a: str) -> Optional[str]:
    return el.get(f"{{{_NS}}}{a}")


def _localname(tag) -> str:
    """Tag name without namespace/prefix (NSC files use no android: namespace)."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _bool(v: Optional[str]) -> Optional[bool]:
    if v is None:
        return None
    return v.strip().lower() == "true"


def _main_from_manifest(manifest, package: str) -> Optional[str]:
    """Find the launcher component (MAIN + LAUNCHER) across <activity> AND
    <activity-alias>. androguard's get_main_activity() ignores aliases, so apps
    whose launcher is an alias (e.g. Chrome) need this."""
    if manifest is None:
        return None
    app = manifest.find("application")
    if app is None:
        return None
    for tag in ("activity", "activity-alias"):
        for el in app.findall(tag):
            for f in el.findall("intent-filter"):
                acts = {_attr(a, "name") for a in f.findall("action")}
                cats = {_attr(c, "name") for c in f.findall("category")}
                if "android.intent.action.MAIN" in acts and \
                   "android.intent.category.LAUNCHER" in cats:
                    return _fqcn(_attr(el, "name"), package)
    return None


def _as_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# source abstraction: hides where the manifest/facts come from
# --------------------------------------------------------------------------- #

class _Source:
    """Uniform view of an artifact for analyze()."""
    def package(self) -> str: ...
    def main_activity(self) -> Optional[str]: ...
    def version_name(self) -> Optional[str]: ...
    def version_code(self) -> Optional[int]: ...
    def min_sdk(self) -> Optional[int]: ...
    def target_sdk(self) -> Optional[int]: ...
    def permissions_used(self) -> list[str]: ...
    def permissions_declared(self) -> list[str]: ...
    def manifest(self): ...        # lxml <manifest> element
    def signing(self) -> Optional["Signing"]: return None
    def nsc_xml(self):             # lxml <network-security-config> element, or None
        return None


class _ApkSource(_Source):
    """Backed by androguard APK(s). For a split set, `apks` holds every apk of
    the same package: identity comes from the base, components are merged from
    all of them (dynamic-feature / Trichrome launchers live in a split)."""
    def __init__(self, apk: APK, apks: "Optional[list[APK]]" = None):
        self._apk = apk
        self._apks = apks or [apk]
        self._merged = None

    def package(self):              return self._apk.get_package()
    def main_activity(self):
        # androguard.get_main_activity() ignores <activity-alias> and only sees
        # the base apk; the merged manifest scan resolves both.
        return (self._apk.get_main_activity()
                or _main_from_manifest(self.manifest(), self.package()))
    def version_name(self):         return self._apk.get_androidversion_name()
    def version_code(self):         return _as_int(self._apk.get_androidversion_code())
    def min_sdk(self):              return _as_int(self._apk.get_min_sdk_version())
    def target_sdk(self):           return _as_int(self._apk.get_target_sdk_version())

    def permissions_used(self):
        out: set[str] = set()
        for a in self._apks:
            out.update(a.get_permissions())
        return sorted(out)

    def permissions_declared(self):
        out: set[str] = set()
        for a in self._apks:
            out.update(a.get_declared_permissions())
        return sorted(out)

    def manifest(self):
        if self._merged is not None:
            return self._merged
        base_m = self._apk.get_android_manifest_xml()
        app = base_m.find("application")
        if app is None or len(self._apks) <= 1:
            self._merged = base_m
            return base_m

        from copy import deepcopy
        comp_tags = {"activity", "activity-alias", "service", "receiver", "provider"}
        seen = {(_localname(e.tag), _attr(e, "name")) for e in list(app)}
        for extra in self._apks:
            if extra is self._apk:
                continue
            eapp = extra.get_android_manifest_xml().find("application")
            if eapp is None:
                continue
            for child in list(eapp):
                tag = _localname(child.tag)
                if tag not in comp_tags:
                    continue
                key = (tag, _attr(child, "name"))
                if key in seen:
                    continue
                seen.add(key)
                app.append(deepcopy(child))
        self._merged = base_m
        return base_m

    def signing(self) -> Optional[Signing]:
        a = self._apk
        schemes = [v for v, ok in (("v1", a.is_signed_v1()),
                                   ("v2", a.is_signed_v2()),
                                   ("v3", a.is_signed_v3())) if ok]
        seen: set[str] = set()
        chain: list[certs.Certificate] = []
        for c in a.get_certificates():
            cert = certs.from_asn1(c)
            if cert.sha256 not in seen:       # v1/v2/v3 often repeat the same cert
                seen.add(cert.sha256)
                chain.append(cert)
        return Signing(schemes=schemes, certificates=chain)

    def nsc_xml(self):
        from androguard.core.axml import AXMLPrinter
        app_el = self._apk.get_android_manifest_xml().find("application")
        ref = _attr(app_el, "networkSecurityConfig") if app_el is not None else None

        def decode(path: str):
            try:
                raw = self._apk.get_file(path)
                root = AXMLPrinter(raw).get_xml_obj()
                if root is None or not hasattr(root, "tag"):
                    return None
                return root, path
            except Exception:
                return None

        # authoritative: resolve the manifest's @xml/... reference to a file path
        if ref and ref.startswith("@"):
            try:
                rid = int(ref[1:], 16)
                arsc = self._apk.get_android_resources()
                for _cfg, value in arsc.get_resolved_res_configs(rid):
                    if isinstance(value, str) and value.endswith(".xml"):
                        got = decode(value)
                        if got:
                            return got
            except Exception:
                pass

        # fallback: scan res/xml* for a network-security-config root
        for path in self._apk.get_files():
            if not (path.startswith("res/xml") and path.endswith(".xml")):
                continue
            got = decode(path)
            if got and _localname(got[0].tag) == "network-security-config":
                return got
        return None


class _ApktoolSource(_Source):
    """Backed by an apktool-decoded directory (text manifest + apktool.yml)."""
    def __init__(self, root: Path):
        self._root = root
        self._m = etree.parse(str(root / "AndroidManifest.xml")).getroot()
        self._yml = _read_apktool_yml(root / "apktool.yml")

    def manifest(self):             return self._m
    def package(self):              return self._m.get("package") or ""

    def version_name(self):
        return self._m.get(f"{{{_NS}}}versionName") or self._yml.get("versionName")

    def version_code(self):
        return _as_int(self._m.get(f"{{{_NS}}}versionCode") or self._yml.get("versionCode"))

    def _sdk(self, attr: str, yml_key: str) -> Optional[int]:
        uses = self._m.find("uses-sdk")
        if uses is not None and _attr(uses, attr) is not None:
            return _as_int(_attr(uses, attr))
        return _as_int(self._yml.get(yml_key))

    def min_sdk(self):    return self._sdk("minSdkVersion", "minSdkVersion")
    def target_sdk(self): return self._sdk("targetSdkVersion", "targetSdkVersion")

    def permissions_used(self):
        return sorted({_attr(e, "name") for e in self._m.findall(".//uses-permission")
                       if _attr(e, "name")})

    def permissions_declared(self):
        return sorted({_attr(e, "name") for e in self._m.findall(".//permission")
                       if _attr(e, "name")})

    def main_activity(self):
        return _main_from_manifest(self._m, self.package())

    def nsc_xml(self):
        app = self._m.find("application")
        ref = _attr(app, "networkSecurityConfig") if app is not None else None

        def load(path):
            try:
                root = etree.parse(str(path)).getroot()
                if root is None or not hasattr(root, "tag"):
                    return None
                return root, str(path)
            except Exception:
                return None

        # @xml/name -> res/xml/name.xml
        if ref and ref.startswith("@xml/"):
            got = load(self._root / "res" / "xml" / f"{ref.split('/', 1)[1]}.xml")
            if got:
                return got
        # fallback: any res/xml file whose root is network-security-config
        xmldir = self._root / "res" / "xml"
        if xmldir.is_dir():
            for p in sorted(xmldir.glob("*.xml")):
                got = load(p)
                if got and _localname(got[0].tag) == "network-security-config":
                    return got
        return None


_YML_KEYS = ("minSdkVersion", "targetSdkVersion", "versionCode", "versionName")


def _read_apktool_yml(path: Path) -> dict[str, str]:
    """Minimal apktool.yml reader (avoids a YAML dependency for a few keys)."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    text = path.read_text(errors="replace")
    for key in _YML_KEYS:
        m = re.search(rf"^\s*{key}:\s*['\"]?([^'\"\n]+)['\"]?\s*$", text, re.MULTILINE)
        if m:
            out[key] = m.group(1).strip()
    return out


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #

def _is_base_apk_name(name: str) -> bool:
    low = name.lower()
    return "config." not in low and not low.startswith("split_") and "split." not in low


def _find_base_apk(apks: list[Path]) -> Optional[Path]:
    if not apks:
        return None
    for p in apks:
        if p.name.lower() in ("base.apk", "base-master.apk"):
            return p
    non_split = [p for p in apks if _is_base_apk_name(p.name)]
    return (non_split or apks)[0]


def _rezip_dir_to_apk(root: Path) -> str:
    """Re-zip a raw-unzipped apk directory into a temp .apk for androguard."""
    tmp = Path(tempfile.mkdtemp(prefix="mbc-rezip-"))
    out = tmp / "repack.apk"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for f in sorted(root.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(root))
    return str(out)


def _apk_source_from_paths(paths: list[Path]) -> _Source:
    """Load a set of apks (split bundle / dir), keep only those of the same
    package as the base, and merge their manifests. Mismatched apks are warned
    and dropped so a mixed directory can't produce a Frankenstein report."""
    pairs = [(p, APK(str(p))) for p in paths]
    base_path = _find_base_apk([p for p, _ in pairs])
    base_apk = next(a for p, a in pairs if p == base_path)
    base_pkg = base_apk.get_package()

    kept = [base_apk]
    for p, a in pairs:
        if a is base_apk:
            continue
        pkg = a.get_package()
        if pkg == base_pkg:
            kept.append(a)
        else:
            ui.console.warn(f"skipping {p.name}: package {pkg!r} != {base_pkg!r}")
    return _ApkSource(base_apk, kept)


def _load_source(target: Target) -> _Source:
    if target.kind == Kind.APK:
        return _ApkSource(APK(str(target.path)))

    if target.kind == Kind.SPLIT:
        tmp = Path(tempfile.mkdtemp(prefix="mbc-split-"))
        with zipfile.ZipFile(target.path) as z:
            z.extractall(tmp)
        apks = sorted(tmp.rglob("*.apk"))
        if not apks:
            raise ValueError(f"no .apk inside split bundle {target.raw}")
        return _apk_source_from_paths(apks)

    if target.kind == Kind.DIR:
        d = target.path
        apks = sorted(d.rglob("*.apk"))
        if apks:
            return _apk_source_from_paths(apks)
        mf = d / "AndroidManifest.xml"
        if mf.exists():
            head = mf.read_bytes()[:4]
            if head == _AXML_MAGIC:                        # raw unzip: binary manifest
                return _ApkSource(APK(_rezip_dir_to_apk(d)))
            return _ApktoolSource(d)                        # apktool: text manifest
        raise ValueError(f"no .apk or AndroidManifest.xml found in directory {target.raw}")

    raise ValueError(f"not an Android artifact: {target.raw}")


# --------------------------------------------------------------------------- #
# analysis
# --------------------------------------------------------------------------- #

def _parse_intent_filter(f) -> IntentFilter:
    data = []
    for d in f.findall("data"):
        spec = DataSpec(
            scheme=_attr(d, "scheme"), host=_attr(d, "host"), port=_attr(d, "port"),
            path=_attr(d, "path"), path_prefix=_attr(d, "pathPrefix"),
            path_pattern=_attr(d, "pathPattern"), mime_type=_attr(d, "mimeType"),
        )
        # drop values that are unresolved resource references (e.g. @7F120265)
        for k, v in list(vars(spec).items()):
            if isinstance(v, str) and v.startswith("@") and v[1:].isalnum() and any(c.isdigit() for c in v[1:]):
                setattr(spec, k, None)
        if any(vars(spec).values()):
            data.append(spec)
    return IntentFilter(
        actions=[_attr(a, "name") for a in f.findall("action") if _attr(a, "name")],
        categories=[_attr(c, "name") for c in f.findall("category") if _attr(c, "name")],
        data=data,
    )


def _uri(d: DataSpec) -> str:
    host = d.host or ""
    port = f":{d.port}" if d.port else ""
    tail = d.path or d.path_prefix or d.path_pattern or ""
    return f"{d.scheme}://{host}{port}{tail}"


def _deep_links_of(comp: Component) -> list[str]:
    """URIs a browser / other app can fire at this component (VIEW + data scheme)."""
    uris: list[str] = []
    for f in comp.intent_filters:
        if _VIEW not in f.actions:
            continue
        uris.extend(_uri(d) for d in f.data if d.scheme)
    return uris


def _component_invocations(comp: Component, package: str) -> list[Invocation]:
    """Static PoC commands for an exported component. No device access: these
    are just the command strings you *could* run (mbcrun runs them)."""
    out: list[Invocation] = []
    target = f"{package}/{comp.name}"

    def add(method: str, cmd: str) -> None:
        out.append(Invocation(comp.name, comp.kind, method, cmd))

    if comp.kind in ("activity", "activity-alias"):
        add("start-explicit", f"am start -n {target}")
        for f in comp.intent_filters:
            for d in f.data:
                if not d.scheme:
                    continue
                cmd = f"am start -a android.intent.action.VIEW -d {shlex.quote(_uri(d))}"
                if "android.intent.category.BROWSABLE" in f.categories:
                    cmd += " -c android.intent.category.BROWSABLE"
                add("deeplink", cmd)
            for a in f.actions:
                if a in ("android.intent.action.MAIN", _VIEW):
                    continue
                add("action", f"am start -a {shlex.quote(a)}")

    elif comp.kind == "service":
        add("start-service", f"am start-service -n {target}")
        for f in comp.intent_filters:
            for a in f.actions:
                add("service-action", f"am start-service -a {shlex.quote(a)}")

    elif comp.kind == "receiver":
        actions = sorted({a for f in comp.intent_filters for a in f.actions})
        if not actions:
            add("broadcast", f"am broadcast -n {target}")
        for a in actions:
            add("broadcast", f"am broadcast -n {target} -a {shlex.quote(a)}")

    elif comp.kind == "provider":
        for auth in (comp.authorities or "").split(";"):
            auth = auth.strip()
            if auth:
                add("provider-query", f"content query --uri content://{auth}/")

    return out


def analyze(target: Target) -> AndroidApp:
    src = _load_source(target)
    package = src.package()
    manifest = src.manifest()
    app_el = manifest.find("application") if manifest is not None else None

    components: list[Component] = []
    deep_links: list[DeepLink] = []
    schemes: set[str] = set()

    if app_el is not None:
        for tag, kind in _COMPONENT_TAGS:
            for el in app_el.findall(tag):
                raw = _attr(el, "exported")
                exported = None if raw is None else (raw == "true")
                filters = [_parse_intent_filter(f) for f in el.findall("intent-filter")]
                if exported is not None:
                    effective = exported
                elif kind == "provider":
                    effective = False
                else:
                    effective = len(filters) > 0

                comp = Component(
                    kind=kind,
                    name=_fqcn(_attr(el, "name"), package),
                    exported=exported,
                    exported_effective=effective,
                    permission=_attr(el, "permission"),
                    authorities=_attr(el, "authorities"),
                    target_activity=(_fqcn(_attr(el, "targetActivity"), package)
                                     if kind == "activity-alias" else None),
                    intent_filters=filters,
                )
                components.append(comp)

                for f in filters:
                    for d in f.data:
                        if d.scheme:
                            schemes.add(d.scheme)
                for uri in _deep_links_of(comp):
                    deep_links.append(DeepLink(uri=uri, component=comp.name))

    invocations = [inv for c in components if c.exported_effective
                   for inv in _component_invocations(c, package)]

    # signing only for a whole package: a directory can't faithfully carry the
    # v2/v3 signature (re-zip drops the signing block; apktool strips it).
    signing = src.signing() if target.kind in (Kind.APK, Kind.SPLIT) else None

    nsc = _parse_nsc(src.nsc_xml())

    return AndroidApp(
        package=package,
        main_activity=src.main_activity(),
        version_name=src.version_name(),
        version_code=src.version_code(),
        min_sdk=src.min_sdk(),
        target_sdk=src.target_sdk(),
        permissions_used=src.permissions_used(),
        permissions_declared=src.permissions_declared(),
        url_schemes=sorted(schemes),
        deep_links=deep_links,
        components=components,
        invocations=invocations,
        signing=signing,
        network_security=nsc,
        misconfig=_collect_misconfig(app_el, nsc, src.target_sdk()),
    )


def _parse_nsc(loaded) -> Optional[NetworkSecurity]:
    """Turn a (root, path) tuple from *.nsc_xml() into a NetworkSecurity."""
    if not loaded:
        return None
    root, path = loaded

    def trusts_user(cfg_el) -> bool:
        for ta in cfg_el.findall("trust-anchors"):
            for c in ta.findall("certificates"):
                if (c.get("src") or "").strip().lower() == "user":
                    return True
        return False

    nsc = NetworkSecurity(source_file=path)

    base = root.find("base-config")
    if base is not None:
        nsc.base_cleartext_permitted = _bool(base.get("cleartextTrafficPermitted"))
        nsc.base_trusts_user_ca = trusts_user(base)

    dbg = root.find("debug-overrides")
    if dbg is not None:
        nsc.debug_overrides_trusts_user_ca = trusts_user(dbg)

    for dc in root.findall("domain-config"):
        domains = [(d.text or "").strip() for d in dc.findall("domain") if (d.text or "").strip()]
        incl = any((d.get("includeSubdomains") or "").lower() == "true"
                   for d in dc.findall("domain"))
        nsc.domains.append(DomainConfig(
            domains=domains,
            include_subdomains=incl,
            cleartext_permitted=_bool(dc.get("cleartextTrafficPermitted")),
            trusts_user_ca=trusts_user(dc),
            pinned=dc.find("pin-set") is not None,
        ))
    return nsc


def _collect_misconfig(app_el, nsc: Optional[NetworkSecurity] = None,
                       target_sdk: Optional[int] = None) -> list[str]:
    out: list[str] = []
    if app_el is None:
        return out
    if _attr(app_el, "allowBackup") == "true":
        out.append('android:allowBackup="true"')
    if _attr(app_el, "debuggable") == "true":
        out.append('android:debuggable="true"')

    manifest_cleartext = _attr(app_el, "usesCleartextTraffic")
    if manifest_cleartext == "true":
        out.append('android:usesCleartextTraffic="true"')

    for f in app_el.findall(".//intent-filter"):
        if _attr(f, "autoVerify") == "true":
            out.append('android:autoVerify="true"')
            break

    # Network Security Config findings (the separate res/xml file)
    if nsc is not None:
        if nsc.base_cleartext_permitted:
            out.append('NSC: base-config cleartextTrafficPermitted="true"')
        if nsc.base_trusts_user_ca:
            out.append("NSC: base-config trusts user CAs")
        if nsc.debug_overrides_trusts_user_ca:
            out.append("NSC: debug-overrides trusts user CAs")
        for d in nsc.domains:
            doms = d.domains
            label = ", ".join(doms[:4]) + (f", … (+{len(doms) - 4} more)" if len(doms) > 4 else "")
            label = label or "?"
            if d.cleartext_permitted:
                out.append(f'NSC: cleartext permitted for {label}')
            if d.trusts_user_ca:
                out.append(f"NSC: trusts user CAs for {label}")
    elif (manifest_cleartext is None and target_sdk is not None and target_sdk < 28):
        # pre-9 default: cleartext allowed when neither the flag nor an NSC is set
        out.append("cleartext allowed by default (targetSdk < 28, no NSC)")

    return out


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

_KIND_TITLES = {
    "activity": "Activities",
    "activity-alias": "Activity-aliases",
    "service": "Services",
    "receiver": "Broadcast receivers",
    "provider": "Content providers",
}


def _filter_summary(f: IntentFilter) -> list[str]:
    lines = []
    if f.actions:
        lines.append("actions: " + ", ".join(a.rsplit(".", 1)[-1] for a in f.actions))
    if f.categories:
        lines.append("categories: " + ", ".join(c.rsplit(".", 1)[-1] for c in f.categories))
    for d in f.data:
        bits = []
        if d.scheme:
            host = d.host or ""
            port = f":{d.port}" if d.port else ""
            tail = d.path or d.path_prefix or d.path_pattern or ""
            bits.append(f"{d.scheme}://{host}{port}{tail}")
        if d.mime_type:
            bits.append(f"mime={d.mime_type}")
        if bits:
            lines.append("data: " + " ".join(bits))
    return lines


def to_report(app: AndroidApp, *, show_all: bool = False) -> ui.Report:
    rep = ui.Report(title=app.package)

    basic = rep.section("Basic info").kv()
    basic.add("Package", app.package)
    basic.add("MainActivity", app.main_activity)
    basic.add("Version", f"{app.version_name} ({app.version_code})")
    basic.add("Min SDK", app.min_sdk)
    basic.add("Target SDK", app.target_sdk)

    if app.signing is not None:
        sec = rep.section("Signing")
        sec.kv().add("Schemes", ", ".join(app.signing.schemes) or "unsigned")
        lst = sec.listing()
        for c in app.signing.certificates:
            lst.add(c.subject, [
                f"SHA-256: {certs.fingerprint(c.sha256)}",
                f"Serial:  {c.serial}",
                f"Valid:   {c.not_before} .. {c.not_after}",
            ])

    rep.section("Uses permissions", hide_if_empty=True).listing().items.extend(
        (p, []) for p in app.permissions_used)
    rep.section("Declared permissions", hide_if_empty=True).listing().items.extend(
        (p, []) for p in app.permissions_declared)

    dl = rep.section("Deep links", hide_if_empty=True).table(["uri", "component"])
    for d in app.deep_links:
        dl.rows.append({"uri": d.uri, "component": d.component})

    for _, kind in _COMPONENT_TAGS:
        comps = app.of_kind(kind)
        if not show_all:
            comps = [c for c in comps if c.exported_effective]
        if not comps:
            continue
        sec = rep.section(_KIND_TITLES[kind], hide_if_empty=True)
        if kind == "provider":
            cols = ["name", "exported", "authorities"]
        elif kind == "activity-alias":
            cols = ["name", "exported", "target"]
        else:
            cols = ["name", "exported", "permission"]
        tbl = sec.table(cols)
        for c in comps:
            row = {"name": c.name, "exported": c.exported_effective}
            if kind == "provider":
                row["authorities"] = c.authorities or ""
            elif kind == "activity-alias":
                row["target"] = c.target_activity or ""
            else:
                row["permission"] = c.permission or ""
            tbl.rows.append(row)

    # inspector: exported components with their intent filters
    inspected = [c for c in app.exported() if c.intent_filters]
    if inspected:
        sec = rep.section("Exposed intent filters", hide_if_empty=True).listing()
        for c in inspected:
            details: list[str] = []
            for f in c.intent_filters:
                details.extend(_filter_summary(f))
            sec.add(f"{c.name}  [{c.kind}]", details)

    # static PoC commands (generated here; executed by mbcrun): grouped by
    # component so a component's name isn't repeated on every command line
    if app.invocations:
        sec = rep.section("Suggested invocations (adb)", hide_if_empty=True).listing()
        groups: dict[str, list[Invocation]] = {}
        order: list[str] = []
        for inv in app.invocations:
            if inv.component not in groups:
                groups[inv.component] = []
                order.append(inv.component)
            groups[inv.component].append(inv)
        for comp in order:
            invs = groups[comp]
            sec.add(f"{comp}  [{invs[0].kind}]",
                    [f"adb shell {i.command}" for i in invs])

    if app.network_security is not None:
        n = app.network_security
        sec = rep.section("Network security", hide_if_empty=True)
        kv = sec.kv()
        if n.base_cleartext_permitted is not None:
            kv.add("Base cleartext", n.base_cleartext_permitted)
        kv.add("Base trusts user CAs", n.base_trusts_user_ca or None)
        kv.add("Debug-overrides user CAs", n.debug_overrides_trusts_user_ca or None)
        if n.domains:
            tbl = sec.table(["domains", "cleartext", "user CAs", "pinned"])
            for d in n.domains:
                doms = d.domains
                shown = ", ".join(doms[:4])
                if len(doms) > 4:
                    shown += f", … (+{len(doms) - 4} more)"
                tbl.rows.append({
                    "domains": shown,
                    "cleartext": "" if d.cleartext_permitted is None else d.cleartext_permitted,
                    "user CAs": d.trusts_user_ca,
                    "pinned": d.pinned,
                })

    mis = rep.section("Potential misconfiguration")
    if app.misconfig:
        mis.listing().items.extend((m, []) for m in app.misconfig)
    else:
        mis.text("none")

    return rep