"""mbc.certs: a small, platform-agnostic X.509 view.

Both platforms need the same certificate shape: Android reads signer certs via
androguard (already asn1crypto objects); iOS reads DeveloperCertificates (DER)
from the provisioning profile. asn1crypto is a transitive dependency of
androguard, so this adds no new top-level requirement.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class Certificate:
    subject: str
    issuer: str
    serial: str
    sha1: str            # lowercase hex
    sha256: str          # lowercase hex
    not_before: Optional[str] = None
    not_after: Optional[str] = None


def _iso(node) -> Optional[str]:
    try:
        return node.native.isoformat()
    except Exception:
        return None


def from_asn1(cert) -> Certificate:
    """Build a Certificate from an asn1crypto x509.Certificate."""
    validity = cert["tbs_certificate"]["validity"]
    return Certificate(
        subject=cert.subject.human_friendly,
        issuer=cert.issuer.human_friendly,
        serial=str(cert.serial_number),
        sha1=cert.sha1.hex(),
        sha256=cert.sha256.hex(),
        not_before=_iso(validity["not_before"]),
        not_after=_iso(validity["not_after"]),
    )


def from_der(der: bytes) -> Certificate:
    """Build a Certificate from raw DER bytes."""
    from asn1crypto import x509
    return from_asn1(x509.Certificate.load(bytes(der)))


def fingerprint(hex_str: str) -> str:
    """Group a hex digest into colon-separated uppercase pairs for display."""
    return ":".join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2)).upper()


# --------------------------------------------------------------------------- #
# loading / conversion (for trust-ca, mb will be used)
# --------------------------------------------------------------------------- #

def load_from_file(path) -> "object":
    """Load an X.509 cert from a PEM or DER file -> asn1crypto x509.Certificate."""
    from asn1crypto import x509, pem
    raw = open(path, "rb").read()
    if pem.detect(raw):
        _, _, der = pem.unarmor(raw)
    else:
        der = raw
    return x509.Certificate.load(der)


def to_der(cert) -> bytes:
    return cert.dump()


def to_pem(cert) -> bytes:
    from asn1crypto import pem
    return pem.armor("CERTIFICATE", cert.dump())


def subject_hash_old(cert) -> str:
    """OpenSSL's -subject_hash_old: MD5 of the subject DER, first 4 bytes as a
    little-endian uint, 8 hex chars. Used to name Android cacerts (<hash>.0)."""
    import hashlib
    md5 = hashlib.md5(cert.subject.dump()).digest()
    val = md5[0] | (md5[1] << 8) | (md5[2] << 16) | (md5[3] << 24)
    return f"{val:08x}"