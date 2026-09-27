"""mbc.ios.macho: read the Code Signing SuperBlob out of a Mach-O.

App Store apps carry no embedded.mobileprovision; their signer certificate and
entitlements live in the executable's LC_CODE_SIGNATURE (what `codesign -d`
and `ldid -e` read). This walks the Mach-O (thin or fat), finds that load
command, and returns the entitlements plist bytes and the CMS signature bytes.

Pure struct parsing; any malformed input yields (None, None) rather than raising.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional, Tuple

_MH_MAGIC = 0xFEEDFACE
_MH_MAGIC_64 = 0xFEEDFACF
_MH_CIGAM = 0xCEFAEDFE       # >I read of a little-endian 32-bit magic
_MH_CIGAM_64 = 0xCFFAEDFE    # >I read of a little-endian 64-bit magic
_FAT_MAGIC = 0xCAFEBABE
_FAT_MAGIC_64 = 0xCAFEBABF

_LC_CODE_SIGNATURE = 0x1D

_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_BLOBWRAPPER = 0xFADE0B01        # wraps the CMS signature
_CSMAGIC_ENTITLEMENTS = 0xFADE7171       # XML entitlements plist


def _first_slice(data: bytes) -> int:
    """Return the byte offset of the first Mach-O slice (0 if thin)."""
    be = struct.unpack_from(">I", data, 0)[0]
    if be in (_FAT_MAGIC, _FAT_MAGIC_64):
        if be == _FAT_MAGIC_64:
            _, _, offset, _ = struct.unpack_from(">iiQQ", data, 8)
        else:
            _, _, offset, _, _ = struct.unpack_from(">iiIII", data, 8)
        return offset
    return 0


def _slice_endian(data: bytes, base: int) -> Optional[Tuple[str, int]]:
    """Return (endian, header_size) for the Mach-O slice at `base`, or None."""
    be = struct.unpack_from(">I", data, base)[0]
    if be == _MH_MAGIC:
        return ">", 28
    if be == _MH_MAGIC_64:
        return ">", 32
    if be == _MH_CIGAM:
        return "<", 28
    if be == _MH_CIGAM_64:
        return "<", 32
    return None


def _codesig_range(data: bytes, base: int) -> Optional[Tuple[int, int]]:
    info = _slice_endian(data, base)
    if info is None:
        return None
    endian, hdr = info
    ncmds = struct.unpack_from(endian + "I", data, base + 16)[0]
    off = base + hdr
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        if cmd == _LC_CODE_SIGNATURE:
            dataoff, datasize = struct.unpack_from(endian + "II", data, off + 8)
            return dataoff, datasize
        off += cmdsize
    return None


def _parse_superblob(data: bytes, start: int) -> Tuple[Optional[bytes], Optional[bytes]]:
    magic, _length, count = struct.unpack_from(">III", data, start)
    if magic != _CSMAGIC_EMBEDDED_SIGNATURE:
        return None, None
    entitlements: Optional[bytes] = None
    signature: Optional[bytes] = None
    for i in range(count):
        _typ, off = struct.unpack_from(">II", data, start + 12 + i * 8)
        pos = start + off
        bmagic, blen = struct.unpack_from(">II", data, pos)
        if bmagic == _CSMAGIC_ENTITLEMENTS:
            entitlements = data[pos + 8:pos + blen]
        elif bmagic == _CSMAGIC_BLOBWRAPPER:
            signature = data[pos + 8:pos + blen]
    return entitlements, signature


def code_signature(path) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Return (entitlements_plist_bytes, cms_signature_bytes) for a Mach-O."""
    try:
        data = Path(path).read_bytes()
        base = _first_slice(data)
        rng = _codesig_range(data, base)
        if rng is None:
            return None, None
        dataoff, _size = rng
        return _parse_superblob(data, base + dataoff)
    except Exception:
        return None, None