"""
IETF OAuth Token Status List, 1 bit per credential (port of packages/verify/src/status-list.js).

Bit ``i`` lives in byte ``floor(i / 8)`` at position ``i % 8``, least significant bit first; the
byte array is zlib-compressed (RFC 1950) and base64url encoded in the ``lst`` claim.
"""
from __future__ import annotations

import zlib

from .jose import b64u, unb64u

MAX_STATUS_LIST_BYTES = 16 * 1024 * 1024


def deflate(data: bytes) -> bytes:
    """zlib (RFC 1950) compress."""
    return zlib.compress(bytes(data))


def inflate(data: bytes, max_bytes: int = MAX_STATUS_LIST_BYTES) -> bytes:
    """
    zlib decompress, stopping as soon as the output passes max_bytes, so a tiny hostile list
    cannot expand into gigabytes. Truncated streams and trailing junk are errors, as they are
    for the JS DecompressionStream.
    """
    decompressor = zlib.decompressobj()
    try:
        out = decompressor.decompress(bytes(data), max_bytes + 1)
    except zlib.error as error:
        raise ValueError(f"invalid status list: {error}") from error
    if len(out) > max_bytes or decompressor.unconsumed_tail:
        raise ValueError("status list too large")
    if not decompressor.eof or decompressor.unused_data:
        raise ValueError("invalid status list: truncated or trailing data")
    return out


def _int32(value: int) -> int:
    # JS bitwise operators work on ToInt32(value). Mirroring that keeps every implementation
    # reading the same bit for the same idx, even for idx >= 2**31 (see the package README).
    return ((int(value) + 2**31) % 2**32) - 2**31


def get_bit(data: bytes, index: int) -> int:
    """Read one status bit (1 = revoked). Indexes beyond the list are 0 (valid)."""
    i = _int32(index)
    byte_index = i >> 3
    if byte_index < 0 or byte_index >= len(data):
        return 0
    return (data[byte_index] >> (i & 7)) & 1


def set_bit(data, index: int, value: int = 1) -> bytearray:
    """Set one status bit, growing the array when needed. Returns the (possibly new) array."""
    out = bytearray(data)
    if (index >> 3) >= len(out):
        out.extend(bytes(max((index >> 3) + 1, len(out) * 2) - len(out)))
    if value:
        out[index >> 3] |= 1 << (index & 7)
    else:
        out[index >> 3] &= ~(1 << (index & 7)) & 0xFF
    return out


def encode_status_list(data: bytes) -> dict:
    """Encode bytes as a status_list claim."""
    return {"bits": 1, "lst": b64u(deflate(data))}


def decode_status_list(claim) -> bytes:
    """Decode a status_list claim to bytes. Only 1-bit lists are supported."""
    if not isinstance(claim, dict) or claim.get("bits") != 1 or isinstance(claim.get("bits"), bool) or not isinstance(claim.get("lst"), str):
        raise ValueError("unsupported status list")
    return inflate(unb64u(claim["lst"]))
