"""
Minimal JOSE helpers, ES256 only (port of packages/verify/src/jose.js).

ES256 is the only algorithm devicebasedauth.org signs with, so there is no algorithm
negotiation to get wrong: anything that is not ES256 with a 64-byte raw ``r‖s`` signature is
rejected before any key is touched.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from ._js import utf8

_B64U = re.compile(r"[A-Za-z0-9_-]*", re.ASCII)
_ES256 = ec.ECDSA(hashes.SHA256())


def b64u(data) -> str:
    """Encode bytes (or a string, as UTF-8) as unpadded base64url."""
    raw = utf8(data) if isinstance(data, str) else bytes(data)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64u(value) -> bytes:
    """Decode unpadded base64url; raises ValueError on anything else (padding included)."""
    if not isinstance(value, str) or not _B64U.fullmatch(value):
        raise ValueError("invalid base64url")
    try:
        return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except Exception as error:  # binascii.Error: a length of 4n+1 is never valid
        raise ValueError("invalid base64url") from error


def _reject_constant(name):
    raise ValueError(f"{name} is not JSON")


def parse_json(data):
    """``JSON.parse`` of bytes the way ``TextDecoder`` + ``JSON.parse`` see them.

    A leading BOM is dropped and invalid UTF-8 becomes U+FFFD (TextDecoder is not fatal), and
    NaN/Infinity, which Python's json accepts but JSON does not, are rejected.
    """
    text = data.decode("utf-8-sig", "replace") if isinstance(data, (bytes, bytearray)) else data
    return json.loads(text, parse_constant=_reject_constant)


def unb64u_json(value):
    """Decode base64url JSON."""
    return parse_json(unb64u(value))


def stringify(value) -> str:
    """``JSON.stringify`` for the JSON values this library signs or hashes."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def sha256_b64u(value) -> str:
    """SHA-256 of a string (UTF-8) or bytes, base64url encoded."""
    return b64u(hashlib.sha256(utf8(value) if isinstance(value, str) else bytes(value)).digest())


def public_jwk(jwk) -> dict:
    """Keep only the public members of a P-256 JWK, in a fixed order."""
    if (not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256"
            or not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str)):
        raise ValueError("expected a P-256 public JWK")
    return {"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"]}


def jwk_thumbprint(jwk) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url): required members in lexicographic order."""
    key = public_jwk(jwk)
    return sha256_b64u(stringify({"crv": key["crv"], "kty": key["kty"], "x": key["x"], "y": key["y"]}))


def _coordinate(value) -> int:
    raw = unb64u(value)
    # WebCrypto refuses P-256 coordinates that are not exactly 32 bytes; so do we.
    if len(raw) != 32:
        raise ValueError("P-256 coordinates must be 32 bytes")
    return int.from_bytes(raw, "big")


def import_public_key(jwk) -> ec.EllipticCurvePublicKey:
    """Import a P-256 public JWK. Raises ValueError for malformed keys or points off the curve."""
    key = public_jwk(jwk)
    return ec.EllipticCurvePublicNumbers(_coordinate(key["x"]), _coordinate(key["y"]), ec.SECP256R1()).public_key()


def import_private_key(jwk) -> ec.EllipticCurvePrivateKey:
    """Import a P-256 private JWK (with ``d``) for signing."""
    if not isinstance(jwk, dict) or not isinstance(jwk.get("d"), str):
        raise ValueError("expected a P-256 private JWK")
    public_jwk(jwk)
    return ec.derive_private_key(_coordinate(jwk["d"]), ec.SECP256R1())


def export_public_jwk(key) -> dict:
    """The public JWK of a private or public P-256 key."""
    public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    numbers = public.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(numbers.x.to_bytes(32, "big")), "y": b64u(numbers.y.to_bytes(32, "big"))}


def generate_key_pair() -> ec.EllipticCurvePrivateKey:
    """Generate a P-256 key. A device keeps it; only the public JWK ever leaves the device."""
    return ec.generate_private_key(ec.SECP256R1())


def sign_jws(header: dict, payload: dict, private_key: ec.EllipticCurvePrivateKey) -> str:
    """Sign a compact JWS with ES256 (raw r‖s signature, as JOSE requires; not DER)."""
    signing_input = f"{b64u(stringify({**header, 'alg': 'ES256'}))}.{b64u(stringify(payload))}"
    r, s = decode_dss_signature(private_key.sign(signing_input.encode("ascii"), _ES256))
    return f"{signing_input}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def decode_jws(jws) -> dict:
    """
    Split and decode a compact JWS without verifying it. Use this to read a credential; never
    trust what it says until verify_jws succeeds. Returns {header, payload, signature,
    signing_input}; raises ValueError('invalid_format').
    """
    if not isinstance(jws, str) or len(jws) > 65536:
        raise ValueError("invalid_format")
    parts = jws.split(".")
    if len(parts) != 3:
        raise ValueError("invalid_format")
    try:
        header = unb64u_json(parts[0])
        payload = unb64u_json(parts[1])
        signature = unb64u(parts[2])
    except Exception as error:
        raise ValueError("invalid_format") from error
    # As in JS, the header may be any object (an array included); the payload must be a plain object.
    if not isinstance(header, (dict, list)) or not isinstance(payload, dict):
        raise ValueError("invalid_format")
    return {"header": header, "payload": payload, "signature": signature, "signing_input": f"{parts[0]}.{parts[1]}"}


def verify_jws(jws, key):
    """
    Verify a compact JWS against a public key (cryptography key or JWK dict).
    Returns the decoded parts, or None when it does not verify. A JWK that cannot be imported
    raises ValueError, as WebCrypto's importKey throws in the JS.
    """
    try:
        decoded = decode_jws(jws)
    except ValueError:
        return None
    header = decoded["header"]
    if not isinstance(header, dict) or header.get("alg") != "ES256" or len(decoded["signature"]) != 64:
        return None
    public = key if isinstance(key, ec.EllipticCurvePublicKey) else import_public_key(key)
    signature = decoded["signature"]
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        public.verify(der, decoded["signing_input"].encode("ascii"), _ES256)
    except InvalidSignature:
        return None
    return decoded
