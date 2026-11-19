"""
Device credentials (typ "dba-device+jwt"), short-lived access tokens (typ "dba-access+jwt") and
DPoP proofs (RFC 9449, typ "dpop+jwt"). Port of packages/verify/src/credential.js; see
spec/credential.md.
"""
from __future__ import annotations

import ipaddress
import os
import re
import time
from collections import OrderedDict

from . import _js
from ._js import get, is_safe_integer
from .grants import VOCABULARY_VERSION, validate_grants
from .status_list import MAX_STATUS_INDEX
from .jose import b64u, decode_jws, export_public_jwk, jwk_thumbprint, public_jwk, sha256_b64u, sign_jws, verify_jws

CREDENTIAL_TYP = "dba-device+jwt"
ACCESS_TYP = "dba-access+jwt"
PROOF_TYP = "dpop+jwt"
STATUS_LIST_TYP = "statuslist+jwt"
CONFIRMATION_TYP = "dba-confirmation+jwt"
DEFAULT_ISSUER = "https://devicebasedauth.org"
#: Seconds of disagreement tolerated between the issuer's, the device's and the verifier's clocks.
CLOCK_SKEW = 60
#: How old a DPoP proof may be. Short, so a captured proof is useless almost at once.
PROOF_MAX_AGE = 60

#: Codes that mean "the issuer could not be reached", not "the credential is bad".
UNAVAILABLE_CODES = ("jwks_unavailable", "status_unavailable")

_SUB = re.compile(r"dev_[A-Za-z0-9]{8,64}", re.ASCII)
_ACCT = re.compile(r"[A-Za-z0-9_-]{1,128}", re.ASCII)
_CID = re.compile(r"crd_[A-Za-z0-9]{8,64}", re.ASCII)


class VerificationError(Exception):
    """
    A verification failure with a stable machine-readable ``code`` (the same codes as the JS).

    ``status`` is the HTTP status a relying party should answer with, as the JS verifier's
    authenticateRequest maps it: 503 when the issuer was unreachable (fail closed, but tell the
    client to retry), 401 for everything wrong with the credential or proof.
    """

    def __init__(self, code: str, message: str | None = None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code

    @property
    def status(self) -> int:
        return 503 if self.code in UNAVAILABLE_CODES else 401


def inspect_credential(jws: str) -> dict:
    """Decode a credential or access token for display. Does NOT verify anything."""
    decoded = decode_jws(jws)
    return {"header": decoded["header"], "payload": decoded["payload"]}


def validate_credential_payload(payload: dict, typ: str = CREDENTIAL_TYP) -> list:
    """Structural checks shared by issuers (before signing) and verifiers (after)."""
    errors: list = []

    def string(key, pattern=None):
        value = get(payload, key)
        if not isinstance(value, str) or (pattern and not pattern.fullmatch(value)):
            errors.append(f"{key} is missing or malformed")

    string("iss"); string("sub", _SUB); string("acct", _ACCT); string("jti"); string("cid", _CID)
    for key in ("iat", "nbf", "exp"):
        if not is_safe_integer(get(payload, key)):
            errors.append(f"{key} must be a NumericDate")
    aud = get(payload, "aud")
    if not isinstance(aud, list) or len(aud) == 0 or any(not isinstance(a, str) for a in aud):
        errors.append("aud must be a list of audiences")
    exp, nbf = get(payload, "exp"), get(payload, "nbf")
    if _js.is_number(exp) and _js.is_number(nbf) and exp <= nbf:
        errors.append("exp must be after nbf")
    if not _js.strict_eq(get(payload, "ver"), VOCABULARY_VERSION):
        errors.append(f"ver must be {VOCABULARY_VERSION}")
    status = get(get(payload, "status"), "status_list")
    idx = get(status, "idx")
    if not _js.truthy(status) or not is_safe_integer(idx) or idx < 0 or idx > MAX_STATUS_INDEX or not isinstance(get(status, "uri"), str):
        errors.append("status.status_list must have idx (0 to 2^31-1) and uri")
    if typ == CREDENTIAL_TYP and not isinstance(get(get(payload, "cnf"), "jkt"), str):
        errors.append("cnf.jkt is required")
    errors.extend(validate_grants(get(payload, "grants")))
    return errors


def _now() -> int:
    return int(time.time())


def verify_credential(jws, *, jwks, issuer: str = DEFAULT_ISSUER, audience: str | None = None,
                      now: int | None = None, typ: str = "device") -> dict:
    """
    Verify a credential or access token signature and claims; returns {header, payload}.

    typ is 'device', 'access' or 'any'. audience None skips the audience check (a relying party
    must always pass its own). Revocation is checked separately (status lists, or online).
    Raises VerificationError with the JS codes: invalid_format, wrong_type, unknown_kid,
    invalid_signature, wrong_issuer, invalid_claims, wrong_audience, not_yet_valid, expired.
    """
    now = _now() if now is None else now
    try:
        decoded = decode_jws(jws)
    except ValueError:
        raise VerificationError("invalid_format", "Not a compact JWS") from None
    header, payload = decoded["header"], decoded["payload"]
    allowed = [CREDENTIAL_TYP, ACCESS_TYP] if typ == "any" else [ACCESS_TYP if typ == "access" else CREDENTIAL_TYP]
    header_typ = get(header, "typ")
    if not _js.includes(allowed, header_typ):
        raise VerificationError("wrong_type", f"Expected typ {' or '.join(allowed)}")
    kid = get(header, "kid")
    keys = get(jwks, "keys")
    # As in JS, an absent kid matches a key that has no kid (undefined === undefined).
    jwk = next((k for k in keys if _js.strict_eq(get(k, "kid"), kid)), None) if isinstance(keys, list) else None
    if jwk is None:
        raise VerificationError("unknown_kid", f"Unknown signing key {_js.to_string(kid)}")
    if not verify_jws(jws, jwk):
        raise VerificationError("invalid_signature", "Signature does not verify")
    if not _js.strict_eq(get(payload, "iss"), issuer):
        raise VerificationError("wrong_issuer", f"Issuer is not {issuer}")
    problems = validate_credential_payload(payload, header_typ)
    if problems:
        raise VerificationError("invalid_claims", "; ".join(problems))
    if audience is not None and audience not in payload["aud"]:
        raise VerificationError("wrong_audience", f"Not valid for {audience}")
    if now + CLOCK_SKEW < payload["nbf"]:
        raise VerificationError("not_yet_valid", "Credential is not valid yet")
    if now - CLOCK_SKEW >= payload["exp"]:
        raise VerificationError("expired", "Credential has expired")
    return {"header": header, "payload": payload}


def verify_confirmation(jws, *, jwks, credential: dict, issuer: str = DEFAULT_ISSUER, audience: str | None = None) -> dict:
    """
    Verify a confirmation (typ "dba-confirmation+jwt", spec/credential.md §9) for an
    already-verified credential payload: issuer signature, issuer, and the binding to the
    credential (same cid, sub and cnf.jkt). Time is not checked here: the evaluator compares
    iat/exp with its clock (pass the payload as context["confirmation"]). Returns {header, payload}.
    Raises VerificationError: invalid_format, wrong_type, unknown_kid, invalid_signature,
    wrong_issuer, invalid_claims, wrong_credential, key_mismatch, wrong_audience.
    """
    try:
        decoded = decode_jws(jws)
    except ValueError:
        raise VerificationError("invalid_format", "Confirmation is not a compact JWS") from None
    header, payload = decoded["header"], decoded["payload"]
    if not _js.strict_eq(get(header, "typ"), CONFIRMATION_TYP):
        raise VerificationError("wrong_type", f"Expected typ {CONFIRMATION_TYP}")
    kid = get(header, "kid")
    keys = get(jwks, "keys")
    jwk = next((k for k in keys if _js.strict_eq(get(k, "kid"), kid)), None) if isinstance(keys, list) else None
    if jwk is None:
        raise VerificationError("unknown_kid", f"Unknown signing key {_js.to_string(kid)}")
    if not verify_jws(jws, jwk):
        raise VerificationError("invalid_signature", "Confirmation signature does not verify")
    if not _js.strict_eq(get(payload, "iss"), issuer):
        raise VerificationError("wrong_issuer", f"Issuer is not {issuer}")
    problems = []
    if not (isinstance(get(payload, "cid"), str) and isinstance(get(payload, "sub"), str) and isinstance(get(get(payload, "cnf"), "jkt"), str)):
        problems.append("cid, sub and cnf.jkt are required")
    iat, exp = get(payload, "iat"), get(payload, "exp")
    if not (is_safe_integer(iat) and is_safe_integer(exp) and exp > iat):
        problems.append("iat and exp must be NumericDates with exp after iat")
    if not isinstance(get(payload, "by_timeout"), bool):
        problems.append("by_timeout must be true or false")
    aud = get(payload, "aud")
    if not (isinstance(aud, list) and all(isinstance(a, str) for a in aud)):
        problems.append("aud must be a list of audiences")
    if problems:
        raise VerificationError("invalid_claims", "; ".join(problems))
    if not _js.strict_eq(payload["cid"], get(credential, "cid")) or not _js.strict_eq(payload["sub"], get(credential, "sub")):
        raise VerificationError("wrong_credential", "Confirmation is for another credential")
    if not _js.strict_eq(payload["cnf"]["jkt"], get(get(credential, "cnf"), "jkt")):
        raise VerificationError("key_mismatch", "Confirmation is for another device key")
    if audience is not None and audience not in aud:
        raise VerificationError("wrong_audience", f"Confirmation is not valid for {audience}")
    return {"header": header, "payload": payload}


# --- htu: the WHATWG URL serialization `${protocol}//${host}${pathname}` -------------------------

_SPECIAL_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21, "file": None}
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):(.*)", re.ASCII | re.DOTALL)
_PATH_SAFE = frozenset(range(0x21, 0x7F)) - {0x22, 0x23, 0x3C, 0x3E, 0x3F, 0x60, 0x7B, 0x7D}
_SINGLE_DOT = (".", "%2e")
_DOUBLE_DOT = ("..", ".%2e", "%2e.", "%2e%2e")


def _encode_segment(segment: str) -> str:
    return "".join(chr(b) if b in _PATH_SAFE else f"%{b:02X}" for b in _js.utf8(segment))


def _normalize_path(path: str, special: bool) -> str:
    if special and path == "":
        return "/"
    if not path.startswith("/"):
        return _encode_segment(path)  # opaque path ("mailto:x"); JS still prints "//" before it
    segments = path[1:].split("/")
    out: list = []
    for i, segment in enumerate(segments):
        last = i == len(segments) - 1
        lowered = segment.lower()
        if lowered in _DOUBLE_DOT:
            if out:
                out.pop()
            if last:
                out.append("")
        elif lowered in _SINGLE_DOT:
            if last:
                out.append("")
        else:
            out.append(_encode_segment(segment))
    return "/" + "/".join(out)


def _normalize_host(authority: str, scheme: str, special: bool) -> str:
    authority = authority.rpartition("@")[2]  # userinfo is never part of host
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            raise ValueError("Invalid URL")
        host = "[" + ipaddress.IPv6Address(authority[1:end]).compressed + "]"
        rest = authority[end + 1:]
        if rest and not rest.startswith(":"):
            raise ValueError("Invalid URL")
        port = rest[1:] if rest else ""
    else:
        host, _, port = authority.partition(":")
        if special:
            host = host.lower()
            if not host.isascii():
                host = host.encode("idna").decode("ascii")
            if host == "" and scheme != "file":
                raise ValueError("Invalid URL")
    if port:
        if not port.isdigit() or not port.isascii() or int(port) > 65535:
            raise ValueError("Invalid URL")
        if int(port) != _SPECIAL_PORTS.get(scheme, -1):
            host = f"{host}:{int(port)}"
    return host


def htu(url: str) -> str:
    """
    Normalize a URL for a DPoP ``htu`` comparison: scheme, host and path only (RFC 9449 §4.3).

    This reproduces what JS ``new URL(url)`` prints for http(s) URLs (lower-case scheme and host,
    default port dropped, empty path as "/", dot segments resolved, unsafe path characters
    percent-encoded), so a proof made by a browser matches the URL a Python server reconstructs.
    Query and fragment are ignored, so "?a=1" never breaks a proof. Raises ValueError for URLs
    JS would reject as invalid. Exotic host forms (hex IPv4, UTS-46-only IDNs) are not mapped.
    """
    if not isinstance(url, str):
        raise ValueError("Invalid URL")
    text = re.sub(r"[\t\n\r]", "", url.strip("".join(chr(c) for c in range(0x21))))
    match = _SCHEME.fullmatch(text)
    if not match:
        raise ValueError("Invalid URL")
    scheme, rest = match.group(1).lower(), match.group(2)
    special = scheme in _SPECIAL_PORTS
    rest = re.split(r"[?#]", rest, maxsplit=1)[0]
    if special:
        rest = rest.replace("\\", "/")
        rest = rest.lstrip("/")  # special schemes ignore any number of slashes before the host
        authority, slash, path = rest.partition("/")
        path = slash + path
    elif rest.startswith("//"):
        authority, slash, path = rest[2:].partition("/")
        path = slash + path
    else:
        authority, path = "", rest
    host = _normalize_host(authority, scheme, special)
    return f"{scheme}://{host}{_normalize_path(path, special)}"


def create_proof(*, private_key, method: str, url: str, credential: str | None = None, nonce: str | None = None,
                 location: dict | None = None, now: int | None = None, jti: str | None = None) -> str:
    """
    Create a DPoP proof for one request with the device key. ``credential`` binds the proof to
    it (ath), so a proof cannot be replayed alongside a different credential.
    """
    payload = {"jti": jti or b64u(os.urandom(16)), "htm": method.upper(), "htu": htu(url), "iat": _now() if now is None else now}
    if credential:
        payload["ath"] = sha256_b64u(credential)
    if nonce:
        payload["nonce"] = nonce
    if location:
        payload["loc"] = location
    return sign_jws({"typ": PROOF_TYP, "jwk": public_jwk(export_public_jwk(private_key))}, payload, private_key)


class ReplayCache:
    """
    A small in-memory jti replay cache, per process. A proof is single-use; remembering jtis for
    longer than a proof can be accepted (2 × max age + skew) is enough to refuse every replay.
    """

    def __init__(self, ttl_seconds: int = PROOF_MAX_AGE * 2 + CLOCK_SKEW, max_entries: int = 100000):
        self.ttl = ttl_seconds
        self.max = max_entries
        self.seen: OrderedDict = OrderedDict()

    def check(self, jti: str, now: int) -> bool:
        """Returns False when the jti was already used (and records it otherwise)."""
        # Entries share one TTL, so insertion order is expiry order.
        while self.seen:
            key, expires = next(iter(self.seen.items()))
            if expires > now:
                break
            del self.seen[key]
        if jti in self.seen:
            return False
        if len(self.seen) >= self.max:
            self.seen.popitem(last=False)
        self.seen[jti] = now + self.ttl
        return True


def verify_proof(proof, *, method: str, url: str, credential: str | None = None, jkt: str | None = None,
                 now: int | None = None, nonce: str | None = None, replay=None) -> dict:
    """
    Verify a DPoP proof for a request. Returns the proof payload plus ``jkt`` (including any
    device-reported ``loc``). ``credential`` checks ath; ``jkt`` is the credential's cnf.jkt;
    ``replay`` is a ReplayCache (or anything with ``check(key, now)``).
    Raises VerificationError: invalid_proof, key_mismatch, stale_proof, use_dpop_nonce,
    replayed_proof.
    """
    now = _now() if now is None else now
    try:
        decoded = decode_jws(proof)
    except ValueError:
        raise VerificationError("invalid_proof", "DPoP proof is not a compact JWS") from None
    header, payload = decoded["header"], decoded["payload"]
    header_jwk = get(header, "jwk")
    if not _js.strict_eq(get(header, "typ"), PROOF_TYP) or not _js.strict_eq(get(header, "alg"), "ES256") or not _js.truthy(header_jwk):
        raise VerificationError("invalid_proof", "DPoP proof header must have typ dpop+jwt, alg ES256 and jwk")
    try:
        thumbprint = jwk_thumbprint(header_jwk)
    except ValueError:
        raise VerificationError("invalid_proof", "DPoP proof jwk is not a P-256 key") from None
    if jkt and thumbprint != jkt:
        raise VerificationError("key_mismatch", "DPoP proof was not signed by the credential key")
    # A jwk with the right members but no point on the curve is a bad proof (401), not a crash.
    try:
        signed = verify_jws(proof, header_jwk)
    except (ValueError, TypeError):
        signed = None
    if not signed:
        raise VerificationError("invalid_proof", "DPoP proof signature does not verify")
    if not _js.strict_eq(get(payload, "htm"), method.upper()):
        raise VerificationError("invalid_proof", "DPoP proof htm does not match the request method")
    if not _js.strict_eq(get(payload, "htu"), htu(url)):
        raise VerificationError("invalid_proof", "DPoP proof htu does not match the request URL")
    iat = get(payload, "iat")
    if not is_safe_integer(iat) or iat > now + CLOCK_SKEW or iat < now - PROOF_MAX_AGE - CLOCK_SKEW:
        raise VerificationError("stale_proof", "DPoP proof iat is outside the allowed window")
    jti = get(payload, "jti")
    if not isinstance(jti, str) or not 8 <= _js.js_len(jti) <= 128:
        raise VerificationError("invalid_proof", "DPoP proof jti is missing")
    if credential is not None and not _js.strict_eq(get(payload, "ath"), sha256_b64u(credential)):
        raise VerificationError("invalid_proof", "DPoP proof ath does not match the credential")
    if nonce is not None and not _js.strict_eq(get(payload, "nonce"), nonce):
        raise VerificationError("use_dpop_nonce", "DPoP nonce required")
    if replay is not None and not replay.check(f"{thumbprint}:{jti}", now):
        raise VerificationError("replayed_proof", "DPoP proof was already used")
    return {**payload, "jkt": thumbprint}
