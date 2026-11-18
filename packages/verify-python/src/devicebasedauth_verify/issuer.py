"""
Signing helpers for issuers and tests (port of packages/verify/src/issuer.js).

Relying parties do not need this module. It exists so tests (here and in other projects) can
mint credentials, access tokens and status lists with the test-only keys in
spec/vectors/credentials.json, exercising the same code paths as production tokens.
"""
from __future__ import annotations

import time

from .credential import ACCESS_TYP, CREDENTIAL_TYP, STATUS_LIST_TYP, validate_credential_payload
from .jose import import_private_key, public_jwk, sign_jws
from .status_list import encode_status_list


def issuer_signer(kid: str, jwk: dict) -> dict:
    """Import an issuer key (private JWK, with d) for signing: {kid, key, public_jwk}."""
    return {"kid": kid, "key": import_private_key(jwk), "public_jwk": {**public_jwk(jwk), "kid": kid, "alg": "ES256", "use": "sig"}}


def jwks_for(keys: list) -> dict:
    """Build a JWKS from issuer keys [{kid, jwk}] (public halves only)."""
    return {"keys": [{**public_jwk(k["jwk"]), "kid": k["kid"], "alg": "ES256", "use": "sig"} for k in keys]}


def sign_credential(payload: dict, signer: dict, typ: str = CREDENTIAL_TYP) -> str:
    """Sign a device credential after validating its payload."""
    problems = validate_credential_payload(payload, typ)
    if problems:
        raise ValueError(f"invalid credential: {'; '.join(problems)}")
    return sign_jws({"typ": typ, "kid": signer["kid"]}, payload, signer["key"])


def sign_access_token(payload: dict, signer: dict) -> str:
    """Sign a short-lived access token (bearer; carries the same grants, no cnf)."""
    return sign_credential(payload, signer, ACCESS_TYP)


def sign_status_list(*, uri: str, data: bytes, issuer: str, signer: dict, ttl: int = 60,
                     now: int | None = None, lifetime: int = 86400) -> str:
    """Sign a status list token for the bytes of one list."""
    now = int(time.time()) if now is None else now
    payload = {"iss": issuer, "sub": uri, "iat": now, "exp": now + lifetime, "ttl": ttl, "status_list": encode_status_list(data)}
    return sign_jws({"typ": STATUS_LIST_TYP, "kid": signer["kid"]}, payload, signer["key"])
