"""
A caching verifier for relying parties (port of packages/verify/src/verifier.js).

Credentials are verified offline with the issuer's JWKS and status lists, both CDN-served and
cached here, so a request costs no round trip to devicebasedauth.org in the common case. When the
issuer cannot be reached and nothing usable is cached, verification fails closed (503), as
spec/credential.md §5 requires.

Requests are framework-neutral: anything with ``method``, ``url`` and ``headers`` (attributes or
dict keys) works, and ``Request`` is provided for convenience. Fetching is injectable: pass
``fetch(url, method=..., headers=..., body=...) -> FetchResponse``; the default uses urllib.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from . import _js
from .credential import (CLOCK_SKEW, DEFAULT_ISSUER, STATUS_LIST_TYP, ReplayCache, VerificationError,
                         verify_credential, verify_proof)
from .grants import evaluate_grants
from .jose import decode_jws, parse_json, unb64u_json, verify_jws
from .status_list import decode_status_list, get_bit

USER_AGENT = "devicebasedauth-verify-python/0.1.0"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


@dataclass
class Request:
    """A framework-neutral request. ``cf`` is Cloudflare's request.cf, when there is one."""

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    cf: Optional[dict] = None


@dataclass
class FetchResponse:
    """What an injected fetch returns: an HTTP status and the raw body."""

    status: Any
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return isinstance(self.status, int) and 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8-sig", "replace") if isinstance(self.body, (bytes, bytearray)) else str(self.body)

    def json(self):
        return parse_json(self.body)


def default_fetch(url: str, method: str = "GET", headers: Optional[dict] = None, body: Optional[bytes] = None,
                  timeout: float = 10) -> FetchResponse:
    """GET/POST with urllib. HTTP errors become responses (not exceptions), as with fetch()."""
    request = urllib.request.Request(url, data=body, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return FetchResponse(response.status, response.read(MAX_RESPONSE_BYTES))
    except urllib.error.HTTPError as error:
        return FetchResponse(error.code, error.read(MAX_RESPONSE_BYTES))


def _field(request, name, default=None):
    if isinstance(request, Mapping):
        return request.get(name, default)
    return getattr(request, name, default)


def header(request, name: str) -> Optional[str]:
    """Case-insensitive header lookup over a dict, a list of pairs or a framework headers object."""
    headers = _field(request, "headers") or {}
    items = headers.items() if hasattr(headers, "items") else headers
    lowered = name.lower()
    for key, value in items:
        if key.lower() == lowered:
            return value
    return None


def network_location(request) -> Optional[dict]:
    """Read Cloudflare's request.cf (when present) and CF-Connecting-IP into a network location."""
    cf = _field(request, "cf") or {}
    ip = header(request, "CF-Connecting-IP") or None
    country, region_code = cf.get("country"), cf.get("regionCode")
    lat = _js.to_number(cf["latitude"]) if cf.get("latitude", _js.MISSING) is not _js.MISSING else None
    lon = _js.to_number(cf["longitude"]) if cf.get("longitude", _js.MISSING) is not _js.MISSING else None
    if not _js.truthy(country) and not ip and lat is None:
        return None
    location = {"country": country, "region": f"{country}-{region_code}" if _js.truthy(country) and _js.truthy(region_code) else None,
                "lat": lat, "lon": lon, "ip": ip}
    return {k: v for k, v in location.items() if v is not None}


def credential_from_request(request) -> Optional[dict]:
    """
    Pull the credential and proof out of request headers: {kind: 'device'|'access', credential,
    proof}. Returns None for requests without a DBA credential, including other bearer tokens,
    which belong to the site's own auth.
    """
    auth = (header(request, "Authorization") or "").strip()
    space = auth.find(" ")
    scheme = auth[:space].lower() if space > 0 else ""
    value = auth[space + 1:].strip() if space > 0 else ""
    # HTTP authentication schemes are case-insensitive (RFC 9110 §11.1).
    if scheme == "dba":
        return {"kind": "device", "credential": value, "proof": header(request, "DPoP") or None}
    if scheme == "bearer":
        try:
            if _js.strict_eq(_js.get(unb64u_json(value.split(".")[0]), "typ"), "dba-access+jwt"):
                return {"kind": "access", "credential": value}
        except Exception:
            pass  # not ours
    return None


def _kid_of(jws: str):
    try:
        return _js.get(unb64u_json(jws.split(".")[0]), "kid")
    except Exception:
        return _js.MISSING


class Verifier:
    """
    Verify devicebasedauth.org credentials for one audience (your site's audience name).

    jwks_ttl / status_ttl bound how long keys and revocation lists are trusted (a status list's
    own ``ttl`` claim can shorten it further); failure_backoff stops a dead issuer being fetched
    on every request; replay=False disables the proof replay cache (not recommended).
    online_api_key enables verify_online (POST {issuer}/api/v1/authorize, metered).
    """

    def __init__(self, audience: str, *, issuer: str = DEFAULT_ISSUER, fetch: Optional[Callable[..., FetchResponse]] = None,
                 now: Optional[Callable[[], int]] = None, jwks_ttl: int = 3600, status_ttl: int = 300, replay=None,
                 failure_backoff: int = 30, accept_access_tokens: bool = True, online_api_key: Optional[str] = None):
        if not audience:
            raise ValueError("Verifier needs an audience")
        self.audience = audience
        self.issuer = issuer
        # Looked up at call time so default_fetch can be replaced (tests do).
        self._fetch = fetch or (lambda url, **kw: default_fetch(url, **kw))
        self._clock = now or (lambda: int(time.time()))
        self.jwks_ttl, self.status_ttl, self.failure_backoff = jwks_ttl, status_ttl, failure_backoff
        self.replay = None if replay is False else (replay or ReplayCache())
        self.accept_access_tokens = accept_access_tokens
        self.online_api_key = online_api_key
        self._jwks_cache: Optional[dict] = None
        self._jwks_failure: Optional[dict] = None
        self._status_cache: dict = {}
        self._status_failures: dict = {}

    def _get(self, url: str, **kw) -> FetchResponse:
        try:
            return self._fetch(url, **kw)
        except Exception as error:  # network errors are failures, never exceptions to the caller
            return FetchResponse(str(error))

    def jwks(self, force: bool = False) -> dict:
        """The issuer's JWKS, cached for jwks_ttl. A stale copy beats none while the issuer is down."""
        now = self._clock()
        if not force and self._jwks_cache and self._jwks_cache["expires"] > now:
            return self._jwks_cache["value"]
        # While the issuer is unreachable, fail fast instead of fetching on every request.
        if self._jwks_failure and self._jwks_failure["until"] > now:
            if self._jwks_cache:
                return self._jwks_cache["value"]
            raise VerificationError("jwks_unavailable", self._jwks_failure["message"])
        response = self._get(f"{self.issuer}/.well-known/jwks.json")
        if not response.ok:
            self._jwks_failure = {"until": now + self.failure_backoff, "message": f"JWKS fetch failed ({response.status})"}
            if self._jwks_cache:
                return self._jwks_cache["value"]
            raise VerificationError("jwks_unavailable", self._jwks_failure["message"])
        self._jwks_failure = None
        self._jwks_cache = {"value": response.json(), "expires": now + self.jwks_ttl}
        return self._jwks_cache["value"]

    def _status_bytes(self, uri: str) -> bytes:
        now = self._clock()
        cached = self._status_cache.get(uri)
        if cached and cached["expires"] > now:
            return cached["bytes"]
        failed = self._status_failures.get(uri)
        if failed and failed["until"] > now:
            raise VerificationError("status_unavailable", failed["message"])
        response = self._get(uri, headers={"Accept": "application/statuslist+jwt"})
        if not response.ok:
            message = f"Status list fetch failed ({response.status})"
            self._status_failures[uri] = {"until": now + self.failure_backoff, "message": message}
            raise VerificationError("status_unavailable", message)
        self._status_failures.pop(uri, None)
        jws = response.text().strip()
        keys = _js.get(self.jwks(), "keys")
        kid = _kid_of(jws)
        key = next((k for k in keys if _js.strict_eq(_js.get(k, "kid"), kid)), None) if isinstance(keys, list) else None
        try:
            decoded = verify_jws(jws, key) if key is not None else None
        except (ValueError, TypeError):
            decoded = None
        # The list must be the issuer's list for exactly this uri, or it could revoke nothing.
        if (not decoded or not _js.strict_eq(_js.get(decoded["header"], "typ"), STATUS_LIST_TYP)
                or not _js.strict_eq(decoded["payload"].get("sub"), uri) or not _js.strict_eq(decoded["payload"].get("iss"), self.issuer)):
            raise VerificationError("status_unavailable", "Status list did not verify")
        exp = decoded["payload"].get("exp")
        if _js.is_safe_integer(exp) and exp < now - CLOCK_SKEW:
            raise VerificationError("status_unavailable", "Status list has expired")
        try:
            data = decode_status_list(decoded["payload"].get("status_list"))
        except (ValueError, TypeError):
            raise VerificationError("status_unavailable", "Status list could not be decoded") from None
        ttl_claim = decoded["payload"].get("ttl")
        ttl = min(self.status_ttl, ttl_claim if _js.is_safe_integer(ttl_claim) else self.status_ttl)
        self._status_cache[uri] = {"bytes": data, "expires": now + ttl}
        return data

    def is_revoked(self, payload: dict) -> bool:
        """Is the credential revoked? Raises status_unavailable when that cannot be known."""
        status = payload["status"]["status_list"]
        return get_bit(self._status_bytes(status["uri"]), status["idx"]) == 1

    def verify(self, credential: str, typ: str = "device") -> dict:
        """Verify signature, claims and revocation; returns {header, payload}."""
        # Reject malformed input before any network fetch.
        try:
            decode_jws(credential)
        except ValueError:
            raise VerificationError("invalid_format", "Not a compact JWS") from None
        keys = self.jwks()
        try:
            result = verify_credential(credential, jwks=keys, issuer=self.issuer, audience=self.audience, now=self._clock(), typ=typ)
        except VerificationError as error:
            # A new signing key may have been published since the cache was filled.
            if error.code != "unknown_kid":
                raise
            keys = self.jwks(force=True)
            result = verify_credential(credential, jwks=keys, issuer=self.issuer, audience=self.audience, now=self._clock(), typ=typ)
        if self.is_revoked(result["payload"]):
            raise VerificationError("revoked", "Credential has been revoked")
        return result

    def authenticate_request(self, request) -> dict:
        """
        Verify a request's credential (and proof) without deciding an action yet. Returns
        {ok: True, kind, payload, proof, credential} or {ok: False, status, code, message}.
        """
        found = credential_from_request(request)
        if not found:
            return {"ok": False, "status": 401, "code": "credential_required"}
        try:
            if found["kind"] == "access" and self.accept_access_tokens is False:
                return {"ok": False, "status": 401, "code": "access_tokens_not_accepted"}
            payload = self.verify(found["credential"], typ=found["kind"])["payload"]
            proof = None
            if found["kind"] == "device":
                if not found["proof"]:
                    return {"ok": False, "status": 401, "code": "proof_required"}
                proof = verify_proof(found["proof"], method=_field(request, "method"), url=_field(request, "url"),
                                     credential=found["credential"], jkt=payload["cnf"]["jkt"], now=self._clock(), replay=self.replay)
            return {"ok": True, "kind": found["kind"], "payload": payload, "proof": proof, "credential": found["credential"]}
        except VerificationError as error:
            return {"ok": False, "status": error.status, "code": error.code, "message": error.message}

    def verify_request(self, request, action: str, resource: Optional[str] = None, location: Optional[dict] = None) -> dict:
        """
        Verify a request end to end and decide one action. Returns {allow, status, code, reasons,
        grant_index, grant, caveats, online_required, credential, device, account, credential_id}.
        status is what to answer with: 200, 401, 403 or 503.
        """
        auth = self.authenticate_request(request)
        if not auth["ok"]:
            return {"allow": False, "status": auth["status"], "code": auth["code"], "message": auth.get("message"), "reasons": []}
        return self.decide(auth["payload"], action, resource=resource, location=location, request=request, proof=auth["proof"])

    def allowed_actions(self, payload: dict, actions: list, *, request=None, proof=None, location=None) -> list:
        """Which of these actions does a verified credential allow right now (offline checks only)?"""
        return [a for a in actions if self.decide(payload, a, location=location, request=request, proof=proof)["allow"]]

    def decide(self, payload: dict, action: str, *, resource: Optional[str] = None, location: Optional[dict] = None,
               request=None, proof: Optional[dict] = None) -> dict:
        """Evaluate grants for an already-verified payload, with the verifier's clock (never the device's)."""
        location = location or {}
        network = location.get("network")
        if network is None and request is not None:
            network = network_location(request)
        device = location.get("device")
        if device is None and proof:
            device = proof.get("loc")
        context = {"now": self._clock(), "action": action, "location": {k: v for k, v in (("network", network), ("device", device)) if v is not None},
                   "online": False}
        if resource is not None:
            context["resource"] = resource
        attestation = payload.get("device", {}).get("attestation") if isinstance(payload.get("device"), dict) else None
        if attestation is not None:
            context["attestation"] = attestation
        result = evaluate_grants(payload["grants"], context)
        return {
            "allow": result["allow"], "status": 200 if result["allow"] else 403,
            "code": "ok" if result["allow"] else "online_required" if result["online_required"] else "forbidden",
            "reasons": result["reasons"], "grant_index": result["grant_index"], "grant": result.get("grant"),
            "caveats": result.get("caveats", {}), "online_required": result["online_required"],
            "credential": payload, "device": payload.get("sub"), "account": payload.get("acct"), "credential_id": payload.get("cid"),
        }

    def verify_online(self, request, action: str, resource: Optional[str] = None, location: Optional[dict] = None) -> dict:
        """
        Ask devicebasedauth.org (metered; billed to your audience account). Needed for grants with
        usage limits, step-up or require.online, and for instant revocation.
        """
        if not self.online_api_key:
            raise ValueError("verify_online needs online_api_key")
        found = credential_from_request(request)
        if not found:
            return {"allow": False, "status": 401, "code": "credential_required", "reasons": []}
        network = (location or {}).get("network") or network_location(request)
        body = {"credential": found["credential"], "proof": found.get("proof"),
                "request": {"method": _field(request, "method"), "url": _field(request, "url")},
                "audience": self.audience, "action": action, "resource": resource,
                "context": {"network": network} if network is not None else {}}
        body = {k: v for k, v in body.items() if v is not None}  # JSON.stringify drops undefined
        response = self._fetch(f"{self.issuer}/api/v1/authorize", method="POST",
                               headers={"Authorization": f"ApiKey {self.online_api_key}", "Content-Type": "application/json"},
                               body=json.dumps(body).encode("utf-8"))
        data = response.json()
        if not response.ok:
            # A 402 means *our* account is out of credit, not that the client did wrong.
            return {"allow": False, "status": 503 if response.status == 402 else response.status,
                    "code": data.get("code") if isinstance(data, dict) else None,
                    "message": data.get("error") if isinstance(data, dict) else None,
                    "reasons": []}
        return {**data, "status": 200 if data.get("allow") else 403}


def create_verifier(audience: str, **options) -> Verifier:
    """Create a Verifier (the JS createVerifier); see Verifier for the options."""
    return Verifier(audience, **options)
