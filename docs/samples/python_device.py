"""A device in Python: enroll with devicebasedauth.org, then call an API with the credential.

Needs `pip install cryptography requests`.

    DBA_ORIGIN=http://localhost:8787 python3 docs/samples/python_device.py

Steps: make a P-256 key; send an enrollment request signed by it (ES256 JWS); print the approval
link for the account owner; poll until approved; then sign a DPoP proof for each request.
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ORIGIN = os.environ.get("DBA_ORIGIN", "https://devicebasedauth.org").rstrip("/")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_json(value) -> str:
    return b64u(json.dumps(value, separators=(",", ":")).encode("utf-8"))


def public_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64u(numbers.x.to_bytes(32, "big")), "y": b64u(numbers.y.to_bytes(32, "big"))}


def sign_jws(header: dict, payload: dict, key: ec.EllipticCurvePrivateKey) -> str:
    """Compact JWS with ES256. `cryptography` returns a DER signature; JOSE wants raw r || s."""
    signing_input = f"{b64u_json({**header, 'alg': 'ES256'})}.{b64u_json(payload)}"
    r, s = decode_dss_signature(key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    return f"{signing_input}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def dpop_proof(key, credential: str, method: str, url: str) -> str:
    """A single-use proof bound to this method, URL (without query) and credential (ath)."""
    htu = url.split("?", 1)[0].split("#", 1)[0]
    payload = {
        "jti": secrets.token_urlsafe(16),
        "htm": method.upper(),
        "htu": htu,
        "iat": int(time.time()),
        "ath": b64u(hashlib.sha256(credential.encode("ascii")).digest()),
    }
    return sign_jws({"typ": "dpop+jwt", "jwk": public_jwk(key)}, payload, key)


def check(response: requests.Response) -> dict:
    body = response.json()
    if not response.ok:
        sys.exit(f"{response.request.method} {response.url}: {body.get('error')} ({body.get('code')})")
    return body


def enroll(key, audiences, grants, name: str) -> str:
    request = sign_jws(
        {"typ": "dba-enroll+jwt", "jwk": public_jwk(key)},
        {"iat": int(time.time()), "aud": audiences, "grants": grants,
         "device": {"name": name, "kind": "server", "key_protection": "software"}},
        key,
    )
    start = check(requests.post(f"{ORIGIN}/api/v1/enrollments", json={"request": request}, timeout=30))
    print("Ask the account owner to approve this device:")
    print(start["approval_url"], flush=True)

    deadline = time.time() + start["expires_in"]
    interval = start["interval"]
    while time.time() < deadline:
        time.sleep(interval)
        poll = check(requests.get(start["poll_url"], timeout=30))
        if poll["status"] == "approved":
            return poll["credential"]
        if poll["status"] != "pending":
            sys.exit(f"Enrollment {poll['status']}")
        interval = poll.get("interval", interval)
    sys.exit("Gave up waiting for approval")


def main():
    # Keep this key safe (a 0600 file, a TPM, a keychain): it is what makes the credential usable.
    key = ec.generate_private_key(ec.SECP256R1())
    credential = enroll(key, ["hashbin.org"], [{"actions": ["hashbin:content:write"]}], "Python sample")
    print("Approved. Credential id:", json.loads(base64.urlsafe_b64decode(credential.split(".")[1] + "=="))["cid"])

    # Use it: devicebasedauth.org is itself a relying party, so ask it who we are.
    url = f"{ORIGIN}/api/v1/whoami"
    me = check(requests.get(url, timeout=30, headers={
        "Authorization": f"DBA {credential}",
        "DPoP": dpop_proof(key, credential, "GET", url),
    }))
    print(f"whoami: account {me['account']}, device {me['device_id']}")
    for description in me["descriptions"]:
        print(" -", description)


if __name__ == "__main__":
    main()
