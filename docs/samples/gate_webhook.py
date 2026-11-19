"""A webhook gate (STATUS B7) in Python: your own approval service.

devicebasedauth.org POSTs it a signed gate request (typ dba-gate+jwt, signed with an issuer key from
the JWKS) whenever a grant that names the gate is used. It answers at once with
{"decision": "allow" | "deny"}, or with 202 and later POSTs a JWS signed with its own key
(typ dba-gate-answer+jwt) to the request's callback. Spec: spec/events.md section 6.

    pip install cryptography requests
    DBA_ORIGIN=http://localhost:8787 python3 docs/samples/gate_webhook.py

It prints its URL and public key as one JSON line; register them as the gate:
    POST /api/v1/gates {"kind": "webhook", "label": "...", "url": URL, "public_jwk": JWK}

This sample's policy: allow hashbin:content:write at once, except resources starting "later:",
which it answers allow a second later through the callback; deny everything else.
"""
import base64
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

ORIGIN = os.environ.get("DBA_ORIGIN", "https://devicebasedauth.org").rstrip("/")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def public_key_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("expected a P-256 key")
    x = int.from_bytes(unb64u(jwk["x"]), "big")
    y = int.from_bytes(unb64u(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def verify_es256(jws: str, jwk: dict) -> bool:
    """ES256 signatures in a JWS are raw r||s (64 bytes); cryptography wants DER."""
    head, body, sig = jws.split(".")
    raw = unb64u(sig)
    if len(raw) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        public_key_from_jwk(jwk).verify(der, f"{head}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # InvalidSignature, or a malformed key
        return False


def sign_es256(header: dict, payload: dict, key: ec.EllipticCurvePrivateKey) -> str:
    signing_input = f"{b64u(json.dumps({'alg': 'ES256', **header}).encode())}.{b64u(json.dumps(payload).encode())}"
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    return f"{signing_input}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class ApprovalService:
    def __init__(self, origin: str, decide):
        self.origin = origin
        self.decide = decide
        # The key late answers are signed with. A real service keeps it (and registers its public
        # half once); this sample makes a fresh one each run.
        self.key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.public_jwk = {"kty": "EC", "crv": "P-256", "x": b64u(numbers.x.to_bytes(32, "big")), "y": b64u(numbers.y.to_bytes(32, "big"))}
        self.jwks = None
        service = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 (http.server's naming)
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode().strip()
                try:
                    request = service.verify(body)
                except ValueError as error:
                    return self.reply(400, {"error": str(error)})
                decision = service.decide(request)
                if decision == "later":
                    threading.Thread(target=service.answer_later, args=(request, "allow", 1.0), daemon=True).start()
                    return self.reply(202, None)
                return self.reply(200, {"decision": decision})

            def reply(self, status, body):
                data = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):  # keep the sample's output to what it promises
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://localhost:{self.server.server_address[1]}/dba-gate"

    def verify(self, jws: str) -> dict:
        """Check a dba-gate+jwt: issuer key from the JWKS, issuer, audience (our URL) and deadline."""
        try:
            header = json.loads(unb64u(jws.split(".")[0]))
            payload = json.loads(unb64u(jws.split(".")[1]))
        except Exception:
            raise ValueError("not a compact JWS")
        if header.get("typ") != "dba-gate+jwt" or header.get("alg") != "ES256":
            raise ValueError(f"unexpected typ {header.get('typ')}")
        if self.jwks is None:
            self.jwks = requests.get(f"{self.origin}/.well-known/jwks.json", timeout=10).json()
        key = next((k for k in self.jwks["keys"] if k.get("kid") == header.get("kid")), None)
        if key is None or not verify_es256(jws, key):
            raise ValueError("signature does not verify")
        if payload.get("iss") != self.origin:
            raise ValueError(f"unexpected issuer {payload.get('iss')}")
        if payload.get("aud") != self.url:
            raise ValueError("this request is for another service")
        if payload.get("exp", 0) < time.time():
            raise ValueError("this request is past its deadline")
        return payload

    def answer_later(self, request: dict, decision: str, delay: float = 0.0) -> dict:
        """Answer a request that got 202 by POSTing a signed answer to its callback."""
        time.sleep(delay)
        claims = {"gate": request["gate"], "request": request["request"], "entry": request["entry"], "decision": decision, "iat": int(time.time())}
        jws = sign_es256({"typ": "dba-gate-answer+jwt"}, claims, self.key)
        return requests.post(request["callback"], data=jws, headers={"Content-Type": "application/jwt"}, timeout=10).json()

    def serve_forever(self):
        self.server.serve_forever()


def policy(request: dict) -> str:
    # The device's name and the resource are someone else's text: decide on them, never run them.
    if request.get("action") == "hashbin:content:write":
        return "later" if str(request.get("resource") or "").startswith("later:") else "allow"
    return "deny"


if __name__ == "__main__":
    service = ApprovalService(ORIGIN, policy)
    print(json.dumps({"url": service.url, "public_jwk": service.public_jwk}), flush=True)
    service.serve_forever()
