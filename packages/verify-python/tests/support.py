"""Shared test setup: import the package from src/ without installing it, and load the vectors."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE_ROOT = os.path.dirname(HERE)
REPO_ROOT = os.path.dirname(os.path.dirname(PACKAGE_ROOT))
SRC = os.path.join(PACKAGE_ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)


def load_vectors(name):
    with open(os.path.join(REPO_ROOT, "spec", "vectors", name), encoding="utf-8") as handle:
        return json.load(handle)


class FakeIssuer:
    """
    An in-memory devicebasedauth.org for tests: serves a JWKS and status lists through an
    injectable fetch, signs credentials with the TEST-ONLY issuer key from credentials.json and
    proofs with the TEST-ONLY device key. Never touches the network.
    """

    ISSUER = "https://devicebasedauth.org"
    STATUS_URI = "https://devicebasedauth.org/status/v1/lists/0"

    def __init__(self, now):
        from devicebasedauth_verify import FetchResponse, import_private_key, issuer_signer, jwks_for
        vectors = load_vectors("credentials.json")
        self.now = now
        self.signer = issuer_signer("test-vectors-1", vectors["test_only_issuer_private_jwk"])
        self.jwks = jwks_for([{"kid": "test-vectors-1", "jwk": vectors["test_only_issuer_private_jwk"]}])
        self.device_key = import_private_key(vectors["test_only_device_private_jwk"])
        self.device_jkt = vectors["device_jkt"]
        self.revoked = bytearray(16)
        self.requests = []
        self.down = False
        self._response = FetchResponse

    def fetch(self, url, method="GET", headers=None, body=None):
        from devicebasedauth_verify import sign_status_list
        self.requests.append((method, url, headers, body))
        if self.down:
            raise OSError("connection refused")
        if url == f"{self.ISSUER}/.well-known/jwks.json":
            import json
            return self._response(200, json.dumps(self.jwks).encode())
        if url == self.STATUS_URI:
            jwt = sign_status_list(uri=url, data=bytes(self.revoked), issuer=self.ISSUER, signer=self.signer, now=self.now())
            return self._response(200, jwt.encode())
        return self._response(404, b'{"error":"not found","code":"not_found"}')

    def count(self, url):
        return sum(1 for r in self.requests if r[1] == url)

    def payload(self, grants=None, idx=3, **overrides):
        now = self.now()
        payload = {
            "iss": self.ISSUER, "sub": "dev_TESTDEVICE01", "acct": "acct_test", "aud": ["hashbin.org"],
            "cid": "crd_TESTCRED0001", "jti": "crd_TESTCRED0001.1", "iat": now, "nbf": now, "exp": now + 3600,
            "cnf": {"jkt": self.device_jkt}, "grants": grants or [{"actions": ["hashbin:content:write"]}],
            "status": {"status_list": {"idx": idx, "uri": self.STATUS_URI}}, "ver": 1,
        }
        payload.update(overrides)
        return payload

    def credential(self, **kw):
        from devicebasedauth_verify import sign_credential
        return sign_credential(self.payload(**kw), self.signer)

    def access_token(self, **kw):
        from devicebasedauth_verify import sign_access_token
        payload = self.payload(**kw)
        del payload["cnf"]
        return sign_access_token(payload, self.signer)

    def proof(self, method, url, credential, **kw):
        from devicebasedauth_verify import create_proof
        return create_proof(private_key=self.device_key, method=method, url=url, credential=credential, now=self.now(), **kw)

    def headers(self, method, url, credential=None, **kw):
        credential = credential or self.credential()
        return {"Authorization": f"DBA {credential}", "DPoP": self.proof(method, url, credential, **kw)}
