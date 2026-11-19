"""The caching Verifier, end to end against an in-memory issuer (injected fetch, no network)."""
import json
import unittest

try:
    from . import support
except ImportError:
    import support

from devicebasedauth_verify import FetchResponse, Request, create_verifier, credential_from_request, network_location

URL = "https://hashbin.org/api/content"
JWKS_URL = "https://devicebasedauth.org/.well-known/jwks.json"


class Clock:
    def __init__(self, t=1795017600):
        self.t = t

    def __call__(self):
        return self.t


class VerifierTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.issuer = support.FakeIssuer(self.clock)
        self.verifier = create_verifier("hashbin.org", fetch=self.issuer.fetch, now=self.clock)

    def request(self, method="POST", url=URL, **kw):
        return Request(method, url, self.issuer.headers(method, url, **kw))

    def test_allows_a_granted_action(self):
        result = self.verifier.verify_request(self.request(), action="hashbin:content:write", resource="doc-1")
        self.assertTrue(result["allow"])
        self.assertEqual((result["status"], result["code"], result["grant_index"]), (200, "ok", 0))
        self.assertEqual((result["account"], result["device"], result["credential_id"]), ("acct_test", "dev_TESTDEVICE01", "crd_TESTCRED0001"))

    def test_denies_an_action_not_granted(self):
        result = self.verifier.verify_request(self.request(), action="hashbin:content:delete")
        self.assertEqual((result["allow"], result["status"], result["code"]), (False, 403, "forbidden"))
        self.assertEqual(result["reasons"], [["action_not_granted"]])

    def test_online_only_grant_reports_online_required(self):
        credential = self.issuer.credential(grants=[{"actions": ["hashbin:content:write"], "require": {"step_up": True}}])
        result = self.verifier.verify_request(self.request(credential=credential), action="hashbin:content:write")
        self.assertEqual((result["allow"], result["code"], result["online_required"]), (False, "online_required", True))

    def test_spend_cap_is_returned_as_a_caveat(self):
        credential = self.issuer.credential(grants=[{"actions": ["hashbin:*"], "limits": {"spend_usd_per_month": 5}}])
        result = self.verifier.verify_request(self.request(credential=credential), action="hashbin:content:write")
        self.assertEqual(result["caveats"], {"spend_usd_per_month": 5})

    def test_revoked_credential(self):
        self.issuer.revoked[0] = 1 << 3  # idx 3
        result = self.verifier.verify_request(self.request(), action="hashbin:content:write")
        self.assertEqual((result["status"], result["code"]), (401, "revoked"))

    def test_replayed_proof_is_refused(self):
        request = self.request()
        self.assertTrue(self.verifier.verify_request(request, action="hashbin:content:write")["allow"])
        again = self.verifier.verify_request(request, action="hashbin:content:write")
        self.assertEqual((again["status"], again["code"]), (401, "replayed_proof"))

    def test_proof_for_another_url_or_method(self):
        headers = self.issuer.headers("POST", URL)
        self.assertEqual(self.verifier.verify_request(Request("POST", URL + "/x", headers), action="hashbin:content:write")["code"], "invalid_proof")
        headers = self.issuer.headers("POST", URL)
        self.assertEqual(self.verifier.verify_request(Request("PUT", URL, headers), action="hashbin:content:write")["code"], "invalid_proof")

    def test_query_string_does_not_break_the_proof(self):
        headers = self.issuer.headers("GET", URL)
        result = self.verifier.verify_request(Request("GET", URL + "?page=2", headers), action="hashbin:content:write")
        self.assertTrue(result["allow"])

    def test_missing_credential_and_missing_proof(self):
        self.assertEqual(self.verifier.verify_request(Request("GET", URL, {}), action="x:y")["code"], "credential_required")
        bare = {"Authorization": f"DBA {self.issuer.credential()}"}
        self.assertEqual(self.verifier.verify_request(Request("GET", URL, bare), action="x:y")["code"], "proof_required")

    def test_other_bearer_tokens_are_not_claimed(self):
        self.assertIsNone(credential_from_request(Request("GET", URL, {"Authorization": "Bearer abc.def.ghi"})))
        self.assertEqual(self.issuer.requests, [])

    def test_access_tokens(self):
        token = self.issuer.access_token()
        request = Request("GET", URL, {"authorization": f"bearer {token}"})  # schemes and header names are case-insensitive
        self.assertTrue(self.verifier.verify_request(request, action="hashbin:content:write")["allow"])
        strict = create_verifier("hashbin.org", fetch=self.issuer.fetch, now=self.clock, accept_access_tokens=False)
        self.assertEqual(strict.verify_request(request, action="hashbin:content:write")["code"], "access_tokens_not_accepted")

    def test_wrong_audience(self):
        other = create_verifier("cronly.org", fetch=self.issuer.fetch, now=self.clock)
        self.assertEqual(other.verify_request(self.request(), action="hashbin:content:write")["code"], "wrong_audience")

    def test_malformed_credential_is_rejected_before_fetching(self):
        result = self.verifier.verify_request(Request("GET", URL, {"Authorization": "DBA not-a-jws", "DPoP": "x"}), action="x:y")
        self.assertEqual(result["code"], "invalid_format")
        self.assertEqual(self.issuer.requests, [])

    def test_jwks_and_status_list_are_cached_with_ttls(self):
        for _ in range(3):
            self.assertTrue(self.verifier.verify_request(self.request(), action="hashbin:content:write")["allow"])
        self.assertEqual((self.issuer.count(JWKS_URL), self.issuer.count(self.issuer.STATUS_URI)), (1, 1))
        self.clock.t += 61  # the list's own ttl claim (60 s) is shorter than status_ttl (300 s)
        self.verifier.verify_request(self.request(), action="hashbin:content:write")
        self.assertEqual((self.issuer.count(JWKS_URL), self.issuer.count(self.issuer.STATUS_URI)), (1, 2))
        self.clock.t += 3600
        self.verifier.verify_request(self.request(), action="hashbin:content:write")
        self.assertEqual(self.issuer.count(JWKS_URL), 2)

    def test_status_list_must_be_for_the_credentials_uri(self):
        def fetch(url, **kw):
            if url == "https://devicebasedauth.org/status/v1/lists/1":
                return self.issuer.fetch(self.issuer.STATUS_URI, **kw)  # a valid list, but for another uri
            return self.issuer.fetch(url, **kw)
        verifier = create_verifier("hashbin.org", fetch=fetch, now=self.clock)
        credential = self.issuer.credential(status={"status_list": {"idx": 3, "uri": "https://devicebasedauth.org/status/v1/lists/1"}})
        result = verifier.verify_request(self.request(credential=credential), action="hashbin:content:write")
        self.assertEqual((result["status"], result["code"]), (503, "status_unavailable"))

    def test_a_stale_copy_of_the_list_cannot_undo_a_revocation(self):
        self.issuer.revoked[0] = 1 << 3  # idx 3
        self.assertEqual(self.verifier.verify_request(self.request(), action="hashbin:content:write")["code"], "revoked")
        self.issuer.revoked[0] = 0  # a CDN edge still serving the list from before the revocation
        self.clock.t += 61
        result = self.verifier.verify_request(self.request(), action="hashbin:content:write")
        self.assertEqual((self.issuer.count(self.issuer.STATUS_URI), result["code"]), (2, "revoked"))

    def test_status_list_without_exp_is_refused(self):
        from devicebasedauth_verify import sign_jws, encode_status_list

        def fetch(url, **kw):
            if url == self.issuer.STATUS_URI:
                payload = {"iss": self.issuer.ISSUER, "sub": url, "iat": self.clock(), "ttl": 60, "status_list": encode_status_list(bytes(16))}
                return FetchResponse(200, sign_jws({"typ": "statuslist+jwt", "kid": self.issuer.signer["kid"]}, payload, self.issuer.signer["key"]).encode())
            return self.issuer.fetch(url, **kw)
        verifier = create_verifier("hashbin.org", fetch=fetch, now=self.clock)
        result = verifier.verify_request(self.request(), action="hashbin:content:write")
        self.assertEqual((result["status"], result["code"]), (503, "status_unavailable"))

    def test_issuer_down_fails_closed_with_backoff(self):
        self.issuer.down = True
        first = self.verifier.verify_request(self.request(), action="hashbin:content:write")
        self.assertEqual((first["allow"], first["status"], first["code"]), (False, 503, "jwks_unavailable"))
        self.verifier.verify_request(self.request(), action="hashbin:content:write")
        self.assertEqual(self.issuer.count(JWKS_URL), 1)  # backing off, not hammering the issuer
        self.issuer.down = False
        self.clock.t += 31
        self.assertTrue(self.verifier.verify_request(self.request(), action="hashbin:content:write")["allow"])

    def test_cached_jwks_survives_an_outage_but_revocation_does_not(self):
        self.assertTrue(self.verifier.verify_request(self.request(), action="hashbin:content:write")["allow"])
        self.issuer.down = True
        self.clock.t += 120  # status list expired from the cache; JWKS still fresh
        result = self.verifier.verify_request(self.request(), action="hashbin:content:write")
        self.assertEqual((result["status"], result["code"]), (503, "status_unavailable"))

    def test_unknown_kid_refetches_the_jwks(self):
        old_jwks = self.issuer.jwks
        self.issuer.jwks = {"keys": []}
        self.verifier.jwks()  # cache a JWKS without the key
        self.issuer.jwks = old_jwks
        # Within the cooldown an unknown kid costs no fetch (anyone can send one)...
        self.assertEqual(self.verifier.verify_request(self.request(), action="hashbin:content:write")["code"], "unknown_kid")
        self.assertEqual(self.issuer.count(JWKS_URL), 1)
        # ...after it, the newly published key is fetched once.
        self.clock.t += 30
        self.assertTrue(self.verifier.verify_request(self.request(), action="hashbin:content:write")["allow"])
        self.assertEqual(self.issuer.count(JWKS_URL), 2)

    def test_device_location_comes_from_the_proof(self):
        grants = [{"actions": ["hashbin:content:write"], "where": {"source": "device", "areas": [{"lat": 38.627, "lon": -90.199, "radius_m": 1000}]}}]
        credential = self.issuer.credential(grants=grants)
        loc = {"lat": 38.627, "lon": -90.199, "acc_m": 20, "t": self.clock.t}
        result = self.verifier.verify_request(self.request(credential=credential, location=loc), action="hashbin:content:write")
        self.assertTrue(result["allow"])
        result = self.verifier.verify_request(self.request(credential=credential), action="hashbin:content:write")
        self.assertEqual(result["reasons"], [["location_unavailable:device"]])

    def test_network_location_from_cloudflare(self):
        request = Request("GET", URL, {"CF-Connecting-IP": "203.0.113.9"}, cf={"country": "US", "regionCode": "MO", "latitude": "38.6", "longitude": "-90.2"})
        self.assertEqual(network_location(request), {"country": "US", "region": "US-MO", "lat": 38.6, "lon": -90.2, "ip": "203.0.113.9"})
        self.assertIsNone(network_location(Request("GET", URL, {})))

    def test_dict_requests_and_header_lists_work(self):
        headers = self.issuer.headers("POST", URL)
        request = {"method": "POST", "url": URL, "headers": list(headers.items())}
        self.assertTrue(self.verifier.verify_request(request, action="hashbin:content:write")["allow"])

    def test_allowed_actions(self):
        credential = self.issuer.credential(grants=[{"actions": ["hashbin:content:read", "hashbin:session"]}])
        auth = self.verifier.authenticate_request(self.request(credential=credential))
        self.assertTrue(auth["ok"])
        self.assertEqual(self.verifier.allowed_actions(auth["payload"], ["hashbin:session", "hashbin:content:write", "hashbin:content:read"], proof=auth["proof"]),
                         ["hashbin:session", "hashbin:content:read"])

    def test_verify_online_posts_to_authorize(self):
        sent = []

        def fetch(url, **kw):
            sent.append((url, kw))
            if url == "https://devicebasedauth.org/api/v1/authorize":
                return FetchResponse(200, json.dumps({"allow": True, "grant_index": 0, "reasons": [[]]}).encode())
            return FetchResponse(402, b'{"error":"Insufficient balance","code":"insufficient_balance"}')

        verifier = create_verifier("hashbin.org", fetch=fetch, now=self.clock, online_api_key="k_test")
        request = self.request()
        result = verifier.verify_online(request, action="hashbin:content:write", resource="doc-1")
        self.assertEqual((result["allow"], result["status"]), (True, 200))
        url, kw = sent[0]
        self.assertEqual((url, kw["method"], kw["headers"]["Authorization"]), ("https://devicebasedauth.org/api/v1/authorize", "POST", "ApiKey k_test"))
        body = json.loads(kw["body"])
        self.assertEqual((body["audience"], body["action"], body["resource"], body["request"]), ("hashbin.org", "hashbin:content:write", "doc-1", {"method": "POST", "url": URL}))

        # A 402 is the relying party's own balance running out: 503 to the client, not 402.
        broke = create_verifier("hashbin.org", issuer="https://devicebasedauth.org/x", fetch=fetch, now=self.clock, online_api_key="k")
        result = broke.verify_online(request, action="hashbin:content:write")
        self.assertEqual((result["allow"], result["status"], result["code"]), (False, 503, "insufficient_balance"))


if __name__ == "__main__":
    unittest.main()
