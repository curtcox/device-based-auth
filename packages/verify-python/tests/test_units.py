"""Unit tests for the building blocks, focused on where Python and JS semantics differ."""
import unittest
import zlib

try:
    from . import support
except ImportError:
    import support

from devicebasedauth_verify import (ReplayCache, VerificationError, b64u, decode_status_list, encode_status_list, evaluate_grants,
                                    generate_key_pair, get_bit, htu, import_private_key, inflate, ip_in_cidr, jwk_thumbprint,
                                    local_time, parse_ip, set_bit, sign_jws, unb64u, valid_time_zone, validate_credential_payload,
                                    validate_grant, verify_jws, export_public_jwk)

VECTORS = support.load_vectors("credentials.json")


class JoseTest(unittest.TestCase):
    def test_base64url(self):
        self.assertEqual(b64u(b"\xfb\xff"), "-_8")
        self.assertEqual(unb64u("-_8"), b"\xfb\xff")
        for bad in ("-_8=", "a+b", "abcde", "a\n", 5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                unb64u(bad)

    def test_thumbprint_matches_the_vectors(self):
        self.assertEqual(jwk_thumbprint(VECTORS["test_only_device_private_jwk"]), VECTORS["device_jkt"])

    def test_sign_and_verify(self):
        key = generate_key_pair()
        jws = sign_jws({"typ": "x"}, {"a": 1}, key)
        self.assertEqual(verify_jws(jws, export_public_jwk(key))["payload"], {"a": 1})
        self.assertIsNone(verify_jws(jws, export_public_jwk(generate_key_pair())))
        head, body, sig = jws.split(".")
        tampered = b64u(b'{"a":2}')
        self.assertIsNone(verify_jws(f"{head}.{tampered}.{sig}", export_public_jwk(key)))
        none_alg = b64u(b'{"alg":"none"}')
        self.assertIsNone(verify_jws(f"{none_alg}.{body}.{sig}", export_public_jwk(key)))

    def test_json_that_python_accepts_but_javascript_does_not(self):
        key = import_private_key(VECTORS["test_only_issuer_private_jwk"])
        good = sign_jws({}, {"n": 1}, key)
        head, _, sig = good.split(".")
        nan = b64u(b'{"n":NaN}')
        self.assertIsNone(verify_jws(f"{head}.{nan}.{sig}", key.public_key()))

    def test_htu_matches_whatwg_url(self):
        # Expected values printed by Node 22's `new URL(u)`: `${protocol}//${host}${pathname}`.
        cases = {
            "https://hashbin.org/api/content?a=1#f": "https://hashbin.org/api/content",
            "HTTPS://Hashbin.ORG:443/a/../b c/%7e": "https://hashbin.org/b%20c/%7e",
            "http://a.org": "http://a.org/",
            "https://a.org:0443/x": "https://a.org/x",
            "http://a.org:8080/": "http://a.org:8080/",
            "https://user:pw@a.org/p": "https://a.org/p",
            "https://[2001:DB8:0:0::1]/x": "https://[2001:db8::1]/x",
            "https://a.org/é": "https://a.org/%C3%A9",
            "https://a.org/a/%2E%2e/b/./c/.": "https://a.org/b/c/",
            "https://a.org/x\\y": "https://a.org/x/y",
            "custom://Host:99/P a": "custom://Host:99/P%20a",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(htu(url), expected)
        with self.assertRaises(ValueError):
            htu("/relative")


class StatusListTest(unittest.TestCase):
    def test_round_trip(self):
        data = set_bit(set_bit(b"", 3), 700)
        decoded = decode_status_list(encode_status_list(data))
        self.assertEqual([i for i in range(1000) if get_bit(decoded, i)], [3, 700])
        self.assertEqual(get_bit(decoded, 10**6), 0)

    def test_bit_index_wraps_like_javascript(self):
        # JS evaluates index >> 3 on a 32-bit integer, so 2**32 + 3 reads bit 3. Mirror it so all
        # implementations agree on revocation for any idx the issuer could assign.
        self.assertEqual(get_bit(bytes([8]), 2**32 + 3), 1)
        self.assertEqual(get_bit(bytes([0xFF]), 2**31), 0)

    def test_decompression_bomb_is_refused(self):
        with self.assertRaises(ValueError):
            inflate(zlib.compress(bytes(17 * 1024 * 1024)))
        with self.assertRaises(ValueError):
            inflate(zlib.compress(b"abc") + b"junk")
        with self.assertRaises(ValueError):
            decode_status_list({"bits": True, "lst": b64u(zlib.compress(b"a"))})


class GrantsTest(unittest.TestCase):
    def test_ip_parsing_follows_the_javascript_parser(self):
        self.assertEqual(parse_ip("010.1.2.3"), (32, 0x0A010203))  # leading zeros are decimal, as in JS
        self.assertIsNone(parse_ip("fe80::1%eth0"))
        self.assertIsNone(parse_ip("1::2::3"))
        self.assertTrue(ip_in_cidr("::ffff:10.0.0.1", "::ffff:10.0.0.0/104"))
        self.assertFalse(ip_in_cidr("10.0.0.1", "::/0"))  # families never match each other
        self.assertTrue(ip_in_cidr("2001:db8:1::5", "2001:db8::/32"))

    def test_time_zones(self):
        for tz in ("UTC", "utc", "America/Chicago", "+05:30", "-08", "−05:00"):
            with self.subTest(tz=tz):
                self.assertTrue(valid_time_zone(tz))
        for tz in ("Nope/Zone", "Factory", "", "+24:00", 5, None):
            with self.subTest(tz=tz):
                self.assertFalse(valid_time_zone(tz))
        self.assertEqual(local_time(0, "+05:30"), {"day": 4, "minutes": 330})  # Thursday 05:30

    def test_unknown_constraints_are_reported_in_javascript_key_order(self):
        result = evaluate_grants([{"actions": ["a:b"], "zeta": 1, "2": 1, "when": {"moon": 1}}], {"now": 0, "action": "a:b"})
        self.assertEqual(result["reasons"], [["unknown_constraint:2", "unknown_constraint:zeta", "unknown_constraint:when.moon"]])

    def test_booleans_are_not_numbers(self):
        self.assertTrue(validate_grant({"actions": ["a:b"], "limits": {"uses": {"count": True, "per": "day"}}}))
        self.assertFalse(validate_grant({"actions": ["a:b"], "limits": {"uses": {"count": 3.0, "per": "day"}}}))
        payload = {"iss": "i", "sub": "dev_ABCDEFGH", "acct": "a", "jti": "j", "cid": "crd_ABCDEFGH", "iat": 1, "nbf": 1, "exp": 2,
                   "aud": ["x"], "ver": True, "status": {"status_list": {"idx": 0, "uri": "u"}}, "cnf": {"jkt": "k"}, "grants": [{"actions": ["a:b"]}]}
        self.assertEqual(validate_credential_payload(payload), ["ver must be 1"])

    def test_null_is_not_absent(self):
        # A present null fails validation (deny) instead of being read as "no restriction".
        result = evaluate_grants([{"actions": ["a:b"], "where": None}], {"now": 0, "action": "a:b"})
        self.assertEqual(result["reasons"], [["invalid_grant"]])

    def test_result_fields(self):
        result = evaluate_grants([{"actions": ["a:b"], "limits": {"uses": {"count": 1, "per": "day"}}}], {"now": 0, "action": "a:b", "online": True})
        self.assertEqual((result["allow"], result["online"], result["caveats"], result["online_required"]),
                         (True, {"uses": {"count": 1, "per": "day"}}, {}, False))
        self.assertEqual(evaluate_grants("nope", {})["reasons"], [["invalid_grants"]])


class ProofHelpersTest(unittest.TestCase):
    def test_replay_cache_forgets_after_its_ttl(self):
        cache = ReplayCache(ttl_seconds=10)
        self.assertTrue(cache.check("a", 100))
        self.assertFalse(cache.check("a", 105))
        self.assertTrue(cache.check("a", 111))

    def test_error_status(self):
        self.assertEqual(VerificationError("expired").status, 401)
        self.assertEqual(VerificationError("status_unavailable").status, 503)


if __name__ == "__main__":
    unittest.main()
