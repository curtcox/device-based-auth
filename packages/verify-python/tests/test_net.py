"""The `net` constraint: the checks of packages/verify/src/net.test.js, plus Python/JS semantics."""
import unittest

try:
    from . import support  # noqa: F401 - puts src/ on the path
except ImportError:
    import support  # noqa: F401

from devicebasedauth_verify import (describe_net, evaluate_grants, grants_need_version2, same_ip, valid_host_name,
                                    validate_credential_payload, validate_grant, validate_net)

W = ["hashbin:content:write"]
LIST = {"id": "adl_OFFICE0001", "uri": "https://status.devicebasedauth.org/v1/addresses/adl_OFFICE0001"}


class NetValidationTest(unittest.TestCase):
    def test_accepts_every_source_and_rule(self):
        self.assertEqual(validate_grant({"actions": W, "net": {
            "client": {"addresses": {"of": "origin", "cidrs": ["203.0.113.0/24"], "lists": [LIST], "dns": {"names": ["vpn.example.com"], "dnssec": True},
                                     "webhook": "gate_ADDRHOOK1"},
                       "route": {"relays": ["dev_RELAYHQ001"], "min_hops": 1, "max_hops": 2, "require_attested": True},
                       "latency": {"max_rtt_ms": 40, "samples": 3, "reuse_s": 60}},
            "server": {"addresses": {"cidrs": ["198.51.100.0/24"]}, "route": {"relays": ["dev_RELAYHQ001"]}, "latency": {"max_rtt_ms": 80}},
        }}), [])

    def test_explains_what_is_wrong(self):
        self.assertEqual(validate_net({"client": {"addresses": {}}}), ["grant.net.client.addresses needs at least one of cidrs, lists, dns or webhook"])
        self.assertIn("grant.net.server.addresses.of \"origin\" is only for net.client (a device sees the server's address directly)",
                      validate_net({"server": {"addresses": {"of": "origin", "cidrs": ["10.0.0.0/8"]}, "route": {"relays": ["dev_RELAYHQ001"]}}}))
        self.assertEqual(validate_net({"client": {"addresses": {"cidrs": ["10.0.0.0/8", "10.0.0.0/8"]}}}), ["grant.net.client.addresses.cidrs has duplicates"])
        self.assertIn("grant.net.client.addresses.lists names a list twice", validate_net({"client": {"addresses": {"lists": [LIST, dict(LIST)]}}}))
        self.assertEqual(validate_net({"client": {"addresses": {"lists": [dict(LIST, uri="http://example.com/x")]}}}),
                         ['grant.net.client.addresses.lists[0] must be { id: "adl_…", uri: "https://…" }'])
        self.assertEqual(validate_net({"client": {"route": {"relays": ["dev_RELAYHQ001"], "max_hops": 5}}}), ["grant.net.client.route.max_hops must be an integer 1–4"])
        self.assertEqual(validate_net({"client": {"latency": {"max_rtt_ms": 40, "samples": 0, "reuse_s": 301}}}),
                         ["grant.net.client.latency.samples must be an integer 1–5", "grant.net.client.latency.reuse_s must be an integer 0–300"])
        self.assertEqual(validate_grant({"actions": W, "net": {"client": {"latency": {"max_rtt_ms": 4, "extra": 1}}}}),
                         ["grant.net.client.latency.extra is not allowed"])

    def test_javascript_semantics(self):
        # true is not 1, 3.0 is 3, null hop counts take the default (JS ??), and JS \s is not Python's \s.
        self.assertTrue(validate_net({"client": {"latency": {"max_rtt_ms": True}}}))
        self.assertEqual(validate_net({"client": {"latency": {"max_rtt_ms": 3.0}}}), [])
        self.assertEqual(validate_net({"client": {"route": {"relays": ["dev_RELAYHQ001"], "min_hops": None, "max_hops": None}}}), [])
        self.assertEqual(validate_net({"client": {"addresses": {"cidrs": ["10.0.0.0/8", 1, True]}}})[-2:],
                         ['grant.net.client.addresses.cidrs[1] must be a CIDR range like "203.0.113.0/24"',
                          'grant.net.client.addresses.cidrs[2] must be a CIDR range like "203.0.113.0/24"'])
        self.assertEqual(validate_net({"client": {"addresses": {"lists": [dict(LIST, uri="https://a.org/x\x1cy")]}}}), [])
        self.assertTrue(validate_net({"client": {"addresses": {"lists": [dict(LIST, uri="https://a.org/x﻿y")]}}}))
        self.assertEqual(validate_net(None), ["grant.net must be an object"])

    def test_host_names(self):
        self.assertTrue(valid_host_name("vpn-egress.example.com"))
        for bad in ("localhost", "Example.com", "192.0.2.1", "-bad.example.com", f"{'a' * 64}.com", "a.com\n", "a.١٢"):
            with self.subTest(bad=bad):
                self.assertFalse(valid_host_name(bad))

    def test_compares_addresses_however_they_are_written(self):
        self.assertTrue(same_ip("2001:db8::1", "2001:DB8:0:0::1"))
        self.assertFalse(same_ip("192.0.2.1", "::ffff:192.0.2.1"))
        self.assertFalse(same_ip("nope", "nope"))


class NetVocabularyTest(unittest.TestCase):
    grant = {"actions": W, "net": {"client": {"addresses": {"cidrs": ["203.0.113.0/24"], "lists": [LIST]}, "latency": {"max_rtt_ms": 40}},
                                   "server": {"latency": {"max_rtt_ms": 80}}}}

    def test_describes_the_rules_in_english(self):
        self.assertEqual(describe_net(self.grant["net"]), [
            "only from 203.0.113.0/24 or the addresses in list adl_OFFICE0001",
            "only from a device answering within 40 ms",
            "sending only to a server answering within 80 ms",
        ])
        self.assertEqual(describe_net({"client": {"addresses": {"of": "origin", "dns": {"names": ["vpn.example.com"], "dnssec": True}},
                                                  "route": {"relays": ["dev_RELAYHQ001", "dev_RELAYEDGE1"], "max_hops": 2, "require_attested": True}}}), [
            "only from devices at the addresses of vpn.example.com (DNSSEC-validated)",
            "only through relays dev_RELAYHQ001 or dev_RELAYEDGE1 (1–2 hops, attested relays only)",
        ])

    def test_credentials_using_net_carry_vocabulary_2(self):
        base = {"iss": "https://devicebasedauth.org", "sub": "dev_ABCDEFGH12", "acct": "acct_1", "aud": ["hashbin.org"], "cid": "crd_ABCDEFGH12",
                "jti": "crd_ABCDEFGH12.1", "iat": 1, "nbf": 1, "exp": 2, "cnf": {"jkt": "x"}, "status": {"status_list": {"idx": 0, "uri": "u"}}}
        self.assertTrue(grants_need_version2([self.grant]))
        self.assertFalse(grants_need_version2([{"actions": W}]))
        self.assertEqual(validate_credential_payload(dict(base, grants=[self.grant], ver=2)), [])
        self.assertEqual(validate_credential_payload(dict(base, grants=[{"actions": W}], ver=2)), [])
        self.assertEqual(validate_credential_payload(dict(base, grants=[self.grant], ver=1)), ["ver must be 2 when a grant uses net"])
        self.assertEqual(validate_credential_payload(dict(base, grants=[self.grant], ver=2.0)), [])
        self.assertEqual(validate_credential_payload(dict(base, grants=[{"actions": W}], ver=3)), ["ver must be 1 or 2"])

    def test_webhook_makes_an_offline_grant_online_only(self):
        grants = [{"actions": W, "net": {"client": {"addresses": {"cidrs": ["10.0.0.0/8"], "webhook": "gate_ADDRHOOK1"}}}}]
        context = {"now": 0, "action": W[0], "location": {"network": {"ip": "192.0.2.1"}}}
        offline = evaluate_grants(grants, context)
        self.assertEqual((offline["reasons"], offline["online_required"]), ([["online_required"]], True))
        self.assertEqual(offline["results"][0]["online"], {"address_webhook": "gate_ADDRHOOK1"})
        allowed = evaluate_grants(grants, dict(context, online=True, address_webhook={"gate_ADDRHOOK1": True}))
        self.assertTrue(allowed["allow"])
        refused = evaluate_grants(grants, dict(context, online=True, address_webhook={"gate_ADDRHOOK1": 1}))
        self.assertEqual(refused["reasons"], [["address_not_allowed"]])


if __name__ == "__main__":
    unittest.main()
