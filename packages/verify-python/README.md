# devicebasedauth-verify (Python)

Verify [devicebasedauth.org](https://devicebasedauth.org) device credentials, DPoP proofs and
status lists, and evaluate their grants, in Python ≥ 3.10. A port of the JavaScript reference
library (`packages/verify`); it passes every conformance vector in `spec/vectors/`. Its only
dependency is `cryptography`.

```sh
pip install "devicebasedauth-verify @ git+https://github.com/curtcox/device-based-auth#subdirectory=packages/verify-python"
```

## Verify a request

`verify_request` checks the credential's signature and claims, the DPoP proof (method, URL,
freshness, replay), revocation, and then the grants for one action. The issuer's JWKS and status
lists are fetched and cached; if they cannot be fetched, the request is refused with 503
(fail closed).

```python
from devicebasedauth_verify import Request, create_verifier

verifier = create_verifier("hashbin.org")  # your audience name; create once, reuse (it caches)


def handle(method, url, headers):
    """Authorize one request; returns (HTTP status, JSON body)."""
    result = verifier.verify_request(Request(method, url, headers),
                                     action="hashbin:content:write", resource="doc-1")
    if not result["allow"]:
        return result["status"], {"error": result["code"], "reasons": result["reasons"]}
    return 200, {"account": result["account"], "device": result["device"], "caveats": result["caveats"]}
```

`url` must be the full URL the client called (`https://host/path?query`); behind a proxy, rebuild
it from the forwarded host and scheme. `result["caveats"]` carries limits you enforce yourself,
such as `spend_usd_per_month`. Grants with usage limits, step-up, gates or `require.online` come back as
`code: "online_required"`; send those to `verifier.verify_online(...)` (needs `online_api_key`).

Fetching is injectable — `create_verifier(audience, fetch=my_fetch, now=my_clock)` — where
`my_fetch(url, method="GET", headers=None, body=None)` returns a `FetchResponse(status, body)`.

Other things to know:

- **Where a request came from.** By default the network location (for `where` and `net` grants)
  is read from Cloudflare's `request.cf` and the `CF-Connecting-IP` header, which a client can set
  itself when you are not behind Cloudflare. Elsewhere, pass
  `location={"network": {"ip": <the socket's peer address>}}` to `verify_request`; without a
  location, network-restricted grants deny.
- **Confirmations.** A `DBA-Confirmation` header (spec/credential.md §9) is verified with the
  credential and its claims passed to the grants; one that does not verify is refused
  (`confirmation_<code>`).
- **Audience policy.** `catalog=[{"action": …, "gates": {"require": True, …}}]` applies your
  action catalog's gate policy offline (spec/evaluation.md §3.8); without it the policy is
  enforced only online.
- **Not in this port:** revocation webhooks (`handleEvent`), and fetching address lists, resolving
  DNS names or timing round trips for `net` grants. The JavaScript library does those.

## Evaluate grants

```python
>>> from devicebasedauth_verify import evaluate_grants
>>> grants = [{"actions": ["hashbin:content:write"],
...            "when": {"tz": "America/Chicago",
...                     "windows": [{"days": ["mon", "tue", "wed", "thu", "fri"], "from": "08:00", "to": "18:00"}]}}]
>>> result = evaluate_grants(grants, {"now": 1795014000, "action": "hashbin:content:write"})
>>> result["allow"], result["grant_index"], result["reasons"]
(True, 0, [[]])
>>> evaluate_grants(grants, {"now": 1795014000, "action": "hashbin:content:delete"})["reasons"]
[['action_not_granted']]
```

Grants that use the `net` constraint (vocabulary 2: such credentials carry `ver: 2`) are judged
on facts you resolve first and pass in the context: `location.network.ip` and `rtt_ms`, `route`
(`{relays, attested, origin}`) or `route_error`, `address_lists` (`{id: {cidrs}}`) and `dns`
(`{name: {addrs, dnssec}}`). Anything not resolved denies with its reason (`rtt_required`,
`address_list_unavailable:<id>`, `dns_unresolved:<name>` …). `Verifier` passes only the network
location, so grants that need lists, DNS or a route deny through `verify_request`; call
`evaluate_grants` with a resolved context for those. A grant whose address may only be allowed by
a webhook is online-only. `validate_net` and `describe_net` explain a `net` member;
spec/evaluation.md §3.10 has the rules.

## Fidelity to the JavaScript reference

Decisions must not depend on which language verifies a credential, so JSON values are judged with
JavaScript semantics (`true` is not `1`, a present `null` is not an absent member, `[]` is truthy,
regexes are ASCII-only), IP addresses use the reference parser rather than `ipaddress`, `htu`
reproduces WHATWG URL serialization, and status-list indexes above 2³¹−1 make a credential
invalid in every implementation. Time zone names come from the system tz database (or the `tzdata` package):
install `tzdata` where the system has none, e.g. on Windows.

## Tests

From the repository root (no install needed):

```sh
python3 -m unittest discover -s packages/verify-python/tests -t packages/verify-python
```
