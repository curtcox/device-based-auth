# Network constraints: address, route and latency

Status: STATUS **B10** (in progress: N1–N4 done, §13a), **D16** (owner's choices),
**D17** (prices, proposed; implemented for address lists). Design summary in the master plan
§3.6. This file is written to be picked up cold.

## 1. What and why

A grant can already say where a device may be (`where`: countries, regions, areas, and
`where.networks`, a CIDR list the request IP must fall in; spec/evaluation.md §3.4). This plan adds
**network constraints**: rules about the *connection* rather than the place. When a grant has
them, communication counts as valid only if the other end of the connection:

- **address**: has an address that an allowlist accepts;
- **route**: is reached through allowed network relays, proven by their signatures;
- **latency**: answers a timed challenge within a maximum round-trip time.

Typical uses: "only from the office egress or the corporate VPN" (address), "only through our
own gateway, never directly" (route), "only from a device within ~40 ms of the server, so a
stolen credential relayed from far away fails" (latency), and the same rules applied by the
device to the server it talks to, so an honest device refuses to send its credential to a
look-alike or relayed endpoint.

Network constraints are **evidence about the connection, not proof of identity**. The device key
still proves who is talking; these rules narrow from where and how.

## 2. Decisions already made (D16, owner)

1. **Both directions.** A grant can constrain the device's connection as seen by the verifier
   (`net.client`), and the connection the device sees to the relying party (`net.server`), which
   the device's SDK or CLI enforces before it sends a request.
2. **Address allowlists** may be any mix of: inline CIDR ranges; **named, updatable lists** owned
   by the account and published signed and CDN-cached like status lists, so changing a list does
   not reissue credentials; **DNS names** resolved by the verifier; and a **customer webhook**
   that says whether an address is allowed (online only, metered).
3. **Routes** are proven only by **signed relay hops**: the traffic passes through DBA-enrolled
   relay devices (VPN egress, proxy, tunnel endpoint) that each sign a hop record bound to the
   request. Origin ASN and Cloudflare ingress points are not accepted as route evidence.
4. **Latency** is a **maximum round-trip time measured by a timed challenge**: the verifier
   issues a nonce, the device signs it, and the verifier times the round trip on its own clock.
   Only an upper bound: nobody can fake being closer, while a lower bound is faked by waiting.

### Consequences to keep visible

- **Address and DNS rules are as strong as the IP the verifier sees.** Anyone who controls an
  allowed address (or a VPN exit inside an allowed range) passes the address rule. A verifier
  that reads the IP from a client-set header (`X-Forwarded-For`) instead of the platform
  (`CF-Connecting-IP`, the socket) can be lied to. Docs and the verify library say so.
- **DNS names are as strong as the resolver.** Without DNSSEC, whoever can poison the verifier's
  resolver can add an address. `dnssec: true` makes an unvalidated answer deny.
- **A route proves the request passed the relays; it does not prove the relays are honest.** A
  compromised relay key lets an attacker forge hops until the relay's credential is revoked.
  Relays are ordinary DBA devices: revocable, renewable, optionally attested.
- **Latency bounds distance, not possession.** A thief who has the private key and sits close to
  the verifier passes. Latency stops a credential *relayed* from a far device (a phished browser
  forwarding challenges), not a stolen key used nearby.
- **Device-side (`net.server`) rules protect the device, not the relying party.** A modified
  device can ignore them. Relying parties never treat a device's report about the server as a
  reason to allow.
- **Browsers cannot see server addresses or choose relays.** The browser SDK can enforce only
  the server latency rule; a grant whose `net.server` has addresses or a route is to be unusable
  from a browser (fails closed, with a clear reason at enrollment time; N7).

## 3. Vocabulary

### 3.1 The `net` constraint

A grant field beside `when` and `where` (spec/evaluation.md §3.10). Old verifiers treat it as an
unknown constraint and deny (fail closed). Credentials that use it have `ver` 2; all others keep
`ver` 1, so older verifiers keep accepting them.

```json
"net": {
  "client": {
    "addresses": {
      "of": "peer",
      "cidrs": ["203.0.113.0/24", "2001:db8:42::/48"],
      "lists": [{ "id": "adl_01JD…", "uri": "https://status.devicebasedauth.org/v1/addresses/adl_01JD…" }],
      "dns": { "names": ["vpn-egress.example.com"], "dnssec": true },
      "webhook": "gat_01JD…"
    },
    "route": { "relays": ["dev_01JDRELAY…"], "min_hops": 1, "max_hops": 2 },
    "latency": { "max_rtt_ms": 40, "samples": 1, "reuse_s": 60 }
  },
  "server": {
    "addresses": { "cidrs": ["198.51.100.0/24"] },
    "route": { "relays": ["dev_01JDRELAY…"] },
    "latency": { "max_rtt_ms": 80 }
  }
}
```

- `client`: checked by whoever verifies the device (offline verifier or DBA online) against the
  connection the device's request arrives on.
- `server`: checked by the device (SDK, CLI, mobile sample) against the connection to the relying
  party, before it sends the credential and before it trusts the response.
- Each of `addresses`, `route` and `latency` is optional; every one present must pass (AND).
  Inside `addresses`, the sources form a **union**: the address must be allowed by at least one
  of `cidrs`, `lists`, `dns` or `webhook`.
- `where.networks` keeps working unchanged. New grants built by our tools should use
  `net.client.addresses.cidrs` instead (the grant builder's `net` section is N9).

### 3.2 Addresses

| Source | Meaning | Who can enforce it |
|--------|---------|--------------------|
| `cidrs` | IPv4/IPv6 CIDR ranges, inline. ≤ 64. | Anyone |
| `lists` | Named address lists (§4), referenced by id and URI. ≤ 8. | Anyone (fetch and cache the list) |
| `dns` | Host names; the address must be one of their current A/AAAA answers. ≤ 16. `dnssec: true` requires a validated answer (DoH with the AD bit). | Anyone who can resolve DNS |
| `webhook` | A registered webhook (a `gate_…` id: the gate registry's `webhook` kind, reused) that answers allow/deny for an address (§5). Client direction only. | DBA online only |

`of` says which address is checked:

- `"peer"` (default): the address the verifier sees directly (platform-reported, never a header
  the client sets).
- `"origin"`: the address the **first relay** recorded for the device in its signed hop (§6).
  Requires `route`. Use it for "devices inside our office, reaching us through our gateway".

Server direction: `addresses` checks the address the device actually connected to (after DNS),
which the CLI and native SDKs read from the socket. `of: "origin"` is not allowed for `server`.

### 3.3 Route

| Field | Meaning |
|-------|---------|
| `relays` | Device ids (`dev_…`) of relay devices allowed on the path. ≤ 16. |
| `min_hops` / `max_hops` | Number of signed hops required / allowed. Default 1 / 4; max 4. |
| `require_attested` | Every relay's key must have hardware attestation (`require.attestation: "hardware"` semantics, applied to the relay credential). |

A relay device is an ordinary DBA device whose credential grants `dba:relay:forward` for the
audience (or `*`) and lists its **egress** addresses in `device.relay.egress` (CIDRs, ≤ 16), set
by the owner at enrollment. The relay must belong to the same account as the credential it
vouches for (cross-account relays are an open question, §14).

### 3.4 Latency

| Field | Meaning |
|-------|---------|
| `max_rtt_ms` | 1–5000. The measured round trip must be ≤ this. |
| `samples` | 1–5 challenges; the **minimum** is compared (jitter only ever adds). Default 1. |
| `reuse_s` | 0–300. A verifier may accept a passing measurement again for this long, but only for the same `cnf.jkt` **and** the same peer address. Default 0 (every request). |

The measured time includes the device's signing time. Hardware keys are slow (TPM ES256 signing
can take 50–200 ms; StrongBox 30–100 ms; WebCrypto and Secure Enclave a few ms). The grant
builder shows the measured signing time of the enrolling device and warns when `max_rtt_ms`
leaves less than 10 ms of network budget.

## 4. Named address lists

- Account-owned objects: `POST /api/v1/address-lists` (`adl_…` id, 128 random bits), `GET`,
  `PUT` to replace the entries, `DELETE`. Up to 10,000 CIDRs per list (stored in the account
  object in chunks of 1,000), 50 lists per account. Scopes `networks:read` / `networks:write`;
  replacing and deleting need a recent sign-in (as gate changes do), because widening a list
  widens every credential that names it. Code: `src/api/address-lists.js`,
  `src/durable-objects/account/address-lists.js`, `src/services/address-lists.js`.
- Published at `status.devicebasedauth.org/v1/addresses/{id}` (also served by the Worker at
  `/status/v1/addresses/{id}`) as a signed JWT (`typ: dba-addresses+jwt`, spec/credential.md §7a:
  issuer key, `iat`, `exp` = `iat` + 24 h, `ver` (monotonic), `cidrs` sorted). Published at most
  once per 60 s per list (debounced on the account's alarm), `Cache-Control: max-age=60`, and
  re-signed every 20 h for 13 months after the list's last change, which the create/replace
  price prepays.
- Issuance accepts only the issuing account's own live lists, named by their canonical URI.
  Online decisions read lists from R2 through a 60 s per-isolate cache. List URIs may be
  `http://` on loopback for local development.
- Verifiers fetch through the CDN, cache for at most `max-age`, and may serve a stale copy for up
  to 10 minutes when the fetch fails; after that the list is **unavailable** and its source
  matches nothing. A list with a lower `ver` than one already seen is ignored (no rollback).
- Deleting a list publishes a signed tombstone (`deleted: true`), which matches nothing and is
  purged two days later. Every credential naming it denies through that source; the dashboard
  is to list those credentials before the delete (N9).
- Lists are readable by anyone who has the URI, which every audience shown the credential has.
  The UI says so ("this list of addresses is visible to the sites you use it with"). An account
  that wants its addresses private uses the webhook source instead.
- `kind: "audience"` lists (not built): an audience may publish lists too (e.g. "hashbin's own
  relays"), so account owners can name them in grants. Same format, owned by the audience's
  account.

## 5. Webhook address check

Reuses the webhook machinery of the gates plan (done/additional_gates.md §4.2, spec/events.md §6):
the account registers a `webhook` gate with `purpose: "address"`, and the grant names it.

- On `/authorize`, DBA posts an issuer-signed `dba-addrcheck+jwt`
  (`{ addr, of, cid, sub, aud, action, iat, jti }`) to the service; it answers synchronously with
  a JWS signed by its registered key: `{ allow, cache_s ≤ 300, jti }`. No late answers: the check
  waits at most 3 s.
- **Fail closed, always.** No answer, an error, a bad signature, or an unpaid request (the owner's
  balance cannot cover it) is "not allowed" by this source; another source in the union may still
  allow. There is no allow-on-timeout here: unlike a gate, nobody is being asked to approve.
- Answers are cached per (webhook, address) for `cache_s` in the account's DO, so a busy device
  does not call the service on every decision.
- Offline verifiers cannot use it: a grant whose only matching path needs the webhook answers
  `online_required`.

## 6. Signed relay hops

### 6.1 The hop record

Each relay that forwards a request adds one `dba-hop+jwt`, signed with the relay's device key:

```json
{ "typ": "dba-hop+jwt", "alg": "ES256", "jwk": { … relay public key … } }
{ "relay": "dev_01JDRELAY…", "rcid": "crt_… (relay credential jti)",
  "prev": "192.0.2.17", "ath": "<hash of the device's DPoP proof>",
  "n": 0, "iat": 1795017600, "jti": "…" }
```

- `prev`: the address the relay received the request from (the device for hop 0, the previous
  relay after that).
- `ath`: the SHA-256 of the device's DPoP proof for this request. Binds the hop to one request;
  the proof's own `jti` replay check stops reuse.
- `n`: hop position, 0 at the device's side.

Headers: `DBA-Route: <hop0>, <hop1>, …` and `DBA-Route-Credentials: <relay credential>, …`
(each relay's own DBA credential, so offline verifiers can check it like any credential).

### 6.2 Two ways a relay signs

- **Inline (HTTP proxy, TLS-terminating gateway, the `dba relay` CLI command):** the relay
  appends its hop and credential to the headers as it forwards.
- **Tunnel (CONNECT proxy, WireGuard/VPN egress that cannot see headers):** the device asks the
  relay for its hop *through the tunnel*, at the relay's attestation endpoint
  (`GET /.well-known/dba-hop?ath=…`, reachable only from inside the tunnel), and attaches it
  itself. The relay signs only for connections it is carrying, and records `prev` from the
  tunnel's inner address.

### 6.3 Checking a route (client direction)

The verifier, before the evaluator runs:

1. Parses the hops; count within `min_hops`…`max_hops`, `n` = 0…k−1 in order.
2. Verifies each relay credential like any credential (signature, `exp`, status list, grant for
   `dba:relay:forward` covering this audience, `require_attested` if asked) and each hop's
   signature by that credential's `cnf.jkt`; `iat` within ±60 s; `ath` equals the device
   proof's hash.
3. Chains the addresses: hop *i*'s sender is hop *i+1*'s `prev`, and that address must lie in
   relay *i*'s `egress`; the **last** relay's `egress` must contain the peer address the verifier
   sees. This is what stops a device from carrying hops it fetched once from a relay and sending
   directly: it would arrive from an address outside every egress range.
4. Every relay id must be in `route.relays`.
5. Passes `context.route = { relays: […], origin: hops[0].prev }` to the evaluator, or
   `context.route_error = "<reason>"`.

### 6.4 Server direction

`net.server.route` means the device sends only through the listed relays (the SDK/CLI configures
the proxy or tunnel itself) and accepts a response only if it carries a hop signed by the
relay nearest the device, over the **response** (`ath` = hash of the response's `DBA-RTT` echo or
body digest), with `prev` inside the relying party's server addresses. Native SDKs and the CLI
only; the browser SDK refuses the grant.

## 7. Latency challenge

### 7.1 Client direction (verifier times the device)

Rides on the DPoP server-nonce flow (RFC 9449 §8, `use_dpop_nonce`) that DBA's own API, the
browser SDK (v1.4.0), the CLI and the samples answer for D15 (§7.1.1 says how the two fit). Built
in `packages/verify/src/rtt.js` and `createVerifier({ rtt: { secret } })`:

1. A request without a fresh RTT nonce gets `401` with `WWW-Authenticate: DPoP
   error="use_dpop_nonce"`, `DPoP-Nonce: <rtt nonce>` and, in the body, `dpop_nonce` and
   `rtt: { samples_left }`.
2. The **RTT nonce** is stateless: `rtt1.` + base64url(issue time in ms ‖ samples taken ‖ best
   round trip so far ‖ jkt hash ‖ peer-address hash ‖ HMAC-SHA-256/128) keyed by a verifier
   secret of at least 32 bytes, shared by every instance that may see the retry. The verifier
   needs no storage; it reads its own issue time back. A nonce older than 10 s is not a
   measurement.
3. The device immediately re-sends the request with a proof whose `nonce` is that value. The
   verifier computes `rtt = now_ms − t_ms` on its own clock (no clock sync with the device), and
   checks the HMAC, the `jkt` and that the peer address is the one the nonce was issued to.
4. With `samples > 1` the verifier repeats and keeps the minimum (carried in the nonce, so still
   stateless). `context.network.rtt_ms` is the result; the evaluator compares it.
5. A passing result may be remembered for `reuse_s` keyed by (`jkt`, peer address), in memory
   (at most 10,000 entries).

Notes:
- On Cloudflare Workers the clock advances between requests (it is frozen only *during* a
  request), so per-request timing is good to about a millisecond. Measured at the edge, it is
  the device-to-edge round trip; measured at an origin behind a proxy, it includes the proxy leg
  (stricter, never looser).
- A request that needs a new TCP/TLS connection for the retry measures more, never less: still
  fail-safe. SDKs keep the connection alive between challenge and retry.
- The challenge costs one extra round trip per request (or per `reuse_s`). Docs show it.

#### 7.1.1 One nonce per proof: fitting with D15

A proof carries one `nonce`, and D15 asks for one for another reason: DBA's account object asks
proofs made before it started for its own random epoch nonce (`dpn_…`), against proof replay
after a restart, and sends `DPoP-Nonce` on its responses. The two must not fight:

- **One challenge answers both.** A verifier that wants a replay nonce and a latency
  measurement issues only the RTT nonce. It is fresh, signed by the verifier and bound to the
  `jkt` and peer address, so it does a replay nonce's job too. A proof never needs two nonces.
- **DBA's own API** (sign-in and confirmation `net` settings, N8, not built): when the account
  object needs a latency measurement, its challenge is an RTT nonce keyed by a secret of its
  own. It meets the D15 rule like the epoch nonce does when its issue time is after the object
  started (it cannot predate the restart, so a proof captured before the restart still fails).
  Without a latency rule the epoch nonce is used, as now.
- **Library.** `verifyProof`'s `nonce` option takes an exact value (D15-style nonces) or a check
  function (`nonce: (value) => ({ ok, rtt_ms })`), so a stateless RTT nonce is checked by HMAC
  and age instead of equality.
- **Clients.** The SDK and CLI keep the last `DPoP-Nonce` per origin, put it in every later
  proof, and retry once, and only for a nonce different from the one kept. For RTT nonces:
  - Clients use an RTT nonce once (a challenge whose body has `rtt.samples_left`) and drop it
    after the exchange: kept for the next proof, it would time that request from this one, and
    the verifier cannot tell a reused nonce from a slow answer.
  - A stale RTT nonce gets a new challenge, not a denial, until `samples` attempts have failed,
    then `rtt_exceeded`. Clients follow `rtt.samples_left` (at most 3 retries), not just one.
  - Commands that hand a proof to another program (`dba headers`, `dba sign`, `dba curl`, which
    ask `POST /api/v1/dpop-nonce` first for DBA's origin) cannot answer a timed challenge for
    another site. They refuse credentials whose every grant is timed, and say so. A timed
    request needs a client that sends the request itself.
- **DBA as the online verifier.** `/authorize` takes the relying party's measurement
  (§7.2). The device's proof there was made for the relying party, so DBA's epoch nonce is
  not involved.

### 7.2 Online (`/authorize`)

DBA does not face the device's connection, so the relying party measures as in §7.1 (the verify
library does it) and passes `context.network.rtt_ms` and the peer address, as it already passes
the IP. The relying party is only ever lying to itself.

### 7.3 Server direction (device times the relying party)

The device needs a reply only the server could have made. Audiences register **server keys**
(a JWKS) in their audience record, published in their catalog. The device sends
`DBA-RTT-Challenge: <random>`; the server answers with `DBA-RTT: <dba-rtt+jwt>` signed by a
server key over the challenge and the request's method and URL; the device times it with a
monotonic clock (`performance.now()` in browsers). `@devicebasedauth/verify` gets
`site.rttEcho()` so a site adds it in one line. This works in browsers too.

## 8. Evaluation

The evaluator stays pure and single (packages/verify). Everything that needs I/O is resolved by
the verifier first and handed in as context, so the vectors stay plain JSON:

| Context field | Filled by |
|---------------|-----------|
| `context.network.ip` | the verifier (platform-reported, never client headers; §10) |
| `context.network.rtt_ms` | §7.1 measurement, or absent |
| `context.address_lists` | `{ id: { cidrs, ver } \| "unavailable" }` for every list the credential names |
| `context.dns` | `{ name: { addrs, dnssec } \| "unresolved" }` |
| `context.address_webhook` | online only: `{ gat_…: true \| false }` |
| `context.route` / `context.route_error` | §6.3: `{ relays, origin, attested }` (one `attested` boolean per hop) or a reason matching `[a-z0-9_]{1,64}` |
| `context.mode` | `offline` / `online` (exists) |

New reasons (spec/evaluation.md §3.10): `address_unavailable` (no peer or origin address),
`address_not_allowed`, `address_list_unavailable:<id>` (informational beside
`address_not_allowed`), `dns_unresolved:<name>`, `dns_unvalidated:<name>`, `route_required`,
`route_invalid:<detail>`, `route_relay_not_allowed`, `rtt_required` (the verifier must challenge;
the verify library turns this into the 401 of §7.1), `rtt_exceeded`, and `online_required` when
only the webhook could allow. `net.server` is not evaluated by verifiers (they ignore it); the
SDK and CLI evaluate it with the same code and the same reasons prefixed `server_`.

## 9. Sign-in and confirmations

"Communication is valid only if…" also covers authentication:

- **Sign in with devicebasedauth.org** and the dashboard: an account setting (per audience or
  default, beside sign-in gates) with a `net.client` block, checked on the consent page's
  requests (DBA faces the browser here, so DBA measures RTT and sees the address itself). The ID
  token's `dba_net` claim records what was checked (`{ addr_ok, route, rtt_ms }`, coarse).
- **Periodic confirmation** (`confirm`): a `net` block on the credential's `confirm` applies to
  the confirm request itself, so a device away from the office cannot refresh its confirmation.

## 10. Security, abuse and privacy

- **IP source**: verifiers take the peer address from the platform: `CF-Connecting-IP` on
  Workers (Cloudflare sets it), the socket address elsewhere; a `trustProxies` option must be set
  explicitly to honour `X-Forwarded-For`, and then only from listed proxy ranges. As built, the Go
  verifier makes the caller choose (`RemoteAddrLocation` or `CloudflareLocation`), but the JS
  `createVerifier` reads `CF-Connecting-IP` whenever the caller passes no
  `check.location.network`, which is only safe on Workers, and has no `trustProxies` (§13a).
- **Relay keys** are device keys: never on DBA's server; relays should be attested
  (`require_attested`) and short-lived; the dashboard shows each relay's recent hop counts.
- **Challenge abuse**: RTT nonces cost the verifier an HMAC and no storage; per-IP rate limits on
  challenges in the verify library; DBA's own endpoints already rate-limit.
- **DNS**: resolution through DoH to a configurable resolver (default Cloudflare 1.1.1.1), with
  a cache bounded by TTL (≥ 30 s, ≤ 300 s) and per-verifier limits on lookups per request (16).
- **Privacy**: credentials reveal CIDRs, host names, list URIs and relay ids to every audience
  they are shown to. Named lists are public to holders of the URI. The issuing UI says so and
  offers the webhook source for private address sets. DBA stores no measured RTTs except the
  coarse value in an online decision's audit row (90 days, like the decision's country).

## 11. Money

Operations in `src/utils/cost-policy.js`, prices in `src/utils/pricing.js`, each passing the
price-floor test; counted in `src/cost-counts.test.js`, then owner approval (D17). Derivations in
docs/business/pricing.md.

| Operation | Worst case counted | Price | Payer |
|-----------|--------------------|-------|-------|
| Address list create / replace (`address_list`) | per started 1,000 ranges: the request, a debounced publish, the later free delete with its tombstone and purge, list and chunk rows, 2 R2 writes | 242 µ$ (proposed) | Owning account |
| Address list published life (`address_list_day`) | re-signing every 20 h up to 13 months after the last change; each create or replace pays for the days it adds (a new list ≈ 6,200 µ$). Lists unchanged for 13 months stop being re-signed and expire (deny) | 15 µ$ per day (proposed) | Owning account |
| Webhook address check (N6) | a signed subrequest + DO cache write | to count | Account that owns the webhook (the issuer) |
| Relay credential | ordinary issue / renew | 87 / 25 µ$ | Relay's account |
| CIDR, DNS, route and latency checks | verifier-side | free to DBA | — |
| Online decision with `net` | lists read through a per-isolate cache; no extra row writes | 14 µ$ (unchanged) | Audience |

List fetches are CDN-cached R2 reads like status lists (misses cost a class-B read and are
covered by the cost brake's free-path budget).

## 12. Spec, verifier and tools

Built: `spec/evaluation.md` §3.10 (`net`, the context table of §8, the reasons) and
`spec/credential.md` §7a (`dba-addresses+jwt`); the evaluator in JS, Python and Go with vectors
for each address source alone and in union, `of: origin` with and without a route, unavailable
lists, unvalidated DNS with `dnssec`, route context (hop count, relay not listed, not attested,
`route_error`), rtt missing / under / over, webhook offline → `online_required`, unknown `net`
field → deny, `where.networks` unchanged; in `@devicebasedauth/verify` list fetch/cache
(`createAddressListResolver`), the DoH resolver (`createDohResolver`) and RTT nonces
(`createRttChallenger`); the SDK and CLI answering timed challenges.

Still to do (phase in brackets):

- `spec/credential.md`: `device.relay.egress`, `dba-hop+jwt` [N5], `dba-addrcheck+jwt` [N6],
  `dba-rtt+jwt` and audience `server_keys` [N7]. Signature vectors for hops [N5] and RTT echoes
  [N7]; vectors for the verifier-side route checks (egress chain break, wrong `ath`, revoked
  relay) [N5].
- `@devicebasedauth/verify`: route verification [N5], `site.rttEcho()` [N7], `trustProxies` and
  a safe default IP source outside Workers (§10); browser copy and SDK bundle regenerated.
  Python and Go: they evaluate `net` from context today; RTT nonces, DoH and list fetching are
  JS-only.
- SDK: time server echoes, evaluate `net.server`; refuse grants it cannot enforce in a browser
  [N7]. New SDK release [N9].
- CLI: `dba relay` (run an inline relay or the tunnel hop endpoint) [N5], `dba address-lists
  list|create|set|delete`, `dba net test <aud>` (measures RTT, address and route as a verifier
  would see them) [N9].
- Site: relay enrollment (egress ranges) [N5]; address-list editor, grant builder `net` section
  with measured signing time, and playground inputs for RTT, lists, DNS answers and routes [N9].
  The inspector, playground and approval page already render `net` in English through
  `describeGrant` ("only from 203.0.113.0/24 or the addresses in list adl_…, through relay
  dev_…, within 40 ms").
- Docs: a "Network constraints" page with CI-executed samples (an offline verifier enforcing
  address + RTT, a relay in front of a sample service, a webhook address service in Node and
  Python, a server adding `rttEcho`) [N9].

## 13. Phases

Each phase ends with `npm test`, `npm run lint`, samples and e2e green, docs regenerated, and its
STATUS row updated.

| Phase | Deliverable | Exit criteria |
|-------|-------------|---------------|
| N1 ✅ | Spec text and vectors for `net` (addresses inline + context-resolved lists/DNS, route context, rtt); evaluator in JS, Python, Go | Every new vector passes in all three; old `where.networks` vectors unchanged |
| N2 ✅ | RTT challenge in the verify library (nonce check function, retry, samples, reuse), SDK/CLI following `samples_left`, `dba headers`/`sign`/`curl` refusing timed credentials (§7.1.1) | A device behind an injected delay fails `max_rtt_ms` and passes without it (real-clock test: 150 ms against 60) |
| N3 ✅ | Named address lists: CRUD, signed publishing on R2, verifier fetch/cache/stale/rollback rules, D17 prices in cost policy | Changing a list changes an offline verifier's decision within 60 s + cache; cost-count test covers the new ops |
| N4 ✅ | DNS source (DoH, DNSSEC flag, TTL bounds) | Tested against a stub resolver incl. unvalidated and failing answers |
| N5 ⬜ | Relays: `dba:relay:forward`, egress at enrollment, `dba-hop+jwt`, inline and tunnel modes, `dba relay`, route verification | e2e through a local inline relay and a CONNECT relay; direct send with replayed hops denied by the egress check |
| N6 ⬜ | Webhook address check on `/authorize` (gate registry `purpose: "address"`, cache) | CI sample service allows and denies; unreachable and unpaid deny |
| N7 ⬜ | Server direction: audience `server_keys`, `rttEcho`, SDK/CLI `net.server` (addresses, route, latency) | CLI refuses a server outside its ranges; browser SDK times a signed echo and refuses unenforceable grants |
| N8 ⬜ | Sign-in and confirmation `net` settings; ID token `dba_net`; the account object's RTT nonce standing in for its D15 epoch nonce (§7.1.1); address lists, DNS and latency for `dba:*` grants on DBA's own API | Playwright: sign-in refused from an address outside the account's setting |
| N9 ⬜ | Tools and docs (§12) not already done per phase; SDK release | Every docs sample runs in CI |

## 13a. Where things stand

**Built (N1–N4).**

- N1: `net` in spec/evaluation.md §3.10 with its vectors; the evaluator in JS
  (`packages/verify/src/net.js`: `validateNet`, `checkNetClient`, `describeNet`; addresses in
  `ip.js`), Python (`net.py`) and Go (`grants_net.go`). Issuance validates `net` and sets `ver` 2
  only for credentials with it.
- N2: `rtt.js` (§7.1) and `createVerifier({ rtt })`: challenge, timing, best of `samples`, reuse
  for `reuse_s`. The browser SDK and CLI answer up to 3 timed challenges and use each timed nonce
  once; `dba headers`/`sign`/`curl` refuse credentials whose every grant is timed.
- N3: named address lists (§4), prices in §11, `createAddressListResolver` (60 s fresh, 10 min
  stale, no rollback, tombstones and expired copies match nothing) used by `createVerifier`
  by default; `/authorize` resolves them from R2.
- N4: `createDohResolver` (`dns.js`: DoH JSON API, A and AAAA, DNSSEC only when both answers
  carry AD, TTL bounded to 30–300 s, failures cached 5 s, at most 16 names per request) and
  `createVerifier({ dns })`.

**Gaps in what is built** (none blocks N5; each fails closed except the first):

- The JS verifier's default IP source is the `CF-Connecting-IP` header (§10). Off Workers a
  client can set it and pass an address rule, unless the caller passes
  `check.location.network.ip` from the socket. Needs a safe default or a required option, and
  `trustProxies`; until then the README and docs should say so.
- `/authorize` resolves address lists but not DNS names, so a grant that relies on `dns` alone
  denies online (`dns_unresolved`); it takes `rtt_ms` and the address from the relying party's
  `context.network`.
- DBA's own API does not resolve lists or DNS for `dba:*` grants (they deny there) [N8].
- `net.server` is accepted at issuance and, as designed, ignored by verifiers, but no SDK or CLI
  enforces it yet, so it protects nothing [N7]. Consider refusing it at issuance until then.
- Issuance accepts `route` and `webhook` grants; they deny everywhere until N5 / N6.
- Lists of other accounts and audience lists (§4 `kind: "audience"`) are refused at issuance.
- No CLI or dashboard editor for lists yet [N9].
- **SDK bundle is 65,454 of its 65,536-byte limit**: the next SDK change needs room first
  (minify whitespace in scripts/build-sdk.mjs, or keep `describeGrant` out of the bundle). No SDK
  release carries `net` support beyond v1.4.0's timed nonces [N9].

**Next: N5 relays** (or N6, whose price also waits on D17). Picking up N5 cold:

1. Spec first (spec/credential.md): the relay grant `dba:relay:forward` (add it to `DBA_SCOPES`
   in `src/services/first-party.js`, which also makes it an API-key scope; decide whether the
   relay names audiences as resources), `device.relay.egress` (CIDRs, ≤ 16), the `dba-hop+jwt`
   format and the `DBA-Route` / `DBA-Route-Credentials` headers (§6), plus signature vectors.
   The evaluator side already exists: it reads `context.route` / `context.route_error` (§8).
2. Issuance: accept `device.relay.egress` from the owner at enrollment approval (`cleanDevice`
   in `src/services/credentials.js` keeps only name, kind and key protection) and on
   `POST /api/v1/credentials`; refuse it without `dba:relay:forward`; same-account relays only
   (§14).
3. Verify library: a route verifier (§6.3) that parses the headers, verifies each relay
   credential through the same JWKS/status path as the device's, checks hop signatures, `iat`,
   `ath` against the device proof, `n` order and the egress chain against the peer address, and
   hands the evaluator `{ relays, origin, attested }` or a `route_error`. Python and Go take the
   result as context, as for lists.
4. `/authorize`: let the relying party pass the hops (its request headers) so DBA can run the
   same route verifier online.
5. CLI `dba relay`: an inline HTTP relay that appends its hop, and the tunnel hop endpoint
   (`GET /.well-known/dba-hop?ath=…`, §6.2). Exit criteria in §13.

## 14. Open questions for later

- Cross-account relays: may a credential name a relay owned by another account (e.g. a shared
  corporate gateway account)? Default in N5: same account only.
- Audience policy: may an audience's catalog **require** `net` rules on an action (as it can
  require gates), e.g. "publishing needs a route through our relays"? Likely yes, mirroring the
  gates plan's catalog policy.
- Private named lists evaluated only online, as a cheaper alternative to running a webhook.
- Whether to also accept origin ASN as a *weak* address source (not route evidence) for
  customers who know it is spoofable-by-VPN.
