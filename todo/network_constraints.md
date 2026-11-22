# Network constraints: address, route and latency

Status: STATUS **B10** (work), **D16** (owner's choices, 2026-11-19), **D17** (prices, open).
These were B8, D14 and D15 when first written; those IDs went to other items first.
Design summary in the master plan §3.6. This file is written to be picked up cold.

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

## 2. Decisions already made (D16, owner, 2026-11-19)

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
- **Browsers cannot see server addresses or choose relays.** The browser SDK enforces only the
  server latency rule; a grant whose `net.server` has addresses or a route is unusable from a
  browser (fails closed, with a clear reason at enrollment time).

## 3. Vocabulary

### 3.1 The `net` constraint

A new grant field, beside `when` and `where`. Old verifiers treat it as an unknown constraint
and deny (fail closed, spec/evaluation.md), so it can ship without breaking anything. Vocabulary
`ver` becomes 2 for credentials that use it.

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
- `where.networks` keeps working unchanged and is evaluated as today. New grants built by our
  tools use `net.client.addresses.cidrs` instead; the grant builder converts.

### 3.2 Addresses

| Source | Meaning | Who can enforce it |
|--------|---------|--------------------|
| `cidrs` | IPv4/IPv6 CIDR ranges, inline. ≤ 64. | Anyone |
| `lists` | Named address lists (§4), referenced by id and URI. ≤ 8. | Anyone (fetch and cache the list) |
| `dns` | Host names; the address must be one of their current A/AAAA answers. ≤ 16. `dnssec: true` requires a validated answer (DoH with the AD bit). | Anyone who can resolve DNS |
| `webhook` | A registered webhook (the gate registry's `webhook` kind, reused) that answers allow/deny for an address (§5). | DBA online only |

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
vouches for, or to an account that granted relaying to it (open question §12).

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

- Account-owned objects: `POST /api/v1/address-lists` (`adl_…` id, 128 random bits), `PUT` to
  replace the entries, `DELETE`. Up to 10,000 CIDRs per list, 50 lists per account. Scopes
  `networks:read` / `networks:write`; changes from the dashboard need a recent sign-in (as gate
  changes do), because widening a list widens every credential that names it.
- Published at `status.devicebasedauth.org/v1/addresses/{id}` as a signed JWT
  (`typ: dba-addresses+jwt`, issuer key, `iat`, `exp` = `iat` + 24 h, `ver` (monotonic),
  `cidrs` sorted). Republished at most once per 60 s per list (debounced, like status lists),
  `Cache-Control: max-age=60`, and once a day to roll `exp`.
- Verifiers fetch through the CDN, cache for at most `max-age`, and may serve a stale copy for up
  to 10 minutes when the fetch fails; after that the list is **unavailable** and its source
  matches nothing. A list with a lower `ver` than one already seen is ignored (no rollback).
- Deleting a list publishes a signed tombstone (`deleted: true`), which matches nothing. Every
  credential naming it denies through that source; the dashboard lists those credentials before
  the delete.
- Lists are readable by anyone who has the URI, which every audience shown the credential has.
  The UI says so ("this list of addresses is visible to the sites you use it with"). An account
  that wants its addresses private uses the webhook source instead.
- `kind: "audience"` lists: an audience may publish lists too (e.g. "hashbin's own relays"), so
  account owners can name them in grants. Same format, owned by the audience's account.

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
browser SDK (v1.4.0), the CLI and the samples already answer for D15 (§7.1.1 says how the two fit):

1. A request without a fresh RTT nonce gets `401` with `WWW-Authenticate: DPoP
   error="use_dpop_nonce"`, `DPoP-Nonce: <rtt nonce>` and, in the body, `dpop_nonce` and
   `rtt: { samples_left }`.
2. The **RTT nonce** is stateless: `base64url(t_ms ‖ jkt-hash ‖ peer-addr-hash ‖ HMAC)` keyed by a
   verifier secret. The verifier needs no storage; it reads its own issue time back.
3. The device immediately re-sends the request with a proof whose `nonce` is that value. The
   verifier computes `rtt = now_ms − t_ms` on its own clock (no clock sync with the device), and
   checks the HMAC, the `jkt` and that the peer address is the one the nonce was issued to.
4. With `samples > 1` the verifier repeats and keeps the minimum. `context.network.rtt_ms` is the
   result; the evaluator compares it.
5. A passing result may be remembered for `reuse_s` keyed by (`jkt`, peer address).

Notes:
- On Cloudflare Workers the clock advances between requests (it is frozen only *during* a
  request), so per-request timing is good to about a millisecond. Measured at the edge, it is
  the device-to-edge round trip; measured at an origin behind a proxy, it includes the proxy leg
  (stricter, never looser).
- A request that needs a new TCP/TLS connection for the retry measures more, never less: still
  fail-safe. SDKs keep the connection alive between challenge and retry.
- The challenge costs one extra round trip per request (or per `reuse_s`). Docs show it.

#### 7.1.1 One nonce per proof: fitting with D15

A proof carries one `nonce`, and since D15 a nonce can already be asked for for another reason:
DBA's account object asks for its own random epoch nonce (`dpn_…`) for its first 60 s, against
proof replay after a restart, and sends `DPoP-Nonce` on its responses. The two must not fight:

- **One challenge answers both.** A verifier that wants a replay nonce and a latency
  measurement issues only the RTT nonce. It is fresh, signed by the verifier and bound to the
  `jkt` and peer address, so it does a replay nonce's job too. A proof never needs two nonces.
- **DBA's own API** (sign-in and confirmation `net` settings, N8): when the account object needs
  a latency measurement, its challenge is an RTT nonce keyed by a secret of its own. It meets
  the D15 rule like the epoch nonce does when its `t_ms` is after the object started (it cannot
  predate the restart, so a proof captured before the restart still fails). Without a latency
  rule nothing changes: the epoch nonce as today.
- **Library.** `verifyProof`'s `nonce` option is an exact value today. N2 lets it also take a
  check function (`nonce: (value) => ({ ok, rtt_ms })`), so a stateless RTT nonce is checked by
  HMAC and age instead of equality; the exact value stays for D15-style nonces.
- **Clients.** The SDK and CLI keep the last `DPoP-Nonce` per origin, put it in every later
  proof, and retry once, and only for a nonce different from the one kept. RTT nonces are
  always new, so they pass that test, but two things change in N2:
  - Clients use an RTT nonce once (a challenge whose body has `rtt.samples_left`) and drop it
    after the exchange: kept for the next proof, it would time that request from this one, and
    the verifier cannot tell a reused nonce from a slow answer.
  - A kept RTT nonce is stale by the next request. The verifier answers it with a new
    challenge, not a denial, until `samples` attempts have failed, then denies
    `rtt_exceeded`. Clients follow `rtt.samples_left` (at most 3 retries), not just one.
  - Commands that hand a proof to another program (`dba headers`, `dba curl`, which ask
    `POST /api/v1/dpop-nonce` first for DBA's origin) cannot answer a timed challenge for
    another site. They refuse grants with `net.client.latency` and say so. A timed request
    needs a client that sends the request itself.
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
| `context.network.ip` | already today (platform, never client headers) |
| `context.network.rtt_ms` | §7.1 measurement, or absent |
| `context.address_lists` | `{ id: { cidrs, ver } \| "unavailable" }` for every list the credential names |
| `context.dns` | `{ name: { addrs, dnssec } \| "unresolved" }` |
| `context.address_webhook` | online only: `{ gat_…: true \| false }` |
| `context.route` / `context.route_error` | §6.3 |
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

- **IP source**: the verify library reads only `request.cf`/`CF-Connecting-IP` on Workers and the
  socket address in Node; a `trustProxies` option must be set explicitly to honour
  `X-Forwarded-For`, and then only from listed proxy ranges.
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

New operations for `src/utils/cost-policy.js` and prices for `src/utils/pricing.js`, each passing
the price-floor test. Numbers come from counting, then owner approval (D17):

| Operation | Worst case to count | Payer |
|-----------|--------------------|-------|
| Address list create / replace | DO write + R2 put (class A) + later republish(es) to roll `exp` for the list's life, prepaid like issuance prepays storage | Owning account |
| Address list daily republish | prepaid by the above; lists not renewed for 13 months stop being republished and expire (deny) | — |
| Webhook address check | a signed subrequest + DO cache write | Account that owns the webhook (the issuer) |
| Relay credential | ordinary issue / renew prices | Relay's account |
| CIDR, DNS, route and latency checks | verifier-side, free to DBA | — |
| Online decision with `net` | unchanged decision price (14 µ$) if counting shows no extra row writes | Audience |

List fetches are CDN-cached R2 reads like status lists (misses cost a class-B read and are
covered by the cost brake's free-path budget).

## 12. Spec, verifier and tools

- `spec/credential.md`: the `net` grant field, `device.relay.egress`, the `dba-addresses+jwt`,
  `dba-hop+jwt`, `dba-addrcheck+jwt` and `dba-rtt+jwt` formats, audience `server_keys`.
- `spec/evaluation.md` §3.10 `net`, with the context table of §8 and the reasons.
- Vectors in all three verifiers (JS, Python, Go): each address source alone and in union;
  `of: origin` with and without a route; unavailable list; stale list rollback ignored;
  unvalidated DNS with `dnssec`; route hop count, order, egress chain break, wrong `ath`,
  revoked relay, relay not listed; rtt missing / under / over / `samples` minimum; webhook
  offline → `online_required`; unknown `net` field → deny; `where.networks` unchanged.
  Signature vectors for hops, lists and RTT echoes.
- `@devicebasedauth/verify`: list fetch/cache, DoH resolver, route verification, RTT nonces,
  `site.rttEcho()`, `trustProxies`; browser copy and SDK bundle regenerated.
- SDK: answer RTT challenges without delay (keep-alive), time server echoes, evaluate
  `net.server`; refuse grants it cannot enforce in a browser. New SDK release.
- CLI: `dba relay` (run an inline relay or the tunnel hop endpoint), `dba address-lists
  list|create|set|delete`, `dba net test <aud>` (measures RTT, address and route as a verifier
  would see them).
- Site: address-list editor, relay enrollment (egress ranges), grant builder `net` section with
  measured signing time, inspector and playground render `net` in English ("only from
  203.0.113.0/24 or the addresses in 'Office', through relay 'HQ gateway', within 40 ms").
- Docs: a "Network constraints" page with CI-executed samples (an offline verifier enforcing
  address + RTT, a relay in front of a sample service, a webhook address service in Node and
  Python, a server adding `rttEcho`).

## 13. Phases

Each phase ends with `npm test`, `npm run lint`, samples and e2e green, docs regenerated, and its
STATUS row updated.

| Phase | Deliverable | Exit criteria |
|-------|-------------|---------------|
| N1 ✅ | Spec text and vectors for `net` (addresses inline + context-resolved lists/DNS, route context, rtt); evaluator in JS, Python, Go | Every new vector passes in all three; old `where.networks` vectors unchanged |
| N2 ✅ | RTT challenge in the verify library (nonce check function, retry, samples, reuse), the account object's RTT nonce standing in for its D15 epoch nonce, SDK/CLI following `samples_left`, `dba headers`/`dba curl` refusing latency grants (§7.1.1) | e2e: a device behind an injected 100 ms delay fails `max_rtt_ms: 40` and passes without it |
| N3 ⬜ | Named address lists: CRUD, signed publishing on R2, verifier fetch/cache/stale/rollback rules, D17 prices in cost policy | Changing a list changes an offline verifier's decision within 60 s + cache; cost-count test covers the new ops |
| N4 ⬜ | DNS source (DoH, DNSSEC flag, TTL bounds) | Tested against a stub resolver incl. unvalidated and failing answers |
| N5 ⬜ | Relays: `dba:relay:forward`, egress at enrollment, `dba-hop+jwt`, inline and tunnel modes, `dba relay`, route verification | e2e through a local inline relay and a CONNECT relay; direct send with replayed hops denied by the egress check |
| N6 ⬜ | Webhook address check on `/authorize` (gate registry `purpose: "address"`, cache) | CI sample service allows and denies; unreachable and unpaid deny |
| N7 ⬜ | Server direction: audience `server_keys`, `rttEcho`, SDK/CLI `net.server` (addresses, route, latency) | CLI refuses a server outside its ranges; browser SDK times a signed echo and refuses unenforceable grants |
| N8 ⬜ | Sign-in and confirmation `net` settings; ID token `dba_net`; the account object's RTT nonce standing in for its D15 epoch nonce (moved from N2: DBA's own API has no latency rule before this phase) | Playwright: sign-in refused from an address outside the account's setting |
| N9 ⬜ | Tools and docs (§12) not already done per phase; SDK release | Every docs sample runs in CI |

## 14. Open questions for later

- Cross-account relays: may a credential name a relay owned by another account (e.g. a shared
  corporate gateway account)? Default in N5: same account only.
- Audience policy: may an audience's catalog **require** `net` rules on an action (as it can
  require gates), e.g. "publishing needs a route through our relays"? Likely yes, mirroring the
  gates plan's catalog policy.
- Private named lists evaluated only online, as a cheaper alternative to running a webhook.
- Whether to also accept origin ASN as a *weak* address source (not route evidence) for
  customers who know it is spoofable-by-VPN.
