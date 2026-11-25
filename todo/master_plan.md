# devicebasedauth.org — master plan

Status of every item lives in [`STATUS.md`](../STATUS.md). Prices and the cost model live in
[`docs/business/pricing.md`](../docs/business/pricing.md). This file is the design, and describes
the system as built unless a passage says otherwise; it is written to be picked up cold.

devicebasedauth.org (DBA) is a pay-as-you-go service for **revocable, device-bound
authentication and authorization**. A customer (a signed-in DBA account) enrolls *devices*
— a browser profile, a phone, a laptop, a server, a script, an agent — and DBA issues each
one a signed **device credential**: a readable list of what the device may do, for which
site, when, and where, bound to a key that only the device holds. Any client or server can
read the credential; any server can verify it offline or ask DBA online. The customer can see
every credential they issued and revoke any of them at any time.

It is a sibling of [hashbin.org](https://github.com/curtcox/hashbin.org) and
[cronly.org](https://github.com/curtcox/cronly). When in doubt about a convention, do what
those repos do, and port their code (Clerk auth, scopes, Stripe deposits, ledger, local mode,
cost policy, route table) rather than rewriting it.

---

## 1. Principles

1. **Private keys never leave the device.** The device generates its key pair and sends only
   the public key. DBA never sees, stores, or transmits a device private key (decision D1).
2. **Credentials are readable.** Anyone holding a credential can decode it with one base64url
   decode and read plain JSON. The site, CLI and SDKs all have an "inspect" view.
3. **Deny by default; grants are explicit.** A device may do exactly what a grant in its
   credential names, under every constraint attached to that grant, and nothing else.
4. **Revocation is always possible and always prepaid.** The cost of revoking is collected when
   a credential is issued, so a customer with a zero balance can still revoke.
5. **No account can cost the service money.** Every billable operation reserves its maximum
   price from a prepaid balance before work begins. Everything free is static, cached, or
   rate-limited and bounded by the cost-safety brake. Every price passes the price-floor test
   (§8.2).
6. **Profit grows with volume.** Every metered operation has a positive margin, so total profit
   is `Σ(per-operation margin) − fixed costs` and rises monotonically with use.
7. **Developers and agents first.** Every action in the web UI has an API equivalent, every API
   has a copy-paste sample that CI actually runs, and the site has built-in tools for
   decoding, building and testing credentials.
8. **Standards over invention.** JOSE/JWT (RFC 7515/7519), DPoP (RFC 9449), OAuth device
   authorization grant (RFC 8628), OAuth/OIDC with PKCE, and the IETF OAuth Token Status List
   for revocation. The novel part is only the grant/constraint vocabulary, which ships with a
   written spec and conformance test vectors.

---

## 2. Concepts

| Term | Meaning |
|------|---------|
| **Account** | A DBA customer holding a prepaid balance (µ$): created by paying with a device (no password; STATUS B9, [done/clerk_free_accounts.md](../done/clerk_free_accounts.md)), or by signing in with Clerk. |
| **Device** | Anything that can hold a private key: browser profile, phone, desktop, server, CLI, CI job, AI agent. Identified by `dev_…` and its public-key thumbprint. |
| **Audience (relying party)** | A site or API that accepts DBA credentials, e.g. `hashbin.org`. Registers an **action catalog** (its vocabulary of actions). |
| **Action** | A namespaced verb from an audience's catalog: `hashbin:content:write`, `cronly:run`, `dba:credentials:issue`. |
| **Grant** | `{actions, resources, constraints}`. One credential carries one or more grants. |
| **Constraint** | A restriction on a grant: time windows, validity range, location, network, usage counts, spend caps. |
| **Device credential** | The signed document (a JWS) binding a device public key to grants for one or more audiences. Identified by `crd_…` (`cid`), stable across renewals. |
| **Proof** | A per-request signature made with the device's private key (DPoP proof JWT) showing the presenter holds the key the credential names. |
| **Status list** | A compressed bitstring published at a URL; bit *n* set = credential with status index *n* is revoked. |
| **Gate** | A device or service that must say yes before DBA allows an action (authorization gate) or trusts a sign-in or credential (authentication gate): the account owner, a DBA device, a TOTP app, a security key or passkey, a customer webhook, or Duo/Okta push (§6.4). |
| **Address list** | A named, account-owned set of CIDR ranges, published signed beside the status lists, that grants name so the addresses can change without reissuing (§3.6). |
| **Relay** | A DBA device that forwards a device's traffic (gateway, VPN egress, tunnel) and signs a hop record for each request it carries, so a grant can require a route through it (§3.6; designed, not built yet). |
| **Enrollment** | The flow that gets a device's public key to DBA and the account owner's approval back, ending in an issued credential. |

---

## 3. The device credential

### 3.1 Format (decision D2)

A compact JWS (`header.payload.signature`, ES256 / P-256). Chosen because:

- the payload is plain JSON after one base64url decode — readable by any client or server;
- every language has a mature verifier; Cloudflare Workers and browsers verify ES256 natively
  with WebCrypto;
- hashbin's ES256 DPoP code carries over.

For mTLS (IoT hardware, Cloudflare API Shield) a device can also get a short-lived (≤ 24 h) X.509
client certificate over its own key (`POST /api/v1/certificate`, spec/credential.md §6a, B3). It
carries no grants or revocation; the JWS stays the primary format.

### 3.2 Example

Header:

```json
{ "typ": "dba-device+jwt", "alg": "ES256", "kid": "dba-2026-11" }
```

Payload:

```json
{
  "iss": "https://devicebasedauth.org",
  "sub": "dev_01JD3W6Q8Y9XGZ7M2C4B5N6P7R",
  "acct": "acct_01JD3V2K…",
  "aud": ["hashbin.org"],
  "cid": "crd_01JD3W7A…",
  "jti": "crd_01JD3W7A….1",
  "iat": 1795017600,
  "nbf": 1795017600,
  "exp": 1797609600,
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  "device": { "name": "Curt's laptop — Firefox", "kind": "browser", "key_protection": "webcrypto-nonextractable" },
  "grants": [
    {
      "actions": ["hashbin:content:write", "hashbin:uploads:read"],
      "resources": ["*"],
      "when": {
        "tz": "America/Chicago",
        "windows": [{ "days": ["mon", "tue", "wed", "thu", "fri"], "from": "08:00", "to": "18:00" }]
      },
      "where": {
        "source": "network",
        "countries": ["US"],
        "areas": [{ "lat": 38.627, "lon": -90.199, "radius_m": 50000 }]
      },
      "limits": { "spend_usd_per_month": 5.00 }
    }
  ],
  "status": { "status_list": { "idx": 48213, "uri": "https://status.devicebasedauth.org/v1/lists/7" } },
  "ver": 1
}
```

Rules:

- `cnf.jkt` is the RFC 7638 thumbprint of the device public key; the full JWK is returned
  alongside the credential and is recomputable from any proof.
- `aud` lists every audience the credential is valid for. Verifiers must require their own
  audience and ignore grants whose action namespace is not theirs.
- `exp` is required. Default lifetime 30 days; minimum 5 minutes; maximum 400 days. Short
  lifetimes plus automatic renewal (§5.4) bound revocation latency for offline verifiers.
- `cid` names the credential across renewals (revoking it revokes every version); `jti` is
  `<cid>.<version>`.
- Unknown constraint types make the grant **deny** (fail closed), so new constraint kinds can
  be added without old verifiers silently over-granting. `ver` is the vocabulary version: `2`
  when any grant has `net` (§3.6), else `1`. The full format is `spec/credential.md`.
- The credential is not secret (it is useless without the private key) but it *does* reveal
  device names and geofences to every audience it is shown to. The issuing UI says so, and
  offers coarse geofences and generic device names (privacy note, §10).

### 3.3 Grant and constraint vocabulary (v1)

| Field | Meaning | Who can enforce it |
|-------|---------|--------------------|
| `actions` | Exact action names or a trailing-`*` prefix (`hashbin:content:*`). | Anyone |
| `resources` | Opaque, audience-defined resource patterns (`*`, `job:nightly-*`, a 256t CID). | The audience |
| `when.windows` | Days of week + local time ranges in an IANA time zone, evaluated against the **verifier's** clock. | Anyone |
| `when.not_before` / `not_after` | Absolute instants narrower than the credential's `nbf`/`exp`. | Anyone |
| `where.source` | `network` (verifier observes request location, e.g. Cloudflare `request.cf`), `device` (device asserts location in its signed proof), or `both`. | See §3.5 |
| `where.countries` / `regions` / `areas` | ISO 3166 codes and circles (lat, lon, radius). | Verifier |
| `where.networks` | CIDR ranges the request must come from. Kept as is; new grants use `net.client.addresses.cidrs`. | Verifier |
| `net.client.addresses` | The device's address must be allowed by inline CIDRs, named address lists, DNS names, or the customer's webhook (any one) (§3.6). | Verifier; webhook DBA online |
| `net.client.route` | The request must arrive through listed relay devices, each signing a hop bound to the request (§3.6). | Verifier |
| `net.client.latency` | The device must answer a timed challenge within `max_rtt_ms` (§3.6). | Verifier |
| `net.server` | The same three rules about the relying party, enforced by the device before it sends (§3.6). | The device (SDK, CLI) |
| `require.attestation` / `verified_boot` / `app_ids` | The device key must carry platform attestation (`hardware`, `strongbox`), a verified boot state, or come from listed apps (§3.5). | Anyone (signed `device.attestation`) |
| `limits.uses` | Max uses per period. Needs a counter → **online authorization only** (§6.2). | DBA online |
| `limits.spend_usd_per_month` | Passed to the audience as a caveat (maps to hashbin/cronly spending caps). | The audience |
| `require.online` | Forces online authorization for every use (instant revocation, usage counters, audit). | DBA online |
| `require.step_up` | The action needs a fresh user approval (push/passkey) at use time. Same as `require.gates` with the `owner` gate. | DBA online |
| `require.gates` | Gate entries that must each approve the use; deny on no answer unless the entry says `on_timeout: "allow"` (§6.4). | DBA online |
| `require.confirmation` | The credential's top-level `confirm` block applies: it authenticates only with a recent confirmation from its gates (§6.4). | Anyone (signed confirmation) |

### 3.4 Evaluation algorithm

Written as `spec/evaluation.md` with JSON test vectors in `spec/vectors/` that every
implementation (`packages/verify`, `packages/verify-python`, `packages/verify-go`, and the sites
that vendor the JS one) must pass in CI:

1. Verify JWS signature against the issuer JWKS (`kid`), `typ`, `iss`, `aud`, `nbf ≤ now < exp`
   (60 s skew).
2. Verify the DPoP proof: signature by the key whose thumbprint is `cnf.jkt`, `htm`/`htu` match the
   request, `iat` within ±60 s, `ath` = hash of the credential, `jti` not replayed (verifier-local
   cache), nonce if the verifier requires one (a server nonce, or a timed one for latency, §3.6).
3. Check revocation: status-list bit for `status.status_list.idx` (cached ≤ TTL) — or online.
4. For a credential with a `confirm` block, check its `DBA-Confirmation` (§6.4).
5. Find any grant whose action matches **and** every constraint passes. If none, deny with the list
   of reasons per grant (shown in dev tools; logged, not returned to anonymous callers). Anything
   that needs I/O (address lists, DNS answers, a timed round trip) is resolved by the verifier
   first and handed to the pure evaluator as context.

### 3.5 Location — what can actually be trusted (decision D4)

Location is the weakest constraint and the plan says so in the docs:

- **`network`**: the verifier uses where the request appears to come from. On Cloudflare this is
  `request.cf.country/region/latitude/longitude`. Spoofable with VPNs/proxies; country-level is
  reasonably reliable, city-level is approximate.
- **`device`**: the device includes `loc: {lat, lon, acc_m, t}` in its signed proof. Only as honest
  as the device and its owner; meaningful for managed/attested devices.
- **`both`**: both must pass.

Attestation of the device key raises trust in the device itself: Android Key Attestation, Apple
App Attest and TPM 2.0 (Microsoft AIK, or EK credential activation) are checked at enrollment and
signed into `device.attestation` (spec/credential.md §3a), which grants can require
(`require.attestation`, `verified_boot`, `app_ids`). Live checks on real hardware are still open
(B5); Android Play Integrity is not offered (D10). Attestation says nothing about a device-reported
location beyond "the key is in hardware of this kind".

### 3.6 Network constraints — address, route, latency (decision D16)

Detailed plan: [`todo/network_constraints.md`](network_constraints.md) (STATUS B10; owner's
choices D16, prices D17). Where `where` constrains the *place*, `net` constrains the
*connection*: when present, communication is valid only if the other end of the connection

- **address**: has an address an allowlist accepts: inline CIDRs, **named address lists** owned
  by the account and published signed and CDN-cached like status lists (editable without
  reissuing), **DNS names** resolved by the verifier (optionally DNSSEC-validated), or a
  **customer webhook** (online only). Any one source may allow;
- **route**: reached the verifier through allowed **relay devices** (DBA-enrolled gateways, VPN
  egresses, tunnels) that each sign a `dba-hop+jwt` bound to the request's DPoP proof, with the
  last relay's registered egress range containing the address the verifier sees;
- **latency**: answered a **timed challenge** within `max_rtt_ms`. The challenge is a stateless
  DPoP server nonce carrying its issue time, so the verifier times the round trip on its own
  clock with no storage. Upper bound only: distance cannot be faked downwards.

Both directions (D16): `net.client` is checked by the verifier about the device; `net.server` is
checked by the device's SDK or CLI about the relying party (its connected address, its relays,
and a signed `DBA-RTT` echo from the audience's registered server keys) before the credential is
sent. Server-direction rules protect the device, never the relying party; browsers can enforce
only the latency one. Everything except the webhook works offline and costs DBA nothing; old
verifiers deny `net` as an unknown constraint. These are evidence about the connection, not
identity: an allowed address or VPN exit passes the address rule, a compromised relay key forges
hops until revoked, and latency stops a credential relayed from afar, not a stolen key used
nearby.

Built so far: the whole `net` vocabulary in the spec, vectors and all three evaluators; inline
CIDRs; named address lists (`/api/v1/address-lists`, published at
`status.devicebasedauth.org/v1/addresses/{id}`, enforced offline and in `/authorize`); DNS names
(DoH in the verify library); client-direction latency (timed nonces in the verify library, SDK
and CLI). Not built yet: relay hops and the webhook address source (grants that need them
deny), `net` settings for sign-in and confirmations, and the device side of `net.server`
(accepted at issuance and ignored by verifiers, as designed, but no SDK or CLI enforces it yet,
so today it protects nothing). What is left, phase by phase, is in the plan's §13a.

---

## 4. Architecture

```
                         devicebasedauth.org (Cloudflare)
┌──────────────────────────────────────────────────────────────────────────┐
│ dba-worker-prod  (src/, frontend/)                                       │
│  API_ROUTES · Clerk sessions · Stripe webhooks · OIDC provider · cron    │
│  issuance & renewal · online /authorize · dev tools · static site        │
│                                                                          │
│  Durable Objects (SQLite)                                                │
│   AccountDO     one per account: balance (µ$), ledger, API keys,         │
│                 devices, credentials, usage counters, gates and gate     │
│                 requests, address lists, settings, recovery, audit       │
│   StatusListDO  one per shard: allocates indexes, holds bits, publishes  │
│   RegistryDO    audiences, action catalogs, OIDC redirect URIs,          │
│                 verified-email index                                     │
│   EnrollmentDO  one enrollment's outcome, for the device's poll (1 h)    │
│   SafetyDO      cost measurement + safety brake                          │
│                                                                          │
│  R2 dba-status-prod → status.devicebasedauth.org (CDN-cached, public)    │
│     /v1/lists/{n}       status lists (signed JWT, zlib bitstring)        │
│     /v1/addresses/{id}  named address lists (signed JWT)                 │
│  Static: /.well-known/jwks.json, /.well-known/openid-configuration,      │
│          /.well-known/dba-ca.pem, /openapi.json, /llms.txt,              │
│          /sdk/vX.Y.Z/dba.js (immutable, SRI)                             │
└──────────────────────────────────────────────────────────────────────────┘
        ▲ enroll / renew / authorize            ▲ JWKS + status lists (cached)
        │                                       │
   devices (browser SDK, CLI, mobile)     relying parties: devicebasedauth.org itself,
                                          hashbin.org, cronly.org, subetha.us,
                                          customer sites
```

- **Issuer signing keys**: ES256 keys in one Worker secret, `ISSUER_KEYS` (a JSON list of
  `{ kid, jwk }`); the first key that is neither `retired` nor `withdrawn` signs, retired keys stay
  in the JWKS so older credentials keep verifying, and withdrawn (compromised) keys are trusted
  nowhere. A compromised issuer key is the worst-case incident: runbook in
  `docs/ops/issuer-key-compromise.md` (withdraw the key, sign with a new one, let live devices
  renew the credentials the withdrawn key signed — "mass force-renew", S9). Moving the signing key
  to an external KMS/HSM is S6 — it adds a per-signature cost and a network hop.
- **Status lists** use the IETF OAuth Token Status List encoding (1 bit per credential, zlib,
  base64url, wrapped in a signed JWT). Each shard holds 262,144 indexes (32 KiB of bits);
  `STATUS_SHARDS` sets how many shards are in use, and a daily alert warns before they fill.
  Revocations are debounced into at most one publish per 30 s per shard, lists are re-signed
  every 12 h, and served with `Cache-Control: max-age=60`. Published through an R2 custom domain
  so cache hits cost nothing and misses cost one class-B read; the Worker also serves them at
  `/status/v1/lists/{n}`.
- **No server-side private device keys, no device secrets in storage.** The DO stores public
  JWKs, credential payloads, and history.
- **Time zones**: windows are evaluated with the IANA data in the runtime (`Intl`); DST edge cases
  get test vectors (port cronly's DST tests).

---

## 5. Device lifecycle

### 5.1 Enrollment flows

All flows end the same way: the account owner approves **a specific public key** with
**specific grants** on a devicebasedauth.org page, and DBA issues the credential.

| Flow | For | How |
|------|-----|-----|
| **Browser SDK** | Web pages, PWAs | `dba.js` generates a non-extractable P-256 key with WebCrypto, stores the `CryptoKey` in IndexedDB, opens an approval popup on devicebasedauth.org (like hashbin's approve-each-save), receives the credential by `postMessage`. The site requests grants; the user can narrow them before approving. |
| **Device approval (modelled on RFC 8628)** | CLI, servers, agents, TVs, IoT | `dba enroll --aud hashbin.org --grant 'hashbin:content:write'` generates a key (OS keychain or TPM where available, else a 0600 file; S13), signs a `dba-enroll+jwt` request and prints the approval URL. The owner approves on any signed-in browser; the CLI polls and saves the credential. |
| **Mobile** | iOS/Android apps | Same as device approval or an in-app browser; key in Secure Enclave / Android Keystore (`key_protection` recorded, attested where possible, §3.5). Sample apps in `docs/samples/android/` and `docs/samples/ios/` (S4). |
| **API (pre-approved)** | Fleets, CI, agents provisioned by an already-trusted device | `POST /api/v1/credentials` with a public key and grants, authorized by an account API key or a DBA credential holding `dba:credentials:issue` (whose own grants bound what it may delegate — a device can never issue more than it holds). |
| **Enrollment token** (B2) | Fleets whose machines make their own keys: kiosks, CI runners, IoT | The owner approves a template once (`POST /api/v1/enrollment-tokens`: audiences, grants, lifetime, max uses, expiry); each device signs its own enrollment request and redeems it with the `dbae_` token (`POST /api/v1/enrollments/redeem`), narrowing but never widening the template. |
| **Agent request** | AI agents | Agent calls `POST /api/v1/enrollments` with its public key and the grants it wants; DBA returns an approval URL for the human. Approval can narrow grants and add spend caps. Same as device approval, exposed through the MCP server (§7.4). |
| **Sign-up** (B9) | A new owner with no account | The device signs an enrollment request and pays the first deposit (`POST /api/v1/signup`, `/signup.html`, `dba signup`, SDK `signUp`); the signed Stripe webhook creates the account and the device gets a dashboard credential (`POST /api/v1/signup/complete`). No Clerk user is made ([done/clerk_free_accounts.md](../done/clerk_free_accounts.md)). |

Anonymous enrollment starts are **stateless**: the pending request (public key, requested
grants, expiry) is an HMAC-signed blob carried in the approval URL and poll token, so a flood of
unauthenticated starts writes nothing and costs only rate-limited Worker requests. Storage is
written once, at approval, and billed to the approving account.

### 5.2 Viewing credentials

The dashboard and the API (`GET /api/v1/credentials`, `GET /api/v1/credentials/{id}`) show:

- every device and credential with status (active / expired / revoked / superseded), audience,
  expiry and last renewal;
- a detail page with the **decoded payload**, the grants rendered in plain English
  ("may publish content on hashbin.org on weekdays 08:00–18:00 Chicago time, from the US,
  up to $5/month"), the raw JWS, public key thumbprint, issuance/renewal/revocation history,
  and (for online-authorized grants) recent decisions and usage counts;
- filters, CSV/JSON export, and a "what can this device do right now?" evaluation.

### 5.3 Revocation

- Revoke one credential, every credential of a device, every credential for an audience, or
  everything on the account (panic button). API and UI.
- Effect: status bit set immediately in the DO (online `/authorize` sees it at once), published
  to the status list within about 30 s, visible to offline verifiers within that plus the CDN's
  60 s and their own cache TTL (docs recommend ≤ 5 min). Also pushed to registered audiences by
  signed webhook (optional). Revoking a credential also revokes what it delegated.
- Revocation is free at the point of use; its worst-case cost is included in the issue price.

### 5.4 Renewal and rotation

- Devices renew before `exp` with `POST /api/v1/credentials/{id}/renew`, authenticated by a DPoP
  proof from the same key. Grants cannot widen on renewal. Renewal is metered (cheaper than
  issue). The SDK and CLI renew automatically at 2/3 of lifetime.
- Key rotation: the device proves possession of both old and new keys (a DPoP proof by the old
  key and a `dba-rotate+jwt` by the new one); the credential keeps its `cid`, gets a new status
  index, and the old index is revoked. Rotation is priced as an issue.
- Budget guards in account settings: issuances per day (default 500) and renewals per credential
  per month (default none) against runaway devices.

---

## 6. Verification

### 6.1 Offline (free, recommended default)

Relying parties verify locally with `@devicebasedauth/verify` (zero-dependency ES module that
runs in Workers, Node, Deno, Bun, browsers) or any JOSE library plus the spec:

```js
import { createVerifier } from '@devicebasedauth/verify';
const dba = createVerifier({ audience: 'hashbin.org' });
const result = await dba.verifyRequest(request, { action: 'hashbin:content:write', resource: cid });
if (!result.allow) return Response.json({ error: 'forbidden', reasons: result.reasons }, { status: 403 });
```

It fetches and caches the JWKS and status lists (both CDN-served; cache hits cost DBA nothing).
Offline verification cannot enforce `limits.uses`, `require.online`, `require.step_up` or
`require.gates`; grants with those constraints deny offline and tell the verifier to go online.
A credential with periodic confirmation (§6.4) also needs a current `DBA-Confirmation`, which
offline verifiers check for free. Network constraints (§3.6) are enforced offline by the verifier
itself (address lists and DNS fetched and cached, latency by a timed DPoP nonce with
`createVerifier({ rtt })`, and, once built, relay hops checked like credentials); only the
webhook address source needs online authorization, to which the relying party passes the peer
address and measured round trip. Audiences whose catalog requires gates (§6.4) are handled with
`createVerifier({ catalog: true })`. The same verifier exists for Python
(`packages/verify-python`) and Go (`packages/verify-go`).

### 6.2 Online (`POST /api/v1/authorize`, metered)

Request: credential, DPoP proof (or the original request's method/URL/headers), action, resource,
context. Response: `{ allow, code, grant_index, reasons, expires_in, … }` (plus `gate_request`
while gates are pending). Gives instant revocation, usage counters, gates, and a per-decision
audit trail the customer can view. Billed per decision to the **audience's** account (decision
D3). An allow without counters or gates may be cached by the caller for `expires_in` (30) seconds.

### 6.3 Short-lived access tokens for curl-only scripts

A device can exchange its credential (with a proof) for a ≤ 10-minute bearer access token for one
audience: `dba token --aud hashbin.org` prints it, so shell scripts can do
`curl -H "Authorization: Bearer $(dba token --aud hashbin.org)"`. This trades key binding for
convenience only for minutes. Audiences decide whether to accept these tokens.

### 6.4 Additional gates (authentication and authorization)

Detailed plan: [`done/additional_gates.md`](../done/additional_gates.md) (STATUS B7; owner's choices D12,
prices D13). Generalizes `require.step_up`.

- **Authorization gate**: *this action is allowed as long as it is approved by this device or
  service.* A grant's `require.gates` lists entries; each entry names 1–5 gates (any one may
  answer), a timeout and what happens on no answer. All entries must allow. Online only.
- **Authentication gate**: *this identity is trusted as valid as long as it is confirmed by this
  device or service.* Applied at sign-in (Sign in with DBA, §9.2, and the DBA dashboard, which
  then needs recovery codes) and optionally over time: a credential with a `confirm` block works
  only while the device holds a confirmation (a short-lived `dba-confirmation+jwt` signed by the
  issuer) no older than `every_s`, so offline verifiers enforce it for free.
- **Gate kinds**: the account owner (step-up), a named DBA device answering with its own
  key, TOTP authenticator apps, WebAuthn security keys and passkeys, a customer webhook service
  (asymmetric signatures both ways), Duo Push and Okta Verify.
- **Fail closed by default**: a deny, or no answer before the timeout, denies. An entry may opt
  into `on_timeout: "allow"`; then no answer by the deadline allows, whether the approver stayed
  silent or could not be reached (D12). This is a veto window, not a check: anyone who can keep
  the gate from answering gets through after the wait. Every allow by timeout is audited,
  announced to the owner, and marked in the decision (`by: "timeout"`), the confirmation
  (`by_timeout`) and the ID token (`acr`). An explicit deny, a deleted gate, or a gate the
  audience's policy rejects always denies; allow-on-timeout is never answerable inline by the
  person it gates.
- **Audiences decide too**: an action catalog entry (or OIDC client) can require gates, limit
  their kinds, and forbid allow-on-timeout (`fail_open: false`). Account owners can add gates but
  never weaken an audience's policy; offline verifiers load the catalog and go online for gated
  actions.
- **Secrets**: TOTP seeds and Duo/Okta API credentials are sealed with a rotatable Worker key and
  never returned or logged. Device private keys still never reach DBA.
- **Money**: each gate contacted is a prepaid operation billed to the account whose gates they
  are; the audience still pays the decision. A gate request the owner cannot pay for is not sent
  and counts as unreachable.

---

## 7. Developer and agent surface

### 7.1 API conventions (ported from cronly)

- REST + JSON under `/api/v1/`; every route declares its access in `API_ROUTES` (`src/index.js`,
  the only dispatch table): `PUBLIC`, `SESSION` (a dashboard session), `DEVICE` (any valid device
  credential: renew, token, certificate, confirm), `AUTHENTICATED` (any caller), or a scope; a
  test fails for any undeclared route. Routes also declare `billable` (the price they charge),
  `free` (public work the cost brake stops) and `idempotent`.
- Errors `{ error, code, ... }`; `402` for balance refusals. `Idempotency-Key` makes a retried
  credential issue or checkout return the first result; enrollment approval, sign-up completion
  and recovery are idempotent by their own ids. Billable responses carry
  `X-DBA-Cost-Microdollars` and, for callers allowed to read it, `X-DBA-Balance-Microdollars`.
- `GET /api/v1/quote` and `?dry_run=1` on every billable route return the price without charging.
- OpenAPI 3.1 at `/openapi.json`, generated from `API_ROUTES`; a drift test keeps it honest.
- DPoP server nonces (RFC 9449 §8, D15): an account's object that has just started asks proofs
  made before it started for its own nonce (`401 use_dpop_nonce`, `DPoP-Nonce`), so a proof
  captured before a restart cannot be replayed; clients ask `POST /api/v1/dpop-nonce` or retry
  once with the nonce.
- Credentials accepted: Clerk session (web), `LocalDev` (local mode only), account API key
  (`dbak_…`, scoped), MCP OAuth access tokens, or a DBA device credential + DPoP proof holding
  `dba:*` actions — DBA is its own first relying party.

### 7.2 Built-in developer tools (pages on the site)

| Tool | What it does |
|------|--------------|
| **Credential inspector** | Paste a JWS: decodes header/payload, verifies signature against the live JWKS, checks revocation, renders grants in English. Runs entirely in the browser. |
| **Grant builder** | Form → grant JSON (with map picker for areas, time-window editor, action picker from each audience's catalog) → copyable `curl`, JS and CLI to request it. |
| **Policy playground** | Credential + action + resource + simulated time/location → allow/deny with per-constraint reasons. Uses the same evaluator as production. |
| **Request signer** | Generates a throwaway key in the browser, builds a DPoP proof for a given request, shows the exact headers. |
| **API explorer** | Try every endpoint against your account; anything that costs money can be sent as a dry run that only quotes. Against a local server nothing is real. |
| **Cost calculator** | On the pricing page: devices × renewals × online decisions → monthly cost, from the same constants as billing. |
| **Audience console** | In the dashboard, for site operators: register an audience, publish an action catalog with gate policies, set OIDC redirect URIs (public clients with PKCE), see online decisions, sign-ins and spend per month. |

### 7.3 SDKs, CLI and samples

- Browser SDK (source `packages/browser-sdk/`, bundled to `frontend/sdk/dba.js`) — versioned,
  immutable releases under `frontend/sdk/vX.Y.Z/` pinned with SRI (hashbin's model; latest
  v1.4.0): `enroll()`, `fetch()`/`headers()` (credential, DPoP, confirmation; answers server
  and timed nonces), `fetchWithGates()`, `renew()`/`autoRenew()` (at 2/3 of lifetime),
  `confirm()`, `token()`, `revoke()`, `describe()`, `signUp()`, `recover()`.
- `packages/verify` — the verifier (§6.1), with Python and Go ports in `packages/verify-python`
  and `packages/verify-go`. Publishing to npm, PyPI and a Go tag is an owner step (L14, S5).
- `packages/cli` — `dba` CLI (Node 22, no dependencies beyond the verifier): `enroll`, `signup`,
  `recover`, `status`/`whoami`, `list`, `inspect`, `import`, `headers`, `sign`, `curl` (a curl
  wrapper that adds the headers), `token`, `certificate`, `renew`, `revoke`, `confirm`,
  `approvals`, `gates`. It renews at 2/3 of lifetime before use.
- Samples for curl, JavaScript (browser, Node, Workers), Python, Go, Android, iOS and TPM.
  **Every sample is a file under `docs/samples/` executed in CI against local mode**; docs code
  blocks marked `data-sample` are checked against those files so they cannot drift.

### 7.4 Agents

- `/llms.txt` and `/llms-full.txt` summarizing the API, flows and pricing.
- An MCP server (`/mcp`, remote, OAuth-protected per the MCP authorization spec) exposing:
  request a credential (returns an approval URL), list/get/inspect/revoke credentials, balance,
  quote, evaluate grants, and list and answer gate requests (as a device's own gate only).
- Agent-oriented defaults: short lifetimes, spend caps, `require.online` so the human sees every
  decision.

---

## 8. Money

### 8.1 Model

cronly's ledger, ported: integer micro-dollars (µ$), prepaid balance, no subscription, no
negative balances, reserve-max-then-settle, verified Stripe webhook credits only, $5 minimum
deposit with the card fee itemized on top (`ceil((credit¢ + 30) / 0.971)`), first-week $20
per-checkout cap, $1,000 maximum per deposit, unused credit never expires while the account
exists.

### 8.2 Price-floor rule

`price × revenueKept (0.92) ≥ 1.5 × worst-case marginal cost`, enforced by a unit test over every
price constant, with rates in `src/utils/cost-policy.js` and prices in `src/utils/pricing.js`
only. Prices and the cost derivation are in
[`docs/business/pricing.md`](../docs/business/pricing.md). Approved by the owner: D6, D11, D15
(the DPoP nonce challenge's floors) and D9 (security email); gate and confirmation prices are
proposed (D13), address-list prices too (D17). Summary (`PRICES` in `src/utils/pricing.js`):

| Operation | Price | Who pays |
|-----------|-------|----------|
| Issue or rotate a credential (includes prepaid revocation, 13 months of record storage and their later deletion) | 87 µ$ | Issuing account |
| Renew (same key) | 25 µ$ | Issuing account |
| Online authorization decision | 14 µ$ ($14 per million) | Audience account |
| OpenID Connect sign-in | 14 µ$ | Audience account |
| Metered API reads (API keys, non-dashboard devices), token exchange, X.509 certificate | 7 µ$ | Caller / issuing account |
| Register or change an audience | 100 µ$ | Audience account |
| Gate request, per gate contacted: local kinds / webhook / Duo or Okta Verify (proposed, D13) | 22 / 23 / 30 µ$ | Account that owns the gates |
| Confirmation issued (proposed, D13) | 14 µ$ | Issuing account |
| Security email (D9) | 200 µ$ | Account it is sent to |
| Named address list create or replace, per started 1,000 ranges, plus per day of published life it adds (proposed, D17) | 242 µ$ + 15 µ$/day | Owning account |
| Offline verification, JWKS, status lists, address lists, web UI reads, revocation, dev tools | Free (cached / rate-limited) | — |

### 8.3 Why no account can cost money

- Every metered call reserves its price before work.
- Free paths are static files, CDN-cached R2 objects, or session-only UI reads behind per-account
  and per-IP rate limits; anonymous enrollment writes nothing (§5.1).
- Revocation is prepaid; record storage is prepaid for 13 months, after which expired records are
  dropped from DO storage by a weekly compaction whose deletes the issue price also prepays
  (revoked devices, deposits and daily/monthly summaries are kept; there is no archive, whose
  per-run write would cost more than the records).
- **Clerk monthly retained users** are the one per-user cost not tied to an operation (free up to
  50,000 MRU). Mitigations: after first sign-in, users can sign into the DBA dashboard with their
  own DBA browser credential (no Clerk session, so no MRU); accounts created by paying with a device
  never become Clerk users (STATUS B9). Closing accounts with zero balance and no live
  credentials after 12 months idle, after notice, is decided in principle (D8) but not built.
- The cost-safety brake (`SafetyDO`, ported from hashbin/cronly): an hourly cron measures cost
  from Cloudflare analytics, alerts at a projected month-end variable cost, then latches a brake
  that stops the free public paths (`free: true` routes) while paid operations keep working.

---

## 9. Integrating the sibling sites

devicebasedauth.org, hashbin.org, cronly.org and subetha.us are the **first-party audiences**
(`FIRST_PARTY` in `src/services/first-party.js`, seeded into the registry and owned by the
operator account). Each catalog mirrors the site's own scope list (hashbin `USER_SCOPES` →
`hashbin:content:write` …; cronly scopes → `cronly:run` …; subetha's token scopes →
`subetha:publish`/`subetha:subscribe` with topics as resources), so a DBA grant maps 1:1 onto
the scope checks the sites already make. `<ns>:session` means "may sign in to the site's web UI".
Progress per site: STATUS S1 (cronly), S2 (hashbin), S15 (subetha).

### 9.1 DBA-issued API keys (device-bound) on each site

Goal: on each site's "API keys" page, a **"Create a device key with devicebasedauth.org"** button,
and the same thing from a terminal with `dba enroll --aud cronly.org`.

Changes in each site repo (DBA does this natively):

1. Vendor `@devicebasedauth/verify` (pinned version, no runtime fetch of code).
2. Add a credential kind `dba` to the auth middleware: `Authorization: DBA <credential>` +
   `DPoP: <proof>`. Verify offline; go online only for grants that demand it.
3. Map the grant's actions to the site's scopes; map `limits.spend_usd_per_month` onto the site's
   existing spending caveat (hashbin `monthly_spend_limit_cents`, cronly key budgets).
4. **Account linking**: the DBA credential names a DBA account (`acct`); the site must know which
   local account that is. A signed-in user links once via "Link devicebasedauth.org" (an OIDC
   round-trip, §9.2) and the site stores `dba_acct → local user`. Credentials from unlinked DBA
   accounts are refused.
5. Keep existing `hbk_`/cronly keys working; DBA keys are an additional credential kind. Tests:
   the shared conformance vectors plus each site's route-table access tests with the new kind.
6. Optionally accept §6.3 short-lived bearer tokens.

### 9.2 "Sign in with devicebasedauth.org" on each site

DBA is an OpenID Connect provider (authorization code + PKCE, public clients whose redirect URIs
are registered on the audience, `/.well-known/openid-configuration`). The ID token includes the
DBA account (`acct`), the device (`dev`, `device_name`), the login credential (`cid`), and, with
sign-in gates (§6.4), `amr`, `acr` and `dba_gates`. Two stages:

- **Stage A — fast**: register DBA as a custom OIDC provider in each site's Clerk application.
  Users get a "devicebasedauth.org" button next to Google/GitHub with almost no site code.
  Limitation: after login the site session is an ordinary Clerk session, so revoking the device
  does not end it (only stops future logins). Needs the sites' Clerk plan to support custom
  OIDC providers (D7). A site may instead run the OIDC flow itself without Clerk, as subetha.us
  does.
- **Stage B — device-bound sessions**: the site's frontend uses `dba.js`; each API call carries
  the device credential + proof (§9.1), so revoking the device ends access within the status-list
  TTL. Page-level authorization uses the same grants (e.g. hide the publish button if the device
  lacks `hashbin:content:write`).

devicebasedauth.org dogfoods Stage B: its dashboard runs on a DBA browser credential ("use this
browser as a device"), after a Clerk sign-in or from sign-up.

### 9.3 Billing across sites

Decided (D3, D5): every site keeps its own separate balance and Stripe product.
DBA charges **the account that issues** for issue/renew, and **the audience operator** for online
decisions and OIDC sign-ins. The sibling sites verify offline, so their users pay DBA (from their DBA balance) only
for issuing and renewing device keys for those sites. There is no shared wallet.

### 9.4 Rollout order

1. DBA itself (dashboard, issuance, revocation, inspector, verify library).
2. cronly (newest codebase, closest conventions, micro-dollar ledger already).
3. hashbin (largest auth surface: API keys, OAuth/DPoP, hosted SDK).
4. subetha.us (added as the fourth audience; device credentials replace its own enrollment).

Work in the sibling sites happens in their repos; this repo holds the shared spec, the verify
packages, conformance vectors, the first-party catalogs and patch series for sites not yet
merged (`integrations/cronly/`).

---

## 10. Security, privacy and abuse

- **Account takeover = control of every device.** A recent sign-in (a Clerk re-verification,
  an approval by one of the owner's passkey, TOTP or other-device gates, or the first ten minutes
  after sign-up or recovery) is required to issue or approve credentials with `dba:*` actions,
  create API keys or enrollment tokens, raise budget limits, change gates, or reinstate a revoked
  device. Every issuance is announced by Web Push to the owner's browsers; per-account issuance
  limits apply. Since an email costs more than an issuance (D9), takeover-sensitive events are
  emailed at once and other issuances in at most one digest an hour, each email charged when
  queued.
- **Issuer key compromise**: rotation runbook, short default lifetimes, `kid` pinning, mass
  force-renew.
- **Gates** (§6.4): push-fatigue limits (one waiting request per subject, number matching at
  sign-in, per-device rate limits that deny rather than count as silence), no self-approval for
  any gate kind, and gate configuration changes behind a recent sign-in.
- **Replay**: DPoP `jti` + `iat` window; online authorize keeps a replay cache; DBA's own API
  also requires its server nonce from proofs made before an account object started, since that
  cache lives in memory (D15, §7.1); docs tell offline verifiers to keep a 2-minute `jti` cache
  (the verify library does it in-isolate by default; a shared cache in a Durable Object is
  optional, `replay-do.js`).
- **Network constraints** (§3.6): verifiers take the peer address from the platform, never from
  client-set headers unless proxies are explicitly trusted (the verify library reads Cloudflare's
  `CF-Connecting-IP`; elsewhere the caller must pass the socket address, see the plan's §13a);
  widening a named address list widens every credential naming it, so replacing or deleting a
  list needs a recent sign-in; relays should be attested and short-lived; credentials reveal
  their CIDRs, host names, list URIs and relays to audiences.
- **XSS in tools**: the inspector renders untrusted JSON — no framework, strict CSP
  (`frontend/_headers`), and everything dynamic escaped before `innerHTML`.
- **Privacy**: credentials reveal device names and geofences to the audiences they are shown to;
  the UI warns and offers coarse areas. DBA never stores device locations except inside the
  grants the customer wrote and (for online decisions) the coarse country of each decision,
  retained 90 days.
- **Legal**: reuse the shared operator profile from cronly (`todo/shared_operator_profile.md`
  there); Terms, Privacy, and an acceptable-use policy forbidding stalkerware-style tracking.

---

## 11. Repository layout

```
src/                     Worker: index.js (API_ROUTES), api/, auth/, durable-objects/
                         (AccountDO and its operations in account/), services/ (issuance,
                         issuer keys, first-party audiences, attestation, OpenAPI, cost
                         monitor), utils/ (pricing, cost-policy)
frontend/                Static site, no build step: dashboard, approval, sign-up and recovery
                         pages, tools/, docs/, sdk/ (dba.js + immutable vX.Y.Z releases)
packages/verify/         @devicebasedauth/verify; verify-python/ and verify-go/ are its ports
packages/browser-sdk/    Browser SDK source (bundled to frontend/sdk/dba.js)
packages/cli/            dba CLI
spec/                    credential.md, evaluation.md, events.md, vectors/*.json (conformance)
docs/                    samples/ (CI-executed), business/ (pricing), ops/ (runbooks),
                         security/ (review log)
integrations/            Patch series for sibling sites (cronly)
todo/  done/             Plans
STATUS.md AGENTS.md      Status (single source of truth) and contributor guide
```

---

## 12. Build order

Phases 0–7 and 11 are done; 8, 9, 10 and 12 are in progress (STATUS S1, S2, L9–L14, B10).

| Phase | Deliverable | Exit criteria |
|-------|-------------|---------------|
| 0 | Remaining decisions (D2, D6–D8); `spec/credential.md`, `spec/evaluation.md`, first 50 test vectors; pricing sheet | Owner approves decisions and draft prices |
| 1 | Scaffold ported from cronly: Worker, local mode, Clerk, Stripe ledger (µ$), API_ROUTES, cost policy, CI, deploy | `npm run dev:local` works with LocalDev auth and fake deposits; CI green |
| 2 | Issuer keys + JWKS; `packages/verify`; inspector and playground pages | Vectors pass in verify library and in the browser |
| 3 | Enrollment (browser SDK, device approval, API), credential registry, dashboard list/detail | A browser and a CLI device enroll locally and show in the dashboard |
| 4 | Revocation, status lists on R2, renewal and rotation, panic button | Revoked credential denied by offline verifier within TTL in an e2e test |
| 5 | Online `/authorize`, usage counters, step-up, audience registry and console | Metered decisions settle correctly under concurrency tests |
| 6 | Docs, OpenAPI, CI-executed samples, CLI, `llms.txt`, MCP server | Every docs sample runs in CI |
| 7 | OIDC provider; DBA dashboard on its own credentials (Stage B) | Sign in to DBA with a DBA browser credential |
| 8 | cronly integration (§9.1, §9.2 Stage A then B) | cronly accepts DBA device keys and DBA sign-in in production |
| 9 | hashbin integration | Same for hashbin |
| 10 | Launch hardening: cost brake, monitoring, security review, legal pages, production acceptance | Launch checklist in STATUS.md all ✅ |
| 11 | Additional gates (§6.4), phases G1–G9 of [`done/additional_gates.md`](../done/additional_gates.md) | Gated authorization, sign-in and periodic confirmation work online and offline; every new vector passes in all three verifiers |
| 12 | Network constraints (§3.6), phases N1–N9 of [`todo/network_constraints.md`](network_constraints.md) | Address, route and latency rules enforced offline in both directions; every new vector passes in all three verifiers |

---

## 13. Deliberately left out of v1

- Server-generated private keys (D1), external KMS for issuer keys (S6), a shared wallet across
  sites (rejected, D5), customer-supplied CAs (B6), delegation chains deeper than one level, a
  native mobile SDK beyond samples (S4), and Android Play Integrity verdicts (D10).
