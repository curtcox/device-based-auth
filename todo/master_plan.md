# devicebasedauth.org — master plan

Status of every item lives in [`STATUS.md`](../STATUS.md). Prices and the cost model live in
[`docs/business/pricing.md`](../docs/business/pricing.md). This file is the design; it is written
to be picked up cold.

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
| **Account** | A DBA customer, signed in with Clerk, holding a prepaid balance (µ$). |
| **Device** | Anything that can hold a private key: browser profile, phone, desktop, server, CLI, CI job, AI agent. Identified by `dev_…` and its public-key thumbprint. |
| **Audience (relying party)** | A site or API that accepts DBA credentials, e.g. `hashbin.org`. Registers an **action catalog** (its vocabulary of actions). |
| **Action** | A namespaced verb from an audience's catalog: `hashbin:content:write`, `cronly:jobs:run`, `dba:credentials:issue`. |
| **Grant** | `{actions, resources, constraints}`. One credential carries one or more grants. |
| **Constraint** | A restriction on a grant: time windows, validity range, location, network, usage counts, spend caps. |
| **Device credential** | The signed document (a JWS) binding a device public key to grants for one or more audiences. The "certificate" in the original brief. |
| **Proof** | A per-request signature made with the device's private key (DPoP proof JWT) showing the presenter holds the key the credential names. |
| **Status list** | A compressed bitstring published at a URL; bit *n* set = credential with status index *n* is revoked. |
| **Enrollment** | The flow that gets a device's public key to DBA and the account owner's approval back, ending in an issued credential. |

---

## 3. The device credential

### 3.1 Format (decision D2)

A compact JWS (`header.payload.signature`, ES256 / P-256). Chosen because:

- the payload is plain JSON after one base64url decode — readable by any client or server;
- every language has a mature verifier; Cloudflare Workers and browsers verify ES256 natively
  with WebCrypto;
- hashbin already ships ES256 DPoP code we can port.

An X.509 export of the same key and grants (for mTLS on IoT hardware and Cloudflare API Shield)
is a backlog item (B3), not the primary format.

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
  "jti": "crt_01JD3W7A…",
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
- Unknown constraint types make the grant **deny** (fail closed), so new constraint kinds can
  be added without old verifiers silently over-granting. `ver` is the vocabulary version.
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
| `where.networks` | CIDR ranges the request must come from. | Verifier |
| `limits.uses` | Max uses per period. Needs a counter → **online authorization only** (§6.2). | DBA online |
| `limits.spend_usd_per_month` | Passed to the audience as a caveat (maps to hashbin/cronly spending caps). | The audience |
| `require.online` | Forces online authorization for every use (instant revocation, usage counters, audit). | DBA online |
| `require.step_up` | The action needs a fresh user approval (push/passkey) at use time. | DBA online |

### 3.4 Evaluation algorithm

Written as `spec/evaluation.md` with JSON test vectors in `spec/vectors/` that every
implementation (our JS verifier, the docs' Python/Go samples, hashbin, cronly) must pass in CI:

1. Verify JWS signature against the issuer JWKS (`kid`), `typ`, `iss`, `aud`, `nbf ≤ now < exp`
   (60 s skew).
2. Verify the DPoP proof: signature by the key whose thumbprint is `cnf.jkt`, `htm`/`htu` match the
   request, `iat` within ±60 s, `ath` = hash of the credential, `jti` not replayed (verifier-local
   cache), nonce if the verifier requires one.
3. Check revocation: status-list bit for `status.status_list.idx` (cached ≤ TTL) — or online.
4. Find any grant whose action matches **and** every constraint passes. If none, deny with the list
   of reasons per grant (shown in dev tools; logged, not returned to anonymous callers).

### 3.5 Location — what can actually be trusted (decision D4)

Location is the weakest constraint and the plan says so in the docs:

- **`network`**: the verifier uses where the request appears to come from. On Cloudflare this is
  `request.cf.country/region/latitude/longitude`. Spoofable with VPNs/proxies; country-level is
  reasonably reliable, city-level is approximate.
- **`device`**: the device includes `loc: {lat, lon, acc_m, t}` in its signed proof. Only as honest
  as the device and its owner; meaningful for managed/attested devices.
- **`both`**: both must pass.

Platform attestation (Apple App Attest, Android Play Integrity, TPM) to raise trust in
device-reported values is backlog (B5); Android Key Attestation of the device key itself is done
(`device.attestation`, spec/credential.md §3a).

---

## 4. Architecture

```
                         devicebasedauth.org (Cloudflare)
┌──────────────────────────────────────────────────────────────────────────┐
│ dba-worker-prod  (src/, frontend/)                                        │
│  API_ROUTES · Clerk sessions · Stripe webhooks · OIDC provider · cron     │
│  issuance & renewal · online /authorize · dev tools · static site         │
│                                                                          │
│  Durable Objects (SQLite)                                                │
│   AccountLedger      balance (µ$), holds, receipts, API keys, audit       │
│   CredentialRegistry per-account devices, credentials, history            │
│   StatusListShard    allocates status indexes, holds bits, publishes      │
│   AudienceRegistry   relying parties, action catalogs, OIDC clients       │
│   UsageCounter       per-credential counters for limits.uses (online)     │
│   PlatformCost       cost measurement + safety brake (ported)             │
│                                                                          │
│  R2 dba-status-prod → status.devicebasedauth.org (CDN-cached, public)     │
│     /v1/lists/{n}  status lists (signed JWT, gzip bitstring)              │
│  Static: /.well-known/jwks.json, /.well-known/openid-configuration,       │
│          /openapi.json, /llms.txt, /sdk/vX.Y.Z/dba.js (immutable, SRI)    │
└──────────────────────────────────────────────────────────────────────────┘
        ▲ enroll / renew / authorize            ▲ JWKS + status lists (cached)
        │                                       │
   devices (browser SDK, CLI, mobile)     relying parties: hashbin.org, cronly.org,
                                          devicebasedauth.org itself, customer sites
```

- **Issuer signing keys**: ES256 keys held as Worker secrets (`ISSUER_KEY_<kid>`), rotated every
  90 days with overlap; public halves in the JWKS. A compromised issuer key is the worst-case
  incident: runbook in `docs/ops/issuer-key-compromise.md` (rotate, republish JWKS without the
  old `kid`, force-renew all live credentials). Moving the signing key to an external KMS/HSM
  is S6 — it adds a per-signature cost and a network hop.
- **Status lists** use the IETF OAuth Token Status List encoding (1 bit per credential, zlib,
  base64url, wrapped in a signed JWT). Each shard holds up to 1M indexes (~125 KB uncompressed,
  far less compressed). Revocations are debounced and republished at most once per 60 s per shard
  with `Cache-Control: max-age=60`. Published through an R2 custom domain so cache hits cost
  nothing and misses cost one class-B read.
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
| **Device code (RFC 8628)** | CLI, servers, agents, TVs, IoT | `dba enroll --aud hashbin.org --grant 'hashbin:content:write'` generates a key (OS keychain / TPM where available, else a 0600 file), shows a short code and URL/QR. The owner approves on any signed-in browser; the CLI polls and saves the credential. |
| **Mobile** | iOS/Android apps | Same as device code or an in-app browser; key in Secure Enclave / Android Keystore (`key_protection` recorded). Sample apps are S-level work. |
| **API (pre-approved)** | Fleets, CI, agents provisioned by an already-trusted device | `POST /api/v1/credentials` with a public key and grants, authorized by an account API key or a DBA credential holding `dba:credentials:issue` (whose own grants bound what it may delegate — a device can never issue more than it holds). |
| **Enrollment token** (B2) | Fleets whose machines make their own keys: kiosks, CI runners, IoT | The owner approves a template once (`POST /api/v1/enrollment-tokens`: audiences, grants, lifetime, max uses, expiry); each device signs its own enrollment request and redeems it with the `dbae_` token (`POST /api/v1/enrollments/redeem`), narrowing but never widening the template. |
| **Agent request** | AI agents | Agent calls `POST /api/v1/enrollments` with its public key and the grants it wants; DBA returns an approval URL for the human. Approval can narrow grants and add spend caps. Same as device code, exposed through the MCP server (§7.4). |

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
  to the status list within ≤ 60 s, visible to offline verifiers within ≤ 60 s + their cache TTL
  (docs recommend ≤ 5 min). Also pushed to registered audiences by signed webhook (optional).
- Revocation is free at the point of use; its worst-case cost is included in the issue price.

### 5.4 Renewal and rotation

- Devices renew before `exp` with `POST /api/v1/credentials/{id}/renew`, authenticated by a DPoP
  proof from the same key. Grants cannot widen on renewal. Renewal is metered (cheaper than
  issue). The SDK and CLI renew automatically at 2/3 of lifetime.
- Key rotation: the device proves possession of both old and new keys; the old credential is
  superseded and its status bit set.
- An account can cap total renewals per credential per month (budget guard for runaway devices).

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
Offline verification cannot enforce `limits.uses`, `require.online` or `require.step_up`; grants
with those constraints deny offline and tell the verifier to go online.

### 6.2 Online (`POST /api/v1/authorize`, metered)

Request: credential, DPoP proof (or the original request's method/URL/headers), action, resource,
context. Response: `{ allow, grant_index, reasons, expires_in }`. Gives instant revocation, usage
counters, step-up, and a per-decision audit trail the customer can view. Billed per decision
to the **audience's** account (decision D3). Short positive decisions may be cached by the
caller for `expires_in` seconds.

### 6.3 Short-lived access tokens for curl-only scripts

A device can exchange its credential (with a proof) for a ≤ 10-minute bearer access token for one
audience: `dba token --aud hashbin.org` prints it, so shell scripts can do
`curl -H "Authorization: Bearer $(dba token --aud hashbin.org)"`. This trades key binding for
convenience only for minutes. Audiences decide whether to accept these tokens.

---

## 7. Developer and agent surface

### 7.1 API conventions (ported from cronly)

- REST + JSON under `/api/v1/`; every route declares `PUBLIC`, `SESSION`, or scopes in
  `API_ROUTES`; a test fails for any undeclared route.
- Errors `{ error, code, ... }`; `402` for balance refusals; `Idempotency-Key` on every POST that
  costs money; every billable response carries `X-DBA-Cost-Microdollars` and the remaining balance.
- `GET /api/v1/quote` and `?dry_run=1` on every billable route return the price without charging.
- OpenAPI 3.1 at `/openapi.json`, generated from `API_ROUTES`; a drift test keeps it honest.
- Credentials accepted: Clerk session (web), account API key (`dbak_…`, scoped, port of hashbin's
  signed-route keys), or a DBA device credential + DPoP proof holding `dba:*` actions — DBA is
  its own first relying party.

### 7.2 Built-in developer tools (pages on the site)

| Tool | What it does |
|------|--------------|
| **Credential inspector** | Paste a JWS: decodes header/payload, verifies signature against the live JWKS, checks revocation, renders grants in English. Runs entirely in the browser. |
| **Grant builder** | Form → grant JSON (with map picker for areas, time-window editor, action picker from each audience's catalog) → copyable `curl`, JS and CLI to request it. |
| **Policy playground** | Credential + action + resource + simulated time/location → allow/deny with per-constraint reasons. Uses the same evaluator as production. |
| **Request signer** | Generates a throwaway key in the browser, builds a DPoP proof for a given request, shows the exact headers. |
| **API explorer** | Try every endpoint against your account (test mode uses a separate test balance; local mode needs nothing). |
| **Cost calculator** | Devices × renewals × online decisions → monthly cost, from the same constants as billing. |
| **Audience console** | For site operators: register an audience, publish an action catalog, get OIDC client credentials, see verification stats and spend. |

### 7.3 SDKs, CLI and samples

- `frontend/sdk/dba.js` browser SDK — versioned, immutable releases pinned with SRI (hashbin's
  model): `enroll()`, `fetch()` (adds credential + DPoP automatically), `renew()`, `inspect()`.
- `packages/verify` — the verifier (§6.1), published to npm.
- `packages/cli` — `dba` CLI (Node, single file): `enroll`, `list`, `inspect`, `revoke`,
  `token`, `sign`, `curl` (a curl wrapper that adds the headers).
- Docs samples for curl+openssl, JavaScript (browser, Node, Workers), Python, and Go. **Every
  sample is a file under `docs/samples/` executed in CI against local mode**; the docs pages
  include them by reference so they cannot drift.

### 7.4 Agents

- `/llms.txt` and `/llms-full.txt` summarizing the API, flows and pricing.
- An MCP server (`/mcp`, remote, OAuth-protected) exposing: request a credential (returns an
  approval URL), list/inspect/revoke credentials, quote, and evaluate policy.
- Agent-oriented defaults: short lifetimes, spend caps, `require.online` so the human sees every
  decision.

---

## 8. Money

### 8.1 Model

Port cronly's ledger exactly: integer micro-dollars (µ$), prepaid balance, no subscription, no
negative balances, reserve-max-then-settle, verified Stripe webhook credits only, $5 minimum
deposit with the card fee itemized on top (`ceil((credit¢ + 30) / 0.971)`), first-week $20
per-checkout cap, unused credit never expires while the account exists.

### 8.2 Price-floor rule

`price × revenueKept (0.92) ≥ 1.5 × worst-case marginal cost`, enforced by a unit test over every
price constant, with rates in `src/utils/cost-policy.js` and prices in `src/utils/pricing.js`
only. Prices and the cost derivation are in
[`docs/business/pricing.md`](../docs/business/pricing.md); the owner approved them 2026-11-18
(decision D6). Summary:

| Operation | Price | Who pays |
|-----------|-------|----------|
| Issue or rotate a credential (includes prepaid revocation, 13 months of record storage and their later deletion) | 85 µ$ | Issuing account |
| Renew (same key) | 25 µ$ | Issuing account |
| Online authorization decision | 14 µ$ ($14 per million) | Audience account |
| OpenID Connect sign-in | 12 µ$ | Audience account |
| Metered API reads (API keys, non-dashboard devices), token exchange, X.509 certificate | 5 µ$ | Caller / issuing account |
| Register or change an audience | 100 µ$ | Audience account |
| Offline verification, JWKS, status lists, web UI reads, revocation, dev tools | Free (cached / rate-limited) | — |

### 8.3 Why no account can cost money

- Every metered call reserves its price before work.
- Free paths are static files, CDN-cached R2 objects, or session-only UI reads behind per-account
  and per-IP rate limits; anonymous enrollment writes nothing (§5.1).
- Revocation is prepaid; record storage is prepaid for 13 months, after which expired records are
  dropped from DO storage by a weekly compaction whose deletes the issue price also prepays
  (an R2 archive was dropped: its per-run write would have cost more than the records; revoked
  devices, deposits and daily/monthly summaries are kept).
- **Clerk monthly retained users** are the one per-user cost not tied to an operation (free up to
  50,000 MRU). Mitigations: after first sign-in, users can sign into the DBA dashboard with their
  own DBA browser credential (no Clerk session, so no MRU); accounts with zero balance and no live
  credentials for 12 months are closed after notice (decision D8).
- Port hashbin/cronly's cost-safety brake: hourly cost measurement from Cloudflare analytics;
  alert at a projected month-end variable cost, then latch a brake that stops new free-tier work.

---

## 9. Integrating the three sites

devicebasedauth.org, hashbin.org and cronly.org all become **audiences**. Each publishes an action
catalog generated from its existing scope list (hashbin `USER_SCOPES` → `hashbin:content:write` …;
cronly scopes → `cronly:jobs:run` …), so a DBA grant maps 1:1 onto the scope checks the sites
already enforce in `API_ROUTES`.

### 9.1 DBA-issued API keys (device-bound) on all three sites

Goal: on each site's "API keys" page, a **"Create a device key with devicebasedauth.org"** button,
and the same thing from a terminal with `dba enroll --aud cronly.org`.

Changes in each site repo (hashbin, cronly; DBA does this natively):

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

### 9.2 "Sign in with devicebasedauth.org" on all three sites

DBA is an OpenID Connect provider (authorization code + PKCE, `/.well-known/openid-configuration`).
The ID token includes the DBA account, the device (`dev_…`, `cnf.jkt`) and the login credential's
`jti`. Two stages:

- **Stage A — fast**: register DBA as a custom OIDC provider in each site's Clerk application.
  Users get a "devicebasedauth.org" button next to Google/GitHub with almost no site code.
  Limitation: after login the site session is an ordinary Clerk session, so revoking the device
  does not end it (only stops future logins). Needs verification that the sites' Clerk plan
  supports custom OIDC providers (decision D7).
- **Stage B — device-bound sessions**: the site's frontend uses `dba.js`; each API call carries
  the device credential + proof (§9.1), so revoking the device ends access within the status-list
  TTL. Page-level authorization uses the same grants (e.g. hide the publish button if the device
  lacks `hashbin:content:write`).

devicebasedauth.org dogfoods Stage B for its own dashboard after the first Clerk sign-in.

### 9.3 Billing across sites

Decided (D3, D5, 2026-11-18): every site keeps its own separate balance and Stripe product.
DBA charges **the account that issues** for issue/renew, and **the audience operator** for online
decisions. hashbin and cronly verify offline, so their users pay DBA (from their DBA balance) only
for issuing and renewing device keys for those sites. There is no shared wallet.

### 9.4 Rollout order

1. DBA itself (dashboard, issuance, revocation, inspector, verify library).
2. cronly (newest codebase, closest conventions, micro-dollar ledger already).
3. hashbin (largest auth surface: API keys, OAuth/DPoP, hosted SDK).

Work in hashbin and cronly happens in those repos; this repo holds the shared spec, the verify
package, conformance vectors and the integration checklists (`todo/integrate_hashbin.md`,
`todo/integrate_cronly.md`, created when step 1 is done).

---

## 10. Security, privacy and abuse

- **Account takeover = control of every device.** Require a passkey or recent re-authentication
  to issue credentials with `dba:*` actions, raise spend caps, or remove revocations; email
  (and push to registered DBA devices) on every issuance; per-account issuance rate limits.
- **Issuer key compromise**: rotation runbook, short default lifetimes, `kid` pinning, mass
  force-renew.
- **Replay**: DPoP `jti` + `iat` window; online authorize keeps a replay cache; docs tell offline
  verifiers to keep a 2-minute `jti` cache (verify library does it in-isolate by default; shared
  replay via a DO is optional).
- **XSS in tools**: the inspector renders untrusted JSON — `textContent` only, strict CSP, no
  framework, port hashbin's `escapeHtml` lint rules.
- **Privacy**: credentials reveal device names and geofences to the audiences they are shown to;
  the UI warns and offers coarse areas. DBA never stores device locations except inside the
  grants the customer wrote and (for online decisions) the coarse country of each decision,
  retained 90 days.
- **Legal**: reuse the shared operator profile from cronly (`todo/shared_operator_profile.md`
  there); Terms, Privacy, and an acceptable-use policy forbidding stalkerware-style tracking.

---

## 11. Repository layout (planned)

```
src/                     Worker: index.js (API_ROUTES), api/, auth/, durable-objects/,
                         services/ (issuance, status lists, oidc), utils/ (pricing, cost-policy)
frontend/                Static site, no build step: dashboard, credential pages, dev tools,
                         docs/, sdk/ (dba.js + immutable vX.Y.Z releases)
packages/verify/         @devicebasedauth/verify (published)
packages/cli/            dba CLI
spec/                    credential.md, evaluation.md, vectors/*.json (conformance)
docs/                    API.md, samples/ (CI-executed), business/ (pricing), ops/ (runbooks)
todo/  done/             Plans
STATUS.md AGENTS.md      Status (single source of truth) and contributor guide
```

---

## 12. Build order

| Phase | Deliverable | Exit criteria |
|-------|-------------|---------------|
| 0 | Remaining decisions (D2, D6–D8); `spec/credential.md`, `spec/evaluation.md`, first 50 test vectors; pricing sheet | Owner approves decisions and draft prices |
| 1 | Scaffold ported from cronly: Worker, local mode, Clerk, Stripe ledger (µ$), API_ROUTES, cost policy, CI, deploy | `npm run dev:local` works with LocalDev auth and fake deposits; CI green |
| 2 | Issuer keys + JWKS; `packages/verify`; inspector and playground pages | Vectors pass in verify library and in the browser |
| 3 | Enrollment (browser SDK, device code, API), CredentialRegistry, dashboard list/detail | A browser and a CLI device enroll locally and show in the dashboard |
| 4 | Revocation, status lists on R2, renewal and rotation, panic button | Revoked credential denied by offline verifier within TTL in an e2e test |
| 5 | Online `/authorize`, usage counters, step-up, audience registry and console | Metered decisions settle correctly under concurrency tests |
| 6 | Docs, OpenAPI, CI-executed samples, CLI, `llms.txt`, MCP server | Every docs sample runs in CI |
| 7 | OIDC provider; DBA dashboard on its own credentials (Stage B) | Sign in to DBA with a DBA browser credential |
| 8 | cronly integration (§9.1, §9.2 Stage A then B) | cronly accepts DBA device keys and DBA sign-in in production |
| 9 | hashbin integration | Same for hashbin |
| 10 | Launch hardening: cost brake, monitoring, security review, legal pages, production acceptance | Launch checklist in STATUS.md all ✅ |

---

## 13. Deliberately left out of v1

- Server-generated private keys (D1), X.509/mTLS (B3; since added as short-lived client certificates, spec/credential.md §6a), hardware attestation (B5), external KMS
  for issuer keys (S6), a shared wallet across sites (rejected, D5), customer-supplied CAs (B6),
  delegation chains deeper than one level, and a native mobile SDK beyond samples (S4).
