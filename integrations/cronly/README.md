# cronly.org integration patches (S5 in cronly)

A six-commit patch series for [cronly](https://github.com/curtcox/cronly) that makes cronly.org a
devicebasedauth.org relying party: device-bound API keys and account linking (this repo's master
plan §9.1, plus the linking half of §9.2). It was prepared without push access to cronly, so it is
delivered as `git format-patch` output.

## Base and how to apply

- **Base:** cronly `origin/main` at `5134a8f` ("L8: show derived run maxima beside job budgets"),
  fetched 2026-11-18. The series applies cleanly there with `git am` and reproduces the tested tree.
- **Vendored verifier:** `packages/verify/src/*.js` (tests excluded) from this repo, first at
  `7dbb8ad` (patch 1) and refreshed to `a6c0d77` (patch 6, which also carries the fixes this
  integration reported). If `packages/verify` changes again, re-copy the
  files and their hashes as `src/vendor/devicebasedauth/README.md` in cronly describes.

```sh
cd cronly
git fetch origin && git checkout -b dba-integration 5134a8f   # or origin/main if it has not moved
git am /path/to/device-based-auth/integrations/cronly/patches/*.patch
npm ci && npm run lint && npm test
```

If `main` has moved, try `git am -3`; the likely conflicts are `STATUS.md`, `src/index.js`
(`API_ROUTES`) and `frontend/openapi.json` (regenerate it with `npm run docs:generate` after resolving).

## The patches

| # | Commit | What it does |
|---|--------|--------------|
| 1 | S5: vendor @devicebasedauth/verify and plan the devicebasedauth.org integration | Unmodified copy in `src/vendor/devicebasedauth/` with a README naming the source commit and each file's SHA-256; `src/vendor/devicebasedauth.test.js` fails on any local edit. STATUS row **S5** and the picked-up-cold plan `todo/dba_integration.md`. |
| 2 | S5: link cronly accounts to devicebasedauth.org accounts over OIDC | `createOidcClient` (issuer `DBA_ISSUER`, default `https://devicebasedauth.org`; client `cronly.org`; redirect `${APP_ORIGIN}/auth/dba/callback`). `SESSION` routes in `API_ROUTES`: `POST /api/dba/link/start`, `POST /api/dba/link/finish` (`{ code, state }`), `GET /api/dba/link`, `DELETE /api/dba/link`. OIDC state/nonce/PKCE verifier stored in the AccountDO, single use, 10-minute TTL, ≤ 10 pending. New **`DbaLinkDO`** (binding `DBA_LINKS`, migration `v3`, both wrangler configs, exported from `index.js` and `platform.js`) is the global DBA account → cronly account index. Fake-issuer test helper. OpenAPI regenerated. |
| 3 | S5: accept devicebasedauth.org credentials and access tokens as API keys | `src/auth/middleware.js` tries DBA first for `DBA …` and for `Bearer …` whose JWS `typ` is `dba-access+jwt` (other bearers stay Clerk). Module-level `createSiteAuth({ audience: 'cronly.org', namespace: 'cronly', scopes: USER_SCOPES, linkedUser, issuer, fetch })` per issuer. Returns `{ account, key_id: <cid>, scopes, session: false, dba: { account, device_id, credential_id } }`. Credential id as key id → metered reads and a monthly key budget from `spend_usd_per_month`. MCP forwards the verified identity to its internal tool requests. `DeviceCredential` OpenAPI scheme. |
| 4 | S5: devicebasedauth.org section and link callback in the workspace | Account page section: status, Link/Unlink, credentials seen, `dba enroll --aud cronly.org --action cronly:run`, `dba curl`/`dba token`, and the `import { DBA } from 'https://devicebasedauth.org/sdk/dba.js'` snippet; all dynamic text escaped. `/auth/dba/callback` serves the workspace, strips `code`/`state` from the URL immediately and posts them to `finish` after sign-in. Playwright test. |
| 5 | S5: document devicebasedauth.org credentials and record acceptance | README, agents guide, `llms.txt`, master-plan credential table, pricing doc; STATUS S5 → 🟨 with an acceptance record. |
| 6 | S5: refresh vendored devicebasedauth verify library (a6c0d77) | OIDC client caches only successful responses; spend caveat limited to cronly-namespace grants; bounded status-list inflation. 1,019 tests pass. |

## Design decisions (details in cronly `todo/dba_integration.md`)

- **Global lookup = a small Durable Object per DBA account** (`DbaLinkDO`, named by the DBA
  account). Every DBA request looks the link up, so it must not queue on a singleton like cronly's
  `SafetyDO`; one object per DBA account makes "one DBA account links to at most one cronly
  account" an atomic claim; cronly uses no KV and KV would be eventually consistent.
  The AccountDO's `dba-link` row is the *confirming* half: a request is accepted only when the
  index names the account and the account names the same DBA account. An interrupted link or
  unlink therefore authorizes nothing, and an unconfirmed claim can be taken over (compare-and-swap).
- **`cronly:session` does not grant `SESSION`.** `SESSION` routes mint API keys, pay and move the
  link; a device credential must not. DBA credentials behave like API keys (they can use MCP).
- **Spend caps fit the existing per-key budgets.** `ledger.js` `reserve()` already enforces
  `key_budget.{day,month}` per `key_id` across holds and settlements. The credential id (`crd_…`,
  never a cronly key id) is the `key_id`; `keyBudget()` maps it to the AccountDO row
  `dba-key:<cid>` whose `monthly_spend_microdollars = Math.round(spend_usd_per_month × 1e6)`
  becomes `{ month }` (UTC month). Reads are metered like API keys (21 µ$ + 2 µ$/job). Queued
  retries re-check the row, so unlink (or expiry) refuses them.
- **Linking is free** like sign-in, rate-limited to 10 a minute per account (owner may choose to
  bill it as a 100 µ$ change).
- Resource-scoped grants (`resources: ["job:…"]`) are evaluated without a resource and so grant
  nothing yet (fail closed).

## Test results (cronly, at the last patch)

- `npm run lint`: clean (also at every intermediate commit).
- `npm test` (Vitest): 65 files, **1,019 tests pass** (1,000 before; 19 new). Every intermediate
  commit also passes. New tests sign credentials, access tokens, status lists and OIDC ID tokens
  with the vendored `issuer.js` and a generated P-256 key, with `fetch` stubbed for JWKS, the
  status list, discovery and the token endpoint. They cover: valid credential → scopes (and never
  `SESSION`); ungranted scope, other namespace → 403 from route access; other audience → 401;
  unlinked and unconfirmed DBA accounts → 403 `account_not_linked`; revoked → 401 (also after the
  status-list cache refreshes); missing / foreign-key / wrong-URL / wrong-method / replayed DPoP
  proof → 401; lower-case `dba` scheme; access-token path and Clerk fall-through; metered read
  charged (21 µ$) and the monthly cap on reads, reservations and a job run; MCP with one proof;
  JWKS outage → 503; link start/finish/status/unlink, single-use and expiring state, one DBA
  account per cronly account, stale-claim takeover, relink release; vendored file hashes.
- `npm run docs:generate`: OpenAPI regenerated; the drift test passes.
- `wrangler deploy --dry-run` with both configs lists `env.DBA_LINKS (DbaLinkDO)` and `DBA_ISSUER`.
- Playwright `npm run test:e2e`: 28/28 pass (run with the system Chrome because the Playwright
  browser download is blocked in this sandbox), including the new account-section/callback test.

## Owner steps

1. Apply, open a PR in cronly, let CI run, merge, deploy (migration `v3` creates `DbaLinkDO`).
2. Add the new `DbaLinkDO` namespace ID to the `COST_SAFETY_DO_NAMESPACES` CI variable so the
   cost monitor counts it.
3. `DBA_ISSUER` is a plain var in `wrangler.toml` (`https://devicebasedauth.org`). For local work
   run one of the two `dev:local` servers on another port (both default to 8787), point
   `DBA_ISSUER` there, and register `http://localhost:8787/auth/dba/callback` for `cronly.org`.
4. At devicebasedauth.org: confirm audience `cronly.org` / namespace `cronly` / redirect
   `https://cronly.org/auth/dba/callback` (already in `src/services/first-party.js`), and fund the
   cronly operator account (only needed if online authorization is enabled later; offline
   verification is free).
5. Optional "Stage A": add devicebasedauth.org as a custom OIDC provider in cronly's Clerk
   application (discovery `https://devicebasedauth.org/.well-known/openid-configuration`, client
   `cronly.org`, PKCE). Independent of linking; needs a Clerk plan with custom providers.
6. Live acceptance: link a real account, `dba enroll --aud cronly.org --action cronly:read`,
   `dba curl https://cronly.org/api/account` (expect a 21 µ$ charge), revoke at DBA and expect 401
   within five minutes.

## Not done / follow-ups

- Revocation seen by the verifier is not written back to the `dba-key:` row, so a run already
  queued by a since-revoked credential can still retry until the credential expires or the
  account unlinks (bounded by job retries and the cap).
- Resource-scoped grants, Stage B device-bound web sessions, and online authorization
  (`limits.uses`, `require.*` deny today).

## Issues found in `packages/verify` (fix here, then re-vendor)

1. `createOidcClient` caches the discovery document and the ID-token JWKS without checking
   `response.ok` (`discovery ||= await (await fetcher(…)).json()`, same for `jwks`). One 5xx JSON
   body is cached for the life of the client, after which `begin()`/`finish()` fail with a
   `TypeError` until the isolate restarts. cronly works around it by building a client per link
   request.
2. `createSiteAuth` reports `caveats.spend_usd_per_month` as the minimum over **all** grants,
   including grants for other audiences' namespaces and grants that do not currently apply. That is
   conservative, but a `hashbin:*` grant's cap also caps cronly use of a multi-audience credential.
   Consider the minimum over grants that match the site's namespace.
3. `status-list.js` `inflate` checks its `maxBytes` bound only after decompressing the whole list,
   so the bound does not prevent the memory use it describes. (Lists are issuer-signed and the
   signature is checked first, so this needs a compromised issuer key.)
