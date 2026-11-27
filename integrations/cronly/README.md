# cronly.org integration patches (S5 in cronly)

**Historical delivery artifact.** This series has since been merged and extended in cronly;
do not apply it again. Current rollout and live acceptance: [sibling integrations](../README.md)
and [STATUS S1](../../STATUS.md).

A six-commit patch series for [cronly](https://github.com/curtcox/cronly) that makes cronly.org a
devicebasedauth.org relying party: device-bound API keys and account linking (this repo's master
plan §9.1, plus the linking half of §9.2), delivered as `git format-patch` output for the cronly
owner to apply (STATUS S1).

## Base and how to apply

- **Base:** cronly `main` at `5134a8f` ("L8: show derived run maxima beside job budgets"). The
  series applies cleanly there with `git am`.
- **Vendored verifier:** `packages/verify/src/*.js` (tests excluded) from this repo at `a6c0d77`
  (patch 1 vendors it, patch 6 refreshes it). That copy predates grant vocabulary 2 (`net`) and
  the `require` members `attestation`, `app_ids`, `verified_boot`, `gates`, `gates_reuse_s` and
  `confirmation`: it refuses `ver: 2` credentials (`invalid_claims`) and denies grants with those
  members (`unknown_constraint`), so it fails closed but should be refreshed. Re-copy the files and
  their hashes as `src/vendor/devicebasedauth/README.md` in cronly describes.

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
| 6 | S5: refresh vendored devicebasedauth verify library (a6c0d77) | The OIDC client caches only successful responses; the spend caveat counts only cronly-namespace grants; status-list inflation is bounded while it runs. |

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

## Tests (cronly, at the last patch)

`npm run lint` is clean and `npm test` passes (1,019 tests, 19 of them new) at every commit of the
series; `npm run docs:generate` leaves no drift; Playwright `npm run test:e2e` passes, including
the account-section and callback test. The new tests sign credentials, access tokens, status
lists and OIDC ID tokens with the vendored `issuer.js` and stub `fetch` for the JWKS, status list,
discovery and token endpoint. They cover scopes from grants (never `SESSION`), wrong audience,
unlinked or unconfirmed accounts (403 `account_not_linked`), revocation, every DPoP proof failure,
access tokens and Clerk fall-through, metered reads and the monthly cap, MCP, a JWKS outage (503),
the link flow (single-use, expiring state, one DBA account per cronly account, stale-claim
takeover), and the vendored file hashes.

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

## Follow-ups

- Revocation seen by the verifier is not written back to the `dba-key:` row, so a run already
  queued by a since-revoked credential can still retry until the credential expires or the
  account unlinks (bounded by job retries and the cap).
- Refresh the vendored verifier (see above).
- Resource-scoped grants, Stage B device-bound web sessions, and online authorization
  (grants with `limits.uses` or online-only `require` members deny today).
