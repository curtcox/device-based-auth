# devicebasedauth.org Project Status

**This file is the single source of truth for project status.** If another document disagrees
with it, this file wins and the other document is stale.

- **Last audited:** 2026-11-25
- **Production:** live at https://devicebasedauth.org since 2026-11-22; pushes to `main` deploy;
  payments open since 2026-11-25 (`DBA_LAUNCH_APPROVED=true`) while Terms and Privacy are still
  drafts (L11). Runbook: [docs/ops/deployment.md](docs/ops/deployment.md).
- **Overall:** the service, verify libraries (JS, Python, Go), browser SDK (v1.4.0), CLI, samples,
  OIDC provider, gates (B7), accounts without Clerk (B9) and attestation (B5) are built and tested
  (`npm test`, `npm run test:samples`, `npm run test:e2e`). What remains is mostly owner work:
  legal review (L11), an independent security review (L12), npm publishing (L14), live checks on
  real devices and vendor accounts, and the open price decisions D13 and D17. Code work in
  progress: network constraints (B10).
- Design: [`todo/master_plan.md`](todo/master_plan.md). Prices: [`docs/business/pricing.md`](docs/business/pricing.md).

---

## How this file works

| Symbol | Meaning |
|--------|---------|
| ✅ | Done and verified |
| 🚧 | In progress |
| 🟨 | Implemented; live acceptance or an owner step remains |
| ⬜ | Not started |
| ❓ | Needs a decision or information from the project owner |

**Owner**: `code` (can be done in this repo), `ops` (needs Cloudflare/Clerk/Stripe/DNS access),
`legal` (owner decision).

Rows have stable IDs (`D…` decision, `L…` launch blocker, `S…` soon after launch, `B…` backlog).
A change that finishes, starts or discovers an item updates its row here in the same commit.
`npm run status` lists the rows that are not done.

---

## Decisions

| ID | Decision | Owner | Status | Outcome or recommendation |
|----|----------|-------|--------|---------------------------|
| D1 | Who generates device private keys | owner | ✅ 2026-11-18 | The device. DBA only ever sees public keys. Master plan §1, §5.1. |
| D2 | Credential format | owner | ❓ Implemented as JWS pending approval | Compact JWS (ES256) with readable "inspect" views everywhere; X.509 export for mTLS (B3). §3.1. |
| D3 | Offline and online verification, and who pays | owner | ✅ 2026-11-18 | Offline free; online decisions metered and billed to the audience. §6. |
| D4 | Location constraints: network-observed, device-reported or both | owner | ✅ 2026-11-18 | Both, chosen per grant with `where.source`; neither is tamper-proof without attestation (B5). §3.5. |
| D5 | Billing across sibling sites | owner | ✅ 2026-11-18 | Separate balances and Stripe products per site. §9.3. |
| D6 | Prices | owner | ✅ 2026-11-18, D15 rises 2026-11-22 | Issue/rotate 87 µ$, renew 25, online decision 14 (D11), metered read 7, token 7, OIDC sign-in 14, audience 100, security email 200 (D9); $5 minimum deposit. Issue, decision, sign-in, read and token are at their floors. Recalibrate from measured costs (S3). [pricing.md](docs/business/pricing.md). |
| D7 | Site sign-in: DBA as a custom OIDC provider inside each site's Clerk app first (Stage A), then device-bound sessions (Stage B); a separate Clerk application for DBA | owner/ops | ❓ | Yes to both; confirm the Clerk plan allows custom OIDC providers. subetha.us signs in with DBA directly, without Clerk (S15). §9.2. |
| D8 | Operating entity and dormant accounts | legal | ❓ | Same LLC and Cloudflare account as hashbin and cronly (cronly D1), shared operator profile; close zero-balance accounts with no live credentials after 12 months idle, after notice. §8.3, §10. |
| D9 | Security email provider and payer | owner | ✅ 2026-11-21 | Amazon SES; a `notice` price of 200 µ$ per email (floor 191), charged to the account. Implemented (S8). |
| D10 | Android Play Integrity (last open part of B5) | owner | ❓ | Do not offer it: verdicts can only be checked with each customer app's own Play Console keys. Android Key Attestation already proves a TEE/StrongBox key, the boot state and the app (`require.app_ids`). Revisit if customers ask and accept uploading their keys. |
| D11 | Online decision price 12 → 14 µ$ | owner | ✅ 2026-11-18 | A decision can also write and later delete a usage-window row or a gate request. |
| D12 | Additional gates on authentication and authorization (master plan §6.4) | owner | ✅ 2026-11-19 | Sign-in gates and optional periodic confirmation; TOTP, security keys/passkeys, customer webhooks, Duo and Okta Verify push, DBA devices and the owner; allow-on-timeout passes on silence or an unreachable gate (explicit deny, a deleted gate and an audience veto still deny); audiences can require gates and forbid allow-on-timeout. [done/additional_gates.md](done/additional_gates.md) §2. |
| D13 | Gate and confirmation prices, and who pays | owner | ❓ Implemented at the proposed prices | 22 µ$ per gate contacted (local kinds and the owner), 23 per webhook gate, 30 per Duo/Okta gate (start and up to 24 polls), 14 per confirmation; billed to the account whose gates they are. A request the owner cannot pay for is sent nowhere and waits for its timeout. [done/additional_gates.md](done/additional_gates.md) §9. |
| D14 | Paid accounts without Clerk | owner | ✅ 2026-11-21 | Pay to create; recovery chosen per account (codes, passkey or another device, a verified email after a 72-hour wait, or none); the owner's gates replace a recent Clerk sign-in; Clerk and Clerk-free accounts can be linked. Open questions O2–O6 in [done/clerk_free_accounts.md](done/clerk_free_accounts.md) §7. |
| D15 | DPoP proof replay after an account object restarts | owner | ✅ 2026-11-22 | DPoP server nonces (RFC 9449 §8): for its first 60 s an account's object asks every proof for its nonce (401 `use_dpop_nonce`); the SDK (v1.4.0), dashboard, CLI and samples answer it. Its round trip is in every device-facing price. Online `/authorize` keeps its replay cache in memory ([review log](docs/security/review-log.md), Known limits). |
| D16 | Network constraints on address, route and latency (master plan §3.6) | owner | ✅ 2026-11-19 | Both directions (`net.client` checked by verifiers, `net.server` by the device's SDK/CLI); addresses from inline CIDRs, named address lists published signed like status lists, DNS names, or a customer webhook (online only); routes proven only by signed hops from DBA-enrolled relays; latency as a maximum round trip timed with a challenge nonce. [todo/network_constraints.md](todo/network_constraints.md) §2. |
| D17 | Network constraint prices | owner | ❓ Implemented for address lists at the proposed prices | Address list create/replace 242 µ$ per started 1,000 ranges plus 15 µ$ for each day it extends the list's published life (a new list ≈ 6,200 µ$); delete free; CIDR, DNS, route and latency checks free (verifier-side). Webhook address check price comes with N6. [todo/network_constraints.md](todo/network_constraints.md) §11. |

## Launch blockers

| ID | Item | Owner | Status | Notes |
|----|------|-------|--------|-------|
| L1 | Credential and evaluation spec, conformance vectors | code | ✅ | [spec/](spec/): 163 evaluation cases; 9 credential, 7 proof and 10 confirmation signature vectors; run in CI by the JS, Python and Go verifiers |
| L2 | Worker scaffold ported from cronly (route table, local mode, Clerk, Stripe µ$ ledger, API keys, CI) | code | ✅ | `src/`, `.github/workflows/` |
| L3 | Issuer keys, JWKS, `@devicebasedauth/verify`, inspector and playground | code | ✅ | Plus grant builder and request signer |
| L4 | Enrollment (browser SDK, CLI, API), credential registry, dashboard | code | ✅ | Credential export as CSV (formula-safe) and JSON; versioned SDK files are served with one CORS header (`scripts/static-headers.test.js`) |
| L5 | Revocation, status lists on R2, renewal, rotation, delegation limits | code | ✅ | Revoking a credential revokes what it delegated |
| L6 | Online authorize, usage counters, step-up, audience registry | code | ✅ | Audience console shows decisions, sign-ins and spend per month. The decision log keeps only the coarse country of a decision, never coordinates, region or IP (master plan §10) |
| L7 | Docs with CI-executed samples, OpenAPI, CLI, llms.txt, MCP | code | ✅ | Docs code blocks marked `data-sample` are checked against the tested samples; `/llms-full.txt` and `/openapi.json` are generated and drift-tested |
| L8 | OIDC provider; the dashboard signs in with DBA credentials | code | ✅ | Consent page and "use this browser as a device" covered in Playwright |
| L9 | Production: Cloudflare zone, R2 + `status.` domain, Clerk, Stripe, secrets, deploys | ops | 🚧 | Live since 2026-11-22 (`verify-production` passes); push deploys on; Stripe webhook secret set and `DBA_LAUNCH_APPROVED=true` 2026-11-25. **Left**: a first real payment, and the live checks in [deployment.md](docs/ops/deployment.md) §3–§4 |
| L10 | Cost-safety brake and monitoring | code/ops | 🟨 | The hourly cron runs the cost monitor once a day (02:07 UTC) and again while its report is missing, stale or failed; daily alert when status-list indexes pass 80% allocated (16 shards ≈ 4.2 M issuances; raising `STATUS_SHARDS` in deployment.md §7). **Left**: watch the first real reports |
| L11 | Terms, Privacy, acceptable use (no covert tracking) | legal | 🟨 | Draft pages with entity, address and jurisdiction placeholders (shared operator profile, cronly D7). **Owner**: legal review; `support@devicebasedauth.org`, the contact on both pages, has no MX records — add Email Routing or change it |
| L12 | Security review of issuance, revocation and verification | code/owner | 🟨 | Self-review done; findings and fixes, each with a test, in [docs/security/review-log.md](docs/security/review-log.md). A stolen `dba:session` device is as strong as the owner's session (only `dba:*` issuance needs a recent sign-in). Open: online `/authorize`'s replay cache is in memory. **Independent review still needed** |
| L13 | Website: dashboard, approval and consent pages, developer tools (incl. API explorer), pricing, docs | code | ✅ | 38 Playwright tests in CI; light/dark; 390 px phone width. Approval page and grant builder warn when an area pinpoints a place and offer a coarser one (master plan §10) |
| L14 | Publish `@devicebasedauth/verify` and the CLI to npm | ops | ⬜ | Code ready (the CLI imports `@devicebasedauth/verify` by name; a test checks every CLI module is packed). **Owner**: `npm publish -w packages/verify`, then `-w packages/cli` |
| L15 | Records do not outlive what paid for them (master plan §8.3) | code | ✅ | `AccountDO.compact()` (weekly at most, on the account's alarm) drops credentials 13 months after issue (≥ 30 days after expiry), devices with nothing left, audit, ledger and receipt rows older than 13 months, and revoked keys, apps and enrollment tokens 13 months after they stopped working; keeps revoked devices, deposits and summaries. OIDC codes and gate requests are deleted at expiry. Deletes are counted in the prices. `src/compaction.test.js`, `src/alarm-pruning.test.js` |

## Soon after launch

| ID | Item | Owner | Status | Notes |
|----|------|-------|--------|-------|
| S1 | cronly accepts DBA device keys and "Sign in with devicebasedauth.org" | code/owner | 🟨 | Six-patch series in [integrations/cronly/](integrations/cronly/) (device keys, access tokens, OIDC account linking, spend caps as key budgets). **Owner**: apply with `git am` in cronly. Stage A/B sign-in are cronly follow-ups |
| S2 | hashbin accepts DBA device keys and "Sign in with devicebasedauth.org" | code/owner | 🟨 | On hashbin branch `claude/dba-integration` (device keys, access tokens, OIDC account linking with spend caps), not merged. **Owner**: review and merge, fund the operator account; Stage A/B are hashbin S23/S24 |
| S3 | Recalibrate prices from a month of measured costs | owner | ⬜ | |
| S4 | Mobile sample apps (iOS Secure Enclave, Android Keystore) | code | 🟨 | [Android](docs/samples/android/): Keystore/StrongBox key class and a dependency-free `DbaClient` (enroll, DPoP, renew) run on a JVM in CI. [iOS](docs/samples/ios/): Swift package (Secure Enclave key, App Attest, `DbaClient`) built and run with a software key against a local server in a macOS CI job. **Needs a run on a real iPhone and Android phone** |
| S5 | Python and Go verifier packages | code | ✅ | `packages/verify-python` and `packages/verify-go` (stdlib only) pass every vector in CI; the Go port is also cross-checked against the JS evaluator. Publishing to PyPI and tagging the Go module are owner steps |
| S6 | Issuer signing keys in an external KMS/HSM | ops | ⬜ | |
| S7 | CLI auto-renewal at 2/3 of lifetime | code | ✅ | `headers`, `sign`, `curl`, `token`, `status --online` renew first when due; `dba renew --if-due` for cron; `--no-renew` / `DBA_AUTO_RENEW=0` |
| S8 | Recent re-authentication before sensitive changes; notices of issuance (master plan §10) | code/ops | 🟨 | API keys, `dba:*` credentials, enrollment tokens and raised limits need a Clerk sign-in within 10 minutes, or a dashboard device re-verified through the owner's gates in the last 10 minutes (403 `reverification_required`). Web Push to up to 5 browsers per account: sensitive events at once, other issuances in an hourly digest. Security email through Amazon SES (D9): sensitive events at once, an hourly digest of the rest, 200 µ$ each when the balance covers it; setting `all`/`sensitive`/`off`. **Owner**: SES domain, IAM key and variables (deployment.md §3a); live checks with real browsers and mail |
| S9 | Issuer-key compromise recovery (master plan §10) | code | ✅ | An `ISSUER_KEYS` entry marked `"withdrawn": true` leaves the JWKS and CA bundle and never signs; credentials it signed that the registry holds renew free (`credential.recovered`), forgeries get `unknown_credential`; the SDK (`autoRenew()`/`keyWithdrawn()`, v1.1.0+) and CLI renew by themselves. Runbook [docs/ops/issuer-key-compromise.md](docs/ops/issuer-key-compromise.md). SDK v1.0.0 must not be used |
| S10 | `?dry_run=1` on every billable route; balance on billable responses (master plan §7.1) | code | ✅ | A dry run quotes the operation and price (and the balance for callers with `account:read`). Billable responses add `balance_microdollars` and `X-DBA-Balance-Microdollars` only for callers with `account:read` |
| S11 | CLI `dba list` (master plan §7.3) | code | ✅ | Table or `--json`, filters `--status`/`--audience`/`--device`, `--all`; with `DBA_API_KEY` or a device holding `dba:credentials:read` |
| S12 | MCP server OAuth-protected per the MCP authorization spec (master plan §7.4) | code | 🟨 | Protected-resource and authorization-server metadata, stateless dynamic client registration, consent page with read-only scopes by default (needs a recent sign-in), 1-hour access tokens and rotating refresh tokens whose reuse revokes the connection; connections are listed and revocable with API keys. **Left**: a live check with a real MCP client |
| S13 | CLI keeps the device key in the OS secret store or TPM (master plan §5.1) | code | 🟨 | `--key-store auto\|os\|file\|tpm` / `DBA_KEY_STORE`. macOS Keychain and Linux Secret Service (checked on a real Mac; both run in CI by [os-keychain.sh](docs/samples/os-keychain.sh)); Windows DPAPI; else a 0600 file. `tpm` (opt-in): tpm2-tools on Linux, attested by EK credential activation (CI sample [tpm/dba-cli.sh](docs/samples/tpm/dba-cli.sh) on swtpm; a rotated TPM key is unattested until re-enrolled; `dba certificate` refuses); on Windows, CNG's Platform Crypto Provider (not attested yet: no NCryptCreateClaim client). **Needs checks on a Windows PC and a physical Linux TPM** |
| S14 | Operation counts checked against the code (master plan §8.2) | code | ✅ | `src/cost-counts.test.js` measures DO requests and row writes per billable operation against `OPERATIONS` in `src/utils/cost-policy.js` |
| S15 | subetha.us accepts DBA device credentials, "Sign in with devicebasedauth.org" and DBA enrollment | code/owner | 🟨 | DBA side live 2026-11-25: `subetha.us` is the fourth first-party audience (namespace `subetha`: `session`, `publish`, `subscribe`, topics as resources; its operator pays its online decisions and sign-ins), added to the production registry by seed v2 without overwriting customer audiences. subetha side deployed (subetha `27ffa0d`): vendored verify, DBA devices as the account's devices, revocation stops attached keys, sign-in with devicebasedauth.org directly (no Clerk). **Owner**: live check (sign in at subetha.us/console, `dba enroll --aud subetha.us …`, `dba curl`, revoke); subetha staging and CI deploy are not set up |

## Backlog

| ID | Status | Item |
|----|--------|------|
| B1 | ✅ | Revocation webhooks to audiences: signed `dba-event+jwt` events ([spec/events.md](spec/events.md)) to an https URL on the audience's domain; `handleEvent` in `@devicebasedauth/verify` applies them before the status-list cache expires; 4 delivery rounds prepaid in the issue price; test button on the audience panel |
| B2 | ✅ | Fleet enrollment tokens: `dbae_` tokens (pre-approved audience, grants, lifetime; ≤ 10,000 uses; ≤ 90 days; digest stored); devices redeem with their own key (`dba enroll` with `DBA_ENROLLMENT_TOKEN`, SDK `enroll(…, { enrollmentToken })`), narrowing but never widening |
| B3 | ✅ | X.509 client certificates for mTLS: `POST /api/v1/certificate` issues a ≤ 24 h certificate over the device's own key, signed by a per-issuer-key CA at `/.well-known/dba-ca.pem`; `dba certificate`. No grants or revocation inside by design (spec/credential.md §6a) |
| B4 | ✅ | Shared replay cache for offline verifiers: `ReplayCacheDO` and `durableReplayCache(env.BINDING)` in `@devicebasedauth/verify` (sharded, fails closed), deployed by the relying party. The Python and Go ports keep in-process caches |
| B5 | 🟨 | Device attestation, signed into `device.attestation` (spec/credential.md §3a), shown on the approval page, dashboard and inspector, dropped on key rotation; grants require it with `require.attestation` (`hardware`/`strongbox`), `require.verified_boot` and `require.app_ids`, checked offline by all three verifiers. **Android Key Attestation** (chain to pinned Google roots, revocation list fail-closed, records the app as `android:<package>:<cert SHA-256>`, which counts only with verified boot). **Apple App Attest** (`secure_enclave` counts only in production builds of pinned apps). **TPM 2.0** with a Microsoft AIK (`format: "tpm"`, AIK CAs checked against the root's CRL), and **EK credential activation** for TPMs without one (`POST /api/v1/enrollments/tpm-activation`; EK certificates checked against 50 manufacturers' CAs and their CRLs, fail closed; ECC EKs not supported; CI sample [tpm/enroll-tpm.sh](docs/samples/tpm/enroll-tpm.sh)). **Needs live checks** on a real Android phone, iPhone app, Windows PC and physical TPM. Play Integrity waits on D10 |
| B6 | ⬜ | Customer-supplied issuer CAs |
| B7 | 🟨 | Additional gates (master plan §6.4, D12, D13; plan [done/additional_gates.md](done/additional_gates.md), G1–G9 all done): `require.gates` on grants; gate kinds owner, DBA device, TOTP, security key/passkey, webhook, Duo Push, Okta Verify; sign-in gates for Sign in with devicebasedauth.org and the dashboard (with recovery codes; loosening them waits for their approval); periodic confirmation (`confirm: { gates, every_s }`, offline-checkable `dba-confirmation+jwt`); audience catalog policies (`gate_required`, no allow-on-timeout). Answered on the dashboard's Approvals page, `/gate.html`, `dba approvals`, SDK `fetchWithGates()` and MCP. **Owner**: D13 prices; live checks with a real Duo Auth API application and Okta org; scan a TOTP QR code with a real phone. Microsoft Authenticator is supported as a TOTP app (no public push API) |
| B8 | ✅ | File size check with a ratchet: per-type limits in the pre-push hook, the unit tests and CI (`scripts/check-file-sizes.mjs`); the baseline is empty |
| B9 | 🟨 | Paid accounts without Clerk (D14; plan [done/clerk_free_accounts.md](done/clerk_free_accounts.md), A0–A8 done): created, funded, used, administered and recovered with only a device and a card ([docs](frontend/docs/accounts.html); `src/clerk-free-accounts.test.js` runs with every `CLERK_*` unset; CI sample [signup-and-recover.sh](docs/samples/signup-and-recover.sh)). Pay to create (`/signup.html`, `dba signup`, SDK `signUp`); recovery by codes, a passkey or another device, or an address verified here after 72 hours; a Clerk sign-in can be linked and unlinked; `user.deleted` never closes an account. **Owner**: legal review of the privacy and terms wording, O2–O6, live checks (deployment.md §3, §4) |
| B10 | 🚧 | Network constraints on address, route and latency, both directions (master plan §3.6, D16, D17; plan [todo/network_constraints.md](todo/network_constraints.md), N1–N9). **Done**: N1 `net.client`/`net.server` grant rule in the spec, vectors and all three verifiers; N2 challenge-timed round trips (timed DPoP nonces; clients answer them); N3 named address lists, published signed and enforced offline and online (`/api/v1/address-lists`, D17 prices); N4 DNS address source in the verify library. What each delivered and what is left: the plan's §13a. **Next**: N5 relays or N6 webhook address check (N6 prices wait on D17). The client side of N2 is in the unversioned SDK (`frontend/sdk/dba.js`), not yet in a release. **The SDK bundle is 65,446 of its 65,536-byte limit**: the next SDK change needs room first (minify whitespace in scripts/build-sdk.mjs, or keep `describeGrant` out of the bundle) |
