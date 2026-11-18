# devicebasedauth.org Project Status

**This file is the single source of truth for project status.** If another document disagrees
with it, this file wins and the other document is stale.

- **Last audited:** 2026-11-18
- **Production:** not deployed (owner steps in [docs/ops/deployment.md](docs/ops/deployment.md)).
- **Overall:** Service, verify library, browser SDK, CLI, samples and OIDC provider implemented and
  tested locally (`npm test`, `npm run test:samples`, `npm run test:e2e`). Prices implemented at the
  proposed values pending D6. Open decisions D2, D6–D8 are implemented with the recommended defaults.
  Design in [`todo/master_plan.md`](todo/master_plan.md); prices in [`docs/business/pricing.md`](docs/business/pricing.md).

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

---

## Decisions needed

| ID | Decision | Owner | Status | Recommendation |
|----|----------|-------|--------|----------------|
| D1 | Who generates device private keys: the device (DBA only ever sees public keys) or DBA (delivers the private key once)? | owner | ✅ Owner chose device-generated 2026-11-18. | Device-generated. DBA never holding private keys removes the biggest breach risk; WebCrypto, keychains, TPMs and Secure Enclave all support it. Master plan §1, §5.1. |
| D2 | Credential format: compact JWS (JSON after base64url decode), plain JSON with detached signature, or X.509 | owner | ❓ Implemented as JWS pending approval. | JWS/ES256, with readable "inspect" views everywhere; X.509 export later (B3). §3.1. |
| D3 | Verification: offline free + online metered, or online-only (every action billed)? Who pays for online decisions? | owner | ✅ Owner chose offline free + online metered, billed to the audience, 2026-11-18. | Offline free; online decisions (instant revocation, usage limits, audit) at ~10 µ$ billed to the audience. §6, pricing.md. |
| D4 | Location constraints: accept network-observed location, device-reported location in the signed proof, or both? | owner | ✅ Owner chose both, selected per grant, 2026-11-18. | Support both with an explicit `where.source`, and document that neither is tamper-proof without attestation (B5). §3.5. |
| D5 | Billing across sites: separate balances per site, or one shared wallet usable on all three? | owner | ✅ Owner chose always separate, 2026-11-18. | Each site keeps its own balance and Stripe product. §9.3. |
| D6 | Prices (issue/rotate 75 µ$, renew 25, online decision 10, metered read 5, token 5, OIDC login 10, audience 100; $5 minimum deposit) | owner | ❓ Implemented pending approval. | Accept; decision and login are at their floors. Recalibrate from measured costs (S3). [pricing.md](docs/business/pricing.md). |
| D7 | Site sign-in: DBA as a custom OIDC provider inside each site's Clerk app first (Stage A), then device-bound sessions (Stage B)? Separate Clerk application for DBA? | owner/ops | ❓ | Yes to both; confirm the Clerk plan allows custom OIDC providers. §9.2. |
| D8 | Operating entity and dormant accounts: same LLC/Cloudflare account as hashbin and cronly; close zero-balance accounts with no live credentials after 12 months idle? | legal | ❓ | Same entity (as cronly D1); shared operator profile; yes to dormant-account closure after notice. §8.3, §10. |

## Launch blockers

| ID | Item | Owner | Status | Notes |
|----|------|-------|--------|-------|
| L1 | Credential and evaluation spec + conformance vectors | code | ✅ | [spec/](spec/): 46 evaluation and 15 signature vectors, run in CI |
| L2 | Worker scaffold ported from cronly (route table, local mode, Clerk, Stripe µ$ ledger, API keys, CI) | code | ✅ | `src/`, `.github/workflows/` |
| L3 | Issuer keys, JWKS, `@devicebasedauth/verify`, inspector + playground | code | ✅ | Plus grant builder and request signer |
| L4 | Enrollment (browser SDK, CLI, API), credential registry, dashboard | code | ✅ | Browser enrollment tested end to end in Playwright |
| L5 | Revocation, status lists on R2, renewal, rotation, delegation limits | code | ✅ | Revoking a credential revokes what it delegated |
| L6 | Online authorize, usage counters, step-up, audience registry | code | ✅ | |
| L7 | Docs with CI-executed samples, OpenAPI, CLI, llms.txt, MCP | code | ✅ | Docs code blocks marked data-sample are checked against the tested samples |
| L8 | OIDC provider; DBA dashboard signs in with DBA credentials | code | ✅ | Consent page and "use this browser as a device" tested in Playwright |
| L9 | Cloudflare zone, R2 bucket + `status.` custom domain, Clerk app, Stripe products, secrets, `DBA_DEPLOY_ENABLED` | ops | ⬜ | [docs/ops/deployment.md](docs/ops/deployment.md) |
| L10 | Cost-safety brake and monitoring | code/ops | 🟨 | Code ✅; needs analytics token and DO namespace ids (L9) |
| L11 | Terms, Privacy, acceptable use (no covert tracking) | legal | 🟨 | DRAFT pages with entity/address/jurisdiction placeholders; owner and legal review needed (shared operator profile, cronly D7) |
| L12 | Security review of issuance, revocation and verification | code/owner | 🟨 | Self-review done (delegation fixes in 8c68a50); independent review still needed |
| L13 | Website: dashboard, approval and consent pages, developer tools, pricing, docs; Playwright tests | code | ✅ | 20 Playwright tests in CI; light/dark; 390 px phone width checked |
| L14 | Publish `@devicebasedauth/verify` (and the CLI) to npm | ops | ⬜ | CLI must import `@devicebasedauth/verify` instead of a relative path before publishing |

## Soon after launch

| ID | Item | Owner | Status | Notes |
|----|------|-------|--------|-------|
| S1 | cronly accepts DBA device keys and "Sign in with devicebasedauth.org" | code | 🚧 | Shared helpers ✅ (`createSiteAuth`, `createOidcClient`); cronly patch in `integrations/cronly/` |
| S2 | hashbin accepts DBA device keys and "Sign in with devicebasedauth.org" | code/owner | 🟨 | Device keys, access tokens and OIDC account linking with spend caps on hashbin branch `claude/dba-integration` (4 commits, 1,064 tests pass); not merged. Owner: review/merge, fund the operator account; Stage A Clerk provider and Stage B device sessions are hashbin S23/S24 |
| S3 | Recalibrate prices from a month of measured costs | owner | ⬜ | |
| S4 | Mobile sample apps (iOS Secure Enclave, Android Keystore) | code | ⬜ | |
| S5 | Python and Go verifier packages | code | ⬜ | Python and Go samples exist in docs/samples |
| S7 | CLI auto-renewal at 2/3 of lifetime (the SDK has it) | code | ⬜ | |
| S6 | Issuer signing keys in an external KMS/HSM | ops | ⬜ | |

## Backlog

| ID | Item |
|----|------|
| B1 | Revocation webhooks to audiences |
| B2 | Credential templates / fleet enrollment tokens |
| B3 | X.509 export for mTLS (Cloudflare API Shield) |
| B4 | Shared replay cache DO for offline verifiers |
| B5 | Device attestation (App Attest, Play Integrity, TPM) |
| B6 | Customer-supplied issuer CAs |
