# devicebasedauth.org Project Status

**This file is the single source of truth for project status.** If another document disagrees
with it, this file wins and the other document is stale.

- **Last audited:** 2026-11-18
- **Production:** not deployed.
- **Overall:** Planning. Design in [`todo/master_plan.md`](todo/master_plan.md); draft prices in
  [`docs/business/pricing.md`](docs/business/pricing.md).

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
| D2 | Credential format: compact JWS (JSON after base64url decode), plain JSON with detached signature, or X.509 | owner | ❓ | JWS/ES256, with readable "inspect" views everywhere; X.509 export later (B3). §3.1. |
| D3 | Verification: offline free + online metered, or online-only (every action billed)? Who pays for online decisions? | owner | ✅ Owner chose offline free + online metered, billed to the audience, 2026-11-18. | Offline free; online decisions (instant revocation, usage limits, audit) at ~10 µ$ billed to the audience. §6, pricing.md. |
| D4 | Location constraints: accept network-observed location, device-reported location in the signed proof, or both? | owner | ✅ Owner chose both, selected per grant, 2026-11-18. | Support both with an explicit `where.source`, and document that neither is tamper-proof without attestation (B5). §3.5. |
| D5 | Billing across sites: separate balances per site, or one shared wallet usable on all three? | owner | ✅ Owner chose always separate, 2026-11-18. | Each site keeps its own balance and Stripe product. §9.3. |
| D6 | Draft prices (issue 75 µ$, renew 25 µ$, online decision 10 µ$, API read 21 µ$, $5 minimum deposit) | owner | ❓ | Accept as starting points; recalibrate from measured costs. [pricing.md](docs/business/pricing.md). |
| D7 | Site sign-in: DBA as a custom OIDC provider inside each site's Clerk app first (Stage A), then device-bound sessions (Stage B)? Separate Clerk application for DBA? | owner/ops | ❓ | Yes to both; confirm the Clerk plan allows custom OIDC providers. §9.2. |
| D8 | Operating entity and dormant accounts: same LLC/Cloudflare account as hashbin and cronly; close zero-balance accounts with no live credentials after 12 months idle? | legal | ❓ | Same entity (as cronly D1); shared operator profile; yes to dormant-account closure after notice. §8.3, §10. |

## Launch blockers

| ID | Item | Owner | Status | Notes |
|----|------|-------|--------|-------|
| L1 | Credential and evaluation spec + conformance vectors | code | ⬜ | Phase 0 |
| L2 | Scaffold ported from cronly (Worker, local mode, Clerk, Stripe µ$ ledger, API_ROUTES, CI) | code | ⬜ | Phase 1 |
| L3 | Issuer keys, JWKS, `@devicebasedauth/verify`, inspector + playground | code | ⬜ | Phase 2 |
| L4 | Enrollment (browser SDK, device code, API), credential registry, dashboard | code | ⬜ | Phase 3 |
| L5 | Revocation, status lists on R2, renewal, rotation | code | ⬜ | Phase 4 |
| L6 | Online authorize, usage counters, audience registry | code | ⬜ | Phase 5 |
| L7 | Docs with CI-executed samples, OpenAPI, CLI, llms.txt, MCP | code | ⬜ | Phase 6 |
| L8 | OIDC provider; DBA dashboard signs in with DBA credentials | code | ⬜ | Phase 7 |
| L9 | Cloudflare zone, R2 bucket + custom domain, Clerk app, Stripe product, secrets | ops | ⬜ | |
| L10 | Cost-safety brake and monitoring | code | ⬜ | Port from hashbin/cronly |
| L11 | Terms, Privacy, acceptable use (no covert tracking) | legal | ⬜ | Shared operator profile |
| L12 | Security review of issuance, revocation and verification | code/owner | ⬜ | |

## Soon after launch

| ID | Item | Owner | Status |
|----|------|-------|--------|
| S1 | cronly accepts DBA device keys and "Sign in with devicebasedauth.org" | code | ⬜ |
| S2 | hashbin accepts DBA device keys and "Sign in with devicebasedauth.org" | code | ⬜ |
| S3 | Recalibrate prices from a month of measured costs | owner | ⬜ |
| S4 | Mobile sample apps (iOS Secure Enclave, Android Keystore) | code | ⬜ |
| S5 | Python and Go verifier packages | code | ⬜ |
| S6 | Issuer signing keys in an external KMS/HSM | ops | ⬜ |

## Backlog

| ID | Item |
|----|------|
| B1 | Revocation webhooks to audiences |
| B2 | Credential templates / fleet enrollment tokens |
| B3 | X.509 export for mTLS (Cloudflare API Shield) |
| B4 | Shared replay cache DO for offline verifiers |
| B5 | Device attestation (App Attest, Play Integrity, TPM) |
| B6 | Customer-supplied issuer CAs |
