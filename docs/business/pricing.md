# devicebasedauth.org pricing and cost model (DRAFT)

Status: **draft for owner review (STATUS D6)**. Nothing here is implemented. Rates are taken from
cronly's `src/utils/cost-policy.js` and hashbin's `docs/business/price-floor.org` (Cloudflare and
Stripe prices checked there on 2026-10-24 and 2026-11-16). Operation counts are estimates from the
design in `todo/master_plan.md`; they must be re-derived from the real code before launch, as cronly
found when its audit corrected several prices upward.

## Rules

- Money is integer micro-dollars (µ$): $1 = 1,000,000 µ$.
- Prepaid balance, no subscription. $5 minimum credit; the Stripe card fee is itemized on top:
  `ceil((credit¢ + 30) / 0.971)`, so a $5 credit costs $5.46.
- Every billable operation reserves its maximum price before doing work and never settles above it.
- **Price-floor test:** `price × 0.92 ≥ 1.5 × worst-case marginal cost` (0.92 = revenue kept after
  refunds and disputes; 1.5 = minimum margin). A unit test runs it over every price constant.
- Included Cloudflare allowances are ignored in the floor (worst case: we are past every free tier).

## Unit rates (µ$)

| Resource | µ$ |
|----------|----|
| Worker request | 0.30 |
| Worker CPU ms | 0.02 |
| Durable Object request | 0.15 |
| DO row written | 1.00 |
| DO row read | 0.001 |
| DO storage, per KB-month | 0.20 |
| R2 class A (write) | 4.50 |
| R2 class B (read, cache miss) | 0.36 |

## Worst-case marginal cost per operation (estimate)

| Operation | Counted | Cost µ$ | Floor µ$ | Draft price µ$ |
|-----------|---------|--------:|---------:|---------------:|
| **Issue credential** | 2 Worker req (0.6), 4 DO req (0.6), 10 row writes (10.0), 10 ms CPU (0.2), 4 KB × 13 months storage (10.4), **prepaid revocation**: 1 req + 2 DO req + 4 writes + 1 status-list publish to R2 + CPU (9.2) | 31.0 | 50.6 | **75** |
| **Renew / rotate** | 1 Worker req, 3 DO req, 6 row writes, 10 ms CPU, 1 KB × 13 months history | 9.6 | 15.7 | **25** |
| **Online authorization decision** | 1 Worker req, 3 DO req, 2 row writes (usage counter, decision log), 0.5 KB × 3 months log, 3 ms CPU, ledger debit batched per audience (amortized ≈ 0) | 3.1 | 5.1 | **10** |
| **API-key read** (list/get) | cronly's audited read cost (rate counter + ledger writes) | 12–13 | 21 | **21** |
| Revoke | Prepaid in issue | — | — | free |
| Offline verification | No request reaches DBA | 0 | — | free |
| JWKS, SDK, docs, dev tools | Static assets (free on Cloudflare) | 0 | — | free |
| Status-list fetch | CDN hit 0; miss = 1 R2 class B (0.36), at most once per list per edge per 60 s | ≈ 0 | — | free |
| Anonymous enrollment start / poll | Stateless signed blob, rate-limited per IP: 1 Worker req (0.3) each | 0.3 | — | free, bounded by rate limit + cost brake |
| Web UI reads (signed in) | Rate-limited per account | small | — | free |

Issuance needs no status-list republish (a new index starts at 0); only revocation does, and
revocations are debounced to at most one publish per shard per 60 s, so 4.5 µ$ is a true worst case.

## What customers would pay

| Scenario | Monthly cost |
|----------|-------------:|
| Developer: 5 devices, 30-day credentials, auto-renewed monthly | 5 × 25 µ$ = **$0.000125** (+ $0.000375 once) |
| Small team: 200 devices, 7-day credentials | 200 × 4.3 × 25 µ$ ≈ **$0.02** |
| Agent fleet: 1,000 agents, 1-hour credentials, 24/7 | 1,000 × 720 × 25 µ$ = **$18.00** |
| Site doing 10M online decisions | 10M × 10 µ$ = **$100** |

A $5 deposit covers ~66,000 issuances or ~500,000 online decisions.

## Margin and break-even

Per-operation margin = `price × 0.92 − cost`: issue ≈ 38 µ$, renew ≈ 13 µ$, decision ≈ 6 µ$.
Profit = Σ margins − fixed costs, so it rises with every operation (master plan principle 6).

Fixed costs specific to DBA, assuming it shares hashbin's Cloudflare account and LLC (as cronly does):
the `devicebasedauth.org` domain (~$11/year) plus Clerk if it ever passes 50,000 monthly retained
users. The $5/month Workers Paid plan is already paid. Break-even on ~$1/month is roughly 26,000
issuances, or 76,000 renewals, or 170,000 online decisions per month.

## Open questions for the owner

1. Are these thin enough? The floor permits issue ≈ 51 µ$, renew ≈ 16 µ$, decision ≈ 6 µ$; the
   drafts leave headroom for audit corrections and should be lowered after a month of measured
   costs (as cronly's S3 does).
2. Should offline verification stay free (recommended: otherwise developers will avoid the
   service), with the online decision price being the part that scales with "actions run"?
3. Online decisions billed to the audience (the site) rather than the device owner?
