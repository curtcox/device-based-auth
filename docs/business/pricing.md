# devicebasedauth.org pricing and cost model

Status: **implemented; prices await owner approval (STATUS D6)**. Prices live only in
`src/utils/pricing.js`; rates and per-operation resource counts live only in
`src/utils/cost-policy.js`. `src/utils/pricing.test.js` fails if any price drops below its floor.
The public pricing page and `GET /api/public/config` read the same constants.

Rates are cronly's (checked 2026-11-15/16) and hashbin's price-floor sheet (2026-10-24). Operation
counts were taken by reading this repository's handlers on 2026-11-18; re-count them whenever a
handler adds a Durable Object call or a storage write.

## Rules

- Money is integer micro-dollars (µ$): $1 = 1,000,000 µ$.
- Prepaid balance, no subscription. $5 minimum credit, card fee itemized on top:
  `ceil((credit¢ + 30) / 0.971)` — a $5 credit costs $5.46. New accounts: at most $20 per payment
  in their first week. Credit is granted only by the verified Stripe webhook.
- A balance never goes negative: every charge checks funds in the same storage transaction.
  Issuance additionally checks funds **before** allocating a status index or signing.
- **Price-floor test:** `price × 0.92 ≥ 1.5 × ceil(worst-case marginal cost)` (0.92 = revenue kept
  after refunds/disputes; 1.5 = minimum margin). Included Cloudflare allowances are ignored.

## Unit rates (µ$)

| Resource | µ$ |
|----------|----|
| Worker request | 0.30 |
| Worker CPU ms | 0.02 |
| Durable Object request | 0.15 |
| DO row written | 1.00 |
| DO storage, per KB-month | 0.20 |
| R2 class A (write) | 4.50 |
| R2 class B (read, cache miss) | 0.36 |

## Prices and worst-case costs

| Operation | Who pays | Counted (per `OPERATIONS`) | Cost µ$ | Floor µ$ | **Price µ$** |
|-----------|----------|----------------------------|--------:|---------:|-------------:|
| Issue a credential (enrollment approval or API) | Issuing account | 3 Worker req, 19 DO req, 19 rows, 80 ms CPU, 6 KB × 13 months, 1 R2 write — includes a **prepaid revocation** and its webhook deliveries, and an enrollment token's check and use counter | 45 | 74 | **75** |
| Rotate a credential to a new key | Issuing account | Same as issue (new status index, old one revoked) | 45 | 74 | **75** |
| Renew (same key) | Issuing account | 1 Worker req, 5 DO req, 5 rows, 10 ms, 1 KB × 13 months | 9 | 15 | **25** |
| Online authorization decision | Audience owner | 1 Worker req, 4 DO req, 4 rows (balance, usage counter, decision row and its later deletion), 0.5 KB × 3 months | 6 | 10 | **10** |
| Metered API read (API key or non-dashboard device) | Caller | 1 Worker req, 3 DO req, 1 row (aggregated on the balance row) | 2 | 4 | **5** |
| Token exchange (≤10-minute bearer token) or X.509 client certificate (≤24 h) | Issuing account | 1 Worker req, 4 DO req, 1 row | 2 | 4 | **5** |
| OpenID Connect sign-in | The site (audience owner) | 2 Worker req, 7 DO req, 4 rows | 6 | 10 | **10** |
| Register or change an audience | Audience owner | 1 Worker req, 3 DO req, 5 rows, 4 KB × 13 months | 17 | 28 | **100** |
| Revocation, offline verification, JWKS, status lists, inspection, enrollment start/poll, dashboard reads | — | Free: prepaid, static, CDN-cached, or rate-limited and behind the cost brake | — | — | **0** |

Decision and login prices sit exactly at their floors (the thinnest margin the rule allows), and
issue is 1 µ$ above its floor since it prepays revocation webhooks and enrollment-token redemption.
Any upward correction found in an audit must raise those prices.

### Why aggregate small charges

A separate ledger row per read, decision or token would cost 1 µ$ each — as much as the operation.
These charges are summed into today's aggregate on the balance row (one write per charge, which the
balance update needs anyway) and flushed as one ledger row per kind when the day rolls over.

### Why issuance is the expensive operation

It carries 13 months of record storage and the full cost of revoking the credential later, so that
revocation is free and always possible, even at a zero balance. That includes telling up to 8
audiences by signed webhook (spec/events.md): four delivery rounds when an endpoint keeps failing.
The revocation shares one outbox row with its webhook deliveries, so the success path writes no
extra rows, and audiences without a webhook cost one registry lookup.

The webhook test button (`POST /api/v1/audiences/{name}/webhook-test`) is charged as a metered read:
1 Worker request, 3 DO requests, one signature and one outbound request.

## What customers would pay

| Scenario | Monthly cost |
|----------|-------------:|
| Developer: 5 devices, 30-day credentials renewed monthly | 5 × 25 µ$ = **$0.000125** |
| Small team: 200 devices, 7-day credentials | 200 × 4.3 × 25 µ$ ≈ **$0.02** |
| Agent fleet: 1,000 agents, 1-hour credentials, 24/7 | 1,000 × 720 × 25 µ$ = **$18.00** |
| Site doing 10 M online decisions | 10 M × 10 µ$ = **$100** |
| Script polling the API 1 M times | 1 M × 5 µ$ = **$5** |

A $5 deposit covers about 66,000 issuances, 200,000 renewals, or 500,000 online decisions.

## Margin and break-even

Margin per operation (`price × 0.92 − cost`): issue ≈ 24 µ$, renew ≈ 14 µ$, decision ≈ 3 µ$,
read/token ≈ 3 µ$, login ≈ 3 µ$. Profit = Σ margins − fixed costs, so it rises with every
operation (master plan principle 6).

Fixed costs specific to devicebasedauth.org, assuming the shared Cloudflare account and LLC (as for
cronly): the domain (~$11/year ≈ $0.92/month) plus Clerk if it ever exceeds 50,000 monthly retained
users. Break-even on $1/month is roughly 31,000 issuances, 71,000 renewals, or 330,000 online
decisions per month.

## Free paths and the cost brake

Free endpoints (`inspect`, enrollment start and describe) are marked `free: true` in `API_ROUTES`.
They write nothing (enrollment requests travel as signed tickets), are rate-limited per IP by the
`PUBLIC_LIMITER` binding, and return 503 when the cost-safety brake is on. The brake latches when a
day of measured Cloudflare cost × 30 exceeds `COST_SAFETY_BRAKE_CENTS` (default $25), or when
measurements are missing for 36 hours. Paid operations keep working: they are prepaid with margin.

## Open questions for the owner

1. Approve these prices (D6), or lower issue/renew towards their floors (74 / 15)?
2. Clerk monthly retained users are the one per-user cost not tied to an operation. Mitigations in
   place: dashboard sign-in with a DBA browser credential (no Clerk session). Proposed (D8, not
   built): close zero-balance accounts with no live credentials after 12 idle months.
