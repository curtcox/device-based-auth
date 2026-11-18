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
| Issue a credential (enrollment approval or API) | Issuing account | 3 Worker req, 20 DO req, 26 rows, 81 ms CPU, 6 KB × 13 months, 1 R2 write — includes a **prepaid revocation** and its webhook deliveries, an enrollment token's check and use counter, and the **deletion of its records** after 13 months | 52 | 85 | **85** |
| Rotate a credential to a new key | Issuing account | Same as issue (new status index, old one revoked) | 52 | 85 | **85** |
| Renew (same key) | Issuing account | 1 Worker req, 5 DO req, 8 rows (incl. later deletion of its ledger, receipt and audit rows), 10 ms, 1 KB × 13 months | 12 | 20 | **25** |
| Online authorization decision | Audience owner | 1 Worker req, 4 DO req, 4 rows (balance, usage counter, decision row and its later deletion), 0.5 KB × 3 months | 6 | 10 | **10** |
| Metered API read (API key or non-dashboard device) | Caller | 1 Worker req, 3 DO req, 1 row (aggregated on the balance row) | 2 | 4 | **5** |
| Token exchange (≤10-minute bearer token) or X.509 client certificate (≤24 h) | Issuing account | 1 Worker req, 4 DO req, 1 row | 2 | 4 | **5** |
| OpenID Connect sign-in | The site (audience owner) | 2 Worker req, 7 DO req, 4 rows | 6 | 10 | **10** |
| Register or change an audience | Audience owner | 1 Worker req, 3 DO req, 8 rows (incl. later deletions), 4 KB × 13 months | 20 | 33 | **100** |
| Revocation, offline verification, JWKS, status lists, inspection, enrollment start/poll, attestation challenges, dashboard reads | — | Free: prepaid, static, CDN-cached, or rate-limited and behind the cost brake | — | — | **0** |

Decision, login and issue prices sit exactly at their floors (the thinnest margin the rule allows).
Issue was 75 µ$ until 2026-11-18, when record compaction (below) added the deletes it prepays.

### Why records are deleted after 13 months

Issuing prepays 13 months of storage for what it writes (credential, device, ledger, receipt and
audit rows). Kept longer, those rows would cost money every month with nothing paying for them, so
the account's Durable Object compacts them (`compact()` in `src/durable-objects/account-do.js`):
an expired credential goes 13 months after it was issued (and no sooner than 30 days after it
expired), a device once it has no credential left and nothing was issued to it for 13 months, and
audit, charge ledger and receipt rows once they are 13 months old. Deleting a row is billed like
writing one, so issue now counts 6 more rows plus a share of the compaction alarm (1 DO request,
1 row); renewals and audience changes count the deletes of their own rows. Compaction runs at most
weekly, so one wake-up serves everything that fell due in between, and stops waking an account
that has nothing left to age out. Kept for good: revoked devices (a revoked key must never return
without a recent sign-in; about 0.1 µ$ a month each), deposits, the daily aggregate ledger rows
and the monthly summaries (one per day or month, not per operation).

Not yet counted: the first metered read, token, decision or sign-in of a day writes that day's
aggregate ledger row, a row the read, token, decision and login counts above omit. Counting it
would put decision and login 2 µ$ above their prices; see S3/D6.
Any upward correction found in an audit must raise those prices.

### Key attestation adds nothing to the issue price

Android key attestation (B5) is checked when the enrollment starts, which is free and behind the
cost brake: one HMAC for the challenge, then parsing and verifying a 3–5 certificate chain (one
RSA or ECDSA verification per certificate, a few ms of CPU, about 0.1 µ$) and Google's revocation
list, fetched at most once an hour per isolate and cached at the edge. The verified result travels
inside the signed approval ticket, so approval and issuance do no extra work.

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

A $5 deposit covers about 58,000 issuances, 200,000 renewals, or 500,000 online decisions.

## Margin and break-even

Margin per operation (`price × 0.92 − cost`): issue ≈ 26 µ$, renew ≈ 11 µ$, decision ≈ 3 µ$,
read/token ≈ 3 µ$, login ≈ 3 µ$. Profit = Σ margins − fixed costs, so it rises with every
operation (master plan principle 6).

Fixed costs specific to devicebasedauth.org, assuming the shared Cloudflare account and LLC (as for
cronly): the domain (~$11/year ≈ $0.92/month) plus Clerk if it ever exceeds 50,000 monthly retained
users. Break-even on $1/month is roughly 38,000 issuances, 90,000 renewals, or 330,000 online
decisions per month.

## Free paths and the cost brake

Free endpoints (`inspect`, enrollment start and describe) are marked `free: true` in `API_ROUTES`.
They write nothing (enrollment requests travel as signed tickets), are rate-limited per IP by the
`PUBLIC_LIMITER` binding, and return 503 when the cost-safety brake is on. The brake latches when a
day of measured Cloudflare cost × 30 exceeds `COST_SAFETY_BRAKE_CENTS` (default $25), or when
measurements are missing for 36 hours. Paid operations keep working: they are prepaid with margin.

## Open questions for the owner

1. Approve these prices (D6), or lower renew towards its floor (20)? Issue is at its floor (85).
2. Clerk monthly retained users are the one per-user cost not tied to an operation. Mitigations in
   place: dashboard sign-in with a DBA browser credential (no Clerk session). Proposed (D8, not
   built): close zero-balance accounts with no live credentials after 12 idle months.
