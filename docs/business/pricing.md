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
| Amazon SES email sent | 100 |

## Prices and worst-case costs

| Operation | Who pays | Counted (per `OPERATIONS`) | Cost µ$ | Floor µ$ | **Price µ$** |
|-----------|----------|----------------------------|--------:|---------:|-------------:|
| Issue a credential (enrollment approval or API) | Issuing account | 4 Worker req, 21 DO req, 26 rows, 93 ms CPU, 6 KB × 13 months, 1 R2 write — includes a **prepaid revocation** and its webhook deliveries, an enrollment token's check and use counter, and the **deletion of its records** after 13 months — plus a **DPoP nonce challenge** (1 Worker req, 1 DO req, 2 ms; D15) | 53 | 87 | **87** |
| Rotate a credential to a new key | Issuing account | Same as issue (new status index, old one revoked) | 53 | 87 | **87** |
| Renew (same key) | Issuing account | 2 Worker req, 6 DO req, 8 rows (incl. later deletion of its ledger, receipt and audit rows), 10 ms, 1 KB × 13 months — plus a **DPoP nonce challenge** (1 Worker req, 1 DO req, 2 ms; D15) | 13 | 22 | **25** |
| Online authorization decision | Audience owner | 1 Worker req, 4 DO req, 6 rows (balance, daily aggregate row, decision row and its later deletion, and either a usage counter and its deletion or a step-up request and its deletion), 15 ms (incl. notices of a step-up request), 0.5 KB × 3 months | 8 | 14 | **14** |
| Gate request, per gate contacted (**proposed, D13**) | Account that owns the gates (the credential's issuer) | 2 Worker req and 4 DO req (the answer: authentication with the rate limit and the account; the alarm that prunes it), 9 rows (balance and daily aggregate row; request row; its answer or timeout settlement; an audit row and its deletion after 13 months; the row's deletion when used or pruned; for TOTP and security keys, the gate row's last step or signature counter), 25 ms (Web Push to up to 5 browsers; the notice of an allow by timeout; code and signature checks), 0.5 KB × 13 months — plus a **DPoP nonce challenge** (1 Worker req, 1 DO req, 2 ms; D15) | 13 | 22 | **22** |
| Webhook gate request, per webhook gate contacted (**proposed, D13**) | Same | As a gate request, plus the signed POST to the service (2 ms) and the transaction recording its outcome (1 row) | 14 | 23 | **23** |
| Duo or Okta Verify gate request, per vendor gate contacted (**proposed, D13**) | Account that owns the gates | As a gate request, plus starting the push (signed subrequest, 1 row) and up to 24 status polls, each an alarm wake-up (24 DO req, ~2 ms each) | 18 | 30 | **30** |
| Confirmation issued (periodic confirmation, **proposed, D13**) | Account that issued the credential (its gates are charged as gate requests) | 2 Worker req, 3 DO req, 5 rows (credential row, balance and daily aggregate row, an audit row and its later deletion), 5 ms (signing), 0.5 KB × 13 months — plus a **DPoP nonce challenge** (1 Worker req, 1 DO req, 2 ms; D15) | 8 | 14 | **14** |
| Security email (D9) | Account it is sent to, when it is queued | 3 DO req (up to 3 alarm wake-ups, one per attempt), 15 rows (charge: balance, ledger and receipt rows and their later deletion; queue row and alarm; attempts' rewrites or deletion and next alarms; an audit row and its deletion; the digest's last-sent row), 10 ms (SigV4 signing per attempt), 0.5 KB × 13 months, **1 SES email** (100 µ$; retried only when SES answered that it did not take it, so at most one is billed) | 117 | 191 | **200** |
| Metered API read (API key or non-dashboard device) | Caller | 2 Worker req, 5 DO req (authentication with the rate limit, charge, up to two for the read), 2 rows (aggregated on the balance row, daily aggregate row) — plus a **DPoP nonce challenge** (1 Worker req, 1 DO req, 2 ms; D15) | 4 | 7 | **7** |
| Token exchange (≤10-minute bearer token), X.509 client certificate (≤24 h), or an MCP app's token refresh (1-hour access token) | Issuing account | 2 Worker req, 5 DO req, 2 rows (balance, daily aggregate row) — plus a **DPoP nonce challenge** (1 Worker req, 1 DO req, 2 ms; D15) | 4 | 7 | **7** |
| OpenID Connect sign-in | The site (audience owner) | 3 Worker req, 8 DO req, 5 rows (incl. daily aggregate row) — plus a **DPoP nonce challenge** (1 Worker req, 1 DO req, 2 ms; D15) | 8 | 14 | **14** |
| Register or change an audience | Audience owner | 2 Worker req, 5 DO req, 8 rows (incl. later deletions), 4 KB × 13 months — plus a **DPoP nonce challenge** (1 Worker req, 1 DO req, 2 ms; D15) | 20 | 33 | **100** |
| Revocation, offline verification, JWKS, status lists, inspection, enrollment start/poll, attestation challenges, dashboard reads | — | Free: prepaid, static, CDN-cached, or rate-limited and behind the cost brake | — | — | **0** |

Decision, login, read, token, issue and confirmation prices sit exactly at their floors (the thinnest margin the
rule allows). The owner approved these prices on 2026-11-18 (D6). That day issue went from 75 to
85 µ$, when record compaction (below) added the deletes it prepays, and decision and login from 10
to 12 µ$, when counting the daily aggregate ledger row (below) raised their floors. Later that day
an audit of online decisions found two more rows in the worst case (a usage window holding a
single decision is written and later deleted; so is a step-up request), so decision went to its
new floor of 14 µ$, also approved by the owner (D11). Step-up requests are now reused while
they wait and deleted when their approval is used, which keeps it at two rows rather than three.

**DPoP nonces (D15, approved by the owner 2026-11-22).** The account's object keeps the DPoP
proofs it has seen in memory, which is empty again whenever the object starts (after a minute or
two idle, a deploy, a move), so for its first 60 s it asks every proof for its nonce (RFC 9449
§8): the device's first request answers `401 use_dpop_nonce` and is sent once more. A device that
calls every few minutes meets this on most calls, so every operation a device can ask for with a
proof counts one more Worker request, its authentication (1 DO request) and 2 ms. That raised the
floors of issue (85 → 87), read and token (5 → 7), OpenID Connect sign-in (12 → 14), confirmation
(12 → 14), gate (20 → 22) and webhook gate (22 → 23) requests; prices moved to the new floors. Online
`/authorize` (paid by the site) is unchanged: it does not ask for nonces (STATUS L12).

### Gate requests (proposed, STATUS D13)

A grant with `require.gates` (or `require.step_up`, which is the built-in owner gate) makes each
use wait for an approval (STATUS B7). The gate request is charged to the account whose gates they
are, once per distinct gate DBA contacts, when the request is opened (retries reuse it); the
audience still pays its online decision, and answering is free. If that account cannot pay, DBA
sends nothing and records the gates as `unpaid`: the request still exists, the owner can answer
it from the dashboard, and otherwise each entry waits for its timeout, so an allow-on-timeout
entry then allows and a deny-on-timeout entry denies. Whether unpaid requests should deny instead
is part of D13. Before gates, a step-up request's rows were counted in the decision price; they
are now paid by the gate price, and the decision price is unchanged.

A `dba-device` gate learns of requests by polling `GET /api/v1/gate-requests`, a free read like
the dashboard's own lists (rate-limited per account).

### Why records are deleted after 13 months

Issuing prepays 13 months of storage for what it writes (credential, device, ledger, receipt and
audit rows). Kept longer, those rows would cost money every month with nothing paying for them, so
the account's Durable Object compacts them (`compact()` in `src/durable-objects/account/compaction.js`):
an expired credential goes 13 months after it was issued (and no sooner than 30 days after it
expired), a device once it has no credential left and nothing was issued to it for 13 months, and
audit, charge ledger and receipt rows once they are 13 months old, and revoked API keys and ended
enrollment tokens 13 months after they stopped working (free to make, capped only while active). Deleting a row is billed like
writing one, so issue now counts 6 more rows plus a share of the compaction alarm (1 DO request,
1 row); renewals and audience changes count the deletes of their own rows. Compaction runs at most
weekly, so one wake-up serves everything that fell due in between, and stops waking an account
that has nothing left to age out. Kept for good: revoked devices (a revoked key must never return
without a recent sign-in; about 0.1 µ$ a month each), deposits, the daily aggregate ledger rows
and the monthly summaries (one per day or month, not per operation).

The first metered read, token, decision or sign-in of a day on an account writes that day's
aggregate ledger row for its kind, so each of those operations counts one row for it (it was
omitted until 2026-11-18, which left decision and login 2 µ$ under their floors).
Any upward correction found in an audit must raise those prices.

The counts are checked against the code: `src/cost-counts.test.js` measures the Durable Object
requests and rows each operation really makes (plus what it prepays for later: pruning and
compaction deletes, revocation, webhooks) and fails when they exceed `OPERATIONS`. Writing it
found metered reads making 4 DO requests where 3 were counted (5 before authentication took over
the rate-limit check, which every authenticated request used to spend a DO request on), an
audience change making 4, and connected MCP apps writing a "last used" row every hour, which is
gone (the hourly refresh records `refreshed_at`). It also found the MCP refresh grant writing a
row per refresh without charging; a refresh now costs a token (7 µ$, about $0.005 a month for an
app connected around the clock), and keeps its refresh digest on the balance row so it writes no
row of its own.

The first read of a new day writes yesterday's aggregate ledger rows and saves the rolled balance
row once (one row a day at most that no operation counts, on accounts active the day before);
before that fix, every read wrote the aggregate rows again until something was charged.

### Security notices ride on the issue price

An account owner can turn on security notices for up to 5 browsers (master plan §10): an encrypted
Web Push message when a credential is issued or rotated, an API key or app connection is created,
or an enrollment token is made. Push services charge nothing; each message costs the account's
Durable Object about 2 ms of CPU (a fresh ECDH key, HKDF and AES-GCM; the VAPID signature is
reused for hours), so issue counts 10 ms for five browsers. Ordinary issuances are announced at
most once an hour per account (the next notice says how many were held back); credentials with
`dba:*` actions, rotations of them, reinstated devices, API keys and enrollment tokens are always
announced. The hourly decision is stored on the balance row the charge writes anyway, so it costs
no extra row. Subscribing a browser is free (a signed-in owner only, at most 5, one row).

### Security email is charged per email (D9)

An email costs more than a whole issuance (SES list price $0.10 per 1,000 is 100 µ$; Postmark-class
providers about 1,500 µ$), so "an email per issuance" would break the price-floor rule. Instead
(STATUS S8, D9): takeover-sensitive events are emailed at once (credentials with `dba:*` actions
and their rotations, reinstated devices, API keys and app connections, enrollment tokens, gates
added or removed, sign-in gate changes, new or used recovery codes, raised limits), and other
issuances and rotations at most once an hour, in one digest read from the audit trail when it is
sent. Each email is charged the `notice` price when it is queued, in its own transaction after
the event, and only if the balance covers it: an account that cannot pay, has no verified address
or turned emails off gets none, and the event itself is never refused or charged more. The owner
chooses `security_email`: `all` (default), `sensitive` (no digest) or `off`; turning it down needs a
recent sign-in and sends one last email. 200 µ$ is just above the 191 µ$ floor, leaving room for
SES's per-GB charge on these few-KB messages; the owner approved it, with SES as the provider, on
2026-11-21 (D9). Queueing a digest reads three rows on every
ordinary issuance (address, setting, queued digest; 0.003 µ$), which the issue price absorbs.

### Key attestation adds nothing to the issue price

Android key attestation (B5) is checked when the enrollment starts, which is free and behind the
cost brake: one HMAC for the challenge, then parsing and verifying a 3–5 certificate chain (one
RSA or ECDSA verification per certificate, a few ms of CPU, about 0.1 µ$) and Google's revocation
list, fetched at most once an hour per isolate and cached at the edge. The verified result travels
inside the signed approval ticket, so approval and issuance do no extra work.

### Why aggregate small charges

A separate ledger row per read, decision or token would cost 1 µ$ each — as much as the operation.
These charges are summed into today's aggregate on the balance row (one write per charge, which the
balance update needs anyway) and flushed as one ledger row per kind when the day rolls over. That
row is counted once in each operation's cost, as if every operation were the only one of its day.

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
| Site doing 10 M online decisions | 10 M × 14 µ$ = **$140** |
| Script polling the API 1 M times | 1 M × 7 µ$ = **$7** |

A $5 deposit covers about 57,000 issuances, 200,000 renewals, or about 357,000 online decisions.

## Margin and break-even

Margin per operation (`price × 0.92 − cost`): issue ≈ 28 µ$, renew ≈ 11 µ$, decision ≈ 5.4 µ$,
read ≈ 3.0 µ$, token ≈ 3.0 µ$, login ≈ 5.5 µ$. Profit = Σ margins − fixed costs, so it rises with every
operation (master plan principle 6).

Fixed costs specific to devicebasedauth.org, assuming the shared Cloudflare account and LLC (as for
cronly): the domain (~$11/year ≈ $0.92/month) plus Clerk if it ever exceeds 50,000 monthly retained
users. Break-even on $1/month is roughly 36,000 issuances, 93,000 renewals, or 186,000 online
decisions per month.

## Free paths and the cost brake

Free endpoints (`inspect`, enrollment start and describe) are marked `free: true` in `API_ROUTES`.
They write nothing (enrollment requests travel as signed tickets), are rate-limited per IP by the
`PUBLIC_LIMITER` binding, and return 503 when the cost-safety brake is on. The brake latches when a
day of measured Cloudflare cost × 30 exceeds `COST_SAFETY_BRAKE_CENTS` (default $25), or when
measurements are missing for 36 hours. Paid operations keep working: they are prepaid with margin.

## Open questions for the owner

1. ~~Approve these prices (D6)~~ Approved 2026-11-18. Renew could still go towards its floor (20).
2. Clerk monthly retained users are the one per-user cost not tied to an operation. Mitigations in
   place: dashboard sign-in with a DBA browser credential (no Clerk session), and accounts created
   by paying with a device, which never become Clerk users at all (STATUS B9). Proposed (D8, not
   built): close zero-balance accounts with no live credentials after 12 idle months.
