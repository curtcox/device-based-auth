# devicebasedauth.org pricing and cost model

Prices live only in `src/utils/pricing.js`; rates and per-operation resource counts live only in
`src/utils/cost-policy.js`. `src/utils/pricing.test.js` fails if any price drops below its floor,
and `src/cost-counts.test.js` fails if an operation does more work than `OPERATIONS` counts. The
public pricing page and `GET /api/public/config` (`price_table`) read the same constants.

**Approval (STATUS decisions).** Approved by the owner: issue/rotate, renew, online decision,
metered read, token, OpenID Connect sign-in and audience (D6, D11, D15), and the security email
`notice` price (D9). **Proposed, awaiting approval:** gate requests and confirmations (D13) and
named address lists (D17); they are implemented and charged at the proposed prices.

Rates are cronly's provider list prices (checked 2026-11-15/16) and hashbin's price-floor sheet.
Re-count `OPERATIONS` whenever a handler adds a Durable Object call or a storage write.

## Rules

- Money is integer micro-dollars (µ$): $1 = 1,000,000 µ$.
- Prepaid balance, no subscription. Deposits of $5 to $1,000 of credit, card fee itemized on top:
  `ceil((credit¢ + 30) / 0.971)` — a $5 credit costs $5.46. New accounts: at most $20 per payment
  in their first week. Credit is granted only by the verified Stripe webhook.
- A balance never goes negative: every charge checks funds in the same storage transaction.
  Issuance additionally checks funds **before** allocating a status index or signing.
- **Price-floor test:** `price × 0.92 ≥ 1.5 × ceil(worst-case marginal cost)` (0.92 = revenue kept
  after refunds/disputes; 1.5 = minimum margin), so the floor is `ceil(1.5 × ceil(cost) / 0.92)`.
  Included Cloudflare allowances are ignored.

## Unit rates (µ$)

| Resource | µ$ |
|----------|----|
| Worker request | 0.30 |
| Worker CPU ms | 0.02 |
| Durable Object request | 0.15 |
| DO row written (a delete counts as a write) | 1.00 |
| DO row read (measured by the cost monitor; too small to count per operation) | 0.001 |
| DO storage, per KB-month | 0.20 |
| R2 class A (write) | 4.50 |
| R2 class B (read, cache miss) | 0.36 |
| Amazon SES email sent | 100 |

## Prices and worst-case costs

Counts are those in `OPERATIONS`. Every operation a device can ask for with a DPoP proof includes a
**DPoP nonce challenge** (D15): an account's object asks for its own nonce during its first 60 s
after starting, so the device's first request may be answered `401 use_dpop_nonce` and sent again
(1 Worker request, 1 DO request, 2 ms, already in the counts below). Online decisions and security
emails do not include it.

| Operation | Who pays | Counted (per `OPERATIONS`) | Cost µ$ | Floor µ$ | **Price µ$** |
|-----------|----------|----------------------------|--------:|---------:|-------------:|
| Issue a credential (enrollment approval or API) | Issuing account | 4 Worker req, 21 DO req, 26 rows, 93 ms CPU, 6 KB × 13 months, 1 R2 write — includes a **prepaid revocation** and its webhook deliveries, an enrollment token's check and use counter, Web Push notices, the **deletion of its records** after 13 months, and the nonce challenge | 53 | 87 | **87** |
| Rotate a credential to a new key | Issuing account | Same as issue (new status index, old one revoked) | 53 | 87 | **87** |
| Renew (same key) | Issuing account | 2 Worker req, 6 DO req, 9 rows (incl. month rollover and later deletion of its ledger, receipt and audit rows), 12 ms, 1 KB × 13 months, incl. the nonce challenge | 14 | 23 | **25** |
| Online authorization decision | Audience owner | 1 Worker req, 4 DO req, 7 rows (balance, daily aggregate row, month summary, decision row and its later deletion, and either a usage counter and its deletion or a step-up request and its deletion), 15 ms (incl. notices of a step-up request), 0.5 KB × 3 months | 9 | 15 | **15** |
| Gate request, per gate contacted (**proposed, D13**) | Account that owns the gates (the credential's issuer) | 2 Worker req, 4 DO req (the answer: authentication with the rate limit and the account; the alarm that prunes it; the nonce challenge), 9 rows (balance and daily aggregate row; request row; its answer or timeout settlement; an audit row and its deletion after 13 months; the row's deletion when used or pruned; for TOTP and security keys, the gate row's last step or signature counter), 27 ms (Web Push to up to 5 browsers; the notice of an allow by timeout; code and signature checks), 0.5 KB × 13 months | 13 | 22 | **22** |
| Webhook gate request, per webhook gate contacted (**proposed, D13**) | Account that owns the gates | As a gate request, plus the signed POST to the service (2 ms) and the transaction recording its outcome (1 row) | 14 | 23 | **23** |
| Duo or Okta Verify gate request, per vendor gate contacted (**proposed, D13**) | Account that owns the gates | As a webhook gate request, plus up to 24 status polls, each an alarm wake-up (24 DO req, ~2 ms each) | 18 | 30 | **30** |
| Confirmation issued (periodic confirmation, **proposed, D13**) | Account that issued the credential (its gates are charged as gate requests) | 2 Worker req, 3 DO req, 5 rows (credential row, balance and daily aggregate row, an audit row and its later deletion), 7 ms (signing), 0.5 KB × 13 months, incl. the nonce challenge | 8 | 14 | **14** |
| Named address list, create or replace, per started 1,000 ranges (**proposed, D17**) | Account that owns the list | 3 Worker req, 8 DO req (the request; a debounced publish from the alarm; the list's later free delete with its tombstone and purge; the nonce challenge), 20 rows (list row, chunk of ranges, charge rows, audit rows, alarm, publish bookkeeping, and their later deletion), 15 ms, 44.5 KB × 13 months, 2 R2 writes (the publish and the delete's tombstone) | 148 | 242 | **242** |
| Named address list, each day its published life is extended to 13 months after a create or replace (**proposed, D17**) | Account that owns the list | Re-signing every 20 hours (1.2 a day): an alarm wake-up, 2 rows, ~5 ms to sign up to 600 KB, one R2 write | 9 | 15 | **15** |
| Security email (D9) | Account it is sent to, when it is queued | 3 DO req (up to 3 alarm wake-ups, one per attempt), 15 rows (charge: balance, ledger and receipt rows and their later deletion; queue row and alarm; attempts' rewrites or deletion and next alarms; an audit row and its deletion; the digest's last-sent row), 10 ms (SigV4 signing per attempt), 0.5 KB × 13 months, **1 SES email** (100 µ$; retried only when SES answered that it did not take it, so at most one is billed) | 117 | 191 | **200** |
| Metered API read (API key or non-dashboard device) | Caller | 2 Worker req, 5 DO req (authentication with the rate limit, charge, up to two for the read, the nonce challenge), 3 rows (balance, daily aggregate row, month summary), 5 ms | 5 | 9 | **9** |
| Token exchange (≤10-minute bearer token), X.509 client certificate (≤24 h), or an MCP app's token refresh (1-hour access token) | Issuing account | 2 Worker req, 5 DO req, 3 rows (balance, daily aggregate row, month summary), 7 ms, incl. the nonce challenge | 5 | 9 | **9** |
| OpenID Connect sign-in | The site (audience owner) | 3 Worker req, 8 DO req, 6 rows (code put, taken and deleted; balance; daily aggregate row; month summary), 12 ms, incl. the nonce challenge | 9 | 15 | **15** |
| Register or change an audience | Audience owner | 2 Worker req, 5 DO req, 8 rows (incl. later deletions), 7 ms, 4 KB × 13 months, incl. the nonce challenge | 20 | 33 | **100** |
| Revocation, offline verification, JWKS, status lists, inspection, enrollment start/poll, attestation challenges, DPoP nonces, dashboard reads | — | Free: prepaid, static, CDN-cached, or rate-limited and behind the cost brake | — | — | **0** |

Issue, decision, read, token, login, gate, webhook gate, vendor gate, confirmation and both address
list prices sit exactly at their floors (the thinnest margin the rule allows). Any upward correction
found when re-counting raises their prices. Online `/authorize` (paid by the site) does not ask for
DPoP nonces (STATUS L12, docs/security/review-log.md).

Month-rollover accounting (D18, 2026-11-27) adds the previously omitted archive write for
renewals, decisions, reads, tokens and sign-ins. Renewals still clear the floor at 25 µ$; the
required floor formula raises decisions/sign-ins to 15 µ$ and reads/tokens to 9 µ$. Counts
are tested across both day and month boundaries on fixed clocks.

### Gate requests (proposed, STATUS D13)

A grant with `require.gates` (or `require.step_up`, which is the built-in owner gate) makes each
use wait for an approval (STATUS B7). The gate request is charged to the account whose gates they
are, once per distinct gate DBA contacts, when the request is opened (retries reuse it); the
audience still pays its online decision, and answering is free. If that account cannot pay, DBA
sends nothing and records the gates as `unpaid`: the request still exists, the owner can answer
it from the dashboard, and otherwise each entry waits for its timeout, so an allow-on-timeout
entry then allows and a deny-on-timeout entry denies. Whether unpaid requests should deny instead
is part of D13. A step-up request's rows are paid by the gate price, not the decision price.

A `dba-device` gate learns of requests by polling `GET /api/v1/gate-requests`, a free read like
the dashboard's own lists (rate-limited per account).

### Named address lists (proposed, STATUS D17)

A grant can name address lists (`net.client.addresses.lists`, STATUS B10 N3). Each list is
published as a signed document beside the status lists and re-signed about daily, so offline
verifiers can enforce it. A create or replace is charged once per started 1,000 ranges, plus one
day of publishing for each day it extends the list's published life to 13 months from now: a new
list prepays 395 days (about $0.006 for up to 1,000 ranges), and changing it a day later pays one
more day. Deleting is free (prepaid). A list not changed for 13 months stops being re-signed and
expires, which denies every grant naming it. Online decisions read lists through a per-isolate
one-minute cache; the R2 reads on a miss are counted with the other free-path reads under the
cost brake, and the decision price does not include them.

### Why records are deleted after 13 months

Issuing prepays 13 months of storage for what it writes (credential, device, ledger, receipt and
audit rows). Kept longer, those rows would cost money every month with nothing paying for them, so
the account's Durable Object compacts them (`compact()` in `src/durable-objects/account/compaction.js`):
an expired credential goes 13 months after it was issued (and no sooner than 30 days after it
expired), a device once it has no credential left and nothing was issued to it for 13 months, and
audit, charge ledger and receipt rows once they are 13 months old, and revoked API keys and ended
enrollment tokens 13 months after they stopped working (free to make, capped only while active).
Deleting a row is billed like writing one, so issue counts its 6 deletes plus a share of the
compaction alarm (1 DO request, 1 row); renewals and audience changes count the deletes of their
own rows. Compaction runs at most weekly, so one wake-up serves everything that fell due in
between, and stops waking an account that has nothing left to age out. Kept for good: revoked
devices (a revoked key must never return without a recent sign-in; about 0.1 µ$ a month each),
deposits, the daily aggregate ledger rows and the monthly summaries (one per day or month, not
per operation).

### How the counts are checked

`src/cost-counts.test.js` measures the Durable Object requests and rows each operation really
makes (plus what it prepays for later: pruning and compaction deletes, revocation, webhooks) and
fails when they exceed `OPERATIONS`. Connected MCP apps record their hourly refresh as
`refreshed_at` and keep the refresh digest on the balance row, so a refresh writes no row of its
own; it is charged as a token (9 µ$, about $0.0065 a month for an app connected around the clock).

The first read of a new day writes yesterday's aggregate ledger rows and saves the rolled balance
row once: one row a day at most, on accounts active the day before, that no operation counts.

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
SES's per-GB charge on these few-KB messages (owner-approved with SES as the provider, D9).
Queueing a digest reads three rows on every ordinary issuance (address, setting, queued digest;
0.003 µ$), which the issue price absorbs.

### Key attestation adds nothing to the issue price

Android key attestation (B5) is checked when the enrollment starts, which is free and behind the
cost brake: one HMAC for the challenge, then parsing and verifying a 3–5 certificate chain (one
RSA or ECDSA verification per certificate, a few ms of CPU, about 0.1 µ$) and Google's revocation
list, fetched at most once an hour per isolate and cached at the edge. The verified result travels
inside the signed approval ticket, so approval and issuance do no extra work.

### Why aggregate small charges

A separate ledger row per read, decision, token or sign-in would cost 1 µ$ each — as much as the
operation. These charges are summed into today's aggregate on the balance row (one write per
charge, which the balance update needs anyway) and flushed as one ledger row per kind when the day
rolls over. That row is counted once in each operation's cost, as if every operation were the
only one of its day.

### Why issuance is the expensive operation

It carries 13 months of record storage and the full cost of revoking the credential later, so that
revocation is free and always possible, even at a zero balance. That includes telling up to 8
audiences by signed webhook (spec/events.md): four delivery rounds when an endpoint keeps failing.
The revocation shares one outbox row with its webhook deliveries, so the success path writes no
extra rows, and audiences without a webhook cost one registry lookup.

The webhook test button (`POST /api/v1/audiences/{name}/webhook-test`) is charged as a metered
read (9 µ$).

## What customers would pay

| Scenario | Monthly cost |
|----------|-------------:|
| Developer: 5 devices, 30-day credentials renewed monthly | 5 × 25 µ$ = **$0.000125** |
| Small team: 200 devices, 7-day credentials | 200 × 4.3 × 25 µ$ ≈ **$0.02** |
| Agent fleet: 1,000 agents, 1-hour credentials, 24/7 | 1,000 × 720 × 25 µ$ = **$18.00** |
| Site doing 10 M online decisions | 10 M × 15 µ$ = **$150** |
| Script polling the API 1 M times | 1 M × 9 µ$ = **$9** |

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

Free public endpoints (inspection, enrollment start and describe, attestation challenges, TPM
activation, DPoP nonces, gate links, sign-up, MCP client registration) are marked `free: true` in
`API_ROUTES`. They write nothing that is not paid for elsewhere (enrollment requests travel as
signed tickets), are rate-limited per IP by the `PUBLIC_LIMITER` binding (240 a minute, like every
Worker path), and return 503 `cost_brake` while the cost-safety brake is on. The hourly cron runs
the cost monitor daily at 02:07 UTC, and again every hour while its last report is missing, stale
or failed. The brake is on when a day of measured Cloudflare cost × 30 exceeds
`COST_SAFETY_BRAKE_CENTS` (default $25), when the measurement fails, or when no report is newer
than 36 hours (unless `COST_SAFETY_FAIL_OPEN=true`); `COST_SAFETY_HARD_STOP=true` forces it on.
Paid operations keep working: they are prepaid with margin.

## Open questions for the owner

1. Renew is 3 µ$ above its floor (22) and could go down to it (D6). Recalibrate all prices from a
   month of measured costs (STATUS S3).
2. Approve or change the proposed gate and confirmation prices (D13) and address list prices (D17).
3. Clerk monthly retained users are the one per-user cost not tied to an operation. Mitigations in
   place: dashboard sign-in with a DBA browser credential (no Clerk session), and accounts created
   by paying with a device, which never become Clerk users at all (STATUS B9). Proposed (D8, not
   built): close zero-balance accounts with no live credentials after 12 idle months.
