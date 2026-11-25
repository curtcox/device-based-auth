# Paid accounts without Clerk

Status: **done** (A0–A8); STATUS **B9**, **D14** (owner's choices). Owner steps left: legal
review of the privacy and terms wording, open questions O2–O6 (§7), and the live checks after
L9 (docs/ops/deployment.md §3, §4). Kept for reference: the design below is as built.

## 1. What and why

A paid devicebasedauth.org account can be created, funded, used, administered and recovered
with only a device and a card, without ever signing in with Clerk. The journey test
`src/clerk-free-accounts.test.js` runs with every `CLERK_*` unset and fails on any read of one;
the CI sample `docs/samples/signup-and-recover.sh` does the same against a local server.

### 1.1 What works the same for any account

A browser or CLI holding a dashboard device credential (our own audience with `dba:session`,
sent as `Authorization: DBA` plus a DPoP proof) counts as a session (`canAccess` in
`src/auth/scopes.js`), so it can deposit (`POST /api/v1/payments/checkout`; the Stripe webhook
credits by `client_reference_id`, never by a Clerk identity), issue and renew credentials, use
`/authorize`, manage audiences, revoke, and read transactions and audit.
`frontend/js/auth.js` loads Clerk only when the browser has no device credential.

### 1.2 Steps that need Clerk on a Clerk account, and their replacements

| Needed | With Clerk | Without Clerk |
|--------|------------|---------------|
| Creating the account | first Clerk sign-in (`user_…` id) | paying with a device (§3.2) |
| A recent sign-in (`requireRecentSignIn` in `src/auth/reverify.js`) for API keys, `dba:*` credentials (so a second dashboard device), connecting an app with Sign in with devicebasedauth.org, gates and sign-in gates, recovery codes, raising budget limits, turning down security email, reinstating a revoked device | a Clerk session with a recent `fva` claim | the first ten minutes after sign-up or recovery (§3.3), or an approval by one of the owner's gates (§3.4) |
| Getting back in after losing every device | signing in with Clerk again | recovery codes, a passkey or second device, or a verified email (§3.5) |
| Security email address | the address Clerk verified | an address verified here (§3.7) |

## 2. Decisions already made (D14, owner)

| Question | Choice |
|----------|--------|
| How does a Clerk-free account come into existence? | **Pay to create.** A device starts a sign-up bound to its public key and pays the first Stripe deposit; the signed webhook creates the account. Nothing is stored until money arrives. |
| How does a Clerk-free owner get back in after losing every device? | **The owner picks, at sign-up and later, any of:** recovery codes, a passkey or second device, a verified email address (SES). Or **none**, accepted explicitly: losing every device then loses the account. |
| What replaces a recent Clerk sign-in? | **The owner's gates**: a passkey, TOTP or another-device gate approves. With no such gate those operations wait until the owner adds one. |
| How do Clerk and Clerk-free accounts relate? | **They coexist and can be linked.** A Clerk-free account may add a Clerk sign-in later; a Clerk account may keep working with only devices. |

## 3. Design

### 3.1 Account ids

Clerk-free accounts get `acct_` plus 26 random base32 characters, made with
`crypto.getRandomValues`. Clerk accounts keep their `user_…` ids. Account ids are already opaque
strings everywhere (the credential's `acct` claim, Durable Object names), so nothing else
changes. The profile row records how the account began: `{ created_via: 'clerk' | 'signup' }`.

### 3.2 Sign-up: pay to create (A1: `src/api/signup.js`)

1. The device makes its key (browser SDK slot `dashboard`, or the CLI) and signs a normal
   `dba-enroll+jwt` enrollment request (`readEnrollRequest` in `src/api/enrollments.js`); `aud`
   and `grants` may be left out. The server ignores any it names: a sign-up always issues the
   dashboard grant set (our audience, `dba:session`), the same set as "Make this browser a device"
   in `frontend/js/dashboard-account.js`.
2. `POST /api/v1/signup` is `PUBLIC`, `free: true` (stopped by the cost brake) and behind
   `PUBLIC_LIMITER` per IP. Its body is `{ request, credit_cents, accept_terms: true }` (the terms
   are still a draft with no version; O6). It checks the deposit (the $5 minimum and the
   first-week $20 cap, `quoteDeposit` in `src/api/payments.js`) and the request, mints the account
   id and a sign-up id (`sup_…`), and opens a Stripe Checkout through `openCheckout` (shared with
   `checkout`) with `client_reference_id = account` and metadata
   `{ kind: 'signup', signup, jkt, terms_accepted, account, credit_cents, product }`. It returns
   the Checkout `url`, a signed `ticket` (`sup_…`: id, account, jwk, jkt, device, attestation,
   lifetime, credit_cents; 30 days) and `interval`. **It writes nothing**, like anonymous
   enrollment starts (master plan §5.1). `?dry_run=1` quotes without a request. `LAUNCH_APPROVED`
   and missing Stripe configuration refuse as for `checkout`; a local server without Stripe
   skips Checkout (`local_payment`).
3. The person pays on Stripe; Checkout returns to `/signup.html#paid`, which keeps the ticket
   beside the SDK key. The CLI polls instead.
4. **Webhook.** `stripeWebhook` keeps every deposit check and, for `kind: 'signup'`, also
   requires a sign-up account id (`acct_` + 26), `metadata.signup` and `metadata.jkt`; any other
   `kind` is refused. `creditSignup` calls `init` with `signup: { id, jkt }`, which creates the
   profile `{ created_via: 'signup', signup, terms_accepted_at }` and **never attaches a sign-up to
   an account that already exists**, then `deposit` (idempotent by Checkout session id).
5. `POST /api/v1/signup/complete` is `PUBLIC`, `billable: 'issue'`. Its body is `{ ticket }`, with
   a DPoP proof by the ticket's key whose `ath` is the ticket's hash. It reads the account's
   sign-up (`op_signup_status`, which writes nothing, so polling before payment creates nothing)
   and answers `{ status: 'pending' }` until it matches; this is also the poll. Then it issues the
   dashboard credential with charge id `signup-<id>`, so a repeat call returns the same
   credential, charged once.
6. **Local mode.** `POST /api/v1/dev/signup-paid` (local only) does what the webhook does for a
   ticket, so samples, Playwright and `npm run dev:local` can sign up end to end.

Cost and price: the webhook's writes are a deposit's plus the profile row (deposits are free);
completion is an ordinary issue that reads the sign-up instead of an enrollment's get and put.
`src/cost-counts.test.js` measures it within `issue` (one more row than a later issue: the
account's compaction schedule, which every account's first issue writes). No new price.

Abuse: creating a Checkout session costs us nothing and Stripe nothing until paid; card testing is
Stripe Radar's job, and $5 is the minimum. The per-IP limiter and the brake bound Worker requests.

### 3.3 The first ten minutes count as a recent sign-in (A2)

Paying is a fresh authentication. A credential issued by `signup/complete`, or by any recovery in
§3.5, counts as **recently signed in for `REVERIFY_MINUTES` (10) after it was issued**. That
breaks the bootstrap loop: the new owner can make recovery codes, add a passkey or approve a
second device straight away. `credential-status`, which the account object already answers on
every device request, returns `signed_in_at` (the later of the credential's `reverified_at` and,
for a sign-up or recovery credential, its issuance), so this costs no extra request.

### 3.4 Recent sign-in through the owner's gates (A2)

`recentlySignedIn` in `src/auth/reverify.js` also accepts a dashboard device whose session was
**re-verified within `REVERIFY_MINUTES` by one of the owner's gates** of kind `webauthn`, `totp`
or `dba-device`. A `dba-device` gate must name a different device from the one asking. The
`owner` kind does not count (the asking device is itself an owner), and neither does a recovery
code.

- `POST /api/v1/session/reverify` (`SESSION`) opens a gate request (purpose `reverify`,
  `src/durable-objects/account/reverify.js`) with one entry any such gate may approve, denying
  after 5 minutes, number-matched like a sign-in. It is charged as one gate request (D13). Once a
  gate approves, `reverified_at` is recorded on the credential's own row: no extra rows, and it
  lasts per device, not per account.
- The `reverification_required` 403 body carries `reverify: { url: '/api/v1/session/reverify',
  gates: [...] }` beside `clerk_error`, and the dashboard's "Sign in again" button uses whichever
  the account has (`frontend/js/dashboard-reverify.js`). Clerk accounts' dashboard devices
  benefit too.
- With no such gate, the 403 says to add a passkey or a second device. Adding a gate itself
  needs a recent sign-in, so §3.3's ten minutes, or a recovery, is how the first one gets added.
  The sign-up flow offers it straight away.

### 3.5 Recovery (codes A3, gates A4, email A5)

Code in `src/api/recovery.js`, `src/durable-objects/account/recovery.js`,
`src/api/email-address.js` and `src/durable-objects/account/email-address.js`. Every recovery
issues a new dashboard credential to a new key, **free** (`issueCredential(…, { free: true })`,
so an empty balance cannot lock the owner out), counts as recently signed in (§3.3), may
reinstate a revoked device, and is audited and announced. The account id, which recovery needs,
is on the Account page and the recovery sheet. `POST /api/v1/recover` is `PUBLIC` but not
`free: true`, so the cost brake never blocks getting back in; the per-IP limiter and per-account
limits bound it. An unknown account answers like a failure and stores nothing.

- **The owner's choice** is read from what exists rather than kept as separate settings that
  could disagree with it. `GET /api/v1/account/recovery` reports the recovery codes left, the
  recovery gates, the verified address and `no_recovery_acknowledged_at`, with `at_risk` while
  there is none of them; `POST { acknowledge_no_recovery: true }` records the explicit choice of
  none ("If I lose this device, I lose this account and its balance"). The Account page warns
  while the account is at risk.
- **Recovery codes.** The dashboard's 10 one-time codes (hashed; making a sheet needs a recent
  sign-in and returns the account id with them). `POST /api/v1/recover` takes
  `{ account, via: 'code', code, request }`: the enrollment request, signed by the new key within
  10 minutes, proves the key, so no DPoP proof is needed and a used code cannot be replayed.
  5 wrong codes per account per 15 minutes.
- **Passkey or second device.** `via: 'gate'` opens a gate request (purpose `recover`, keyed by
  the new key) to the account's `webauthn` and `dba-device` gates, one entry, denied after 10
  minutes. It returns the number the new device shows (approvers type it, including on the
  approval page; a passkey can answer on the new device itself through `/gate.html`, since
  passkeys sync), the approval page link, and a signed `rcv_` ticket.
  `POST /api/v1/recover/complete` with a DPoP proof bound to the ticket answers `pending` until a
  gate approves, then issues the credential (charge id from the request, so a repeat returns the
  same one). At most 3 new requests per account per hour; an account without such gates answers
  409 `no_recovery_gate`. TOTP gates do not recover (O2). A dashboard device registered as a
  `dba-device` gate answers for that gate as the device.
- **Verified email.** `POST /api/v1/account/email` (recent sign-in) emails a link to
  `/email-link.html` through SES, charged the notice price; the page posts it to
  `/api/v1/account/email/verify`, and the address becomes the security email and recovery
  address (`email_source: 'verified'`). The registry maps each verified address, as
  `SHA-256("dba-email\n" + lower-cased address)`, to the one account it recovers (another account
  verifying it gets 409 `email_in_use`); `DELETE /api/v1/account/email` (recent sign-in) releases
  it. `via: 'email'` answers the same whether or not the address is known, and its ticket never
  names the account (completion looks it up again). The emailed link starts a **72-hour wait**
  (O1, `EMAIL_RECOVERY_WAIT_MS`), told to every browser and by email; any dashboard sign-in
  cancels it (`POST /api/v1/account/recovery { cancel_email_recovery }`, shown on the Account
  page). At most three recovery emails per account per hour; one the balance cannot pay goes
  free. Pages need a click before anything happens, so mail scanners that open links change
  nothing. Email is the weakest method, and the sign-up page says so.

### 3.6 Linking Clerk, both ways (A6)

- **A Clerk-free account adds a Clerk sign-in** ("Add a password sign-in" on the Account page,
  offered to accounts made by paying; the API allows any account without a link). With a recent
  sign-in, the owner signs up with Clerk and the dashboard posts the Clerk session token to
  `POST /api/v1/account/clerk-link` (`src/durable-objects/account/clerk-link.js`). It refuses a
  Clerk user whose own account has history (a balance, any ledger row, credential or API key, or a
  link to another account). Linking writes the account (`clerk_sub`) first, then marks the Clerk
  user's own account `linked_to` (so `user.deleted` reaches the linked one), then sets the Clerk
  user's `public_metadata.dba_account` through Clerk's Backend API; a retry after Clerk fails
  goes through. Ops step (docs/ops/deployment.md §3): the Clerk session token carries
  `{"dba_account": "{{user.public_metadata.dba_account}}"}`.
- **The middleware** takes `dba_account` from the Clerk session (else `sub`) and passes the Clerk
  user to the `init` call it already makes, which refuses (401, creating nothing) unless the
  account's `clerk_sub` names that user, so a stale or forged claim opens nothing and no request
  is added. The Clerk webhook routes by `public_metadata.dba_account` too.
- **Unlinking** (`DELETE /api/v1/account/clerk-link`) needs a recent sign-in plus either a live
  dashboard device or a recovery method, and clears a Clerk-sourced address too. An unlinked
  Clerk user can later be linked to another account.
- **A Clerk account can keep working with only devices.** Recovery (§3.5) and gate
  re-verification (§3.4) do not depend on how the account began. Deleting the Clerk user never
  closes the DBA account (`user.deleted` only forgets the link and a Clerk-sourced address).
- Linking is a free dashboard action with one call to Clerk. Playwright cannot cover the Clerk
  window (it needs a real Clerk application); the live check is in docs/ops/deployment.md §3.

### 3.7 Security email

The profile records `email_source: 'clerk' | 'verified'`. The Clerk webhook overwrites only an
address that came from Clerk. Everything else about email (STATUS S8) is the same for both kinds
of account.

### 3.8 Clients (A7)

- **Pages.** `/signup.html` ("Create an account with this browser": deposit, terms and privacy
  tick box, then Checkout) keeps the new key and its pending sign-up in the dashboard's device
  slot (`dashboard`), so after paying the dashboard opens signed in with it. After paying it
  offers recovery codes (shown once, with a download), links to add a passkey or verify an email,
  or accepting no way back. `/recover.html` offers all three ways and resumes a waiting recovery
  on the next visit. Linked from the home page, pricing, the sign-in panel and the site map.
- **CLI** (`packages/cli/account.js`, `commands/account.js`). `dba signup --accept-terms
  [--deposit N]` prints the Checkout link (no QR code), polls, and saves a dashboard device; it
  prints a recovery sheet unless `--no-recovery-codes` (a CLI account has no dashboard to make
  one later). `dba recover --account acct_… --code …` (or `--via gate`, `--email`). Both keep
  the key and a `pending.json` before waiting, so `--resume` finishes later.
- **Browser SDK** v1.3.0: `signUp({ creditCents, acceptTerms })`, `recover(…)`, `finish()`.
- Locally, the page and CLI pay through `POST /api/v1/dev/signup-paid`, so `npm run dev:local`,
  the browser tests and the samples can sign up.

## 4. Tests: what proves it

All new Vitest suites run with **`CLERK_SECRET_KEY`, `CLERK_PUBLISHABLE_KEY` and
`CLERK_WEBHOOK_SECRET` unset**, with `ENVIRONMENT: 'production'` and `LAUNCH_APPROVED: 'true'`.

- **Stripe test hook.** `env.STRIPE_FETCH` replaces Stripe's HTTP client in tests only
  (`Stripe.createFetchHttpClient(env.STRIPE_FETCH)`), like `env.CLERK_VERIFY_TOKEN`. Webhook
  events are signed for real with a test secret: `stripe.webhooks.generateTestHeaderString`
  (stripe 14.25, Node crypto), or an HMAC-SHA256 over `timestamp.payload` in WebCrypto if the
  tests run where Node crypto is missing.
- **Payments** (phase A0, `src/payments.test.js`): a dashboard device opens Checkout; the webhook
  credits once; a replay credits nothing; a bad signature, an amount that does not match, an
  unpaid session or a foreign product is refused; the first-week cap and `launch_pending` hold.
- **The journey test** (`src/clerk-free-accounts.test.js`), the test that backs the docs' claim:
  sign up, then webhook, then complete; `whoami`; deposit again as the device; issue a credential
  for another audience and `/authorize` with it; make recovery codes and add a passkey gate within
  the ten minutes; after the ten minutes, get refused, re-verify through the gate, then create an
  API key and approve a second dashboard device; lose both devices and recover with a code.
- **A guard test**: for every route the journey uses, `canAccess` passes for a `dba:session`
  device, and the route's handler does not read `env.CLERK_*`. A route that becomes Clerk-only
  then fails CI.
- Refusals: completion with the wrong key, an unpaid or foreign ticket, an expired ticket; a
  replayed recovery code; too many recovery tries; gate-recovery flooding; an email-recovery wait
  cancelled by a device; linking a Clerk user that already has history.
- Per area: `src/signup.test.js`, `src/session-reverify.test.js`, `src/recovery.test.js`,
  `src/email-recovery.test.js`, `src/clerk-link.test.js`; costs in `src/cost-counts.test.js`.
- **Playwright** `signup.spec.js` (local mode through `dev/signup-paid`: signs up, makes a
  recovery sheet, recovers with a code in another browser) and `reverify.spec.js`.
  `/email-link.html` is not covered: the local server sends no email.
- **CI sample** `docs/samples/signup-and-recover.sh` runs in `npm run test:samples` and is
  embedded in the docs page.

## 5. Phases

| Phase | Work | Done when |
|-------|------|-----------|
| **A0** ✅ | Tests for payments (§4) and the `STRIPE_FETCH` hook. Done: `src/payments.test.js`, `stripeClient` in `src/api/payments.js`. | Checkout and webhook covered, with Clerk unset. |
| **A1** ✅ | Account ids (§3.1), `POST /signup`, the webhook's signup kind, `signup/complete`, `dev/signup-paid`, the cost count. Done: `src/api/signup.js`, `src/signup.test.js` (production, Clerk unset). | A paid account exists and is used with no Clerk configured. |
| **A2** ✅ | The first ten minutes (§3.3) and re-verification through gates (§3.4), including the 403 body and the dashboard panel. Done: `src/durable-objects/account/reverify.js`, `POST /api/v1/session/reverify`, `frontend/js/dashboard-reverify.js`; tests `src/session-reverify.test.js`, Playwright `reverify.spec.js`. | A Clerk-free owner can add a second device and create API keys. |
| **A3** ✅ | Recovery status, recovery codes onto a new device, accepting no recovery (§3.5). **The journey test.** Done: `POST /api/v1/recover`, `/api/v1/account/recovery`; tests `src/recovery.test.js` and the journey `src/clerk-free-accounts.test.js` (production, Clerk unset, every `CLERK_*` read recorded, every route checked open to a device or key). | The journey test passes. |
| **A4** ✅ | Recovery by passkey or second device. Done: `POST /api/v1/recover` with `via: 'gate'` and `POST /api/v1/recover/complete`; tests in `src/recovery.test.js`, cost in `src/cost-counts.test.js`. | Gate recovery tests pass. |
| **A5** ✅ | Verified email, `email_source`, email recovery with the waiting period (72 hours, O1 approved). Done: `src/durable-objects/account/email-address.js`, `src/api/email-address.js`, `via: 'email'`, `/email-link.html`, the Account page's address and "Getting back in" sections; tests `src/email-recovery.test.js`. | Email tests pass (SES faked as in `src/security-email.test.js`). |
| **A6** ✅ | Clerk linking both ways (§3.6), plus the ops step for the session token. Done: `POST`/`DELETE /api/v1/account/clerk-link`, `src/durable-objects/account/clerk-link.js`, the webhook's `user.deleted`, the Account page's "Password sign-in" section, docs/ops/deployment.md §3; tests `src/clerk-link.test.js`. | Link and unlink tests pass. |
| **A7** ✅ | Sign-up and recovery pages, CLI `signup`/`recover`, SDK release, Playwright. Done: `/signup.html`, `/recover.html`, links from the home page, pricing, the sign-in panel and the site map; `dba signup` and `dba recover` (`packages/cli/account.js`, `commands/account.js`); browser SDK v1.3.0 (`signUp`, `recover`, `pending`, `finish`); tests `packages/browser-sdk/account.test.js`, `packages/cli/account.test.js`, Playwright `signup.spec.js`. | `npm run test:e2e` passes. |
| **A8** ✅ | Docs (§6), CI sample, STATUS (B9, S8 note), `git mv` this file to `done/`. Done: `frontend/docs/accounts.html` (linked from the docs, the site map and llms.txt), sample `docs/samples/signup-and-recover.sh` in `npm run test:samples` and embedded in the docs page (checked by Playwright `site.spec.js`), privacy and terms wording marked [LEGAL REVIEW], pricing.md, master plan, README, the refund runbook in docs/ops/deployment.md §4. | Docs state the claim and link the journey test. |


## 6. Documentation (A8)

- `frontend/docs/accounts.html` (its own page: the main docs page is near its size limit),
  linked from the docs' table of contents and Concepts, the site map and `llms.txt`: an account
  can be created, funded and used with only a device and a card; what is the same either way;
  each recovery choice and its trade-off; what "none" means.
- `frontend/privacy.html` (Clerk only for people who choose it; what Stripe receives; the email
  index stores a hash) and `frontend/terms.html` (device-only accounts; a balance with no way
  back in; refunds, O3), both marked [LEGAL REVIEW].
- `docs/business/pricing.md`: device-only sign-up never creates a Clerk user (no MRU).
- `docs/ops/deployment.md`: the Clerk session-token claim (§3, A6) and the refund runbook for
  paid sign-ups that were never completed (§4).

## 7. Open questions for the owner

| ID | Question | Recommendation |
|----|----------|----------------|
| O1 | Waiting period before email recovery takes effect | ✅ **72 hours**, cancellable by any dashboard device or browser (owner approved; `EMAIL_RECOVERY_WAIT_MS`) |
| O2 | Can a TOTP gate recover an account, or only re-verify? | Re-verify yes; recover no (it often lives on the phone that was lost) |
| O3 | A balance nobody can reach (sign-up paid and never completed, or every device lost with no recovery) | Refund to the original card on request within 90 days, by Stripe payment id; legal to confirm |
| O4 | Dormant-account notices (D8) for an account with no email | Push to its browsers; with nothing to reach, close after 12 months as D8 says |
| O5 | A price for sign-up itself | None beyond the issue price, unless the floor test says otherwise |
| O6 | Which terms version a sign-up accepts | Add a version to `terms.html` at legal review; sign-up then records it (it records `terms_accepted_at` only) |

## 8. Things that must stay true

- Device private keys never reach the server. Sign-up and recovery see only public keys and
  DPoP proofs.
- Credit comes only from the signed Stripe webhook. Sign-up creates the account only there.
- Anonymous sign-up and recovery starts write nothing. Storage is written when money arrives,
  or when a recovery succeeds.
- Every new route is declared in `API_ROUTES` with its access; billable routes reserve first.
- One credential evaluator (`packages/verify`).
