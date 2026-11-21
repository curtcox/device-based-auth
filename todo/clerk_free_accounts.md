# Paid accounts without Clerk

Status: **A0–A5 done** (2026-11-21), A6 next; STATUS **B9**, **D14** (owner's choices, 2026-11-21).
This file is written to be picked up cold.

## 1. What we found (2026-11-21)

The question: can someone create and use a paid devicebasedauth.org account without ever signing
in with Clerk? **Not on 2026-11-21, when this plan was written; yes since A3** (sign-up, recent
sign-in through gates and recovery codes; `src/clerk-free-accounts.test.js`). They can *use* one, but only after a Clerk sign-in created it, and
several account-control steps still need Clerk.

### 1.1 Already works without Clerk

Once an account exists, a browser or CLI holding a dashboard device credential (a credential for
our own audience with `dba:session`, sent as `Authorization: DBA` plus a DPoP proof) can do most
things with no Clerk session:

- **Deposit.** `POST /api/v1/payments/checkout` is `SESSION` access, and `canAccess` in
  `src/auth/scopes.js` accepts a `dba:session` device as a session. The Stripe webhook
  (`stripeWebhook` in `src/api/payments.js`) credits by `client_reference_id`, never by a Clerk
  identity.
- **Spend.** Issuing credentials without `dba:*` actions, renewals, `/authorize`, audiences,
  revocation, reading transactions and audit.
- **Dashboard.** `frontend/js/auth.js` loads Clerk only when the browser has no device
  credential.

### 1.2 Still needs Clerk in production

1. **Creating the account.** The account id is the Clerk session's `sub`
   (`authenticate` in `src/auth/middleware.js`); `op_init` in `src/durable-objects/account-do.js`
   creates the account on first sight of that id. Every way to get a first credential needs an
   existing session or key: approving an enrollment and creating API keys are `SESSION`
   routes, and enrollment tokens need `credentials:issue`. `LocalDev` works only when
   `ENVIRONMENT` is `local`.
2. **Recent sign-in** (`requireRecentSignIn` in `src/auth/reverify.js`) accepts only a Clerk
   session with a recent `fva` claim (or local mode, or an API key). A dashboard device gets
   `403 reverification_required` for: creating API keys; issuing, approving or templating
   credentials with `dba:*` actions (so it **cannot add a second dashboard device**); connecting
   an app with "Sign in with devicebasedauth.org" (`src/api/oidc.js`); changing gates and sign-in
   gates; making recovery codes; raising budget limits; turning down security email; reinstating a
   revoked device.
3. **Recovery** after losing every device works only by signing in with Clerk again.
4. **Security email** goes only to the address Clerk verified (`src/auth/clerk-webhook.js`).
5. **No tests covered payments at all**, so even the part in §1.1 was unproven. Fixed by A0
   (`src/payments.test.js`).

## 2. Decisions already made (D14, owner, 2026-11-21)

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

### 3.2 Sign-up: pay to create (done in A1: `src/api/signup.js`)

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
   and missing Stripe configuration refuse as for `checkout`.
3. The person pays on Stripe. `success_url` is `/app.html#signup` (A7 builds that page, which
   keeps the ticket beside the SDK key). The CLI polls instead.
4. **Webhook.** `stripeWebhook` keeps every existing check and, for `kind: 'signup'`, also
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

### 3.3 The first ten minutes count as a recent sign-in (done in A2)

Paying is a fresh authentication. A credential issued by `signup/complete`, or by any recovery in
§3.5, counts as **recently signed in for `REVERIFY_MINUTES` after it was issued**. That breaks the
bootstrap loop: the new owner can make recovery codes, add a passkey or approve a second device
straight away. The account Durable Object already answers `credential-status` on every device
request; add the credential's `issued_via` and `iat` to that answer, so this costs no extra
request.

### 3.4 Recent sign-in through the owner's gates (done in A2)

As built: `credential-status` returns `signed_in_at` (the later of the credential's
`reverified_at` and, for a `signup` credential, its issuance), so the middleware gets it in the call
it already makes; the re-verification is recorded on the credential's own row rather than a
`dashsess:` row, so it adds no rows, and it lasts per device, not per account. The request
(purpose `reverify`) is one entry any such gate may approve, denying after 5 minutes; it is
treated like a sign-in for number matching. It is charged as one gate request (D13).


`recentlySignedIn` in `src/auth/reverify.js` also accepts a dashboard device whose session was
**re-verified within `REVERIFY_MINUTES` by one of the owner's gates** of kind `webauthn`, `totp`
or `dba-device`. A `dba-device` gate must name a different device from the one asking. The
`owner` kind does not count (the asking device is itself an owner), and neither does a recovery
code.

- `POST /api/v1/session/reverify` (`SESSION`) opens a gate request to the account's re-auth
  gates, using the gate request engine (`src/durable-objects/gate-requests.js`). Once a gate
  approves, the `dashsess:cid:…` row (see `op_dashboard_confirm` in
  `src/durable-objects/account/sign-in.js`) records `reverified_at`.
- The `reverification_required` 403 body gains
  `reverify: { url: '/api/v1/session/reverify', gates: [...] }` beside `clerk_error`, and the
  device message stops saying "sign in with your password". The dashboard's "Sign in again"
  button uses whichever the account has.
- This helps Clerk accounts too: their dashboard devices stop being refused.
- With no such gate, the 403 says to add a passkey or a second device. Adding a gate itself
  needs a recent sign-in, so §3.3's ten minutes, or a recovery, is how the first one gets added.
  The sign-up flow offers it straight away.

### 3.5 Recovery (codes done in A3, gates in A4, email in A5)

As built in A3 (`src/api/recovery.js`, `src/durable-objects/account/recovery.js`): the owner's
choice is **read from what exists** rather than kept as separate booleans that could disagree with
it. `GET /api/v1/account/recovery` reports the recovery codes left and
`no_recovery_acknowledged_at`, with `at_risk` while there are neither; `POST` with
`{ acknowledge_no_recovery: true }` records the acceptance (A4 and A5 add gates and email to the
report). `POST /api/v1/recover` takes `{ account, via: 'code', code, request }`; the enrollment
request, signed by the new key within 10 minutes, proves the key (a used code cannot be replayed),
so no DPoP proof is needed. It is not `free: true`, so the cost brake never blocks getting back in;
the per-IP limiter and 5 wrong codes per account per 15 minutes bound it. The credential is
**issued free** (`issueCredential(…, { free: true })`), so an empty balance cannot lock the owner
out (each recovery uses one of 10 codes, and a sheet needs a recent sign-in); it may reinstate a
revoked device. Making codes returns the account id with them for the recovery sheet. An unknown
account answers like a wrong code and stores nothing.

As built in A4: `via: 'gate'` opens a gate request (purpose `recover`, keyed by the new key) to the
account's `webauthn` and `dba-device` gates, one entry, denied after 10 minutes; it returns the
number the new device shows (approvers type it, including on the approval page), the approval
page link for passkeys, and a signed `rcv_` ticket. `POST /api/v1/recover/complete` with a DPoP
proof bound to the ticket answers `pending` until a gate approves, then issues the credential
(free, charge id from the request, so a repeat returns the same one). At most 3 new requests per
account per hour; an unknown account or one without such gates answers 409 `no_recovery_gate` and
stores nothing. TOTP gates do not recover (O2). A dashboard device registered as a `dba-device`
gate now answers for that gate as the device (before, the Worker saw it only as the owner, so a
second dashboard browser could never answer as a device gate); it types the number like any device.
The recovery report lists `recovery_gates`.

As built in A5: `POST /api/v1/account/email` (recent sign-in) emails a link to `/email-link.html`,
charged the notice price; the page posts it to `/api/v1/account/email/verify`, and the address
becomes the security email and recovery address (`email_source: 'verified'`). The registry maps
each verified address, as `SHA-256("dba-email\n" + lower-cased address)`, to the one account it
recovers (another account verifying it gets 409 `email_in_use`); `DELETE /api/v1/account/email`
(recent sign-in) releases it. `via: 'email'` answers the same whether or not the address is known
and its ticket never names the account (completion looks it up again). The emailed link starts a
**72-hour wait** (O1, approved by the owner 2026-11-21), told to
every browser and by email; any dashboard sign-in cancels it (`POST /api/v1/account/recovery
{ cancel_email_recovery }`, shown on the Account page). At most three recovery emails per account
per hour; one the balance cannot pay goes free. Pages need a click before anything happens, so mail
scanners that open links change nothing. Playwright does not cover `/email-link.html` yet: the local
server sends no email (A7).

The original design:

The owner's choice is kept in account settings as
`recovery: { codes: bool, gates: bool, email: bool, none_acknowledged_at }`. It is set at sign-up
and changed later on the Account page; changing it needs a recent sign-in. Every recovery issues a
new dashboard credential to a new key, is audited, is pushed to every browser and emailed, and
counts as recently signed in (§3.3). The account id is shown on the Account page and printed on
the recovery sheet, because recovery needs it.

- **Recovery codes.** These are today's codes (`op_recovery_codes`: 10, hashed). Today a code only
  opens a gated session (`op_dashboard_recover`); add recovery onto a new device.
  `POST /api/v1/recover` (`PUBLIC`, `free: true`, per-IP limiter, and 5 tries per account per 15
  minutes like gate codes) takes `{ account, via: 'code', code, request }` plus a DPoP proof by
  the new key. It uses up the code and issues the credential.
- **Passkey or second device.** `{ account, via: 'gate', request }` opens a gate request to the
  account's `webauthn` and `dba-device` gates. The approval shows a two-digit number the new
  device displays, as sign-in gates do. A passkey can answer on the new device itself through
  `/gate.html`, since passkeys sync. The new device polls. Allow at most 3 such requests per
  account per hour, so nobody can flood an owner with approvals.
- **Verified email.** `POST /api/v1/account/email` (`SESSION` plus a recent sign-in) sends a
  verification link through SES (`src/services/email.js`), charged the `notice` price. The
  verified address becomes the security email address. `{ via: 'email', email, request }` looks
  the account up in an index (`RegistryDO`, `email:<sha256 of the lowercased address>`, written at
  verification) and emails a link. Clicking it starts a **waiting period** (open question O1,
  recommended 72 hours). During the wait every browser and device is told, and any dashboard
  device can cancel. After it, the new device gets its credential. Email is the weakest method,
  and the sign-up page says so.
- **None.** Sign-up asks the owner to tick "If I lose this device, I lose this account and its
  balance". The dashboard keeps a banner until a method is added.

### 3.6 Linking Clerk, both ways

- **Clerk-free account adds a Clerk sign-in.** On the Account page (with a recent sign-in), the
  owner signs up with Clerk, and the dashboard posts the new Clerk session token to
  `POST /api/v1/account/clerk-link`. The server verifies the token. It refuses if that Clerk user
  already has a DBA account with any balance, credentials or history. Otherwise it sets the Clerk
  user's `public_metadata.dba_account` through Clerk's Backend API and records `clerk_sub` in the
  profile. Ops step: customize Clerk's session token with
  `{"dba_account": "{{user.public_metadata.dba_account}}"}`. The middleware then uses
  `claims.dba_account || claims.sub` as the account, with no extra Durable Object read. The Clerk
  webhook routes by `public_metadata.dba_account` too. Unlinking needs a recent sign-in, plus
  either a live dashboard device or a recovery method.
- **Clerk account keeps working with only devices.** Daily use already works (§1.1). Recovery
  (§3.5) and gate re-verification (§3.4) do not depend on how the account began, so a Clerk
  account can set them up and stop signing in with Clerk. Deleting the Clerk user must not close
  the DBA account. Check that the webhook ignores `user.deleted` (today it handles only
  `user.created` and `user.updated`), and clear the email only if it came from Clerk.

### 3.7 Security email

The profile gets `email_source: 'clerk' | 'verified'`. The Clerk webhook overwrites only an
address that came from Clerk. Everything else about email (STATUS S8) is unchanged.

### 3.8 Clients

- **Frontend.** A sign-up page (`frontend/signup.html` or a panel in `app.html`): "Create an
  account with this browser", a deposit picker, the terms and privacy tick box, recovery choices,
  then Checkout. On return it completes sign-up, offers to set up recovery and a passkey during the
  ten minutes, and opens the dashboard. Add a call to action on `index.html` and `pricing.html`.
  An account recovery page covers code, gate and email.
- **CLI.** `dba signup --deposit 5` prints the Checkout URL and a QR code, polls, and saves a
  dashboard device. `dba recover --account acct_… --code …` (and `--via gate|email`).
- **Browser SDK.** `signup({ creditCents })` and `recover(...)`. Cut a minor release.

## 4. Tests: what proves it

All new Vitest suites run with **`CLERK_SECRET_KEY`, `CLERK_PUBLISHABLE_KEY` and
`CLERK_WEBHOOK_SECRET` unset**, with `ENVIRONMENT: 'production'` and `LAUNCH_APPROVED: 'true'`.

- **Stripe test hook.** `env.STRIPE_FETCH` replaces Stripe's HTTP client in tests only
  (`Stripe.createFetchHttpClient(env.STRIPE_FETCH)`), like `env.CLERK_VERIFY_TOKEN`. Webhook
  events are signed for real with a test secret: `stripe.webhooks.generateTestHeaderString`
  (stripe 14.25, Node crypto), or an HMAC-SHA256 over `timestamp.payload` in WebCrypto if the
  tests run where Node crypto is missing.
- **Payments as they are today** (phase A0): a dashboard device opens Checkout; the webhook
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
- **Playwright** `signup.spec.js` (local mode through `dev/signup-paid`) and `recover.spec.js`
  (codes, and a passkey with the virtual authenticator `gates.spec` already uses).
- **CI sample** `docs/samples/signup.mjs`: sign up locally, complete, call `whoami`, issue a
  credential. It runs in `npm run test:samples`.

## 5. Phases

| Phase | Work | Done when |
|-------|------|-----------|
| **A0** ✅ | Tests for today's payments (§4 first bullets) and the `STRIPE_FETCH` hook. Done: `src/payments.test.js`, `stripeClient` in `src/api/payments.js`. The account is still created by a LocalDev sign-in standing in for Clerk, then the env turns into production with Clerk unset; A1 replaces that with sign-up. | Checkout and webhook covered, with Clerk unset. |
| **A1** ✅ | Account ids (§3.1), `POST /signup`, the webhook's signup kind, `signup/complete`, `dev/signup-paid`, the cost count. Done: `src/api/signup.js`, `src/signup.test.js` (production, Clerk unset). | A paid account exists and is used with no Clerk configured. |
| **A2** ✅ | The first ten minutes (§3.3) and re-verification through gates (§3.4), including the 403 body and the dashboard panel. Done: `src/durable-objects/account/reverify.js`, `POST /api/v1/session/reverify`, `frontend/js/dashboard-reverify.js`; tests `src/session-reverify.test.js`, Playwright `reverify.spec.js`. | A Clerk-free owner can add a second device and create API keys. |
| **A3** ✅ | Recovery status, recovery codes onto a new device, accepting no recovery (§3.5). **The journey test.** Done: `POST /api/v1/recover`, `/api/v1/account/recovery`; tests `src/recovery.test.js` and the journey `src/clerk-free-accounts.test.js` (production, Clerk unset, every `CLERK_*` read recorded, every route checked open to a device or key). | The journey test passes. |
| **A4** ✅ | Recovery by passkey or second device. Done: `POST /api/v1/recover` with `via: 'gate'` and `POST /api/v1/recover/complete`; tests in `src/recovery.test.js`, cost in `src/cost-counts.test.js`. | Gate recovery tests pass. |
| **A5** ✅ | Verified email, `email_source`, email recovery with the waiting period (72 hours, O1 approved). Done: `src/durable-objects/account/email-address.js`, `src/api/email-address.js`, `via: 'email'`, `/email-link.html`, the Account page's address and "Getting back in" sections; tests `src/email-recovery.test.js`. | Email tests pass (SES faked as in `src/security-email.test.js`). |
| **A6** | Clerk linking both ways (§3.6), plus the ops step for the session token. | Link and unlink tests pass. |
| **A7** | Sign-up and recovery pages, CLI `signup`/`recover`, SDK release, Playwright. | `npm run test:e2e` passes. |
| **A8** | Docs (§6), CI sample, STATUS (B9 done, S8 note), `git mv` this file to `done/`. | Docs state the claim and link the journey test. |

A minimum Clerk-free launch is A0–A3, the sign-up page and code recovery from A7, and A8.

## 6. Documentation to write (phase A8)

- `frontend/docs/index.html`, a new **Accounts** section: an account can be created, funded and
  used with only a device and a card, without Clerk; what is the same either way; each recovery
  choice and its trade-off; what "none" means. Regenerate `llms.txt`/`llms-full.txt`
  (`npm run docs:generate`).
- `frontend/privacy.html`: Clerk only for people who choose it; what Stripe receives; the email
  index stores a hash. Mark it [LEGAL REVIEW].
- `frontend/terms.html`: device-only accounts; a balance with no way back in; refunds (O3). Mark
  it [LEGAL REVIEW].
- `docs/business/pricing.md`: Clerk monthly retained users fall further, because device-only
  sign-up never creates a Clerk user.
- `todo/master_plan.md`: the glossary's "Account" row ("signed in with Clerk") and §8.3.
- `docs/ops/deployment.md`: the Clerk session-token claim (A6) and a refund runbook for paid
  sign-ups that were never completed.

## 7. Open questions for the owner

| ID | Question | Recommendation |
|----|----------|----------------|
| O1 | Waiting period before email recovery takes effect | ✅ **72 hours**, cancellable by any dashboard device or browser (owner approved 2026-11-21; `EMAIL_RECOVERY_WAIT_MS`) |
| O2 | Can a TOTP gate recover an account, or only re-verify? | Re-verify yes; recover no (it often lives on the phone that was lost) |
| O3 | A balance nobody can reach (sign-up paid and never completed, or every device lost with no recovery) | Refund to the original card on request within 90 days, by Stripe payment id; legal to confirm |
| O4 | Dormant-account notices (D8) for an account with no email | Push to its browsers; with nothing to reach, close after 12 months as D8 says |
| O5 | A price for sign-up itself | None beyond the issue price, unless the floor test says otherwise |
| O6 | Which terms version a sign-up accepts | Add a version to `terms.html` at legal review; sign-up then records it (today it records `terms_accepted_at` only) |

## 8. Things that must stay true

- Device private keys never reach the server. Sign-up and recovery see only public keys and
  DPoP proofs.
- Credit comes only from the signed Stripe webhook. Sign-up creates the account only there.
- Anonymous sign-up and recovery starts write nothing. Storage is written when money arrives,
  or when a recovery succeeds.
- Every new route is declared in `API_ROUTES` with its access; billable routes reserve first.
- One credential evaluator (`packages/verify`).
