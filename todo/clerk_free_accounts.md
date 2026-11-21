# Paid accounts without Clerk

Status: **A0 done** (2026-11-21), A1 next; STATUS **B9**, **D14** (owner's choices, 2026-11-21).
This file is written to be picked up cold.

## 1. What we found (2026-11-21)

The question: can someone create and use a paid devicebasedauth.org account without ever signing
in with Clerk? **Not today.** They can *use* one, but only after a Clerk sign-in created it, and
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

### 3.2 Sign-up: pay to create

1. The device makes its key (browser SDK slot `dashboard`, or the CLI) and signs a normal
   `dba-enroll+jwt` enrollment request (`readEnrollRequest` in `src/api/enrollments.js`). The
   server ignores the requested audience and grants: a sign-up always issues the dashboard grant
   set (our audience, `dba:session`), the same set as "Make this browser a device" in
   `frontend/js/dashboard-account.js`.
2. `POST /api/v1/signup` is `PUBLIC`, `free: true` (stopped by the cost brake) and behind
   `PUBLIC_LIMITER` per IP. Its body is `{ request, credit_cents, terms_version }`. It checks the
   request and the deposit (the usual $5 minimum and the first-week $20 cap), mints the account id
   and a signup id (`sup_…`), and creates a Stripe Checkout session like `checkout` does, with
   `client_reference_id = account` and metadata
   `{ product, kind: 'signup', account, credit_cents, signup, jkt, terms_version }`. It returns
   the Checkout `url`, a signed `signup_ticket` (`signToken('sup_', …)`: id, account, jwk, jkt,
   device, exp) and a poll token. **It writes nothing**, like anonymous enrollment starts
   (master plan §5.1). `?dry_run=1` quotes the total. Respect `LAUNCH_APPROVED` exactly as
   `checkout` does.
3. The person pays on Stripe. `success_url` goes to the sign-up page, which kept the ticket
   (IndexedDB, beside the SDK key). The CLI polls instead.
4. **Webhook.** `stripeWebhook` keeps every existing check and, for `kind: 'signup'`, also
   requires `metadata.signup` and `metadata.jkt`. It calls `init` with
   `{ account, created_via: 'signup', terms_version }`, then `deposit` (already idempotent by
   Checkout session id), then records `{ status: 'paid', account, jkt }` in `ENROLLMENTS` under
   the signup id. A replayed event changes nothing.
5. `POST /api/v1/signup/complete` is `PUBLIC`, `billable: 'issue'`. Its body is `{ ticket }`, with
   a DPoP proof made by the ticket's key (`verifyProof` with the ticket's `jkt`). It requires the
   `ENROLLMENTS` row to say `paid` for the same jkt and account, then issues the dashboard
   credential, charging the issue price to the new balance. A repeat call returns the same
   credential, stored in the `ENROLLMENTS` row as `approveEnrollment` does. Tickets last 30 days,
   so a closed tab can come back later.
6. **Local mode.** `POST /api/v1/dev/signup-paid` (local only, refused elsewhere like
   `dev/deposit`) does what the webhook does without Stripe, so samples, Playwright and
   `npm run dev:local` can sign up end to end.

Cost and price: the webhook's writes are a deposit's writes (deposits are free) plus one
`ENROLLMENTS` row; completion is an ordinary issue. Add the op counts to
`src/utils/cost-policy.js` and extend the price-floor test. If the floor test says sign-up needs a
price of its own, propose one under D14 rather than hiding it in the deposit.

Abuse: creating a Checkout session costs us nothing and Stripe nothing until paid; card testing is
Stripe Radar's job, and $5 is the minimum. The per-IP limiter and the brake bound Worker requests.

### 3.3 The first ten minutes count as a recent sign-in

Paying is a fresh authentication. A credential issued by `signup/complete`, or by any recovery in
§3.5, counts as **recently signed in for `REVERIFY_MINUTES` after it was issued**. That breaks the
bootstrap loop: the new owner can make recovery codes, add a passkey or approve a second device
straight away. The account Durable Object already answers `credential-status` on every device
request; add the credential's `issued_via` and `iat` to that answer, so this costs no extra
request.

### 3.4 Recent sign-in through the owner's gates

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

### 3.5 Recovery

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
| **A1** | Account ids (§3.1), `POST /signup`, the webhook's signup kind, `signup/complete`, `dev/signup-paid`, op counts and the price-floor test. | A paid account exists and is used with no Clerk configured. |
| **A2** | The first ten minutes (§3.3) and re-verification through gates (§3.4), including the 403 body and the dashboard button. | A Clerk-free owner can add a second device and create API keys. |
| **A3** | Recovery settings, recovery codes onto a new device, the "none" acknowledgement (§3.5). **The journey test.** | The journey test passes. |
| **A4** | Recovery by passkey or second device. | Gate recovery tests pass. |
| **A5** | Verified email, `email_source`, email recovery with the waiting period. | Email tests pass (SES faked as in `src/security-email.test.js`). |
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
| O1 | Waiting period before email recovery takes effect | 72 hours, cancellable by any dashboard device or browser |
| O2 | Can a TOTP gate recover an account, or only re-verify? | Re-verify yes; recover no (it often lives on the phone that was lost) |
| O3 | A balance nobody can reach (sign-up paid and never completed, or every device lost with no recovery) | Refund to the original card on request within 90 days, by Stripe payment id; legal to confirm |
| O4 | Dormant-account notices (D8) for an account with no email | Push to its browsers; with nothing to reach, close after 12 months as D8 says |
| O5 | A price for sign-up itself | None beyond the issue price, unless the floor test says otherwise |

## 8. Things that must stay true

- Device private keys never reach the server. Sign-up and recovery see only public keys and
  DPoP proofs.
- Credit comes only from the signed Stripe webhook. Sign-up creates the account only there.
- Anonymous sign-up and recovery starts write nothing. Storage is written when money arrives,
  or when a recovery succeeds.
- Every new route is declared in `API_ROUTES` with its access; billable routes reserve first.
- One credential evaluator (`packages/verify`).
