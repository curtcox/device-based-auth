# Deploying devicebasedauth.org (owner steps)

Everything below needs dashboard or credential access, so only the project owner can do it
(STATUS L9). Code-side checks (`scripts/check-deployment-secrets.mjs`, `scripts/verify-production.mjs`)
run in `.github/workflows/deploy.yml`.

**Production state.** §1–§5 are done: production is live, every push to `main` deploys, and
payments are open (`DBA_STRIPE_WEBHOOK_SECRET` set, `DBA_LAUNCH_APPROVED=true`). Left (STATUS L9,
L14): a first real payment, the post-deploy checks in §3 and §4, and §6. The steps stay written
for a fresh deploy (a new account, or rebuilding after a loss).

## How configuration reaches the Worker

| Where | What |
|-------|------|
| `wrangler.toml` `[vars]` | `ENVIRONMENT`, `APP_ORIGIN`, `ISSUER`, `STATUS_ORIGIN`, `APP_AUDIENCE`, `STATUS_SHARDS`, `WORKER_NAME` |
| `wrangler.toml` bindings | Durable Objects `ACCOUNTS`, `STATUS`, `REGISTRY`, `ENROLLMENTS`, `SAFETY`; R2 `STATUS_BUCKET` (`dba-status-prod`); rate limit `PUBLIC_LIMITER`; static assets `ASSETS`; hourly cron `7 * * * *` |
| GitHub secrets and variables (environment `production`) | Mapped to Worker names in `deploy.yml`'s `env` (mostly by dropping the `DBA_` prefix) and pushed by `scripts/push-worker-secrets.mjs` with `wrangler secret bulk` on every deploy |

GitHub name → Worker name (S = secret, V = variable; **required** ones are checked by
`check-deployment-secrets.mjs` before anything changes):

| GitHub | Worker | Section |
|--------|--------|---------|
| S `CLOUDFLARE_API_TOKEN` (**required**, deploy only) | — | §1 |
| S `CLOUDFLARE_ACCOUNT_ID` (**required**) | `CLOUDFLARE_ACCOUNT_ID` | §1 |
| S `CLOUDFLARE_ANALYTICS_TOKEN` | `CLOUDFLARE_ANALYTICS_TOKEN` | §1 |
| V `DBA_DO_NAMESPACES` | `COST_SAFETY_DO_NAMESPACES` | §1 |
| S `DBA_ISSUER_KEYS` (**required**) | `ISSUER_KEYS` | §2 |
| S `DBA_TOKEN_SIGNING_KEY` (**required**) | `TOKEN_SIGNING_KEY` | §2 |
| S `DBA_PUSH_VAPID_KEY` | `PUSH_VAPID_KEY` | §2 |
| S `DBA_GATE_SEALING_KEYS` | `GATE_SEALING_KEYS` | §2 |
| S `DBA_CLERK_SECRET_KEY`, `DBA_CLERK_PUBLISHABLE_KEY`, `DBA_CLERK_WEBHOOK_SECRET` (**required**) | `CLERK_SECRET_KEY`, `CLERK_PUBLISHABLE_KEY`, `CLERK_WEBHOOK_SECRET` | §3 |
| V `DBA_OPERATOR_ACCOUNT` (**required**) | `OPERATOR_ACCOUNT` | §3 |
| V `DBA_EMAIL_PROVIDER`, `DBA_SES_REGION`, `DBA_EMAIL_FROM`; S `DBA_SES_ACCESS_KEY_ID`, `DBA_SES_SECRET_ACCESS_KEY` (all or none) | `EMAIL_PROVIDER`, `SES_REGION`, `EMAIL_FROM`, `SES_ACCESS_KEY_ID`, `SES_SECRET_ACCESS_KEY` | §3a |
| S `STRIPE_SECRET_KEY` (shared with the sibling sites), `DBA_STRIPE_WEBHOOK_SECRET` | `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | §4 |
| V `DBA_STRIPE_CREDIT_PRODUCT_ID`, `DBA_STRIPE_CARD_COST_PRODUCT_ID` | `STRIPE_CREDIT_PRODUCT_ID`, `STRIPE_CARD_COST_PRODUCT_ID` | §4 |
| V `DBA_LAUNCH_APPROVED` | `LAUNCH_APPROVED` (`true` opens payments) | §4 |
| V `DBA_DEPLOY_ENABLED` | — (push deploys on) | §5 |
| S `ALERT_WEBHOOK_URL` | `ALERT_WEBHOOK_URL` | §7 |
| V `DBA_COST_SAFETY_HARD_STOP` | `COST_SAFETY_HARD_STOP` (`true` stops the free endpoints) | §7 |

The push skips empty values and never deletes a Worker secret, so clearing a GitHub variable does
not undo it: set it to another value (`DBA_LAUNCH_APPROVED=false`) or run
`npx wrangler secret delete NAME`. Two optional settings have no GitHub mapping and are set by
hand with `npx wrangler secret put NAME`: `COST_SAFETY_BRAKE_CENTS` (the brake's monthly
projection limit, default 2500 = $25) and `COST_SAFETY_FAIL_OPEN=true` (do not brake only because
the cost report is more than 36 hours old). `GIT_SHA` is set by the deploy itself. Settings
that exist only for local work (`STATUS_PUBLISH_DELAY_MS`, and the attestation test roots and
`TPM_EK_TEST_CA`, which are honoured only when `ENVIRONMENT` is `local`) live in
`wrangler.local.toml` or the test environment and are never set in production.

## 1. Cloudflare

1. Add the `devicebasedauth.org` zone to the same Cloudflare account as hashbin and cronly (the
   Workers Paid plan is already paid there). The Worker routes `devicebasedauth.org/*` and
   `www.devicebasedauth.org/*` need DNS records to receive traffic: if none exist, add proxied
   `AAAA` records for `@` and `www` with content `100::`.
2. Create the R2 bucket `dba-status-prod` and connect the custom domain
   `status.devicebasedauth.org` to it (R2 → bucket → Settings → Custom domains; leave the r2.dev
   URL off). Add a cache rule for that hostname that ignores query strings, so cache-busting
   requests cannot multiply R2 reads.
3. Create a deploy API token with *Account · Workers Scripts:Edit*, *Account · Workers R2
   Storage:Edit*, *Account · Account Settings:Read* and *Zone · Workers Routes:Edit* (zone
   devicebasedauth.org) as the GitHub secret `CLOUDFLARE_API_TOKEN`, and a read-only *Account
   Analytics* token as `CLOUDFLARE_ANALYTICS_TOKEN`. Store the account id as the GitHub secret
   `CLOUDFLARE_ACCOUNT_ID`.
4. After the first deploy (§5), which creates the Durable Object namespaces, copy the five
   namespace IDs of `dba-worker-prod` (Workers → Durable Objects) into the GitHub variable
   `DBA_DO_NAMESPACES` (comma-separated). Until the analytics token and namespaces are set, the cost
   monitor fails and the brake stops the free endpoints.

## 2. Keys

```bash
node scripts/generate-issuer-key.mjs dba-YYYY-MM
```

Store the output, wrapped in a JSON array (`[ … ]`), as the GitHub secret `DBA_ISSUER_KEYS`. Store a
random 48+ character string as `DBA_TOKEN_SIGNING_KEY` (`openssl rand -base64 48`; the check
requires 32+). Never reuse the local key from `wrangler.local.toml`; the deploy check refuses
`local-` key ids. Routine rotation: put the new entry **first** (the first entry that is neither
`"retired": true` nor `"withdrawn": true` signs) and keep the old one, which stays in the JWKS,
until every credential it signed has expired (400 days at most). After a compromise follow
[issuer-key-compromise.md](issuer-key-compromise.md) instead.

Security notices (Web Push to the owner's browsers when credentials, API keys or enrollment
tokens are issued, master plan §10) need a VAPID key: store the output of
`node scripts/generate-issuer-key.mjs --vapid` as `DBA_PUSH_VAPID_KEY`. Keep it for good: browsers
subscribe to this exact key, so replacing it silently ends every subscription (owners would have to
turn notices on again). Without it the dashboard does not offer notices.

TOTP gates (STATUS B7) keep each authenticator app's seed sealed with AES-256-GCM. Store
`[{"kid":"gate-YYYY-MM","key":"<output of openssl rand -base64 32>"}]` as `DBA_GATE_SEALING_KEYS`.
To rotate, put a new key **first** (it seals; every listed key still opens) and keep the old one
until no gate uses it. A leaked sealing key together with a copy of the Durable Object storage
exposes every TOTP seed: delete and re-add every TOTP gate after rotating. Without the secret the
dashboard cannot add TOTP gates (other gates work).

## 3. Clerk

Create a separate Clerk application for devicebasedauth.org (Google and GitHub sign-in, like
hashbin, with email addresses still collected) and its production instance for the domain: add
the DNS records Clerk lists as CNAMEs with the Cloudflare proxy **off**, and give Google and
GitHub production OAuth credentials of your own. Secrets: `DBA_CLERK_SECRET_KEY`,
`DBA_CLERK_PUBLISHABLE_KEY`; add a webhook to `https://devicebasedauth.org/webhooks/clerk` for
`user.created`/`user.updated`/`user.deleted` and store its signing secret as
`DBA_CLERK_WEBHOOK_SECRET`. Set the GitHub variable `DBA_OPERATOR_ACCOUNT` to your own Clerk user
id: that account owns the first-party audiences (devicebasedauth.org, hashbin.org, cronly.org,
subetha.us) and pays for their online decisions and OpenID Connect sign-ins, so keep it funded.

Use session token version 2 (the default for new Clerk applications): its `fva` claim says how many
minutes ago the user last verified a factor. Creating API keys, approving or issuing `dba:*`
credentials, and raising budget limits need `fva` within 10 minutes (STATUS S8); without the claim
those operations are refused. Check after deploying: sign in, wait 11 minutes, try to create an API
key (expect "Please confirm it is you"), sign in again, and it succeeds.

The `user.created`/`user.updated` webhook also carries the user's primary email address; once
Clerk has verified it, it is where security emails go (next section), unless the owner verified an
address with devicebasedauth.org itself. `user.deleted` never closes an account: it forgets the
link and the address that came from Clerk.

**Linking a password sign-in to an account made without Clerk (STATUS B9).** Customize the session
token (Clerk dashboard → Sessions → Customize session token) with:

```json
{ "dba_account": "{{user.public_metadata.dba_account}}" }
```

The Worker writes `public_metadata.dba_account` through Clerk's Backend API when an owner links a
sign-in, and accepts the claim only when that account names the same Clerk user back. Check after
deploying: create an account by paying (no Clerk), add a password sign-in on its Account page, sign
out, and sign in with that password sign-in: the dashboard opens the same account id.

## 3a. Security email (Amazon SES, optional; STATUS S8, D9)

Takeover-sensitive events (credentials that can act on the account, API keys and connected apps,
enrollment tokens, gates, sign-in gates and recovery codes, raised limits, reinstated devices)
are emailed at once, other issuances in at most one digest an hour; each email costs the account
the `notice` price when it is queued. Without this section nothing is emailed or charged, and the
Web Push notices still work.

1. In Amazon SES (any region; `us-east-1` is fine), verify the domain `devicebasedauth.org` with
   Easy DKIM (add the three CNAME records in Cloudflare DNS), set a custom MAIL FROM domain, and
   publish a DMARC record. Request production access (leave the sandbox), stating that the mail is
   transactional security notices to verified account owners.
2. Create an IAM user allowed only `ses:SendEmail` on that identity. Store its access key as the
   GitHub secrets `DBA_SES_ACCESS_KEY_ID` and `DBA_SES_SECRET_ACCESS_KEY`.
3. Set the GitHub variables `DBA_EMAIL_PROVIDER=ses`, `DBA_SES_REGION` (for example `us-east-1`) and
   `DBA_EMAIL_FROM` (for example `devicebasedauth.org <security@devicebasedauth.org>`). The deploy
   check refuses a partial set.
4. Check after deploying: with a funded account, create an API key and expect an email within a
   minute; the ledger shows a `notice` charge and the audit trail `email.sent`.

## 4. Stripe

Reuse the shared Stripe account. Create two products ("devicebasedauth.org prepaid credit" and
"Card payment cost (non-refundable)") and set `DBA_STRIPE_CREDIT_PRODUCT_ID` /
`DBA_STRIPE_CARD_COST_PRODUCT_ID` variables (live-mode IDs). Add a webhook endpoint
`https://devicebasedauth.org/webhooks/stripe` for `checkout.session.completed` and
`checkout.session.async_payment_succeeded`; store its secret as `DBA_STRIPE_WEBHOOK_SECRET`.
`STRIPE_SECRET_KEY` is the shared secret. In production, payments answer 503 `launch_pending`
until `DBA_LAUNCH_APPROVED=true`. A quick check that the webhook secret is in place: an unsigned
POST to the webhook answers `invalid_signature`.

Sign-up by payment (STATUS B9) uses the same products and webhook: the Checkout session's metadata
has `kind: signup`, and the webhook creates the account. Check after deploying: on
`/signup.html`, pay $5, come back signed in, and see the deposit and the account id on the Account
page (a test card needs test-mode products, webhook and key, so in production this is a real $5).

**Refunding a sign-up that was paid but never completed** (the person closed the page and lost the
browser's key, so nobody holds the account): find the Checkout session in Stripe (metadata `kind:
signup`; `client_reference_id` is the account id, which has a balance and no credentials), refund
it there per the terms, and leave the account empty; it is closed with other dormant accounts (D8).

## 5. Deploy

Set the GitHub variable `DBA_DEPLOY_ENABLED=true` to deploy on every push to `main` (or run the
workflow by hand from `main`). The workflow lints, tests, checks secrets, deploys
(`wrangler deploy`), pushes secrets and runs `scripts/verify-production.mjs` (health and deployed
commit, public-only JWKS, OpenID configuration, a price quote, a status list, `LocalDev` refused,
the home page). A deploy restarts every account object, so devices meet a DPoP nonce challenge on
their next request (STATUS D15).

## 6. Publish the packages

`npm publish --access public` in `packages/verify` (and then `packages/cli`) under the
`@devicebasedauth` npm scope, so relying parties can `npm install @devicebasedauth/verify`
(STATUS L14). Until then they can vendor `packages/verify/src` (zero dependencies).

## 7. After launch

- Watch the cost report (SafetyDO) and alerts (`ALERT_WEBHOOK_URL`, posted when the brake turns
  on and for the status-list capacity alert below).
- Recalibrate prices from a month of measured costs (STATUS S3).
- **Status-list capacity.** Every issuance and rotation takes a status index for good (indexes are
  never reused), and there are `STATUS_SHARDS` × 262,144 of them (16 shards: about 4.2 million).
  A daily alert fires at 80% allocated; when every shard is full, issuance answers 503 `capacity`.
  Raise `STATUS_SHARDS` in `wrangler.toml` and deploy: new shards are used at once, full ones are
  skipped, and existing credentials keep their lists. Never lower it (lists of live credentials
  would stop being served).
- **Issuer key compromise:** [issuer-key-compromise.md](issuer-key-compromise.md).
