# Deploying devicebasedauth.org (owner steps)

Everything below needs dashboard or credential access, so only the project owner can do it
(STATUS L9). Code-side checks (`scripts/check-deployment-secrets.mjs`, `scripts/verify-production.mjs`)
run in `.github/workflows/deploy.yml`.

## 1. Cloudflare

1. Add the `devicebasedauth.org` zone to the same Cloudflare account as hashbin and cronly (the
   Workers Paid plan is already paid there).
2. Create the R2 bucket `dba-status-prod` and connect the custom domain
   `status.devicebasedauth.org` to it (R2 → bucket → Settings → Custom domains). Add a cache rule for
   that hostname that ignores query strings, so cache-busting requests cannot multiply R2 reads.
3. The first deploy creates the Durable Object namespaces. Afterwards, copy their IDs (Workers →
   Durable Objects) into the GitHub variable `DBA_DO_NAMESPACES` (comma-separated) for the cost brake.
4. Create an API token with *Workers Scripts:Edit*, *Workers R2 Storage:Edit*, *Account Settings:Read*
   (GitHub secret `CLOUDFLARE_API_TOKEN`) and a read-only *Account Analytics* token
   (`CLOUDFLARE_ANALYTICS_TOKEN`). Set `CLOUDFLARE_ACCOUNT_ID`.

## 2. Keys

```bash
node scripts/generate-issuer-key.mjs dba-2026-11
```

Store the output, wrapped in a JSON array (`[ … ]`), as the GitHub secret `DBA_ISSUER_KEYS`. Store a
random 48+ character string as `DBA_TOKEN_SIGNING_KEY` (`openssl rand -base64 48`). Never reuse the
local key from `wrangler.local.toml`; the deploy check refuses `local-` key ids.

## 3. Clerk

Create a separate Clerk application for devicebasedauth.org (Google and GitHub sign-in, like
hashbin). Secrets: `DBA_CLERK_SECRET_KEY`, `DBA_CLERK_PUBLISHABLE_KEY`; add a webhook to
`https://devicebasedauth.org/webhooks/clerk` for `user.created`/`user.updated` and store its signing
secret as `DBA_CLERK_WEBHOOK_SECRET`. Set the GitHub variable `DBA_OPERATOR_ACCOUNT` to your own
Clerk user id: that account owns the first-party audiences (devicebasedauth.org, hashbin.org,
cronly.org) and pays for their online decisions and OpenID Connect sign-ins, so keep it funded.

Use session token version 2 (the default for new Clerk applications): its `fva` claim says how many
minutes ago the user last verified a factor. Creating API keys, approving or issuing `dba:*`
credentials, and raising budget limits need `fva` within 10 minutes (STATUS S8); without the claim
those operations are refused. Check after deploying: sign in, wait 11 minutes, try to create an API
key (expect "Please confirm it is you"), sign in again, and it succeeds.

## 4. Stripe

Reuse the shared Stripe account. Create two products ("devicebasedauth.org prepaid credit" and
"Card payment cost (non-refundable)") and set `DBA_STRIPE_CREDIT_PRODUCT_ID` /
`DBA_STRIPE_CARD_COST_PRODUCT_ID` variables. Add a webhook endpoint
`https://devicebasedauth.org/webhooks/stripe` for `checkout.session.completed` and
`checkout.session.async_payment_succeeded`; store its secret as `DBA_STRIPE_WEBHOOK_SECRET`.
`STRIPE_SECRET_KEY` is the shared secret. Payments stay closed until `DBA_LAUNCH_APPROVED=true`.

## 5. Deploy

Set the GitHub variable `DBA_DEPLOY_ENABLED=true` (or run the workflow by hand). The workflow lints,
tests, checks secrets, deploys, pushes secrets and runs `scripts/verify-production.mjs`.

## 6. Publish the packages

`npm publish --access public` in `packages/verify` (and later `packages/cli`) under the
`@devicebasedauth` npm scope, so relying parties can `npm install @devicebasedauth/verify`.
Until then they can vendor `packages/verify/src` (zero dependencies).

## 7. After launch

- Watch the cost report (SafetyDO) and alerts (`ALERT_WEBHOOK_URL`).
- Recalibrate prices from a month of measured costs (STATUS S3).
- **Status-list capacity.** Every issuance and rotation takes a status index for good (indexes are
  never reused), and there are `STATUS_SHARDS` × 262,144 of them (16 shards: about 4.2 million).
  A daily alert fires at 80% allocated; when every shard is full, issuance answers 503 `capacity`.
  Raise `STATUS_SHARDS` in `wrangler.toml` and deploy: new shards are used at once, full ones are
  skipped, and existing credentials keep their lists. Never lower it (lists of live credentials
  would stop being served).
