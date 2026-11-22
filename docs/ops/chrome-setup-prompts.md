# Prompts for Claude in Chrome: Cloudflare, Clerk and Stripe setup (STATUS L9)

Paste these into the Claude in Chrome extension, one at a time, in order. Each one starts cold
and does the browser side of [deployment.md](deployment.md) §1, §3 and §4.

**How secrets move.** Claude in Chrome will not copy API keys, signing secrets or tokens into
forms, and these values should not pass through a chat anyway. So each prompt stops when a
secret is shown. You copy it from the page and store it from a terminal in this repo:

```bash
gh secret set NAME
```

`gh` asks for the value and hides what you paste. Non-secret values (IDs, the publishable key)
come back in Claude's report; set them with `gh variable set NAME --body VALUE`, or paste the
report back into Claude Code.

State on 2026-11-21: no GitHub secrets or variables are set, and the `devicebasedauth.org` zone
already uses Cloudflare nameservers (registered at Cloudflare) but has no A/AAAA records.

---

## 1. Cloudflare (§1)

```text
I'm setting up production for devicebasedauth.org, a Cloudflare Worker. Work in the Cloudflare
dashboard (dash.cloudflare.com), where I'm signed in. Use the account that already holds the
zones hashbin.org and cronly.org; if devicebasedauth.org is in a different account, stop and tell
me.

Rules: never delete or change existing DNS records, rules, buckets or tokens; only add. Ask me
before anything that costs money or accepts terms. Never copy a secret value (token, key) into a
form or into your reply: when a token value is shown, stop and tell me so I can copy it myself.

Do these in order and report after each:

1. Confirm the zone devicebasedauth.org is active in that account, and that the account is on
   the Workers Paid plan. Tell me the Account ID (shown on the zone's Overview page, right column).
   The Account ID is not secret; include it in your report.

2. DNS (zone devicebasedauth.org → DNS → Records). First list every existing record. Then, only
   if there is no record yet for that name, add:
   - AAAA, name "@", content "100::", Proxied (orange cloud) on
   - AAAA, name "www", content "100::", Proxied on
   These placeholders let the Worker routes devicebasedauth.org/* and www.devicebasedauth.org/*
   receive traffic. If a record already exists for either name, leave it and tell me what it is.

3. R2 (account → R2 Object Storage). If R2 is not enabled yet, stop and ask me before enabling
   it. Create a bucket named exactly "dba-status-prod" (automatic location, Standard storage
   class). Then open the bucket → Settings → Custom Domains → Connect domain, and connect
   "status.devicebasedauth.org". Wait until its status is Active (or tell me what it says).
   Do not enable the r2.dev public URL.

4. Cache rule (zone devicebasedauth.org → Caching → Cache Rules → Create rule). Name it
   "status: ignore query strings". When incoming requests match: Hostname equals
   "status.devicebasedauth.org". Then: Cache eligibility "Eligible for cache"; under Cache key,
   set Query string to ignore all query strings (Exclude all). Leave other settings at their
   defaults. Deploy it.

5. Deploy API token (My Profile → API Tokens → Create Token → Create Custom Token). Name:
   "dba deploy (GitHub Actions)". Permissions:
   - Account · Workers Scripts · Edit
   - Account · Workers R2 Storage · Edit
   - Account · Account Settings · Read
   - Zone · Workers Routes · Edit
   Account resources: Include → the account above only. Zone resources: Include → Specific zone →
   devicebasedauth.org. No IP filtering, no TTL. Continue to summary and create it. When the
   token value appears, STOP and tell me: "Copy the deploy token now and run
   gh secret set CLOUDFLARE_API_TOKEN". Wait for me to say done before going on.

6. Analytics API token (Create Token → Create Custom Token). Name: "dba cost monitor (read only)".
   Permissions: Account · Account Analytics · Read. Account resources: the same account only.
   Create it, then STOP and tell me: "Copy the analytics token now and run
   gh secret set CLOUDFLARE_ANALYTICS_TOKEN". Wait for me to say done.

Final report: the Account ID; the DNS records you found and the ones you added; the bucket and
custom-domain status; the cache rule; the names and permissions of both tokens (never their
values); anything you skipped and why.
```

Then store the account ID (it is a secret in the workflow, though not sensitive):

```bash
gh secret set CLOUDFLARE_ACCOUNT_ID
```

---

## 2. Clerk application and domain (§3, part 1)

```text
I'm setting up Clerk for devicebasedauth.org. Work in the Clerk dashboard (dashboard.clerk.com),
where I'm signed in, and in the Cloudflare dashboard for DNS. The sibling site hashbin.org already
has its own Clerk application; use it only as a reference, never change it.

Rules: only add things; never delete or change existing applications, DNS records or settings
outside the new application. Ask me before choosing or changing a paid plan or accepting terms.
Never copy a secret value (secret key, client secret, signing secret) into a form or into your
reply: when one is shown or needed, stop and tell me.

1. Create a new Clerk application named "devicebasedauth.org". Sign-in options: Google and
   GitHub only (like hashbin; turn off email/password and other options if they're on by default,
   but leave email addresses collected, because security email goes to the user's verified
   primary address).

2. Plan check (read only): tell me which Clerk plan this application is on and whether that plan
   allows (a) custom OAuth/OIDC providers in an application ("custom provider" under SSO
   connections) and (b) customizing the session token. Quote what the pricing or settings page
   says. Do not upgrade anything.

3. Create the production instance for the domain devicebasedauth.org (the instance switcher at
   the top: Development → Production; choose "use the same settings as development" if offered).
   Clerk will then list DNS records to add (Frontend API "clerk", Account Portal "accounts",
   email "clkmail" and two DKIM records "clk._domainkey" / "clk2._domainkey", or whatever it
   lists). Add each one in Cloudflare (zone devicebasedauth.org → DNS → Records) exactly as Clerk
   shows them, as CNAME records with Proxy status "DNS only" (grey cloud; Clerk does not work
   behind the proxy). Skip any that already exist and tell me. Then click Verify in Clerk and
   report the result; if SSL certificates are still pending, say so.

4. In the production instance, open the Google and GitHub social connections. Production needs
   our own OAuth credentials. For each, tell me the exact "Authorized redirect URI" / "callback
   URL" Clerk shows (not secret), then STOP. I'll create the Google and GitHub OAuth apps
   separately and paste the client secrets myself.

Report: the application name, the plan findings, every DNS record you added (name, target,
proxy status), the Verify result, and the two redirect URIs.
```

### 2b. Google and GitHub OAuth apps (for Clerk production)

```text
I need OAuth credentials for Clerk's production sign-in on devicebasedauth.org. I'll give you
the two redirect URIs Clerk showed: GOOGLE_REDIRECT=<paste> GITHUB_REDIRECT=<paste>.

Rules: ask me before creating a Google Cloud project, accepting terms, or publishing an app.
Never copy a client secret anywhere; when one is shown, stop so I can copy it.

A. GitHub (github.com → Settings → Developer settings → OAuth Apps → New OAuth App, on my
   personal account): Application name "devicebasedauth.org", Homepage URL
   "https://devicebasedauth.org", Authorization callback URL = GITHUB_REDIRECT. Register it, then
   click "Generate a new client secret" and STOP: tell me to copy the Client ID and secret into
   Clerk (production instance → SSO connections → GitHub → "Use custom credentials").

B. Google (console.cloud.google.com): use a project named "devicebasedauth" if one exists,
   otherwise ask me before creating it. Configure the OAuth consent screen / Google Auth Platform:
   External, app name "devicebasedauth.org", support email = my account's address (ask me which),
   authorized domain devicebasedauth.org, scopes openid, email and profile only. Then create an
   OAuth client ID: type "Web application", name "Clerk production", Authorized redirect URI =
   GOOGLE_REDIRECT. When the client secret is shown, STOP and tell me to copy the Client ID and
   secret into Clerk (production instance → SSO connections → Google → custom credentials).
   Ask me before clicking "Publish app" to move the consent screen out of Testing.

Report what you created (names, client IDs, redirect URIs) and anything left for me.
```

---

## 3. Clerk sessions, webhook and keys (§3, part 2)

Run after the production instance is verified.

```text
Continue setting up the Clerk application "devicebasedauth.org" in dashboard.clerk.com. Work in
its PRODUCTION instance only (check the instance switcher at the top before each step).

Rules: only change this application's production instance. Never copy a secret value (secret
key, webhook signing secret) into a form or into your reply: when one is shown, stop and tell me.
Ask before entering personal data.

1. Sessions → find the session token version setting, if shown, and tell me which version is in
   use. We need version 2 (it carries the "fva" claim). If it is version 1, stop and tell me; do
   not change it without asking.

2. Sessions → Customize session token. If the claims editor is empty, set it to exactly:
   { "dba_account": "{{user.public_metadata.dba_account}}" }
   If it already has claims, stop and show me them instead of overwriting. Save.

3. Webhooks → Add Endpoint. Endpoint URL: https://devicebasedauth.org/webhooks/clerk
   Description: "dba worker". Subscribe to exactly these events: user.created, user.updated,
   user.deleted. Create it. Then, on the endpoint page, the Signing Secret is hidden behind a
   reveal button: STOP and tell me "Copy the signing secret and run
   gh secret set DBA_CLERK_WEBHOOK_SECRET". (The endpoint will fail deliveries until the site is
   deployed; that's expected.)

4. API Keys (production): tell me the Publishable key (starts pk_live_; it is public, so include
   it in your report). For the Secret key, STOP and tell me "Copy the secret key and run
   gh secret set DBA_CLERK_SECRET_KEY". Do not reveal or copy it yourself.

5. Operator user: Users → find my own user (ask me which email address is mine). If it does not
   exist, ask me before creating it with that address. Report its user ID (starts user_).

Report: session token version, the claims you saved, the webhook endpoint and its events, the
publishable key, my user ID, and anything left for me.
```

Then:

```bash
gh secret set DBA_CLERK_PUBLISHABLE_KEY
```

```bash
gh variable set DBA_OPERATOR_ACCOUNT --body user_XXXXXXXX
```

---

## 4. Stripe (§4)

```text
I'm adding devicebasedauth.org to my existing Stripe account (dashboard.stripe.com, signed in).
The account is shared with hashbin.org and cronly; never change their products, webhooks or
settings. Work in LIVE mode (check the test-mode toggle is off) unless I say otherwise.

Rules: only add things. Ask before accepting terms or changing account settings. Never copy a
secret (API secret key, webhook signing secret) into a form or into your reply: when one is
shown, stop and tell me.

1. Product catalog → Add product, twice. If either already exists with the same name, don't make
   a second; report the existing one.
   a. Name "devicebasedauth.org prepaid credit". Description "Prepaid usage credit for
      devicebasedauth.org." No image. Do not add a fixed price if Stripe lets you skip it (the
      site creates prices per checkout); if a price is required, use one-time $1.00 USD and tell
      me. Tax code: leave default and tell me what it is.
   b. Name "Card payment cost (non-refundable)". Description "Card processing cost for a
      devicebasedauth.org deposit." Same price handling as (a).
   Report both product IDs (prod_…; not secret).

2. Developers → Webhooks → Add endpoint (or "Add destination" → Webhook endpoint). URL:
   https://devicebasedauth.org/webhooks/stripe . Events from "Your account", exactly:
   checkout.session.completed and checkout.session.async_payment_succeeded. Use the account's
   default API version. Description "devicebasedauth.org". Create it, then STOP at the signing
   secret (whsec_…) and tell me "Copy it and run gh secret set DBA_STRIPE_WEBHOOK_SECRET".

3. Developers → API keys: tell me whether a restricted key named for hashbin or cronly exists
   and which permissions it has (names and permissions only). Do not create or reveal any key.
   Then STOP and ask me whether to use the standard secret key or a new restricted key for
   devicebasedauth.org.

4. Repeat steps 1 and 2 in TEST mode (toggle on), so the post-deploy check can pay with a test
   card. Report the test-mode product IDs separately and stop at the test webhook secret too.

Report: live and test product IDs, both webhook endpoints and their events, the API key
findings, and anything left for me.
```

Then (live IDs):

```bash
gh variable set DBA_STRIPE_CREDIT_PRODUCT_ID --body prod_XXXXXXXX
```

```bash
gh variable set DBA_STRIPE_CARD_COST_PRODUCT_ID --body prod_XXXXXXXX
```

```bash
gh secret set STRIPE_SECRET_KEY
```

Payments stay closed until `DBA_LAUNCH_APPROVED=true`, so these can be set before launch.

---

## 5. After the first deploy: Durable Object namespace IDs (§1.3)

```text
In the Cloudflare dashboard (the account holding devicebasedauth.org), open Workers & Pages →
Durable Objects (or Storage & Databases → Durable Objects). List the namespaces belonging to the
Worker "dba-worker-prod": AccountDO, StatusListDO, RegistryDO, EnrollmentDO and SafetyDO, with
each namespace ID. Change nothing. Report them as one comma-separated line of IDs, plus a table
of class name → ID. Namespace IDs are not secret.
```

```bash
gh variable set DBA_DO_NAMESPACES --body "id1,id2,id3,id4,id5"
```

---

## Not covered here

- The generated secrets (`DBA_ISSUER_KEYS` with kid `dba-2026-11`, `DBA_TOKEN_SIGNING_KEY`,
  `DBA_PUSH_VAPID_KEY`, `DBA_GATE_SEALING_KEYS` with kid `gate-2026-11`; deployment.md §2) were
  generated and set as repository secrets on 2026-11-21, checked by
  `scripts/check-deployment-secrets.mjs` first, and never printed or written to disk.
- Amazon SES security email (§3a) is optional and is AWS, not one of these three services.
- Setting `DBA_DEPLOY_ENABLED=true` (§5) is the last step, after the secret check passes.
