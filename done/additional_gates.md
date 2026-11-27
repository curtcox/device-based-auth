# Additional gates on authentication and authorization

Status: **done** (G1–G9); STATUS **B7**, **D12** (owner's choices), **D13** (prices, proposed).
Design summary in the master plan §6.4. Kept for reference: the design below is as built; §11a
maps it to the code.

## 1. What and why

A grant can say `require.step_up: true`: every use waits for the account owner to approve it from
a signed-in browser or dashboard device. **Gates** generalize that: named devices or services that
must say yes before DBA lets something happen. Step-up is the `owner` gate.

- **Authorization gate**: *this action is allowed as long as it is approved by this device or
  service.* Attached to a grant; checked on each use.
- **Authentication gate**: *this identity is trusted as valid as long as it is confirmed by this
  device or service.* Checked at **sign-in** (Sign in with DBA, the DBA dashboard) and,
  optionally, **periodically**: a credential is usable only while it holds a recent confirmation.

Both **fail closed**: a gate that says no, or that does not answer, denies. Each gate entry can
instead opt into **allow on timeout**: if no answer arrives within its timeout, the action or
sign-in goes ahead. In that case the wait does not depend on whether DBA reached the gate: no
answer is no answer, whether the approver ignored the request or could not be reached (owner's
choice, D12).

Gate kinds in v1:

| Kind | What answers | DBA stores |
|------|--------------|------------|
| `owner` (built in) | Any browser signed in to the account, or a dashboard device (`dba:session`). This is step-up. | nothing new |
| `dba-device` | One named DBA device, signing its answer with its own key (SDK, CLI, mobile sample, or the dashboard open on that device). | the device id |
| `totp` | Whoever holds an authenticator app (Google Authenticator, Authy, 1Password, Microsoft Authenticator in code mode…) types its current code. | the TOTP seed, sealed (§7) |
| `webauthn` | A security key or passkey (YubiKey, Titan, platform passkey) signs a WebAuthn assertion. | the public key credential |
| `webhook` | The customer's own HTTPS approval service answers allow or deny, at once or later. | URL and the service's public key |
| `duo` | Duo Push to a Duo user (Duo Auth API). | Duo integration key, secret key (sealed), API host, Duo username |
| `okta-verify` | Okta Verify push to an Okta user (Okta Factors API). | Okta org URL, API token (sealed), user and factor ids |

Microsoft Authenticator push has no public third-party API that we know of (it serves Microsoft
Entra ID); it is supported as a `totp` app.

## 2. Decisions already made (D12, owner)

1. Authentication gates apply at sign-in **and** optionally periodically, through a short-lived
   signed confirmation that offline verifiers check for free.
2. v1 gate kinds: TOTP apps, security keys and passkeys, customer webhook services, and push MFA
   vendors directly (Duo, Okta Verify), plus DBA devices and the existing owner approval.
3. "No response" for allow-on-timeout means silence **or** unreachable: an undelivered request
   (service down, no push subscription, vendor error) passes once the timeout runs out, like an
   unanswered one. An explicit deny always denies.
4. Audiences can require gates on their actions and sign-ins, and can forbid allow-on-timeout
   for them. Account owners can add gates but never weaken an audience's.

### Consequences to keep visible

- **Allow-on-timeout is a veto window, not a check.** Anyone who can stop the gate from answering
  (switch off the approver's phone, take down the webhook, wait for a Duo outage) gets through
  after the timeout. The UI, inspector and docs say so in those words; every allow by timeout is
  audited, announced to the owner (§8) and marked in the decision and ID token.
- **A request DBA cannot pay for is unreachable.** If the gate owner's balance cannot cover the
  gate price, DBA sends nothing and the entry waits for its timeout (decision 3). For
  deny-on-timeout entries this denies; for allow-on-timeout entries it allows. This is listed in
  D13 so the owner confirms it with the prices.
- **What still denies regardless of timeout**: an explicit deny; a gate that has been deleted or
  disabled (there is no gate to wait for, so nothing to time out; otherwise deleting a phone's gate
  would silently turn its grants into timers); a gate the audience's policy does not accept (§6);
  and a revoked or expired credential.
- **Allow-on-timeout is refused where the requester controls the silence.** TOTP and security-key
  gates can be answered inline by the person signing in (§5.1). There, "no response" is that
  person choosing not to answer, so allow-on-timeout would be no gate at all. A gate entry with
  `on_timeout: "allow"` is therefore only ever answered on the separate approval surface (§4.3),
  never inline, and config that could only be answered inline is refused (400 `invalid_gates`).

## 3. Vocabulary

### 3.1 Gate entries

A **gate entry** names one or more gates of the account and how long to wait:

```json
{ "any": ["gate_01JE…", "owner"], "timeout_s": 300, "on_timeout": "deny" }
```

- `any`: 1–5 gate ids of the issuing account (or `owner`). One allow from any of them satisfies
  the entry.
- `timeout_s`: 10–86 400, default 300.
- `on_timeout`: `deny` (default) or `allow`.
- The first answer settles the entry; later answers are recorded but change nothing.
- A list of entries means **all** must be satisfied (`[{any:[phone]}, {any:[yubikey]}]` = both).
  At most 3 entries.
- No gate in an entry may be the requesting device itself (a `dba-device` gate naming the
  credential's own device is refused at issuance; `owner` already excludes it, as step-up does).

### 3.2 Authorization: `require.gates`

```json
"require": {
  "gates": [
    { "any": ["gate_phone"], "timeout_s": 120, "on_timeout": "allow" }
  ],
  "gates_reuse_s": 0
}
```

- Online only, like `step_up`: offline evaluation fails the grant with `online_required`.
- `gates_reuse_s` (0–3600, default 0): one approval covers repeated uses of the same
  (credential, action, resource, audience) for this long. 0 = each approval is spent by one use.
- `require.step_up: true` stays valid and means exactly
  `gates: [{ any: ["owner"], timeout_s: 600, on_timeout: "deny" }]`; `step_up` and `gates`
  together are invalid. The grant builder writes `gates`.
- Gate ids are `gate_` + 8–64 alphanumerics. `dba:*` grants cannot have gates (DBA checks them
  per request with no gate engine).
- Old verifiers deny `require.gates` as an unknown constraint (fail closed); nothing more needed.

### 3.3 Authentication at sign-in: account settings

```json
"sign_in_gates": {
  "default":   [{ "any": ["gate_yubikey", "gate_totp"], "timeout_s": 300, "on_timeout": "deny" }],
  "audiences": { "cronly.org": [{ "any": ["gate_phone"], "timeout_s": 60, "on_timeout": "allow" }] },
  "dashboard": [{ "any": ["gate_yubikey"], "timeout_s": 300, "on_timeout": "deny" }]
}
```

Stored on the account (`GET/PUT /api/v1/settings/sign-in-gates`). Only the signed-in owner may
change them, from the dashboard or a dashboard (`dba:session`) device (API keys and other
devices get 403 `session_required`), with a recent sign-in. A change
that loosens a list (an entry no longer matched by a new one whose gates are among its gates and
that does not newly allow on timeout) opens a `settings` gate request on the loosened lists'
current entries (at most 3, `fail_open: false`, so silence never approves it), keyed by a hash of
the exact change; the PUT answers 202 `gate_pending` until it is allowed, then the same PUT
applies. A stolen session cannot switch the gates off. `audiences` override `default` for that
OIDC client; `dashboard` covers DBA itself. The `owner` gate cannot be a sign-in gate (the owner
is who signs in). Audiences can demand more (§6).

### 3.4 Authentication over time: `confirm`

A credential may carry a top-level `confirm` block:

```json
"confirm": { "gates": [{ "any": ["gate_phone"], "timeout_s": 300, "on_timeout": "deny" }], "every_s": 28800 }
```

- `every_s`: 300–604 800. The credential authenticates only while the device holds a
  **confirmation** issued within the last `every_s` seconds.
- Issuance copies `require.confirmation: true` into every grant, so verifiers that predate this
  deny the credential (unknown constraint) instead of ignoring the top-level claim.
- A confirmation is a JWS signed by the issuer key, typ `dba-confirmation+jwt`:

  ```json
  { "iss": "https://devicebasedauth.org", "sub": "dev_…", "aud": ["hashbin.org"],
    "cid": "<credential cid>", "cnf": { "jkt": "<same as credential>" },
    "iat": 1795017600, "exp": 1795046400,
    "gates": [{ "kind": "dba-device", "by": "answer" }], "by_timeout": false }
  ```

- The device sends it as `DBA-Confirmation: <jws>` with the credential and DPoP proof. Verifiers
  check signature, `iss`, `cid` and `sub` = the credential's (the stable `cid`, so a renewal keeps
  the confirmation; a rotation changes `cnf.jkt` and needs a new one), `cnf.jkt` = credential `cnf.jkt`,
  `iat ≤ now < exp` (60 s skew). Missing → `confirmation_required`; expired →
  `confirmation_expired`; `by_timeout: true` and the action's policy forbids it (§6) →
  `confirmation_by_timeout_refused`.
- Renewal, rotation, token exchange (§6.3 of the master plan) and X.509 certificates need a current
  confirmation; tokens and certificates never outlive it.
- Online `/authorize` uses DBA's own record (`confirmed_until` on the credential row), so the
  owner can end confirmation instantly for online audiences ("Stop trusting now",
  `POST /api/v1/credentials/{cid}/unconfirm`); offline verifiers stop within `every_s` at most,
  or at once on revocation.
- `confirm` is set by the issuer: on `POST /api/v1/credentials`, or by the owner on the
  enrollment approval page. It is refused with `dba:*` grants, and `require.confirmation` cannot
  be written by hand. A credential starts unconfirmed.

## 4. Gate requests (the engine)

### 4.1 One engine for every purpose

Gate requests are `gatereq:` rows in the AccountDO (gates themselves are `gate:` rows):

```
{ id: "gtr_…", purpose: "authorize" | "sign_in" | "dashboard" | "confirm" | "settings" | "reverify" | "recover",
  cid, device_id, device_name, subject: { audience, action, resource } | { client_id } | { cid },
  entries: [{ any, timeout_s, on_timeout, deadline, delivered: {gate: "sent"|"failed"},
              answer: { gate, decision, at, by } | null, outcome: null|"allow"|"deny", by_timeout }],
  number: "47", created_at, approved_until, spent }
```

- Creation is idempotent per (purpose, cid, subject) and the grant's exact gate list while one is
  waiting: retries reuse it, one notice per request. A different gate list needs its own approval.
- Outcome of an entry: first answer; else at `deadline`, `on_timeout`. Of the request: deny if any
  entry denies, allow when all allow. Later answers to a settled entry get 409, answers after the
  deadline 410 `expired`. A request whose gates are all deleted (or are only the requesting
  device) denies at once.
- Deadlines are evaluated lazily when the request is read (no alarm needed for correctness). An
  unanswered request is kept 5 minutes past its last deadline so the site's next retry settles it
  (that is when an allow by timeout is seen, audited and announced); the alarm prunes rows and
  returns for vendor polls (§4.4).
- `/authorize` keeps its async contract: `{ allow: false, code: "gate_pending", gate_request:
  { id, retry_after, deadline, approve_url } }` (`step_up_required` for a `step_up` grant;
  `approve_url` only when a TOTP or security-key gate can answer); the caller retries. The browser SDK's
  `fetchWithGates()` and `dba curl --dba-wait[=SECONDS]` resend with a fresh proof every
  `retry_after` s while a site answers 403 `gate_pending`. A settled allow says how:
  `gates: [{ kind, by: "answer" | "timeout" }]`; callers must not cache it beyond `gates_reuse_s`.
- Step-up routes (`/api/v1/step-ups`) are a filtered view of `owner` gate requests; the
  dashboard's Approvals page lists every gate request.

### 4.2 Delivery per kind

| Kind | Delivery | "Failed" means |
|------|----------|----------------|
| `owner` | Web Push to the account's browsers, dashboard Approvals page | no subscription |
| `dba-device` | The device polls `GET /api/v1/gate-requests` (filtered to its gates; CLI `dba approvals --watch`, MCP `list_gate_requests`); each request lists `answer_as: [{ entry, gate }]` | device revoked |
| `totp`, `webauthn` | Web Push to the owner linking the approval page; or inline at sign-in (§5.1) | no subscription and not inline |
| `webhook` | POST of a `dba-gate+jwt` (signed with the issuer key, checkable with the JWKS; spec/events.md §6) to the service URL, in the background once the decision has answered `gate_pending` | non-2xx, timeout (10 s), bad answer |
| `duo` | Duo Auth API `POST /auth/v2/auth` (factor push, `async=1`), then `/auth/v2/auth_status` | API error, user not enrolled |
| `okta-verify` | Okta `POST /api/v1/users/{uid}/factors/{fid}/verify`, then polls the transaction | API error |

Per decision 3, "failed" changes nothing about timing: the entry waits for its deadline. It is
recorded and shown ("not delivered: no push subscription") so owners can fix their setup.

### 4.3 Answering

`POST /api/v1/gate-requests/{id}/answer` with `{ entry, gate, decision: "allow"|"deny", proof }`:

| Kind | Proof |
|------|-------|
| `owner` | Clerk session or `dba:session` device (not the requester) |
| `dba-device` | DPoP-authenticated request from that device, credential holding `dba:approvals:answer`, not revoked (a dashboard device registered as a gate answers as that gate) |
| `totp` | `{ code }`; ±1 step; each step accepted once per gate (replay row until the step expires) |
| `webauthn` | WebAuthn assertion over a challenge bound to the request id and decision; RP ID `devicebasedauth.org`; user verification per gate setting; sign counter checked |
| `webhook` | Synchronous JSON answer `{ "decision": "allow" }` to DBA's POST, or `202` then a callback to `/api/v1/gate-links/{link}/callback` whose body is a `dba-gate-answer+jwt` signed by the service's registered key (ES256) over `{ request, entry, decision, iat }` |
| `duo`, `okta-verify` | Vendor status `allow`/`deny` from DBA's own polling; never trusted from the client |

The **approval surface** is `/gate.html#<link>` (`/approve.html` is enrollment approval): a `dbag_`
link signed with `TOKEN_SIGNING_KEY` names the account and request and expires a minute after its
last deadline. It shows who asks for what (device, action, resource, audience, coarse country,
the request's number) and offers the factors the entry accepts, through the public
`GET/POST /api/v1/gate-links/{link}[/answer]` (behind the cost brake; 5 wrong tries per gate per
15 minutes). A TOTP or security-key holder who is not the account owner (a manager, a parent) can
answer there without a DBA session: the factor is the authentication. TOTP accepts each step
once (the gate row keeps the last accepted step); security keys keep their signature counter; the
assertion's challenge binds request, entry, decision and a per-request salt. Everything dynamic
is escaped; the page renders untrusted device names and resources.

Requests time out for answering at their deadline; an answer after it is refused (410 `expired`).

### 4.4 Vendor polling bounds

Duo and Okta answers are pulled, not pushed. The AccountDO alarm polls at most every 5 s and at
most 24 times per entry, then treats the vendor as silent until the deadline. Poll times are kept
in memory, bounded by the time since the push started, so polls write nothing; a poll that cannot
be read counts as waiting. Vendor hosts are pinned to the vendors' domains (no SSRF). The gate
price (§9) prepays the maximum polls.

## 5. Authentication flows

### 5.1 Sign in with devicebasedauth.org (OIDC)

After consent and before the authorization code is issued (`op_sign_in` in
`src/durable-objects/account/sign-in.js`, one account request, so the login price is unchanged):

1. Resolve the gates: `sign_in_gates.audiences[client]` or `default`, plus whatever the audience
   requires (§6). None → the ordinary flow.
2. Open (or reuse, per site, requester and gate list) a `sign_in` gate request.
   `/oauth/authorize` answers `{ pending, gate_request }` and the consent page asks again every
   `retry_after` s, showing the request's two-digit **number**. The number is only in the consent
   page's response; approvers on the approval page or a device must send it with an allow
   (`wrong_number`), webhook services need not (number matching against push fatigue).
3. TOTP and security-key gates on deny-on-timeout entries can be answered right on the consent
   page by the person signing in (inline). Allow-on-timeout entries refuse answers from the
   signed-in session (`not_inline`, §2).
4. On allow, issue the code. The ID token adds `amr` values (RFC 8176: `otp` for TOTP, `hwk` for
   security keys and DBA devices with hardware attestation, `swk` for other DBA devices, `mfa`
   when any gate passed by answer), `acr` = `urn:devicebasedauth.org:acr:gated` (all answered)
   or `urn:devicebasedauth.org:acr:gated-timeout` (some passed by timeout), and
   `dba_gates: [{ kind, by }]`. `acr_values` in the request lets the audience ask for a level;
   a weaker result is a sign-in error (`access_denied`, `acr_not_met`).
5. On deny or a deny-on-timeout: redirect with `error=access_denied`.

### 5.2 The DBA dashboard

- After a Clerk sign-in, a local sign-in or a dashboard device's sign-in (Stage B), if
  `sign_in_gates.dashboard` is set, the session is **locked**: every route except
  `/api/v1/session*`, `whoami` and revocation (the panic button must always work) answers 403
  `sign_in_gate_required` until the gate request settles allow. `POST /api/v1/session/confirm`
  opens the `dashboard` request (number matching as for sign-in) and takes this page's own
  TOTP/security-key answer for deny-on-timeout entries; a locked session cannot use
  `/gate-requests/{id}/answer`, which could approve other requests. Sessions are keyed
  `sid:<Clerk sid>`, `local:<name>` or `cid:<credential>`; a confirmation lasts 7 days
  (`dashsess:` rows, pruned). The state (`open | confirmed | locked`) comes back from the account
  request every call already makes.
- **Recovery codes** come first: enabling a deny-on-timeout dashboard gate requires that the
  account has 10 one-time recovery codes (shown once, stored as SHA-256 hashes). Using one
  (`POST /api/v1/session/recover`) passes the dashboard gate, is audited and announced, and
  invalidates that code.
- A recent re-authentication (S8) does not bypass the dashboard gate; it is checked in addition.

### 5.3 Periodic confirmation

- `POST /api/v1/credentials/{cid}/confirm` (DPoP from the credential's key) opens or reads the
  credential's `confirm` gate request and answers `pending`, `denied`, or `confirmed` with the
  confirmation JWS; the device repeats the call to poll. It is charged `confirm` when a
  confirmation is issued; its gates are charged as gate requests.
- The SDK (`confirm()`, and `headers()`/`fetch()` before a request) and the CLI (`dba confirm`,
  and `dba headers`/`curl` before a request; `DBA_AUTO_CONFIRM=0` turns that off) ask for a new
  confirmation when there is none or it ends within 30 s, and send it as `DBA-Confirmation`.
  Calls to DBA's own API (renew, token, revoke) do not wait for one.
- The dashboard's credential page shows the confirmation state and a "Stop trusting now" button
  (`…/unconfirm`, sets `confirmed_until` to now; offer revocation for offline audiences).

## 6. Audience policy

An audience's catalog entry may carry a `gates` policy, and its OIDC client a `sign_in_gates`
policy:

```json
{ "action": "cronly:secrets:write", "description": "Set and rotate secrets.",
  "gates": { "require": true, "kinds": ["webauthn", "dba-device"], "fail_open": false } }
```

- `require: true`: a grant for this action counts only if it has a gate entry whose gates are all
  of `kinds` (any kind if `kinds` is absent). Checked at issuance for exact action names (400
  `gate_required`, with the policy in the error, so the grant builder can add one; kinds are
  checked in the account) and at every `/authorize`, which also catches wildcard grants and
  older credentials (reason `gate_required`) before any gate request is opened.
- `fail_open: false`: an allow by timeout counts as deny for this action (`by_timeout_refused`),
  in `/authorize` and in confirmations presented for it.
- The same shape on the OIDC client governs sign-ins; `acr_values` can ask per request.
- **Offline verifiers** must enforce this too, or an ungated credential would pass. The JS
  verifier fetches the audience's public catalog with `createVerifier({ audience, catalog: true })`
  (`GET /api/v1/audiences/{name}`, cached like the JWKS; a stale copy is kept when a refresh fails,
  since policies only tighten; no copy at all fails closed, 503 `catalog_unavailable`) or takes a
  static one; the Python and Go verifiers take a static catalog. For an action whose policy
  requires gates they return `online_required`; for `fail_open: false` they refuse confirmations
  with `by_timeout: true`.
- The audience console edits these policies per catalog action and for signing in
  (`PATCH /api/v1/audiences/{name}`, the audience price).
- Account owners can add gates but never remove an audience's requirement or turn its
  `fail_open: false` back on.

## 7. Secrets

- TOTP seeds, Duo secret keys and Okta API tokens are the customer secrets DBA stores. They are
  sealed with AES-256-GCM (`src/services/sealing.js`) under the Worker secret `GATE_SEALING_KEYS`
  (a JSON list of `{ kid, key }`: the first seals, every one opens, so a key rotates by putting a
  new one first), per-record random nonce, AAD = account id + gate id; stored only in the
  account's DO; never returned after creation, never logged, never in audit details; deleting the
  gate deletes the blob. docs/ops/deployment.md covers setting and rotating it and what a leak
  means (every TOTP gate must be re-added).
- Webhook services use asymmetric keys in both directions (DBA signs with the issuer key; the
  service registers a public key), so DBA stores no shared secret for them.
- WebAuthn stores public keys only.
- Device private keys still never reach DBA: a `dba-device` gate answers with its own key.

## 8. Security, abuse and visibility

- **Push fatigue**: one waiting request per subject (dedupe), number matching at sign-in, at most
  10 gate requests per (device, gate) per hour (then a denial with `gate_rate_limited`; for
  allow-on-timeout entries this is a deny, not a silence, so flooding cannot be used to force the
  timeout).
- **Every allow by timeout** writes `gate.allowed_by_timeout` to the audit log, shows in the
  decision log with its reason, and is announced to the owner's browsers ("cronly:run was
  allowed because nobody answered within 2 minutes"), batched hourly like other notices.
- **Self-approval** is impossible for every kind: the requester device cannot answer allow for
  its own request (it may deny).
- **Configuration changes** (adding, editing, deleting gates; sign-in gate settings) need a recent
  sign-in (S8) and are announced at once like `dba:*` issuance.
- The credential carries gate ids and kinds only, never labels, phone numbers, usernames or URLs
  (it is shown to every audience).
- The grant builder, approval page, inspector and dashboard render allow-on-timeout entries in a
  warning style with the plain-English meaning: "allowed if nobody answers within 2 minutes".
- Webhook URLs follow the rules in `src/services/webhooks.js` (https on a public host name and
  the default port, no credentials or fragment; `http://localhost` in local mode) and have a test
  (`POST /api/v1/gates/{id}/test`: a signed `gate.test` event, charged the read price; dashboard
  "Test" button, `dba gates test`).

## 9. Money

Operations in `src/utils/cost-policy.js`, prices in `src/utils/pricing.js`, each passing the
price-floor test and counted in `src/cost-counts.test.js`; derivations in
docs/business/pricing.md. All four are proposed, awaiting the owner (D13):

| Operation (`PRICES` key) | Worst case counted | Price | Payer |
|-----------|--------------------|-------|-------|
| Gate request, local kinds (`owner`, `dba-device`, `totp`, `webauthn`) (`gate`) | request row and its deletion, answer or timeout settlement, audit row, notices (push CPU), WebAuthn/TOTP checks and replay state, DPoP nonce challenge | 22 µ$ | Account that owns the gates (credential issuer; for sign-in, the signing-in account) |
| Gate request, `webhook` (`gate_webhook`) | the above + 1 signed subrequest + the row recording its outcome | 23 µ$ | same |
| Gate request, `duo` / `okta-verify` (`gate_vendor`) | the above + 1 start + up to 24 status polls | 30 µ$ | same |
| Confirmation issued (`confirm`) | credential row, charge and audit rows, signing; its gates are charged as gate requests | 14 µ$ | Account that issued the credential |

Charged per gate actually contacted, when the request is created (reserve the maximum first, as
everywhere). Step-up (the owner gate) is billed this way too. The audience still pays the online
decision. Answering is free. A gate request the owner cannot pay for is not sent (`unpaid`) and is
treated as unreachable: it waits for its timeout (§2). Adding and removing gates is free; listing
them is a metered read for API keys, like other reads.

## 10. Spec, verifier and tools

All built; where each lives:

- `spec/credential.md` §9: `confirm` claim and the `dba-confirmation+jwt` format;
  `spec/events.md` §6: the `dba-gate+jwt` webhook format and the `dba-gate-answer+jwt` callback.
- `spec/evaluation.md` §3.6–3.9: `require.gates`, `require.gates_reuse_s`,
  `require.confirmation` (online only for gates), the catalog policy, the confirmation step
  between revocation and grants; reasons `gate_pending`, `gate_denied`,
  `gate_required`, `by_timeout_refused`, `confirmation_required`, `confirmation_expired`,
  `confirmation_by_timeout_refused`.
- Vectors (all three verifiers): gates offline → `online_required`; step_up and the equivalent
  gates evaluate the same; confirmation present / missing / expired / wrong `cid` / wrong `jkt` /
  bad signature / by-timeout under a `fail_open: false` policy; catalog-required gates offline.
- Verifiers: `DBA-Confirmation` in `verifyRequest` (JS), `verify_request` (Python) and the Go
  `AuthResult.Confirmation`, each refusing a bad one with `confirmation_<code>` (401); the JS
  `catalog` option (§6). SDK (from v1.2.0): `confirm()`, confirmation auto-refresh in
  `headers()`/`fetch()`, `fetchWithGates()`.
- CLI: `dba gates [--json]`, `dba gates add --kind dba-device|webhook`, `dba gates remove`,
  `dba gates test` (an API key; devices cannot pass the recent-sign-in check; TOTP, security keys,
  Duo and Okta are set up on the dashboard), `dba approvals [--watch] | allow | deny` (answer as a
  `dba-device` gate), `dba confirm [--wait]`, `dba curl --dba-wait[=SECONDS]` (named so it never
  collides with a curl option; options that would hide the response are refused in that mode).
- Site: the dashboard's Gates page (TOTP with a QR code from `frontend/js/qr.js`, written here so
  no third-party code ships; security keys; devices; webhooks with a test; Duo/Okta forms;
  sign-in gates; recovery codes), Approvals page, the approval page `/gate.html`, "Require
  periodic confirmation" on the enrollment approval page; grant builder, inspector and playground
  understand `gates` and `confirm`; the audience console edits catalog gate policies.
- Docs: `/docs/#gates` with CI-executed samples (webhook approval services in Node
  `docs/samples/gate-webhook.mjs` and Python `gate_webhook.py`, answering as a `dba-device` from
  the CLI `approve-from-cli.sh`); `llms.txt`; MCP tools `list_gates`, `list_gate_requests` and
  `answer_gate_request`. MCP answers only as a device's own `dba-device` gate: answering as the
  owner would let an agent holding an API key pose as the owner gate, which no key may do.

## 11. Phases

Each phase ends with `npm test`, `npm run lint`, samples and e2e green, docs regenerated, and its
STATUS row updated.

| Phase | Deliverable | Exit criteria |
|-------|-------------|---------------|
| G1 ✅ | Spec text and vectors for `require.gates`, `require.confirmation`, confirmations, catalog policy; evaluator in JS, Python, Go | Every new vector passes in all three; step_up ≡ owner gate |
| G2 ✅ | Gate registry (`gate:` rows, CRUD routes, scopes `gates:read`/`gates:write`), `gatereq:` engine replacing `stepup:`, `owner` and `dba-device` kinds, `/authorize` integration, timeouts both ways, audit and notices, D13 prices in cost policy | Concurrency tests: one answer settles; timeout allow/deny; deleted gate denies; balance refusal behaves per §2; cost-count test covers the new ops |
| G3 ✅ | Audience gate policy: catalog field, issuance check, `/authorize` check, verify library `catalog` option | An ungated grant for a required action is refused online and gets `online_required` offline |
| G4 ✅ | `totp` and `webauthn` gates, sealing key, approval page | Playwright: approve with a virtual authenticator and a TOTP code; replayed code refused |
| G5 ✅ | `webhook` gate: signed request, sync answer, signed callback | CI sample service approves and denies; unreachable service follows `on_timeout` |
| G6 ✅ | Sign-in gates: OIDC consent, number matching, inline factors, `amr`/`acr`/`dba_gates`, dashboard gate, recovery codes | Playwright: OIDC sign-in waits for and passes a gate; `acr_values` enforced; dashboard locked until confirmed; recovery code works once |
| G7 ✅ | Periodic confirmation: `confirm` at issuance, confirm endpoints, confirmation JWT, offline check, renew/token/certificate rules, SDK and CLI refresh | e2e: an offline verifier denies after `every_s` without a new confirmation and accepts after one |
| G8 ✅ | `duo` and `okta-verify` gates (sealed credentials, polling bounds); confirm whether Microsoft Authenticator push is open to third parties | Tested against recorded vendor responses; live checks are owner steps after L9 |
| G9 ✅ | Tools and docs (§10) not already done per phase; SDK release | Every docs sample runs in CI |

## 11a. Where it lives

- Spec and vectors (G1): spec/evaluation.md §3.6–3.9, spec/credential.md §9, spec/events.md §6;
  gate and confirmation vectors in `spec/vectors/` pass in JS, Python and Go
  (`verifyConfirmation` / `verify_confirmation` / `VerifyConfirmation`).
- Registry and engine (G2): `src/durable-objects/gates.js` (`gate:` and `gatereq:` rows),
  `src/durable-objects/gate-requests.js` (approval links, delivery), `src/api/gates.js`,
  `/authorize` integration in `src/durable-objects/account/authorize.js`.
- Audience policy (G3): `cleanGatePolicy` in `src/api/audiences.js`; `validateIssue` in
  `src/services/credentials.js` and `checkGatesForIssue` in the account.
- Factors (G4): `src/services/{sealing,totp,webauthn}.js`; TOTP and security-key gates start
  `pending` (`POST /api/v1/gates` returns the secret or creation options once) and become active
  with `POST /api/v1/gates/{id}/activate`; pending gates cannot be named at issuance and count as
  deleted in requests.
- Webhooks (G5): `{ kind: "webhook", label, url, public_jwk }`, active at once.
- Sign-in (G6): `src/durable-objects/account/sign-in.js`, `src/api/sign-in-gates.js`,
  `src/api/oidc.js`.
- Confirmation (G7): `confirmCredential` / `unconfirmCredential` in `src/api/credentials.js`.
  Tokens drop `require.confirmation` and end by `confirmed_until`; certificates too.
- Vendors (G8): `src/services/vendors.js`. Duo: `{ api_host (api-*.duosecurity.com),
  integration_key, secret_key, username }`, `POST /auth/v2/auth` (factor=push, async=1) then
  `GET /auth/v2/auth_status`, signed per Duo's v2 scheme (HMAC-SHA1; the test reproduces Duo's
  published example). Okta: `{ org_url (*.okta.com, oktapreview, okta-emea, okta-gov), api_token,
  user_id, factor_id }`, `POST …/factors/{fid}/verify` then the poll link (pinned to the same user
  and factor). Tested against recorded vendor responses.
- Tools and docs (G9): §10.

Owner steps left (STATUS B7): the D13 prices, live checks with a real Duo Auth API application
and a real Okta org, and scanning a TOTP QR code with a real phone app once.

## 12. Open questions for later

- An "I didn't ask for this" button on deny that also offers to revoke the requesting device
  (designed, not built).
- k-of-n quorum (`at_least: 2` of a list) beyond all-of / any-of.
- Per-device sign-in gates (e.g. only for the kiosk), in addition to per audience.
- Location- or time-conditioned gates ("approval needed only outside office hours") — today the
  same effect needs two grants.
