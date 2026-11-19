# Additional gates on authentication and authorization

Status: STATUS **B7** (work) and **D12** (owner's choices, 2026-11-19), **D13** (prices, open).
Design summary in the master plan §6.4. This file is written to be picked up cold.

## 1. What and why

Today a grant can say `require.step_up: true`: every use waits for the account owner to approve it
from a signed-in browser or dashboard device (`src/durable-objects/account-do.js`, `stepup:` rows,
`/api/v1/step-ups`). This plan generalizes that into **gates**: named devices or services that must
say yes before DBA lets something happen.

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
| `owner` (built in) | Any browser signed in to the account, or a dashboard device (`dba:session`). This is today's step-up. | nothing new |
| `dba-device` | One named DBA device, signing its answer with its own key (SDK, CLI, mobile sample, or the dashboard open on that device). | the device id |
| `totp` | Whoever holds an authenticator app (Google Authenticator, Authy, 1Password, Microsoft Authenticator in code mode…) types its current code. | the TOTP seed, sealed (§7) |
| `webauthn` | A security key or passkey (YubiKey, Titan, platform passkey) signs a WebAuthn assertion. | the public key credential |
| `webhook` | The customer's own HTTPS approval service answers allow or deny, at once or later. | URL and the service's public key |
| `duo` | Duo Push to a Duo user (Duo Auth API). | Duo integration key, secret key (sealed), API host, Duo username |
| `okta-verify` | Okta Verify push to an Okta user (Okta Factors API). | Okta org URL, API token (sealed), user and factor ids |

Microsoft Authenticator push is only available to Microsoft Entra ID. Unless phase G8 turns up a
public third-party push API, it is supported as a `totp` app only.

## 2. Decisions already made (D12, owner, 2026-11-19)

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
  `gates: [{ any: ["owner"], timeout_s: 600, on_timeout: "deny" }]`. Existing credentials keep
  working; the grant builder writes `gates` from now on.
- Old verifiers deny `require.gates` as an unknown constraint (fail closed); nothing more needed.

### 3.3 Authentication at sign-in: account settings

```json
"sign_in_gates": {
  "default":   [{ "any": ["gate_yubikey", "gate_totp"], "timeout_s": 300, "on_timeout": "deny" }],
  "audiences": { "cronly.org": [{ "any": ["gate_phone"], "timeout_s": 60, "on_timeout": "allow" }] },
  "dashboard": [{ "any": ["gate_yubikey"], "timeout_s": 300, "on_timeout": "deny" }]
}
```

Stored on the account (`GET/PUT /api/v1/settings/sign-in-gates`; changing them needs a recent
sign-in, and loosening them also needs the current gates to pass, so a stolen session cannot
switch them off). `audiences` override `default` for that OIDC client; `dashboard` covers DBA
itself. Audiences can demand more (§6).

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
    "cid": "<credential jti>", "cnf": { "jkt": "<same as credential>" },
    "iat": 1795017600, "exp": 1795046400,
    "gates": [{ "kind": "dba-device", "by": "answer" }], "by_timeout": false }
  ```

- The device sends it as `DBA-Confirmation: <jws>` with the credential and DPoP proof. Verifiers
  check signature, `iss`, `cid` = credential `jti`, `cnf.jkt` = credential `cnf.jkt`,
  `iat ≤ now < exp` (60 s skew). Missing → `confirmation_required`; expired →
  `confirmation_expired`; `by_timeout: true` and the action's policy forbids it (§6) →
  `confirmation_by_timeout_refused`.
- Renewal, rotation, token exchange (§6.3 of the master plan) and X.509 certificates need a current
  confirmation; tokens and certificates never outlive it.
- Online `/authorize` uses DBA's own record (`confirmed_until` on the credential row), so the
  owner can end confirmation instantly for online audiences ("Stop trusting this device now");
  offline verifiers stop within `every_s` at most, or at once on revocation.

## 4. Gate requests (the engine)

### 4.1 One engine for every purpose

Generalize `stepup:` rows in the AccountDO into `gatereq:` rows:

```
{ id: "gtr_…", purpose: "authorize" | "sign_in" | "confirm",
  cid, device_id, device_name, subject: { audience, action, resource } | { client_id } | { cid },
  entries: [{ any, timeout_s, on_timeout, deadline, delivered: {gate: "sent"|"failed"},
              answer: { gate, decision, at, by } | null, outcome: null|"allow"|"deny", by_timeout }],
  number: "47", created_at, approved_until, spent }
```

- Creation is idempotent per (purpose, cid, subject) while one is waiting, as step-up is today:
  retries reuse it, one notice per request.
- Outcome of an entry: first answer; else at `deadline`, `on_timeout`. Of the request: deny if any
  entry denies, allow when all allow.
- Deadlines are evaluated lazily when the request is read (no alarm needed for correctness); the
  existing alarm prunes rows at `deadline + approved window` and returns for vendor polls (§4.4).
- `/authorize` keeps its async contract: `{ allow: false, code: "gate_pending", gate_request:
  { id, retry_after, deadline } }`; the caller retries. SDK and CLI get an
  `authorizeWithGates()` / `--wait` helper that polls until settled. A settled allow says how:
  `gates: [{ kind, by: "answer" | "timeout" }]`; callers must not cache it beyond `gates_reuse_s`.
- Step-up routes (`/api/v1/step-ups`) stay as a filtered view of `owner` gate requests.

### 4.2 Delivery per kind

| Kind | Delivery | "Failed" means |
|------|----------|----------------|
| `owner` | Web Push to the account's browsers (existing), dashboard list | no subscription |
| `dba-device` | Web Push to that device's browser if subscribed; the device also polls `GET /api/v1/gate-requests?mine=1` (SDK, CLI `dba approvals --watch`) | device revoked, or nothing to push to |
| `totp`, `webauthn` | Push to the owner with an approval link; or inline at sign-in (§5.1) | no subscription and not inline |
| `webhook` | POST of a `dba-gate+jwt` (signed with the issuer key, checkable with the JWKS) to the service URL | non-2xx, timeout (10 s), bad answer |
| `duo` | Duo Auth API `POST /auth/v2/auth` (factor push, `async=1`), then `/auth/v2/auth_status` | API error, user not enrolled |
| `okta-verify` | Okta `POST /api/v1/users/{uid}/factors/{fid}/verify`, then polls the transaction | API error |

Per decision 3, "failed" changes nothing about timing: the entry waits for its deadline. It is
recorded and shown ("not delivered: no push subscription") so owners can fix their setup.

### 4.3 Answering

`POST /api/v1/gate-requests/{id}/answer` with `{ entry, gate, decision: "allow"|"deny", proof }`:

| Kind | Proof |
|------|-------|
| `owner` | Clerk session or `dba:session` device (not the requester), as step-up today |
| `dba-device` | DPoP-authenticated request from that device, credential holding `dba:approvals:answer`, not revoked |
| `totp` | `{ code }`; ±1 step; each step accepted once per gate (replay row until the step expires) |
| `webauthn` | WebAuthn assertion over a challenge bound to the request id and decision; RP ID `devicebasedauth.org`; user verification per gate setting; sign counter checked |
| `webhook` | Synchronous JSON answer `{ "decision": "allow" }` to DBA's POST, or `202` then a callback whose body is a JWS signed by the service's registered key (ES256) over `{ request, entry, decision, iat }` |
| `duo`, `okta-verify` | Vendor status `allow`/`deny` from DBA's own polling; never trusted from the client |

The **approval surface** is a page on devicebasedauth.org (`/approve.html#gtr_…`, link carries an
HMAC token naming the request) that shows who asks for what (device, action, resource, audience,
coarse country, the request's number) and offers the factors the entry accepts. A TOTP or
security-key holder who is not the account owner (a manager, a parent) can answer there without
a DBA session: the factor is the authentication. Escape everything dynamic; it renders untrusted
device names and resources.

Requests time out for answering at their deadline; an answer after it is refused (410 `expired`).

### 4.4 Vendor polling bounds

Duo and Okta answers are pulled, not pushed. The AccountDO alarm polls at most every 5 s and at
most 24 times per entry, then treats the vendor as silent until the deadline. The gate price
(§9) prepays the maximum polls.

## 5. Authentication flows

### 5.1 Sign in with devicebasedauth.org (OIDC)

In `src/api/oidc.js`, after consent and before the authorization code is issued:

1. Resolve the gates: `sign_in_gates.audiences[client]` or `default`, plus whatever the audience
   requires (§6). None → today's flow.
2. Create a `sign_in` gate request. The consent page switches to "Waiting for approval" and
   shows the request's two-digit **number**; pushes and the approval page ask the approver to
   pick that number (number matching against push fatigue).
3. TOTP and security-key gates on deny-on-timeout entries can be answered right on the consent
   page by the person signing in (inline). Allow-on-timeout entries are never inline (§2).
4. On allow, issue the code. The ID token adds `amr` values (RFC 8176: `otp` for TOTP, `hwk` for
   security keys and DBA devices with hardware attestation, `swk` for other DBA devices, `mfa`
   when any gate passed by answer), `acr` = `urn:devicebasedauth.org:acr:gated` (all answered)
   or `urn:devicebasedauth.org:acr:gated-timeout` (some passed by timeout), and
   `dba_gates: [{ kind, by }]`. `acr_values` in the request lets the audience ask for a level;
   a weaker result is a sign-in error (`access_denied`, `acr_not_met`).
5. On deny or a deny-on-timeout: redirect with `error=access_denied`.

### 5.2 The DBA dashboard

- After a Clerk sign-in (or a dashboard device's sign-in, Stage B), if `sign_in_gates.dashboard`
  is set, the session is **unconfirmed**: every route except the gate flow, sign-out and
  revocation (the panic button must always work) answers 403 `sign_in_gate_required` until the
  gate request settles allow. The confirmation is remembered per Clerk session id (`sid`) or
  dashboard credential until that session ends.
- **Recovery codes** come first: enabling a deny-on-timeout dashboard gate requires that the
  account has 10 one-time recovery codes (shown once, stored hashed). Using one passes the
  dashboard gate, is audited and pushed to every browser, and invalidates that code.
- A recent re-authentication (S8) does not bypass the dashboard gate; it is checked in addition.

### 5.3 Periodic confirmation

- `POST /api/v1/credentials/{id}/confirm` (DPoP from the credential's key) creates a `confirm`
  gate request; `GET …/confirm/{gtr}` returns `pending`, `denied`, or the confirmation JWS.
- SDK and CLI request a new confirmation at 2/3 of `every_s`, early enough for the entry's
  timeout, alongside auto-renewal (S7). `dba status` shows "Confirmed until".
- The dashboard's device page shows each `confirm` credential's last confirmation, how it passed,
  and a "Stop trusting this device now" button (sets `confirmed_until` to now; offer revocation
  for offline audiences).

## 6. Audience policy

An audience's catalog entry may carry a `gates` policy, and its OIDC client a `sign_in_gates`
policy:

```json
{ "action": "cronly:jobs:delete", "description": "Delete a job",
  "gates": { "require": true, "kinds": ["webauthn", "dba-device"], "fail_open": false } }
```

- `require: true`: a grant for this action counts only if it has a gate entry whose gates are all
  of `kinds` (any kind if `kinds` is absent). Checked at issuance (400 `gate_required`, with the
  policy in the error, so the grant builder can add one) and at every `/authorize` (catalog
  changes apply at once to older credentials: reason `gate_required`).
- `fail_open: false`: an allow by timeout counts as deny for this action (`by_timeout_refused`),
  in `/authorize` and in confirmations presented for it.
- The same shape on the OIDC client governs sign-ins; `acr_values` can ask per request.
- **Offline verifiers** must enforce this too, or an ungated credential would pass. The verify
  library (and the Python and Go ports) take `createVerifier({ audience, catalog })` or fetch the
  audience's public catalog (`GET /api/v1/audiences/{name}`, cached like the JWKS) and, for an
  action whose policy requires gates, return `online_required`. For `fail_open: false` they refuse
  confirmations with `by_timeout: true`.
- Account owners can add gates but never remove an audience's requirement or turn its
  `fail_open: false` back on.

## 7. Secrets

- TOTP seeds, Duo secret keys and Okta API tokens are the first customer secrets DBA stores. They
  are sealed with AES-256-GCM under a Worker secret `GATE_SEALING_KEY_<kid>` (rotatable, like
  issuer keys), per-record random nonce, AAD = account id + gate id; stored only in the account's
  DO; never returned after creation, never logged, never in audit details; deleting the gate
  deletes the blob. A runbook entry covers rotating the sealing key and what a leak of it means
  (all sealed secrets must be re-enrolled).
- Webhook services use asymmetric keys in both directions (DBA signs with the issuer key; the
  service registers a public key), so DBA stores no shared secret for them.
- WebAuthn stores public keys only.
- Device private keys still never reach DBA: a `dba-device` gate answers with its own key.

## 8. Security, abuse and visibility

- **Push fatigue**: one waiting request per subject (dedupe), number matching at sign-in, at most
  10 gate requests per (device, gate) per hour (then 429 `gate_rate_limited`; for allow-on-timeout
  entries this is a deny, not a silence, so flooding cannot be used to force the timeout), and a
  "I didn't ask for this" button on deny that also offers to revoke the requesting device.
- **Every allow by timeout** writes `gate.allowed_by_timeout` to the audit log, shows in the
  decision log with its reason, and is announced to the owner's browsers ("cronly:jobs:run was
  allowed because nobody answered within 2 minutes"), batched hourly like other notices.
- **Self-approval** is impossible for every kind: the requester device cannot answer allow for
  its own request (it may deny).
- **Configuration changes** (adding, editing, deleting gates; sign-in gate settings) need a recent
  sign-in (S8) and are announced at once like `dba:*` issuance.
- The credential carries gate ids and kinds only, never labels, phone numbers, usernames or URLs
  (it is shown to every audience).
- The grant builder, approval page, inspector and dashboard render allow-on-timeout entries in a
  warning style with the plain-English meaning: "allowed if nobody answers within 2 minutes".
- Webhook URLs follow the existing rules in `src/services/webhooks.js` (https, public host, no
  credentials or fragment) and have a test button.

## 9. Money

New operations for `src/utils/cost-policy.js` and prices for `src/utils/pricing.js`, each passing
the price-floor test. Proposed shape (numbers come from counting, then owner approval, D13):

| Operation | Worst case to count | Payer |
|-----------|--------------------|-------|
| Gate request, local kinds (`owner`, `dba-device`, `totp`, `webauthn`) | request row + deletion, answer write, notice (push CPU), WebAuthn/TOTP verify CPU, approval-page reads | Account that owns the gates (credential issuer; for sign-in, the signing-in account) |
| Gate request, `webhook` | the above + 1 signed subrequest (+ callback request) | same |
| Gate request, `duo` / `okta-verify` | the above + 1 start + up to 24 status subrequests | same |
| Confirmation | gate request price + a token's signing | same |

Charged per gate actually contacted, when the request is created (reserve the maximum first, as
everywhere). The audience still pays the online decision. Answering is free. A gate request the
owner cannot pay for is not sent and is treated as unreachable (§2). Gate CRUD is a metered write
for API keys and free from the dashboard, like other settings.

## 10. Spec, verifier and tools

- `spec/credential.md`: `confirm` claim; `require.gates`, `require.gates_reuse_s`,
  `require.confirmation`; the `dba-confirmation+jwt` format; the `dba-gate+jwt` webhook format
  (or in `spec/events.md` beside the revocation events).
- `spec/evaluation.md`: §3.6 adds `gates` (online only) and `confirmation`; a new step between
  revocation and grants for the confirmation; new reasons `gate_pending`, `gate_denied`,
  `gate_required`, `by_timeout_refused`, `confirmation_required`, `confirmation_expired`,
  `confirmation_by_timeout_refused`.
- Vectors (all three verifiers): gates offline → `online_required`; step_up and the equivalent
  gates evaluate the same; confirmation present / missing / expired / wrong `cid` / wrong `jkt` /
  bad signature / by-timeout under a `fail_open: false` policy; catalog-required gates offline.
- `@devicebasedauth/verify`: `DBA-Confirmation` header parsing in `verifyRequest`; `catalog`
  option; browser copy and SDK bundle regenerated (`npm run docs:generate`); SDK
  `authorizeWithGates()`, confirmation auto-refresh; new SDK release `vX.Y.Z`.
- CLI: `dba gates list|add|remove|test`, `dba approvals [--watch]` (answer as a `dba-device`
  gate), `dba confirm`, `--wait` on calls that may hit a gate.
- Site: gates page (add TOTP with QR, register a security key, pick a device, webhook with test,
  Duo/Okta forms), approval page, sign-in gate settings, recovery codes; grant builder, inspector
  and playground understand `gates` and `confirm`; audience console edits catalog gate policies.
- Docs: a "Gates" page with CI-executed samples (a webhook approval service in Node and Python,
  answering as a `dba-device` from the CLI, an online check that waits for a gate, an offline
  verifier checking a confirmation); `llms.txt`; MCP tools to list gates and answer as the
  connected account's owner (never as a gate the MCP app could fake).

## 11. Phases

Each phase ends with `npm test`, `npm run lint`, samples and e2e green, docs regenerated, and its
STATUS row updated.

| Phase | Deliverable | Exit criteria |
|-------|-------------|---------------|
| G1 | Spec text and vectors for `require.gates`, `require.confirmation`, confirmations, catalog policy; evaluator in JS, Python, Go | Every new vector passes in all three; step_up ≡ owner gate |
| G2 | Gate registry (`gate:` rows, CRUD routes, scopes `gates:read`/`gates:write`), `gatereq:` engine replacing `stepup:`, `owner` and `dba-device` kinds, `/authorize` integration, timeouts both ways, audit and notices, D13 prices in cost policy | Concurrency tests: one answer settles; timeout allow/deny; deleted gate denies; balance refusal behaves per §2; cost-count test covers the new ops |
| G3 | Audience gate policy: catalog field, issuance check, `/authorize` check, verify library `catalog` option | An ungated grant for a required action is refused online and gets `online_required` offline |
| G4 | `totp` and `webauthn` gates, sealing key, approval page | Playwright: approve with a virtual authenticator and a TOTP code; replayed code refused |
| G5 | `webhook` gate: signed request, sync answer, signed callback | CI sample service approves and denies; unreachable service follows `on_timeout` |
| G6 | Sign-in gates: OIDC consent, number matching, inline factors, `amr`/`acr`/`dba_gates`, dashboard gate, recovery codes | Playwright: OIDC sign-in waits for and passes a gate; `acr_values` enforced; dashboard locked until confirmed; recovery code works once |
| G7 | Periodic confirmation: `confirm` at issuance, confirm endpoints, confirmation JWT, offline check, renew/token/certificate rules, SDK and CLI refresh | e2e: an offline verifier denies after `every_s` without a new confirmation and accepts after one |
| G8 | `duo` and `okta-verify` gates (sealed credentials, polling bounds); confirm whether Microsoft Authenticator push is open to third parties | Tested against recorded vendor responses; live checks are owner steps after L9 |
| G9 | Tools and docs (§10) not already done per phase; SDK release | Every docs sample runs in CI |

## 12. Open questions for later

- k-of-n quorum (`at_least: 2` of a list) beyond all-of / any-of.
- Per-device sign-in gates (e.g. only for the kiosk), in addition to per audience.
- Location- or time-conditioned gates ("approval needed only outside office hours") — today the
  same effect needs two grants.
