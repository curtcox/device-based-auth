# Security review log (STATUS L12)

Findings from reviewing issuance, revocation and verification, and the fix for each. Every fix
has a test and its commit mentions L12. STATUS L12 holds the overall state; this file keeps the
detail. Add new findings to the end of "Found and fixed", and keep "Known limits" true to the code.

## Standing measures

- Self-review of issuance, revocation, delegation and verification done; an **independent review
  is still needed** (STATUS L12).
- Budget guards in the dashboard: daily issuance limit and per-credential monthly renewal cap
  (master plan §5.4, §10).
- HMAC-signed tokens (`dbae_`, `dbamcp_`, poll tokens…) accept only the canonical base64url tag, so
  no token has a second valid spelling.
- DPoP proofs to DBA's own API are accepted once per account, and an account object that started
  less than 60 s ago requires its own DPoP nonce (below, D15).

## Found and fixed

- **Idempotent issuance.** A repeated `Idempotency-Key` on `POST /credentials` (or two approvals of
  one enrollment racing) issued a second, unpaid credential outside the daily limit. A retry
  returns the first credential, a different request with the same key gets 422
  `idempotency_key_reused`, and OpenAPI lists the header only on routes that honour it.
- **Revoked devices.** Issuing to a revoked device's key reinstated it on every path, so a stolen,
  revoked device holding a fleet token could re-enroll itself. Only a person with a recent sign-in
  (or an API key) reinstates (`device.reinstated` audited); token redemption and delegation get
  403 `device_revoked` (master plan §10). Rotating a credential onto a revoked device's key gets 403
  `device_revoked`, and onto another live device's key 409 `key_in_use` (it overwrote that device's
  record).
- **Rotated-away keys.** After a key rotation the old version (old key) still passed online
  `/authorize`, which checked only `revoked_at`, and DBA's own API whenever the new status entry
  reused the old index in another shard (indexes are per shard; the check compared the index
  alone). Both compare the (index, list URI) pair.
- **Access tokens and exhausted grants.** Online `/authorize` refuses access tokens when the
  audience sets `accept_access_tokens: false`, and a grant out of uses does not spend (or ask for) a
  step-up approval.
- **DPoP replay on DBA's API.** Proofs were checked for method, URL and age but not reuse, and DPoP
  does not sign the body, so captured headers could be replayed within the proof window with
  another body (say, delegating a credential to the captor's key). Each proof is accepted once per
  account (401 `replayed_proof`).
- **`dba:*` grants with online limits.** DBA's API evaluated a device's `dba:*` grants with
  `online: true` but did not enforce the usage counters or step-up approvals that returns, so a
  `dba:credentials:issue` grant limited to 3 uses a day (or needing approval) was unlimited. Such
  grants do not count there, and issuance refuses `limits.uses`/`require.step_up` on grants with
  `dba:` actions (400 `invalid_grants`).
- **OIDC redirect URIs.** Any scheme whose host was `localhost` passed, so an audience owner could
  register `javascript://localhost/…`, and the consent page (which follows the redirect even on
  Cancel) would run their script on devicebasedauth.org with the victim's session. Redirect URIs
  follow the MCP clients' rule (https, or http on a loopback address; no fragment or credentials),
  `/oauth/authorize` refuses other schemes for records stored earlier, the consent page follows
  only http(s) addresses, and enrollment `return_origin` allows http only on localhost.
  `/oauth/userinfo` does not answer for MCP apps' access tokens.
- **Narrow API keys granting `dba:` scopes.** A key (or MCP app) with only `credentials:issue`
  could issue a credential or enrollment token granting `dba:session` (or any `dba:` scope), so a
  narrow CI key became a device with every scope. Keys grant `dba:` actions only within their own
  scopes, named exactly (403 `insufficient_scope`).
- **JWKS refetch amplification.** The relying-party verifiers (JS, Python, Go) refetched the JWKS on
  every credential with an unknown `kid`, so anyone could make a site fetch DBA's JWKS once per
  request. A forced refetch happens at most once per 30 s (`jwksCooldown` / `jwks_cooldown` /
  `JWKSCooldown`).
- **Audience reads and delegation depth.** `GET /audiences?mine=1` (a public route that
  authenticates itself) skipped the `audiences:read` scope check and read metering, so any key or
  `dba:` device read its audiences' full records, webhook URLs included, for free. Delegation is one
  level deep as master plan §13 says (a delegated credential holding `dba:credentials:issue` could
  delegate again; 403 `delegation_depth`).
- **Usage limits multiplied.** `limits.uses` counters in online `/authorize` were per credential
  and grant index: each delegated credential (which must copy its parent's limit) got a fresh
  counter, so a device limited to 3 uses a day could delegate itself any number more, and an
  access token (which keeps only its audience's grants, so its indexes shift) spent another grant's
  counter or a fresh one. Delegates spend the parent grant's counter (`usage_from`, recorded at
  issuance) and token indexes map back to the credential's (`src/usage-limits.test.js`,
  spec/evaluation.md §3.5).
- **Self-approval.** Step-up approval routes accept dashboard devices (`dba:session`), so a
  credential holding both `dba:session` and a `require.step_up` grant approved its own requests. A
  device cannot approve a request it made (403 `self_approval`; it may still deny).
- **Negative location accuracy.** A device-reported location with a negative `acc_m` shrank the
  distance instead of widening it, so `acc_m: -1e7` matched any `where.source: "device"` area.
  Negative accuracy never matches, like a missing one (JS, Python, Go; vector "negative device
  accuracy never matches").
- **Delegated audiences.** A delegating device could name audiences its own credential lacked
  (enrollment tokens already refused this), so a delegate could identify the account to a site its
  delegator could not reach. Delegated `aud` must be within the delegator's (403 `not_narrower`).
- **Stale status lists.** The relying-party verifiers (JS, Python, Go) accepted a status list with
  no `exp` and took each refetched list as is, so a stale CDN copy from before a revocation brought
  the credential back until the next refetch. Lists must carry `exp`, and every bit a verifier has
  seen set stays set (the issuer never clears one; spec/credential.md §7).
- **`dba curl` exposed its headers.** The credential and DPoP proof were on curl's command line,
  where any local user can read them (ps), and since DPoP does not sign the body, the proof could be
  raced to the same URL with another body. The headers go through a private 0600 file
  (`-H @file`, curl 7.55+).
- **TPM attestation chains** (found by an independent review of the attestation code). The chain
  check verified only signatures, so one genuine Microsoft-issued AIK (a restricted TPM key signs
  any data not starting `TPM_GENERATED`, a TBSCertificate included) could issue a certificate for a
  software key and get it attested `security_level: tpm`, satisfying `require.attestation:
  hardware`. Every certificate above the leaf must be a CA (basicConstraints cA, keyCertSign when
  keyUsage is present, pathLenConstraint; `requireCaChain`, also applied to Android chains as
  defense in depth), and the AIK certificate must carry basicConstraints with cA false (WebAuthn
  §8.3.1). A malformed basicConstraints in `ek_chain` answers 400, not 500.
- **Recovery caps reset by eviction.** The hourly caps on recoveries anyone may start (three by
  gate and three by email per account, each pushing or emailing the owner and possibly charging
  them a gate request or an email) were counted in the account object's memory, which starts from
  zero whenever the object is evicted after a short idle, so a stranger who paused between bursts
  could flood an owner and drain their balance. The counts are on the profile row
  (`src/recovery.test.js`, `src/email-recovery.test.js` restart the object between starts).
- **DPoP replay after a restart (D15).** DBA's own API checked each proof once against a cache in
  the account object's memory, which is empty whenever the object starts (an eviction after
  70–140 s idle, a deploy, a move); a proof is accepted for up to 120 s after its `iat`, so a
  captured proof and credential could be sent once more, with another body, after a restart. For
  its first 60 s an object requires its own nonce (RFC 9449 §8) in every proof whose `iat` is
  earlier than 60 s after its start, which no earlier object could have accepted, answering 401
  `use_dpop_nonce` with `DPoP-Nonce`. The browser SDK (v1.4.0 and later), the dashboard, the CLI
  and the samples answer it, and the extra round trip is counted in the prices it affects
  (`src/dpop-nonce.test.js`, `src/cost-counts.test.js`, every CI sample after a forced restart).

## Known limits

- **A stolen `dba:session` device is as strong as the owner's session.** It can issue itself a new
  non-`dba:` credential without step-up; only `dba:*` issuance (and API keys, enrollment tokens and
  raised limits) needs a recent sign-in.
- **Online `/authorize` keeps its replay cache in memory.** A DPoP proof is accepted for up to
  120 s after its `iat` (`PROOF_MAX_AGE` 60 s plus `CLOCK_SKEW` 60 s), and the account's object
  forgets the proofs it saw when it starts (after 70–140 s idle, a deploy, a move), so a captured
  proof can be replayed once, after a restart, to a site that relies on `/authorize` alone. DBA's own API closes
  that gap with server nonces (D15); `/authorize` does not, because the nonce would have to travel
  back through the site (a `use_dpop_nonce` decision the site relays as a 401 with `DPoP-Nonce`,
  which the browser SDK v1.4.0 already answers) and every denial is billed to the site as a
  decision, so each challenge would cost it an extra 15 µ$. A site that also checks proofs with its
  own replay cache (`durableReplayCache`, B4) is not exposed. Whether to add the relay and how to
  bill it is the owner's decision.
- **Some limits are in memory on purpose.** The per-account request rate limit, new gate requests
  per device and gate, and wrong TOTP or security-key answers per gate are kept in the account
  object's memory and reset when it starts: their callers are the owner's own devices, or the
  requests are paid for. Caps on what strangers can start (anonymous recoveries) are in storage.
- **Older browser SDKs.** SDK versions before v1.4.0 do not answer a DPoP nonce challenge, so their
  first requests after an account object starts fail (D15).
- **Issuer key withdrawal leaves status lists signed by the old key for up to about 12 hours**
  (docs/ops/issuer-key-compromise.md step 3): there is no command to re-sign every shard at once.
- **The JS verifier trusts `CF-Connecting-IP` by default.** Unless the caller passes
  `check.location.network`, `createVerifier` takes the client address (for `net.client` address
  rules and network location) from that header, which only Cloudflare guarantees. A verifier running
  elsewhere must strip it at its edge or pass the address itself; the Python port has the same
  default, the Go port makes the caller choose. A `trustProxies`-style option is not built (B10).
