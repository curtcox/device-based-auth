# Runbook: issuer signing key compromise

The issuer key signs every credential, access token (including connected MCP apps'),
confirmation, X.509 client certificate, status list, address list, ID token, revocation webhook
event and webhook-gate request. Whoever holds it can mint credentials that every verifier
accepts until the key leaves the JWKS.

`DBA_ISSUER_KEYS` (Worker secret `ISSUER_KEYS`) is a JSON list of
`{ kid, jwk, retired?: true, withdrawn?: true }` (`src/services/issuer.js`). The first entry that is
neither retired nor withdrawn signs. Retired keys stay in the JWKS (routine rotation); withdrawn
keys are trusted nowhere, except for the recovery renewal in step 2.

1. **Generate a new key** (`node scripts/generate-issuer-key.mjs dba-YYYY-MM-incident`). Set
   `DBA_ISSUER_KEYS` to the new key **first**, followed by the compromised key marked
   `"withdrawn": true` (mark any other key you also distrust the same way). Push to `main` or run
   the deploy workflow; `check-deployment-secrets.mjs` refuses a list with no active key. The new
   key signs; the JWKS and `/.well-known/dba-ca.pem` omit the withdrawn `kid`, so everything it
   signed fails with `unknown_kid` once verifier caches expire (≤ 1 hour with the default
   `jwksTtl`; a verifier refetches on an unknown kid, at most once every 30 seconds
   (`jwksCooldown`), so credentials from the new key may be refused for up to 30 seconds by a
   verifier that fetched just before).
2. **Recovery renewal (mass force-renew)**: devices do not re-enroll. `POST
   /api/v1/credentials/{cid}/renew` still accepts a credential signed by a withdrawn key, but only
   when the account's registry holds that exact credential byte for byte (so anything the attacker
   minted, even reusing a real `cid`, is refused with `unknown_credential`), it is unrevoked and
   unexpired, it is the current version, and the DPoP proof comes from its key. The result is
   signed by the new key, keeps `cid` and the status index, and, unless it also rotates the key,
   is free and does not count against renewal caps (audit event `credential.recovered`). Every
   other API answers a withdrawn-key credential with 401 `reissue_required` (naming the renew
   URL). The browser SDK's `autoRenew()` and the CLI (within an hour, on its next use of the
   credential) notice the missing `kid` in the JWKS and renew by themselves; other clients should
   renew when they see `reissue_required` or `unknown_kid`. Credentials that expire before their
   device comes back need a new enrollment. Announce the incident on the status page and email
   account owners.
3. **Status lists** are re-signed by the new key when they are next published: the hourly cron
   re-signs every shard last published more than 12 hours ago, and a revocation re-signs its own
   shard about 30 seconds later. There is no command that re-signs every shard at once, so for up
   to about 12 hours some lists are still signed by the withdrawn key and verifiers that fetch them
   fail their status check with `unknown_kid`. Revoking a throwaway credential re-signs only the
   shard it was allocated from. Named address lists are re-signed on their own schedule (every 20
   hours, or when changed).
4. **Investigate** how the secret leaked (GitHub secret access logs, Cloudflare audit log). If the
   same path could expose `DBA_TOKEN_SIGNING_KEY`, rotate it too. That HMAC key signs API keys,
   enrollment tokens, enrollment tickets and poll tokens, sign-up and recovery tickets, OIDC codes,
   MCP app client ids and refresh tokens, gate links and email links, so all of them stop working:
   owners create new API keys and enrollment tokens, and connected MCP apps must connect again.
5. **Remove the withdrawn key** from `DBA_ISSUER_KEYS` once the longest credential lifetime
   (400 days at most; check `max(exp)` in the audit trail) has passed. Until then keep it: without
   it, recovery renewal is impossible.
6. Record the incident in `STATUS.md` and the audit trail.

Prevention: STATUS S6 (keep the issuer key in an external KMS/HSM so the Worker never holds it).
