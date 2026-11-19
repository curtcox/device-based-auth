# Runbook: issuer signing key compromise

The issuer key signs every credential, access token, status list and ID token. Whoever holds it
can mint credentials that every verifier accepts until the key leaves the JWKS.

1. **Generate a new key** (`node scripts/generate-issuer-key.mjs dba-YYYY-MM-incident`). Set
   `DBA_ISSUER_KEYS` to the new key **first**, followed by the compromised key marked
   `"withdrawn": true` (drop any other keys you also distrust the same way). Redeploy. The new key
   signs; the JWKS and `/.well-known/dba-ca.pem` omit the withdrawn `kid`, so every credential it
   signed fails with `unknown_kid` once verifier caches expire (≤ 1 hour with the default
   `jwksTtl`; a verifier refetches on an unknown kid, at most once every 30 seconds, so credentials
   from the new key may be refused for up to 30 seconds by a verifier that fetched just before).
2. **Recovery renewal (mass force-renew)**: devices do not re-enroll. `POST
   /api/v1/credentials/{cid}/renew` still accepts a credential signed by a withdrawn key, but only
   when the account's registry holds that exact credential byte for byte (so anything the attacker
   minted, even reusing a real `cid`, is refused with `unknown_credential`), it is unrevoked and
   unexpired, and the DPoP proof comes from its key. The result is signed by the new key, keeps
   `cid` and the status index, is free and does not count against renewal caps (audit event
   `credential.recovered`). Every other API answers a withdrawn-key credential with 401
   `reissue_required`. The browser SDK's `autoRenew()` and the CLI (within an hour, on its next
   use of the credential) notice the missing `kid` in the JWKS and renew by themselves; other
   clients should renew when they see `reissue_required` or `unknown_kid`. Credentials that expire
   before their device comes back need a new enrollment. Announce the incident on the status page
   and email account owners.
3. **Status lists** are re-signed by the new key at the next publish (hourly cron, or any
   revocation). Trigger it by revoking a throwaway credential if needed.
4. **Investigate** how the secret leaked (GitHub secret access logs, Cloudflare audit log), rotate
   `DBA_TOKEN_SIGNING_KEY` too if the same path could expose it (that invalidates API keys,
   pending enrollments and OIDC codes; users create new API keys).
5. **Remove the withdrawn key** from `DBA_ISSUER_KEYS` once the longest credential lifetime
   (400 days at most; check `max(exp)` in the audit trail) has passed. Until then keep it: without
   it, recovery renewal is impossible.
6. Record the incident in `STATUS.md` and the audit trail.

Prevention: STATUS S6 (keep the issuer key in an external KMS/HSM so the Worker never holds it).
