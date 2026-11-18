# Runbook: issuer signing key compromise

The issuer key signs every credential, access token, status list and ID token. Whoever holds it
can mint credentials that every verifier accepts until the key leaves the JWKS.

1. **Generate a new key** (`node scripts/generate-issuer-key.mjs dba-YYYY-MM-incident`) and set
   `DBA_ISSUER_KEYS` to a list containing **only** the new key. Redeploy. The JWKS now omits the
   compromised `kid`, so every credential it signed fails with `unknown_kid` once verifier caches
   expire (≤ 1 hour with the default `jwksTtl`; verifiers refetch immediately on an unknown kid).
2. **Re-issue**: every legitimate credential was signed by the old key and is now invalid. Devices
   cannot renew (renewal requires a valid credential), so owners must re-enroll. Announce this on
   the status page and email account owners.
3. **Status lists** are re-signed by the new key at the next publish (hourly cron, or any
   revocation). Trigger it by revoking a throwaway credential if needed.
4. **Investigate** how the secret leaked (GitHub secret access logs, Cloudflare audit log), rotate
   `DBA_TOKEN_SIGNING_KEY` too if the same path could expose it (that invalidates API keys,
   pending enrollments and OIDC codes; users create new API keys).
5. Record the incident in `STATUS.md` and the audit trail.

Prevention: STATUS S6 (keep the issuer key in an external KMS/HSM so the Worker never holds it).
