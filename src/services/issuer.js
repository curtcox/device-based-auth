import { issuerSigner, jwksFor } from '../../packages/verify/src/issuer.js';
import { DEFAULT_ISSUER } from '../../packages/verify/src/credential.js';

let cache = { source: null, keys: null, signer: null };

/**
 * Issuer signing keys come from the ISSUER_KEYS secret: a JSON list of
 * { kid, jwk (private P-256), retired?: true, withdrawn?: true }. The first key that is neither
 * retired nor withdrawn signs. Retired keys stay in the JWKS so credentials signed before a routine
 * rotation keep verifying. Withdrawn keys (compromised: docs/ops/issuer-key-compromise.md) are
 * trusted nowhere, except that a device may renew a credential they signed when the account's
 * registry holds that exact credential (recovery renewal, master plan §10 "mass force-renew").
 */
export function issuerKeys(env) {
  if (cache.source !== env.ISSUER_KEYS) {
    let keys;
    try { keys = JSON.parse(env.ISSUER_KEYS || '[]'); } catch { keys = []; }
    if (!Array.isArray(keys) || !keys.length || keys.some(k => typeof k.kid !== 'string' || !k.jwk?.d)) throw new Error('ISSUER_KEYS is missing or invalid');
    cache = { source: env.ISSUER_KEYS, keys, signer: null };
  }
  return cache.keys;
}

/** The current signing key. */
export async function activeSigner(env) {
  const keys = issuerKeys(env);
  if (!cache.signer) {
    const active = keys.find(k => !k.retired && !k.withdrawn);
    if (!active) throw new Error('No active issuer key');
    cache.signer = await issuerSigner(active);
  }
  return cache.signer;
}

/** Keys verifiers may trust: every configured key except withdrawn ones. */
export function trustedIssuerKeys(env) { return issuerKeys(env).filter(k => !k.withdrawn); }

/** Public JWKS for every trusted key. */
export function jwks(env) { return jwksFor(trustedIssuerKeys(env)); }

/** JWKS of withdrawn keys: only for recognizing credentials that need a recovery renewal. */
export function withdrawnJwks(env) { return jwksFor(issuerKeys(env).filter(k => k.withdrawn)); }

/** The `iss` claim: https://devicebasedauth.org in production, the local origin in development. */
export function issuerName(env) { return env.ISSUER || DEFAULT_ISSUER; }

/** This service's own audience name. */
export function appAudience(env) { return env.APP_AUDIENCE || 'devicebasedauth.org'; }

/** Where a shard's status list is published. */
export function statusUri(env, shard) { return `${env.STATUS_ORIGIN || 'https://status.devicebasedauth.org'}/v1/lists/${shard}`; }
