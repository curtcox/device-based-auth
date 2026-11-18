import { issuerSigner, jwksFor } from '../../packages/verify/src/issuer.js';
import { DEFAULT_ISSUER } from '../../packages/verify/src/credential.js';

let cache = { source: null, keys: null, signer: null };

/**
 * Issuer signing keys come from the ISSUER_KEYS secret: a JSON list of
 * { kid, jwk (private P-256), retired?: true }. The first non-retired key signs; every
 * listed key is published in the JWKS so credentials signed before a rotation keep verifying.
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
    const active = keys.find(k => !k.retired);
    if (!active) throw new Error('No active issuer key');
    cache.signer = await issuerSigner(active);
  }
  return cache.signer;
}

/** Public JWKS for every configured key. */
export function jwks(env) { return jwksFor(issuerKeys(env)); }

/** The `iss` claim: https://devicebasedauth.org in production, the local origin in development. */
export function issuerName(env) { return env.ISSUER || DEFAULT_ISSUER; }

/** This service's own audience name. */
export function appAudience(env) { return env.APP_AUDIENCE || 'devicebasedauth.org'; }

/** Where a shard's status list is published. */
export function statusUri(env, shard) { return `${env.STATUS_ORIGIN || 'https://status.devicebasedauth.org'}/v1/lists/${shard}`; }
