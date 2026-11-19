/**
 * Sealing for the customer secrets gates need (TOTP seeds now; Duo and Okta keys later), STATUS
 * B7 / todo/additional_gates.md §7. AES-256-GCM under a Worker secret, GATE_SEALING_KEYS: a JSON
 * list of { kid, key } (key: 32 random bytes, base64), the first one sealing and every one
 * unsealing, so a key can be rotated by putting a new one first and re-sealing at leisure.
 * Each blob has its own random nonce and is bound (AAD) to the account and gate it belongs to, so
 * a blob copied to another gate or account does not open. Sealed blobs live only in the account's
 * Durable Object and are never returned, logged or put in audit details.
 */
import { b64u, unb64u } from '../../packages/verify/src/jose.js';

const encoder = new TextEncoder();
let cache = { source: null, keys: [] };

async function keys(env) {
  if (cache.source !== env.GATE_SEALING_KEYS) {
    let list;
    try { list = JSON.parse(env.GATE_SEALING_KEYS || '[]'); } catch { list = []; }
    if (!Array.isArray(list) || !list.length) throw new Error('GATE_SEALING_KEYS is missing or invalid');
    const imported = [];
    for (const { kid, key } of list) {
      const raw = Uint8Array.from(atob(String(key)), c => c.charCodeAt(0));
      if (typeof kid !== 'string' || raw.length !== 32) throw new Error('GATE_SEALING_KEYS entries need a kid and a 32-byte base64 key');
      imported.push({ kid, key: await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']) });
    }
    cache = { source: env.GATE_SEALING_KEYS, keys: imported };
  }
  return cache.keys;
}

const aad = (account, gateId) => encoder.encode(`dba-gate-secret\n${account}\n${gateId}`);

/** Seal bytes for one gate of one account: { kid, iv, ct } (base64url). */
export async function seal(env, { account, gateId }, bytes) {
  const [active] = await keys(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(account, gateId) }, active.key, bytes));
  return { kid: active.kid, iv: b64u(iv), ct: b64u(ct) };
}

/** Open a sealed blob; throws when the key is unknown or the blob belongs elsewhere. */
export async function unseal(env, { account, gateId }, blob) {
  const key = (await keys(env)).find(k => k.kid === blob?.kid);
  if (!key) throw new Error(`gate sealing key ${blob?.kid} is not configured`);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64u(blob.iv), additionalData: aad(account, gateId) }, key.key, unb64u(blob.ct)));
}
