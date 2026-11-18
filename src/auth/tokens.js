// HMAC-signed, self-routing tokens (ported from cronly's crypto.js / hashbin's signed keys):
// the payload names its account, so no lookup table is needed to route it.
import { b64u, unb64u } from '../../packages/verify/src/jose.js';
const encoder = new TextEncoder();

/** SHA-256 digest of a string, base64url. Credentials are stored only as digests. */
export async function digest(value) { return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)))); }

async function hmacKey(secret) { return crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']); }

/** Sign a payload into "<prefix><body>.<tag>". */
export async function signToken(prefix, payload, secret) {
  if (!secret) throw new Error('Missing signing key');
  const body = b64u(JSON.stringify(payload));
  const tag = await crypto.subtle.sign('HMAC', await hmacKey(secret), encoder.encode(`${prefix}${body}`));
  return `${prefix}${body}.${b64u(new Uint8Array(tag))}`;
}

/** Verify and decode a signed token; null when invalid or expired (payload.exp in seconds). */
export async function verifyToken(token, prefix, secret, maxLength = 16384) {
  try {
    if (!secret || typeof token !== 'string' || token.length > maxLength || !token.startsWith(prefix)) return null;
    const [body, tag, extra] = token.slice(prefix.length).split('.');
    if (extra !== undefined || !await crypto.subtle.verify('HMAC', await hmacKey(secret), unb64u(tag), encoder.encode(`${prefix}${body}`))) return null;
    const payload = JSON.parse(new TextDecoder().decode(unb64u(body)));
    if (payload.exp !== undefined && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
