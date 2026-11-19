/**
 * A software FIDO2 authenticator for tests: makes ES256 credentials and assertions the way a
 * security key does (WebAuthn §6.1 authenticator data, CBOR attestation object with fmt "none").
 */
import { b64u, unb64u } from '../packages/verify/src/jose.js';

const encoder = new TextEncoder();

/** Minimal CBOR encoder: unsigned/negative integers, byte strings, text, arrays and Maps. */
export function encodeCbor(value) {
  const head = (major, n) => n < 24 ? [major << 5 | n] : n < 256 ? [major << 5 | 24, n] : n < 65536 ? [major << 5 | 25, n >> 8, n & 255] : [major << 5 | 26, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255];
  const out = [];
  const put = v => {
    if (typeof v === 'number') out.push(...(v >= 0 ? head(0, v) : head(1, -1 - v)));
    else if (v instanceof Uint8Array) { out.push(...head(2, v.length), ...v); }
    else if (typeof v === 'string') { const b = encoder.encode(v); out.push(...head(3, b.length), ...b); }
    else if (Array.isArray(v)) { out.push(...head(4, v.length)); v.forEach(put); }
    else if (v instanceof Map) { out.push(...head(5, v.size)); for (const [k, x] of v) { put(k); put(x); } }
    else throw new Error(`cannot encode ${v}`);
  };
  put(value);
  return new Uint8Array(out);
}

/** Raw r‖s (64 bytes) → ASN.1 DER, as authenticators sign. */
function rawToDer(raw) {
  const int = bytes => { let i = 0; while (i < bytes.length - 1 && bytes[i] === 0) i++; let v = bytes.slice(i); if (v[0] & 0x80) v = new Uint8Array([0, ...v]); return [0x02, v.length, ...v]; };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}

const sha256 = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof bytes === 'string' ? encoder.encode(bytes) : bytes));

export async function softAuthenticator({ uv = true } = {}) {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const id = crypto.getRandomValues(new Uint8Array(32));
  let counter = 0;
  const flags = (attested) => 0x01 | (uv ? 0x04 : 0) | (attested ? 0x40 : 0);
  const data = async (rpId, attested) => {
    const count = new Uint8Array(4); new DataView(count.buffer).setUint32(0, counter);
    const parts = [...await sha256(rpId), flags(attested), ...count];
    if (attested) {
      const cose = encodeCbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, unb64u(jwk.x)], [-3, unb64u(jwk.y)]]));
      parts.push(...new Uint8Array(16), id.length >> 8, id.length & 255, ...id, ...cose);
    }
    return new Uint8Array(parts);
  };
  const client = (type, challenge, origin) => b64u(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  return {
    id: b64u(id),
    /** navigator.credentials.create, JSON-encoded the way the dashboard sends it. */
    async register(options, origin) {
      const attestationObject = encodeCbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', await data(options.rp.id, true)]]));
      return { clientDataJSON: client('webauthn.create', options.challenge, origin), attestationObject: b64u(attestationObject) };
    },
    /** navigator.credentials.get for one challenge. */
    async assert({ challenge, rpId }, origin, { tamperCounter } = {}) {
      counter = tamperCounter ?? counter + 1;
      const authenticatorData = await data(rpId, false);
      const clientDataJSON = client('webauthn.get', challenge, origin);
      const signed = new Uint8Array([...authenticatorData, ...await sha256(unb64u(clientDataJSON))]);
      const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, signed));
      return { credential_id: b64u(id), clientDataJSON, authenticatorData: b64u(authenticatorData), signature: b64u(rawToDer(raw)) };
    }
  };
}
