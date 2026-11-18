import { b64u, unb64u } from '../packages/verify/src/jose.js';

/**
 * A browser's side of Web Push for tests: a subscription with real keys, and decryption of an
 * aes128gcm message (RFC 8291, RFC 8188).
 */
export async function pushBrowser(endpoint = 'https://fcm.googleapis.com/fcm/send/test-endpoint') {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const auth = crypto.getRandomValues(new Uint8Array(16));
  const subscription = { endpoint, keys: { p256dh: b64u(publicRaw), auth: b64u(auth) } };
  async function decrypt(body) {
    const bytes = new Uint8Array(body);
    const salt = bytes.slice(0, 16);
    const rs = new DataView(bytes.buffer, bytes.byteOffset).getUint32(16);
    const idlen = bytes[20]; const asPublic = bytes.slice(21, 21 + idlen);
    const asKey = await crypto.subtle.importKey('raw', asPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: asKey }, pair.privateKey, 256));
    const hkdf = async (s, ikm, info, n) => new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: s, info }, await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']), n * 8));
    const te = new TextEncoder();
    const join = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
    const ikm = await hkdf(auth, shared, join(te.encode('WebPush: info\0'), publicRaw, asPublic), 32);
    const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16);
    const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12);
    const record = bytes.slice(21 + idlen);
    if (record.length > rs) throw new Error('more than one record');
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']), record));
    let end = plain.length - 1; while (end >= 0 && plain[end] === 0) end--;
    if (plain[end] !== 2) throw new Error('missing last-record delimiter');
    return JSON.parse(new TextDecoder().decode(plain.slice(0, end)));
  }
  return { subscription, decrypt, unb64u };
}

/** A fake push service recording what it receives; `status(endpoint)` picks each reply. */
export function pushService(status = () => 201) {
  const sent = [];
  const fetch = async (url, init) => { sent.push({ url, init }); return new Response(null, { status: status(url) }); };
  return { sent, fetch };
}
