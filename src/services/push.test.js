import { describe, it, expect } from 'vitest';
import { cleanSubscription, encryptMessage, nextNotice, noticeText, sendNotice, NOTICE_INTERVAL_MS } from './push.js';
import { pushBrowser, pushService } from '../../test-utils/push.js';
import { unb64u, b64u } from '../../packages/verify/src/jose.js';

const env = { ENVIRONMENT: 'production', APP_ORIGIN: 'https://devicebasedauth.org' };

describe('push subscriptions', () => {
  it('accepts the push services of common browsers and nothing else', async () => {
    const { subscription } = await pushBrowser();
    for (const endpoint of ['https://fcm.googleapis.com/fcm/send/x', 'https://updates.push.services.mozilla.com/wpush/v2/x', 'https://web.push.apple.com/QG/x', 'https://wns2-by3p.notify.windows.com/w/?token=x']) {
      expect(cleanSubscription({ ...subscription, endpoint }, env).endpoint).toBe(endpoint);
    }
    for (const endpoint of ['https://evil.example/x', 'http://fcm.googleapis.com/x', 'https://fcm.googleapis.com:8443/x', 'https://u:p@fcm.googleapis.com/x', 'https://fcm.googleapis.com.evil.example/x', 'https://notify.windows.com.evil.example/x', 'http://localhost:9000/x', 'not a url']) {
      expect(() => cleanSubscription({ ...subscription, endpoint }, env), endpoint).toThrow(/subscription/);
    }
    expect(cleanSubscription({ ...subscription, endpoint: 'http://localhost:9000/x' }, { ENVIRONMENT: 'local' }).endpoint).toBe('http://localhost:9000/x');
  });

  it('checks the browser keys', async () => {
    const { subscription } = await pushBrowser();
    expect(() => cleanSubscription({ ...subscription, keys: { ...subscription.keys, auth: b64u(new Uint8Array(15)) } }, env)).toThrow(/auth/);
    expect(() => cleanSubscription({ ...subscription, keys: { ...subscription.keys, p256dh: b64u(new Uint8Array(65)) } }, env)).toThrow(/p256dh/);
    expect(() => cleanSubscription({ ...subscription, keys: { p256dh: 'not base64!', auth: subscription.keys.auth } }, env)).toThrow(/p256dh/);
    expect(() => cleanSubscription(null, env)).toThrow(/subscription/);
  });
});

describe('message encryption (RFC 8291)', () => {
  it('encrypts so only the subscribed browser can read it', async () => {
    const browser = await pushBrowser();
    const body = await encryptMessage(browser.subscription, JSON.stringify({ title: 'hi', body: 'there' }));
    expect(new DataView(body.buffer).getUint32(16)).toBe(4096);
    expect(body[20]).toBe(65);
    expect(await browser.decrypt(body)).toEqual({ title: 'hi', body: 'there' });
    const other = await pushBrowser();
    await expect(other.decrypt(body)).rejects.toThrow();
  });

  it('matches the worked example of RFC 8291 §5', async () => {
    // Appendix A of RFC 8291: fixed keys and salt give a fixed message.
    const fromB64u = s => unb64u(s);
    const asRaw = fromB64u('BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8');
    const asPublic = { kty: 'EC', crv: 'P-256', x: b64u(asRaw.slice(1, 33)), y: b64u(asRaw.slice(33)) };
    const asPrivate = { ...asPublic, d: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw' };
    const ephemeral = { privateKey: await crypto.subtle.importKey('jwk', asPrivate, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']), publicKey: await crypto.subtle.importKey('jwk', asPublic, { name: 'ECDH', namedCurve: 'P-256' }, true, []) };
    const subscription = { endpoint: 'https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV', keys: { p256dh: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4', auth: 'BTBZMqHH6r4Tts7J_aSIgg' } };
    const body = await encryptMessage(subscription, 'When I grow up, I want to be a watermelon', { ephemeral, salt: fromB64u('DGv6ra1nlYgDCS1FRnbzlw') });
    expect(b64u(body)).toBe('DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN');
  });
});

describe('sending', () => {
  it('posts an encrypted, VAPID-signed message', async () => {
    const browser = await pushBrowser();
    const service = pushService();
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const result = await sendNotice({ ...env, PUSH_VAPID_KEY: JSON.stringify(jwk), PUSH_FETCH: service.fetch }, browser.subscription, { title: 'T', body: 'B', tag: 'cred-crd_1' });
    expect(result).toMatchObject({ ok: true, status: 201, gone: false });
    const { url, init } = service.sent[0];
    expect(url).toBe(browser.subscription.endpoint);
    expect(init.headers).toMatchObject({ 'Content-Encoding': 'aes128gcm', TTL: '86400', Urgency: 'high' });
    expect(init.headers.Topic).toBeUndefined();
    expect(await browser.decrypt(init.body)).toEqual({ title: 'T', body: 'B', tag: 'cred-crd_1' });
    const [, t, k] = init.headers.Authorization.match(/^vapid t=([^,]+), k=(.+)$/);
    expect(unb64u(k)).toHaveLength(65);
    const [h, p, s] = t.split('.');
    expect(JSON.parse(new TextDecoder().decode(unb64u(p)))).toMatchObject({ aud: 'https://fcm.googleapis.com', sub: 'https://devicebasedauth.org' });
    expect(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, unb64u(s), new TextEncoder().encode(`${h}.${p}`))).toBe(true);
  });

  it('reports browsers that unsubscribed, and never throws', async () => {
    const browser = await pushBrowser();
    const local = { ENVIRONMENT: 'local' };
    expect(await sendNotice({ ...local, PUSH_FETCH: pushService(() => 410).fetch }, browser.subscription, { title: 'T', body: 'B' })).toMatchObject({ ok: false, gone: true });
    expect(await sendNotice({ ...local, PUSH_FETCH: async () => { throw new TypeError('down'); } }, browser.subscription, { title: 'T', body: 'B' })).toMatchObject({ ok: false, error: 'network_error' });
    expect(await sendNotice({ ENVIRONMENT: 'production' }, browser.subscription, { title: 'T', body: 'B' })).toMatchObject({ ok: false, error: 'push_unavailable' });
  });
});

describe('notice coalescing', () => {
  it('announces at most one ordinary issuance an hour, counting those held back, and urgent ones always', () => {
    const state = {}; const t = 1_000_000;
    expect(nextNotice(state, t, false)).toBe(1);
    expect(nextNotice(state, t + 1, false)).toBe(0);
    expect(nextNotice(state, t + 2, false)).toBe(0);
    expect(nextNotice(state, t + 3, true)).toBe(3);
    expect(nextNotice(state, t + 4, false)).toBe(0);
    expect(nextNotice(state, t + 3 + NOTICE_INTERVAL_MS, false)).toBe(2);
  });

  it('cleans untrusted text', () => {
    expect(noticeText('a\u0000b‮c'.padEnd(100, 'x'))).toBe('abc'.padEnd(64, 'x'));
  });
});
