import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DBA } from './dba.js';
import { generateKeyPair, signCredential, issuerSigner } from '../verify/src/index.js';

/** A DBA instance holding a credential with the given lifetime, signed by key `kid`. */
async function holding({ lifetime, kid = 'k1' }) {
  const pair = await generateKeyPair(true);
  const signer = await issuerSigner({ kid, jwk: await crypto.subtle.exportKey('jwk', pair.privateKey) });
  const issue = () => {
    const iat = Math.floor(Date.now() / 1000);
    const payload = { iss: 'https://devicebasedauth.org', sub: 'dev_12345678', acct: 'a', aud: ['example.com'], cid: 'crd_12345678', jti: 'crd_12345678.1', iat, nbf: iat, exp: iat + lifetime, cnf: { jkt: 'x'.repeat(43) }, device: { name: 'd', kind: 'browser', key_protection: 'software' }, grants: [{ actions: ['example:read'] }], status: { status_list: { idx: 1, uri: 'https://status.devicebasedauth.org/v1/lists/0' } }, ver: 1 };
    return signCredential(payload, signer);
  };
  const dba = new DBA();
  dba.state = { credential: await issue() };
  // Like the real renew(): a fresh credential from the (now current) key.
  dba.renew = vi.fn(async () => { dba.state = { credential: await issue() }; return {}; });
  return dba;
}

const jwksWith = kids => vi.fn(async () => new Response(JSON.stringify({ keys: kids.map(kid => ({ kid })) })));

describe('browser SDK auto-renewal', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it('does not renew at once when two thirds of the lifetime is beyond setTimeout\'s range', async () => {
    vi.stubGlobal('fetch', jwksWith(['k1']));
    const dba = await holding({ lifetime: 400 * 86400 });
    dba.autoRenew();
    await vi.advanceTimersByTimeAsync(30 * 86400 * 1000);
    expect(dba.renew).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(240 * 86400 * 1000);
    expect(dba.renew).toHaveBeenCalledTimes(1);
  });

  it('renews at two thirds of a short lifetime', async () => {
    vi.stubGlobal('fetch', jwksWith(['k1']));
    const dba = await holding({ lifetime: 3000 });
    dba.autoRenew();
    await vi.advanceTimersByTimeAsync(1990 * 1000);
    expect(dba.renew).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(20 * 1000);
    expect(dba.renew).toHaveBeenCalledTimes(1);
  });

  it('renews at once when the issuer has withdrawn the signing key', async () => {
    vi.stubGlobal('fetch', jwksWith(['k2']));
    const dba = await holding({ lifetime: 30 * 86400 });
    expect(await dba.keyWithdrawn()).toBe(true);
    dba.autoRenew();
    await vi.advanceTimersByTimeAsync(0);
    expect(dba.renew).toHaveBeenCalledTimes(1);
    // The mock renews with the same kid, which the JWKS still lacks: checked once, no loop.
    await vi.advanceTimersByTimeAsync(60 * 1000);
    expect(dba.renew).toHaveBeenCalledTimes(1);
  });

  it('never renews on a guess: an unreachable or empty JWKS is not a withdrawal', async () => {
    const dba = await holding({ lifetime: 30 * 86400 });
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline'); }));
    expect(await dba.keyWithdrawn()).toBe(false);
    vi.stubGlobal('fetch', jwksWith([]));
    expect(await dba.keyWithdrawn()).toBe(false);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 500 })));
    expect(await dba.keyWithdrawn()).toBe(false);
  });
});

describe('browser SDK confirmations and gates (STATUS B7 G9)', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('asks for a confirmation, sends it, and waits while a site says gate_pending', async () => {
    const { testEnv, call, newDevice, enroll, worker, ORIGIN } = await import('../../test-utils/env.js');
    const env = await testEnv();
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    // A phone that answers as a dba-device gate.
    const phone = await newDevice();
    const phoneCred = (await enroll(env, 'alice', phone, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:approvals:answer'] }] })).approve.body.credential;
    const gate = (await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'dba-device', label: 'Phone', device_id: (await import('../verify/src/index.js')).inspectCredential(phoneCred).payload.sub } })).body.id;
    const asPhone = async (method, path, body) => call(env, method, path, { headers: await phone.headers(method, path, phoneCred), body });

    const laptop = await newDevice();
    const issued = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: laptop.publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], confirm: { gates: [{ any: [gate], timeout_s: 120 }], every_s: 3600 } } });
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);

    // The site answers gate_pending once, then checks the confirmation header is there.
    let siteCalls = 0; const seen = [];
    vi.stubGlobal('location', { href: 'https://hashbin.org/', origin: 'https://hashbin.org', host: 'hashbin.org' });
    vi.stubGlobal('fetch', async (input, init) => {
      const request = new Request(input, init);
      if (request.url.startsWith(ORIGIN)) return worker.fetch(request, env);
      siteCalls++; seen.push({ confirmation: request.headers.get('DBA-Confirmation'), dpop: request.headers.get('DPoP'), body: await request.text() });
      if (siteCalls === 1) return Response.json({ allow: false, code: 'gate_pending', gate_request: { id: 'gtr_site', retry_after: 1 } }, { status: 403 });
      return Response.json({ ok: true });
    });

    const dba = new DBA({ origin: ORIGIN });
    dba.state = { privateKey: laptop.privateKey, publicJwk: laptop.publicJwk, credential: issued.body.credential };
    dba.save = async () => {};
    expect(dba.confirmation).toBeNull();

    let pending = null;
    const confirming = dba.confirm({ onPending: req => { pending = req; } });
    expect(dba.confirm()).toBe(confirming); // one wait for concurrent callers
    // The phone sees the request and allows it while the SDK waits.
    let items = [];
    for (let i = 0; i < 50 && !items.length; i++) { items = (await asPhone('GET', '/api/v1/gate-requests')).body.items; if (!items.length) await new Promise(r => setTimeout(r, 20)); }
    await asPhone('POST', `/api/v1/gate-requests/${items[0].id}/answer`, { ...items[0].answer_as[0], decision: 'allow' });
    const result = await confirming;
    expect(pending).toMatchObject({ purpose: 'confirm' });
    expect(result).toMatchObject({ status: 'confirmed' });
    expect(dba.confirmation).toBe(result.confirmation);

    let told = null;
    const response = await dba.fetchWithGates('https://hashbin.org/api/content', { method: 'POST', body: 'hello' }, { onPending: req => { told = req; } });
    expect(await response.json()).toEqual({ ok: true });
    expect(told).toEqual({ id: 'gtr_site', retry_after: 1 });
    expect(seen).toHaveLength(2);
    expect(seen.every(s => s.confirmation === result.confirmation && s.body === 'hello')).toBe(true);
    expect(seen[0].dpop).not.toBe(seen[1].dpop); // a fresh proof each time

    // A denied confirmation rejects; headers({ confirm: false }) never waits.
    dba.state.confirmation = null;
    const denied = dba.confirm();
    items = [];
    for (let i = 0; i < 50 && !items.length; i++) { items = (await asPhone('GET', '/api/v1/gate-requests')).body.items; if (!items.length) await new Promise(r => setTimeout(r, 20)); }
    await asPhone('POST', `/api/v1/gate-requests/${items[0].id}/answer`, { ...items[0].answer_as[0], decision: 'deny' });
    await expect(denied).rejects.toMatchObject({ code: 'gate_denied' });
    expect(Object.keys(await dba.headers('GET', 'https://hashbin.org/', { confirm: false }))).toEqual(['Authorization', 'DPoP']);
  }, 20000);
});

describe('browser SDK DPoP nonces (STATUS D15)', () => {
  afterEach(() => { vi.unstubAllGlobals(); });

  it('sends a request once more with the nonce a just-started account object asks for, and to sites that ask', async () => {
    const { testEnv, call, newDevice, enroll, worker, ORIGIN } = await import('../../test-utils/env.js');
    const { decodeJws } = await import('../verify/src/index.js');
    const env = await testEnv();
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    const laptop = await newDevice();
    const credential = (await enroll(env, 'alice', laptop)).approve.body.credential;
    const toDba = []; const toSite = [];
    vi.stubGlobal('location', { href: 'https://hashbin.org/', origin: 'https://hashbin.org', host: 'hashbin.org' });
    vi.stubGlobal('fetch', async (input, init) => {
      const request = new Request(input, init);
      const nonce = decodeJws(request.headers.get('DPoP') || 'e30.e30.x').payload.nonce;
      if (request.url.startsWith(ORIGIN)) { toDba.push(nonce); return worker.fetch(request, env); }
      toSite.push({ nonce, body: await request.text() });
      // A site that follows RFC 9449 §8 itself.
      if (nonce !== 'site-nonce-1') return Response.json({ error: 'use_dpop_nonce' }, { status: 401, headers: { 'DPoP-Nonce': 'site-nonce-1', 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"' } });
      return Response.json({ ok: true });
    });
    const dba = new DBA({ origin: ORIGIN });
    dba.state = { privateKey: laptop.privateKey, publicJwk: laptop.publicJwk, credential };
    dba.save = async () => {};

    env.ACCOUNTS.restart('alice');
    expect(await dba.api('/api/v1/whoami', { auth: true })).toMatchObject({ account: 'alice' });
    expect(toDba).toEqual([undefined, expect.stringMatching(/^dpn_/)]);
    // The nonce is kept for later proofs to that origin.
    await dba.api('/api/v1/whoami', { auth: true });
    expect(toDba[2]).toBe(toDba[1]);

    const response = await dba.fetch('https://hashbin.org/api/content', { method: 'POST', body: 'hello' });
    expect(await response.json()).toEqual({ ok: true });
    expect(toSite).toEqual([{ nonce: undefined, body: 'hello' }, { nonce: 'site-nonce-1', body: 'hello' }]);
    // A 401 that is not a nonce challenge is returned as it is, once.
    vi.stubGlobal('fetch', async () => Response.json({ code: 'revoked' }, { status: 401 }));
    expect((await dba.fetch('https://hashbin.org/x')).status).toBe(401);
  });

  it('answers a site\'s timed challenges at once, as many as it asks for (B10 N2)', async () => {
    const { testEnv, call, newDevice, enroll, worker, ORIGIN } = await import('../../test-utils/env.js');
    const { createVerifier } = await import('../verify/src/index.js');
    const env = await testEnv();
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    const laptop = await newDevice();
    const grants = [{ actions: ['hashbin:content:write'], net: { client: { latency: { max_rtt_ms: 40, samples: 2 } } } }];
    const credential = (await enroll(env, 'alice', laptop, { grants })).approve.body.credential;
    let ms = Date.now(); const delays = [90, 20]; let sent = 0;
    const verifier = createVerifier({ issuer: ORIGIN, audience: 'hashbin.org', fetch: (url, init) => worker.fetch(new Request(url, init), env), rtt: { secret: 's'.repeat(32), now: () => ms } });
    vi.stubGlobal('location', { href: 'https://hashbin.org/', origin: 'https://hashbin.org', host: 'hashbin.org' });
    vi.stubGlobal('fetch', async (input, init) => {
      const request = new Request(input, init);
      if (sent++) ms += delays.shift() ?? 0;
      const result = await verifier.verifyRequest(request, { action: 'hashbin:content:write', location: { network: { ip: '203.0.113.7' } } });
      return Response.json({ allow: result.allow, code: result.code, ...(result.dpop_nonce ? { dpop_nonce: result.dpop_nonce, rtt: result.rtt } : {}) }, { status: result.allow ? 200 : result.status, headers: result.headers || {} });
    });
    const dba = new DBA({ origin: ORIGIN });
    dba.state = { privateKey: laptop.privateKey, publicJwk: laptop.publicJwk, credential };
    const response = await dba.fetch('https://hashbin.org/api/content', { method: 'POST', body: 'hello' });
    expect(await response.json()).toEqual({ allow: true, code: 'ok' });
    expect(sent).toBe(3); // the first request, a slow sample, then a fast one
  });

  it('on a real clock, a device behind an injected delay fails the round-trip rule and passes without it (B10 N2)', async () => {
    const { testEnv, call, newDevice, enroll, worker, ORIGIN } = await import('../../test-utils/env.js');
    const { createVerifier } = await import('../verify/src/index.js');
    const env = await testEnv();
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    const laptop = await newDevice();
    const grants = [{ actions: ['hashbin:content:write'], net: { client: { latency: { max_rtt_ms: 60 } } } }];
    const credential = (await enroll(env, 'alice', laptop, { grants })).approve.body.credential;
    const verifier = createVerifier({ issuer: ORIGIN, audience: 'hashbin.org', fetch: (url, init) => worker.fetch(new Request(url, init), env), rtt: { secret: 's'.repeat(32) } });
    let delay = 0;
    vi.stubGlobal('location', { href: 'https://hashbin.org/', origin: 'https://hashbin.org', host: 'hashbin.org' });
    vi.stubGlobal('fetch', async (input, init) => {
      const request = new Request(input, init);
      await new Promise(resolve => setTimeout(resolve, delay));
      const result = await verifier.verifyRequest(request, { action: 'hashbin:content:write', location: { network: { ip: '203.0.113.7' } } });
      return Response.json({ code: result.code, reasons: result.reasons, ...(result.dpop_nonce ? { dpop_nonce: result.dpop_nonce, rtt: result.rtt } : {}) }, { status: result.allow ? 200 : result.status, headers: result.headers || {} });
    });
    const dba = new DBA({ origin: ORIGIN });
    dba.state = { privateKey: laptop.privateKey, publicJwk: laptop.publicJwk, credential };
    const post = () => dba.fetch('https://hashbin.org/api/content', { method: 'POST', body: 'hello' });
    await post(); // warm the verifier's JWKS and status list caches
    delay = 150;
    expect(await (await post()).json()).toEqual({ code: 'forbidden', reasons: [['rtt_exceeded']] });
    delay = 0;
    expect((await post()).status).toBe(200);
  });
});
