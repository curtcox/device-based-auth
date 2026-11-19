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
