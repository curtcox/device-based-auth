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
