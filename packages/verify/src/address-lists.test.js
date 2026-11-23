import { describe, it, expect, beforeEach } from 'vitest';
import { createAddressListResolver, grantAddressLists, ADDRESS_LIST_TYP } from './address-lists.js';
import { generateKeyPair, exportPublicJwk, signJws } from './jose.js';

// todo/network_constraints.md §4: verifiers cache a list at most 60 s, serve a stale copy up to
// 10 minutes while fetches fail, never go back to a lower ver, and a tombstone matches nothing.

const ISSUER = 'https://devicebasedauth.org';
const ID = 'adl_OFFICE0001';
const URI = `https://status.devicebasedauth.org/v1/addresses/${ID}`;
const REF = { id: ID, uri: URI };

let key; let jwks; let now; let served; let fetches;
beforeEach(async () => {
  const pair = await generateKeyPair(true);
  key = { kid: 'k1', key: pair.privateKey };
  jwks = { keys: [{ ...(await exportPublicJwk(pair.publicKey)), kid: 'k1' }] };
  now = 1_800_000_000; served = null; fetches = 0;
});

const sign = (claims, signer = key, header = {}) => signJws({ typ: ADDRESS_LIST_TYP, kid: signer.kid, ...header }, { iss: ISSUER, sub: URI, id: ID, iat: now, exp: now + 86400, ...claims }, signer.key);
const resolver = (options = {}) => createAddressListResolver({
  issuer: ISSUER, now: () => now, jwks: async () => jwks,
  fetch: async () => { fetches++; return served === null ? { ok: false, status: 503 } : { ok: true, text: async () => served }; },
  ...options
});

describe('address list resolver', () => {
  it('fetches, verifies and caches a list for 60 seconds', async () => {
    served = await sign({ ver: 3, cidrs: ['192.0.2.0/24'] });
    const r = resolver();
    expect(await r.resolveAll([REF])).toEqual({ [ID]: { cidrs: ['192.0.2.0/24'], ver: 3 } });
    now += 59; await r.resolveAll([REF]);
    expect(fetches).toBe(1);
    served = await sign({ ver: 4, cidrs: ['198.51.100.0/24'] });
    now += 2;
    expect((await r.resolveAll([REF]))[ID].cidrs).toEqual(['198.51.100.0/24']);
    expect(fetches).toBe(2);
  });

  it('serves a stale copy for 10 minutes while fetches fail, then none', async () => {
    served = await sign({ ver: 1, cidrs: ['192.0.2.0/24'] });
    const r = resolver();
    await r.resolveAll([REF]);
    served = null;
    now += 60 + 599;
    expect((await r.resolveAll([REF]))[ID].ver).toBe(1);
    now += 2;
    expect((await r.resolveAll([REF]))[ID]).toBe('unavailable');
    // Back online: the list is used again.
    served = await sign({ ver: 1, cidrs: ['192.0.2.0/24'] });
    now += 10;
    expect((await r.resolveAll([REF]))[ID].ver).toBe(1);
  });

  it('never goes back to a lower ver', async () => {
    served = await sign({ ver: 5, cidrs: ['192.0.2.0/24'] });
    const r = resolver();
    await r.resolveAll([REF]);
    served = await sign({ ver: 4, cidrs: ['0.0.0.0/0'] });
    now += 61;
    expect(await r.resolveAll([REF])).toEqual({ [ID]: { cidrs: ['192.0.2.0/24'], ver: 5 } });
  });

  it('a tombstone matches nothing, and a later list cannot be an older one', async () => {
    served = await sign({ ver: 2, cidrs: ['192.0.2.0/24'] });
    const r = resolver();
    await r.resolveAll([REF]);
    served = await sign({ ver: 3, deleted: true, cidrs: [] });
    now += 61;
    expect((await r.resolveAll([REF]))[ID]).toBe('unavailable');
    served = await sign({ ver: 2, cidrs: ['192.0.2.0/24'] });
    now += 61;
    expect((await r.resolveAll([REF]))[ID]).toBe('unavailable');
  });

  it('refuses lists that are forged, for another id or URI, expired, or of another type', async () => {
    const other = await generateKeyPair(true);
    const cases = [
      await sign({ ver: 1, cidrs: [] }, { kid: 'k1', key: other.privateKey }),
      await sign({ ver: 1, cidrs: [], id: 'adl_SOMEOTHER1' }),
      await sign({ ver: 1, cidrs: [], sub: 'https://evil.example/list' }),
      await sign({ ver: 1, cidrs: [], iss: 'https://evil.example' }),
      await sign({ ver: 1, cidrs: [], exp: now - 3600 }),
      await sign({ ver: 1, cidrs: [] }, key, { typ: 'statuslist+jwt' }),
      await sign({ ver: '1', cidrs: [] }),
      await sign({ ver: 1, cidrs: [7] })
    ];
    for (const jwt of cases) {
      served = jwt;
      expect((await resolver().resolveAll([REF]))[ID]).toBe('unavailable');
    }
  });

  it('a copy that expires while cached stops matching', async () => {
    served = await sign({ ver: 1, cidrs: ['192.0.2.0/24'], exp: now + 30 });
    const r = resolver({ maxAge: 3600, staleFor: 0 });
    expect((await r.resolveAll([REF]))[ID].ver).toBe(1);
    now += 120;
    expect((await r.resolveAll([REF]))[ID]).toBe('unavailable');
  });

  it('asks for fresh keys once when the list is signed by a key it has not seen', async () => {
    const pair = await generateKeyPair(true);
    const rotated = { kid: 'k2', key: pair.privateKey };
    const fresh = { keys: [...jwks.keys, { ...(await exportPublicJwk(pair.publicKey)), kid: 'k2' }] };
    const forced = [];
    served = await sign({ ver: 1, cidrs: ['192.0.2.0/24'] }, rotated);
    const r = resolver({ jwks: async force => { forced.push(force); return force ? fresh : jwks; } });
    expect((await r.resolveAll([REF]))[ID].ver).toBe(1);
    expect(forced).toEqual([false, true]);
  });

  it('collects each list once from the grants', () => {
    const grants = [{ net: { client: { addresses: { lists: [REF, { id: 'adl_VPNEXIT01', uri: 'https://x/y' }] } } } }, { net: { client: { addresses: { lists: [REF] } } } }, { actions: ['a:b'] }];
    expect(grantAddressLists(grants).map(l => l.id)).toEqual([ID, 'adl_VPNEXIT01']);
  });
});
