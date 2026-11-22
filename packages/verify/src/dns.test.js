import { describe, it, expect } from 'vitest';
import { createDohResolver, grantDnsNames, DNS_DEFAULTS } from './dns.js';

/** A stub DoH JSON endpoint: zone[name] = { A, AAAA, ttl, ad, status, fail }. */
function stub(zone) {
  const calls = [];
  const fetch = async url => {
    const u = new URL(url); const name = u.searchParams.get('name'); const type = u.searchParams.get('type');
    calls.push(`${name} ${type}`);
    const z = zone[name];
    if (!z) return Response.json({ Status: 3, AD: true, Answer: [] });
    if (z.fail) return new Response('busy', { status: 503 });
    const Answer = [{ name, type: 5, TTL: 60, data: 'alias.example.net.' }, ...(z[type] || []).map(data => ({ name, type: type === 'A' ? 1 : 28, TTL: z.ttl ?? 60, data }))];
    return Response.json({ Status: z.status ?? 0, AD: z.ad === true, Answer });
  };
  return { fetch, calls };
}

describe('DNS-over-HTTPS resolver', () => {
  it('collects A and AAAA answers and reports DNSSEC only when both are validated', async () => {
    const { fetch } = stub({ 'vpn.example.com': { A: ['192.0.2.1'], AAAA: ['2001:db8::1'], ad: true }, 'plain.example.com': { A: ['192.0.2.2'] } });
    const dns = createDohResolver({ fetch });
    expect(await dns.resolve('vpn.example.com')).toEqual({ addrs: ['192.0.2.1', '2001:db8::1'], dnssec: true });
    expect(await dns.resolve('plain.example.com')).toEqual({ addrs: ['192.0.2.2'], dnssec: false });
  });

  it('an unknown name has no addresses; a failing or broken resolver leaves the name unresolved', async () => {
    const { fetch } = stub({ 'down.example.com': { fail: true }, 'servfail.example.com': { status: 2 } });
    const dns = createDohResolver({ fetch });
    expect(await dns.resolve('nx.example.com')).toEqual({ addrs: [], dnssec: true });
    expect(await dns.resolve('down.example.com')).toBe('unresolved');
    expect(await dns.resolve('servfail.example.com')).toBe('unresolved');
    expect(await createDohResolver({ fetch: async () => { throw new Error('offline'); } }).resolve('a.example.com')).toBe('unresolved');
  });

  it('caches for the TTL, bounded to 30–300 s, and failures for 5 s', async () => {
    let t = 1000;
    const zone = { 'short.example.com': { A: ['192.0.2.1'], ttl: 1 }, 'long.example.com': { A: ['192.0.2.2'], ttl: 86400 }, 'down.example.com': { fail: true } };
    const { fetch, calls } = stub(zone);
    const dns = createDohResolver({ fetch, now: () => t });
    for (const name of Object.keys(zone)) await dns.resolve(name);
    t += 29; for (const name of Object.keys(zone)) await dns.resolve(name);
    expect(calls.length).toBe(6 + 2); // only the failure was asked again (after 5 s)
    t += 1; await dns.resolve('short.example.com');
    expect(calls.length).toBe(10);
    t += 270; await dns.resolve('long.example.com');
    expect(calls.length).toBe(12);
  });

  it('resolves at most 16 distinct names per request', async () => {
    const { fetch } = stub({});
    const names = Array.from({ length: 20 }, (_, i) => `h${i}.example.com`);
    const answers = await createDohResolver({ fetch }).resolveAll([...names, names[0]]);
    expect(Object.keys(answers)).toEqual(names.slice(0, DNS_DEFAULTS.maxNames));
  });

  it('finds the names in a credential\'s grants', () => {
    expect(grantDnsNames([{ actions: ['a:b'] }, { actions: ['a:b'], net: { client: { addresses: { dns: { names: ['a.example.com', 'b.example.com'] } } } } }])).toEqual(['a.example.com', 'b.example.com']);
    expect(grantDnsNames(null)).toEqual([]);
  });
});
