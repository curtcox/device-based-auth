import { describe, it, expect } from 'vitest';
import { validateGrant, describeGrant, isNarrowing, grantsNeedVersion2 } from './grants.js';
import { validHostName, validateNet } from './net.js';
import { validateCredentialPayload } from './credential.js';
import { sameIp } from './ip.js';

const W = ['hashbin:content:write'];
const LIST = { id: 'adl_OFFICE0001', uri: 'https://status.devicebasedauth.org/v1/addresses/adl_OFFICE0001' };

describe('net validation', () => {
  it('accepts every source and rule', () => {
    expect(validateGrant({ actions: W, net: {
      client: { addresses: { of: 'origin', cidrs: ['203.0.113.0/24'], lists: [LIST], dns: { names: ['vpn.example.com'], dnssec: true }, webhook: 'gate_ADDRHOOK1' }, route: { relays: ['dev_RELAYHQ001'], min_hops: 1, max_hops: 2, require_attested: true }, latency: { max_rtt_ms: 40, samples: 3, reuse_s: 60 } },
      server: { addresses: { cidrs: ['198.51.100.0/24'] }, route: { relays: ['dev_RELAYHQ001'] }, latency: { max_rtt_ms: 80 } }
    } })).toEqual([]);
  });

  it('explains what is wrong', () => {
    expect(validateNet({ client: { addresses: {} } })).toEqual(['grant.net.client.addresses needs at least one of cidrs, lists, dns or webhook']);
    expect(validateNet({ server: { addresses: { of: 'origin', cidrs: ['10.0.0.0/8'] }, route: { relays: ['dev_RELAYHQ001'] } } })).toContain('grant.net.server.addresses.of "origin" is only for net.client (a device sees the server\'s address directly)');
    expect(validateNet({ client: { addresses: { cidrs: ['10.0.0.0/8', '10.0.0.0/8'] } } })).toEqual(['grant.net.client.addresses.cidrs has duplicates']);
    expect(validateNet({ client: { addresses: { lists: [LIST, LIST] } } })).toEqual(expect.arrayContaining(['grant.net.client.addresses.lists names a list twice']));
    expect(validateNet({ client: { addresses: { lists: [{ ...LIST, uri: 'http://example.com/x' }] } } })).toEqual(['grant.net.client.addresses.lists[0] must be { id: "adl_…", uri: "https://…" }']);
    expect(validateNet({ client: { route: { relays: ['dev_RELAYHQ001'], max_hops: 5 } } })).toEqual(['grant.net.client.route.max_hops must be an integer 1–4']);
    expect(validateNet({ client: { latency: { max_rtt_ms: 40, samples: 0, reuse_s: 301 } } })).toEqual(['grant.net.client.latency.samples must be an integer 1–5', 'grant.net.client.latency.reuse_s must be an integer 0–300']);
    expect(validateGrant({ actions: W, net: { client: { latency: { max_rtt_ms: 4, extra: 1 } } } })).toEqual(['grant.net.client.latency.extra is not allowed']);
  });

  it('host names are lower case with a non-numeric top label', () => {
    expect(validHostName('vpn-egress.example.com')).toBe(true);
    expect(validHostName('localhost')).toBe(false);
    expect(validHostName('Example.com')).toBe(false);
    expect(validHostName('192.0.2.1')).toBe(false);
    expect(validHostName('-bad.example.com')).toBe(false);
    expect(validHostName(`${'a'.repeat(64)}.com`)).toBe(false);
  });

  it('compares addresses however they are written', () => {
    expect(sameIp('2001:db8::1', '2001:DB8:0:0::1')).toBe(true);
    expect(sameIp('192.0.2.1', '::ffff:192.0.2.1')).toBe(false);
    expect(sameIp('nope', 'nope')).toBe(false);
  });
});

describe('net and the rest of the vocabulary', () => {
  const grant = { actions: W, net: { client: { addresses: { cidrs: ['203.0.113.0/24'], lists: [LIST] }, latency: { max_rtt_ms: 40 } }, server: { latency: { max_rtt_ms: 80 } } } };

  it('describes the rules in English', () => {
    expect(describeGrant(grant)).toBe('May "hashbin:content:write", on any resource, only from 203.0.113.0/24 or the addresses in list adl_OFFICE0001, only from a device answering within 40 ms, sending only to a server answering within 80 ms.');
    expect(describeGrant({ actions: W, net: { client: { addresses: { of: 'origin', dns: { names: ['vpn.example.com'], dnssec: true } }, route: { relays: ['dev_RELAYHQ001', 'dev_RELAYEDGE1'], max_hops: 2, require_attested: true } } } }))
      .toBe('May "hashbin:content:write", on any resource, only from devices at the addresses of vpn.example.com (DNSSEC-validated), only through relays dev_RELAYHQ001 or dev_RELAYEDGE1 (1–2 hops, attested relays only).');
  });

  it('a narrowed grant keeps its parent\'s net unchanged', () => {
    expect(isNarrowing(grant, grant)).toBe(true);
    expect(isNarrowing({ actions: W }, grant)).toBe(false);
    expect(isNarrowing({ ...grant, net: { client: { latency: { max_rtt_ms: 40 } } } }, grant)).toBe(false);
    expect(isNarrowing(grant, { actions: W })).toBe(true);
  });

  it('credentials using net carry vocabulary 2', () => {
    const base = { iss: 'https://devicebasedauth.org', sub: 'dev_ABCDEFGH12', acct: 'acct_1', aud: ['hashbin.org'], cid: 'crd_ABCDEFGH12', jti: 'crd_ABCDEFGH12.1', iat: 1, nbf: 1, exp: 2, cnf: { jkt: 'x' }, status: { status_list: { idx: 0, uri: 'u' } } };
    expect(grantsNeedVersion2([grant])).toBe(true);
    expect(grantsNeedVersion2([{ actions: W }])).toBe(false);
    expect(validateCredentialPayload({ ...base, grants: [grant], ver: 2 })).toEqual([]);
    expect(validateCredentialPayload({ ...base, grants: [{ actions: W }], ver: 2 })).toEqual([]);
    expect(validateCredentialPayload({ ...base, grants: [grant], ver: 1 })).toEqual(['ver must be 2 when a grant uses net']);
    expect(validateCredentialPayload({ ...base, grants: [{ actions: W }], ver: 3 })).toEqual(['ver must be 1 or 2']);
  });
});
