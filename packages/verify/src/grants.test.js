import { describe, it, expect } from 'vitest';
import { validateGrant, validateGrants, evaluateGrants, evaluateGrant, isNarrowing, describeGrant, ipInCidr, parseIp, localTime, inWindow, distanceMeters, actionMatches, resourceMatches, grantGates, STEP_UP_GATES } from './grants.js';

const at = iso => Math.floor(Date.parse(iso) / 1000);
const base = { actions: ['hashbin:content:write'] };
const ctx = (extra = {}) => ({ now: at('2026-11-18T15:00:00Z'), action: 'hashbin:content:write', resource: 'x', ...extra });

describe('validation', () => {
  it('accepts a full grant', () => {
    expect(validateGrant({ actions: ['hashbin:content:*', 'cronly:jobs:run'], resources: ['job:*'], when: { tz: 'America/Chicago', windows: [{ days: ['mon', 'fri'], from: '22:00', to: '06:00' }], not_before: 1, not_after: 2 }, where: { source: 'both', countries: ['US'], regions: ['US-MO'], areas: [{ lat: 38.6, lon: -90.2, radius_m: 5000 }], networks: ['10.0.0.0/8', '2001:db8::/32'] }, limits: { uses: { count: 5, per: 'day' }, spend_usd_per_month: 5 }, require: { online: true, step_up: false } })).toEqual([]);
  });
  it('rejects unknown keys, bad actions, bad windows and empty where', () => {
    expect(validateGrant({ actions: ['nope'] })[0]).toMatch(/namespace/);
    expect(validateGrant({ ...base, color: 'red' })[0]).toMatch(/not a known constraint/);
    expect(validateGrant({ ...base, when: { tz: 'Mars/Base', windows: [{ from: '09:00', to: '09:00' }] } }).length).toBe(2);
    expect(validateGrant({ ...base, where: { source: 'network' } })[0]).toMatch(/at least one/);
    expect(validateGrant({ ...base, where: { source: 'device', countries: ['US'] } })[0]).toMatch(/only use areas/);
    expect(validateGrants([])).toHaveLength(1);
  });
});

describe('matching', () => {
  it('matches actions and resources', () => {
    expect(actionMatches('hashbin:*', 'hashbin:content:write')).toBe(true);
    expect(actionMatches('hashbin:content:*', 'hashbin:uploads:read')).toBe(false);
    expect(actionMatches('hashbin:*', 'hashbinx:a')).toBe(false);
    expect(resourceMatches('job:*', 'job:nightly')).toBe(true);
    expect(resourceMatches('job:a', 'job:ab')).toBe(false);
  });
  it('parses IPs and CIDRs', () => {
    expect(ipInCidr('203.0.113.7', '203.0.113.0/24')).toBe(true);
    expect(ipInCidr('203.0.114.7', '203.0.113.0/24')).toBe(false);
    expect(ipInCidr('2001:db8::1', '2001:db8::/32')).toBe(true);
    expect(ipInCidr('::ffff:203.0.113.7', '::ffff:203.0.113.0/120')).toBe(true);
    expect(ipInCidr('203.0.113.7', '2001:db8::/32')).toBe(false);
    expect(parseIp('1.2.3.256')).toBe(null);
    expect(parseIp('1::2::3')).toBe(null);
  });
  it('computes distance', () => { expect(Math.round(distanceMeters({ lat: 0, lon: 0 }, { lat: 0, lon: 1 }) / 1000)).toBe(111); });
});

describe('time windows', () => {
  it('uses local time including DST', () => {
    expect(localTime(at('2026-07-01T14:30:00Z'), 'America/Chicago')).toEqual({ day: 3, minutes: 9 * 60 + 30 });
    expect(localTime(at('2026-12-01T14:30:00Z'), 'America/Chicago')).toEqual({ day: 2, minutes: 8 * 60 + 30 });
  });
  it('handles overnight windows on the day they start', () => {
    const w = { days: ['fri'], from: '22:00', to: '06:00' };
    expect(inWindow(w, { day: 5, minutes: 23 * 60 })).toBe(true);
    expect(inWindow(w, { day: 6, minutes: 5 * 60 })).toBe(true);
    expect(inWindow(w, { day: 5, minutes: 5 * 60 })).toBe(false);
    expect(inWindow({ from: '00:00', to: '24:00' }, { day: 0, minutes: 1439 })).toBe(true);
  });
});

describe('evaluation', () => {
  it('denies by default and explains why', () => {
    const r = evaluateGrants([{ actions: ['hashbin:uploads:read'] }], ctx());
    expect(r.allow).toBe(false); expect(r.reasons).toEqual([['action_not_granted']]);
  });
  it('allows the first passing grant', () => {
    const r = evaluateGrants([{ actions: ['x:y'] }, { ...base, limits: { spend_usd_per_month: 5 } }], ctx());
    expect(r).toMatchObject({ allow: true, grant_index: 1, caveats: { spend_usd_per_month: 5 } });
  });
  it('fails closed on unknown constraints', () => {
    expect(evaluateGrant({ ...base, where: { source: 'network', countries: ['US'], planet: 'earth' } }, ctx()).reasons).toEqual(['unknown_constraint:where.planet']);
  });
  it('checks network and device location', () => {
    const where = { source: 'both', areas: [{ lat: 38.627, lon: -90.199, radius_m: 50000 }] };
    const now = ctx().now;
    const good = { network: { lat: 38.6, lon: -90.2 }, device: { lat: 38.63, lon: -90.2, acc_m: 30, t: now } };
    expect(evaluateGrant({ ...base, where }, ctx({ location: good })).ok).toBe(true);
    expect(evaluateGrant({ ...base, where }, ctx({ location: { network: good.network } })).reasons).toEqual(['location_unavailable:device']);
    expect(evaluateGrant({ ...base, where }, ctx({ location: { ...good, device: { ...good.device, t: now - 3600 } } })).reasons).toEqual(['location_stale:device']);
    expect(evaluateGrant({ ...base, where: { source: 'network', countries: ['US'], networks: ['10.0.0.0/8'] } }, ctx({ location: { network: { country: 'US', ip: '11.0.0.1' } } })).reasons).toEqual(['network_not_allowed']);
    expect(evaluateGrant({ ...base, where: { source: 'network', regions: ['US-MO'] } }, ctx({ location: { network: { country: 'US', region: 'US-IL' } } })).reasons).toEqual(['outside_location:network']);
  });
  it('requires online checks for usage limits and step-up', () => {
    const grant = { ...base, limits: { uses: { count: 1, per: 'day' } } };
    const offline = evaluateGrants([grant], ctx());
    expect(offline).toMatchObject({ allow: false, online_required: true });
    const online = evaluateGrants([grant], ctx({ online: true }));
    expect(online).toMatchObject({ allow: true, online: { uses: { count: 1, per: 'day' } } });
  });
});

describe('narrowing', () => {
  const parent = { actions: ['hashbin:*'], resources: ['job:*'], when: { not_after: 100 } };
  it('accepts strictly narrower grants', () => {
    expect(isNarrowing({ actions: ['hashbin:content:write'], resources: ['job:a'], when: { not_after: 100 }, where: { source: 'network', countries: ['US'] } }, parent)).toBe(true);
  });
  it('rejects wider actions, resources or dropped constraints', () => {
    expect(isNarrowing({ actions: ['cronly:jobs:run'], resources: ['job:a'], when: { not_after: 100 } }, parent)).toBe(false);
    expect(isNarrowing({ actions: ['hashbin:x'], when: { not_after: 100 } }, parent)).toBe(false);
    expect(isNarrowing({ actions: ['hashbin:x'], resources: ['job:a'], when: { not_after: 200 } }, parent)).toBe(false);
  });
});

it('describes grants in plain English', () => {
  expect(describeGrant({ actions: ['hashbin:content:write'], when: { tz: 'America/Chicago', windows: [{ days: ['mon', 'tue', 'wed', 'thu', 'fri'], from: '08:00', to: '18:00' }] }, where: { source: 'network', countries: ['US'] }, limits: { spend_usd_per_month: 5 } }))
    .toBe('May "hashbin:content:write", on any resource, weekdays 08:00–18:00 (America/Chicago time), only from US (as seen from its network connection), spending at most $5.00 per month.');
});

describe('gates', () => {
  it('fills in defaults and treats step_up as the owner gate', () => {
    expect(grantGates({ actions: ['x:y'], require: { gates: [{ any: ['gate_PHONE0001'] }] } })).toEqual([{ any: ['gate_PHONE0001'], timeout_s: 300, on_timeout: 'deny' }]);
    expect(grantGates({ actions: ['x:y'], require: { step_up: true } })).toEqual(STEP_UP_GATES);
    expect(grantGates({ actions: ['x:y'] })).toBe(null);
  });
  it('reports what the gate engine must do online', () => {
    const grant = { actions: ['hashbin:content:write'], require: { gates: [{ any: ['owner'], timeout_s: 60, on_timeout: 'allow' }], gates_reuse_s: 120 } };
    const result = evaluateGrants([grant], { now: 0, action: 'hashbin:content:write', online: true, policy: { gates: { fail_open: false } } });
    expect(result.online).toEqual({ gates: [{ any: ['owner'], timeout_s: 60, on_timeout: 'allow' }], gates_reuse_s: 120, fail_open: false });
  });
  it('says plainly that allow-on-timeout lets silence through', () => {
    expect(describeGrant({ actions: ['cronly:jobs:run'], require: { gates: [{ any: ['owner', 'gate_PHONE0001'], timeout_s: 120, on_timeout: 'allow' }, { any: ['gate_YUBIKEY01'] }], gates_reuse_s: 3600 } }))
      .toBe('May "cronly:jobs:run", on any resource, approved by the account owner or gate gate_PHONE0001, or allowed anyway if nobody answers within 2 minutes, approved by gate gate_YUBIKEY01 within 5 minutes, one approval covering repeated uses for 1 hour.');
  });
});
