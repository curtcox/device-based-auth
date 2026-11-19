import { describe, it, expect, beforeEach } from 'vitest';
import { canAccess } from './scopes.js';
import { testEnv, call, newDevice, enroll } from '../../test-utils/env.js';

// STATUS L12: devicebasedauth.org checks a device's dba:* grants per request and keeps no usage
// counters or step-up approvals for them, so a grant that needs either must not count as allowing.
const device = grants => ({ session: false, device: { dba: true, payload: { grants }, location: {} } });

describe('device grants on devicebasedauth.org\'s own API', () => {
  it('allows a plain dba:* grant', () => {
    expect(canAccess(device([{ actions: ['dba:credentials:read'] }]), 'credentials:read')).toBe(true);
  });

  it('does not treat a grant with a usage limit or step-up as unlimited', () => {
    expect(canAccess(device([{ actions: ['dba:credentials:issue'], limits: { uses: { count: 1, per: 'day' } } }]), 'credentials:issue')).toBe(false);
    expect(canAccess(device([{ actions: ['dba:credentials:issue'], require: { step_up: true } }]), 'credentials:issue')).toBe(false);
    expect(canAccess(device([{ actions: ['dba:credentials:issue'], require: { gates: [{ any: ['owner'] }] } }]), 'credentials:issue')).toBe(false);
    // Another grant without them still counts.
    expect(canAccess(device([{ actions: ['dba:credentials:issue'], require: { step_up: true } }, { actions: ['dba:credentials:issue'] }]), 'credentials:issue')).toBe(true);
  });
});

describe('issuing dba:* grants', () => {
  let env;
  beforeEach(async () => {
    env = await testEnv();
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
  });

  it('refuses usage limits and step-up on dba:* actions, which devicebasedauth.org cannot enforce', async () => {
    for (const extra of [{ limits: { uses: { count: 3, per: 'day' } } }, { require: { step_up: true } }]) {
      const { approve } = await enroll(env, 'alice', await newDevice(), { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:credentials:issue'], ...extra }] });
      expect(approve.status).toBe(400);
      expect(approve.body.code).toBe('invalid_grants');
    }
    const { approve } = await enroll(env, 'alice', await newDevice(), { aud: ['devicebasedauth.org', 'hashbin.org'], grants: [{ actions: ['dba:credentials:issue'] }, { actions: ['hashbin:content:write'], require: { step_up: true } }] });
    expect(approve.status).toBe(200);
  });
});
