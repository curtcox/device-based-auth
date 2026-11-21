import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, enroll } from '../test-utils/env.js';
import { inspectCredential, decodeJws } from '../packages/verify/src/index.js';
import { gateHelpers } from '../test-utils/gates.js';

// STATUS B7 (done/additional_gates.md): gates on signing in (G6), loosening them (finished in G9),
// and the dashboard sign-in gate with its recovery codes.

let env; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  env = await testEnv();
  for (const who of ['alice', 'operator']) await call(env, 'POST', '/api/v1/dev/deposit', { auth: who, body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => { Date.now = realNow; });
const { audit, phoneGate } = gateHelpers(() => env);

describe('sign-in gates (G6)', () => {
  const redirect_uri = 'https://cronly.org/auth/dba/callback';
  /** Sign in to cronly.org as alice: POST /oauth/authorize, and the token exchange when it passes. */
  async function signIn(extra = {}, as = 'alice') {
    const verifier = 'v'.repeat(43);
    const challenge = await (await import('../packages/verify/src/index.js')).sha256b64u(verifier);
    const body = { client_id: 'cronly.org', redirect_uri, response_type: 'code', scope: 'openid', code_challenge: challenge, code_challenge_method: 'S256', approve: true, ...extra };
    const consent = await call(env, 'POST', '/oauth/authorize', { auth: as, body });
    if (consent.body.pending || !new URL(consent.body.redirect).searchParams.get('code')) return consent.body;
    const form = new URLSearchParams({ grant_type: 'authorization_code', code: new URL(consent.body.redirect).searchParams.get('code'), redirect_uri, client_id: 'cronly.org', code_verifier: verifier });
    const token = await call(env, 'POST', '/oauth/token', { body: form.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    return { ...consent.body, id_token: decodeJws(token.body.id_token).payload };
  }
  const error = result => new URL(result.redirect).searchParams.get('error_description');

  it('signs in at once without gates (acr session), and refuses acr_values it cannot meet', async () => {
    expect((await signIn()).id_token).toMatchObject({ acr: 'urn:devicebasedauth.org:acr:session', amr: ['session'] });
    expect(error(await signIn({ acr_values: 'urn:devicebasedauth.org:acr:gated' }))).toMatch(/acr_not_met/);
  });

  it('refuses the owner gate for sign-in, and validates entries', async () => {
    expect((await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { default: [{ any: ['owner'] }] } })).body.code).toBe('invalid_gates');
    expect((await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { default: [{ any: ['gate_NOSUCHGATE'] }] } })).body.code).toBe('unknown_gate');
  });

  it('waits for a device gate with number matching, then puts the gates in the ID token', async () => {
    const { gate, as } = await phoneGate();
    expect((await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { audiences: { 'cronly.org': [{ any: [gate], timeout_s: 120 }] } } })).status).toBe(200);
    const pending = await signIn();
    expect(pending).toMatchObject({ pending: true, gate_request: { purpose: 'sign_in', action: 'sign_in', audience: 'cronly.org', number: expect.stringMatching(/^\d\d$/) } });
    expect((await signIn()).gate_request.id).toBe(pending.gate_request.id);
    // The approver does not see the number; it types what the sign-in page shows.
    expect((await as('GET', `/api/v1/gate-requests/${pending.gate_request.id}`)).body.number).toBeUndefined();
    const path = `/api/v1/gate-requests/${pending.gate_request.id}/answer`;
    const wrong = pending.gate_request.number === '10' ? '11' : '10';
    expect((await as('POST', path, { gate, decision: 'allow', number: wrong })).body.code).toBe('wrong_number');
    expect((await as('POST', path, { gate, decision: 'allow', number: pending.gate_request.number })).body.status).toBe('allowed');
    const done = await signIn({ acr_values: 'urn:devicebasedauth.org:acr:gated' });
    expect(done.id_token).toMatchObject({ acr: 'urn:devicebasedauth.org:acr:gated', amr: ['session', 'swk', 'mfa'], dba_gates: [{ kind: 'dba-device', by: 'answer' }] });
    // Spent: the next sign-in asks again.
    expect((await signIn()).pending).toBe(true);
  });

  it('returns access_denied when the gate refuses, and honours acr_values against a timeout', async () => {
    const { gate, as } = await phoneGate();
    await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { default: [{ any: [gate], timeout_s: 30, on_timeout: 'allow' }] } });
    const pending = await signIn();
    await as('POST', `/api/v1/gate-requests/${pending.gate_request.id}/answer`, { gate, decision: 'deny' });
    const denied = await signIn();
    expect(new URL(denied.redirect).searchParams.get('error')).toBe('access_denied');
    // After the denial's time, a new request; nobody answers it.
    t += 31000;
    expect((await signIn()).pending).toBe(true);
    t += 31000;
    // Allowed by silence: not enough for a site that asks for an answered sign-in…
    expect(error(await signIn({ acr_values: 'urn:devicebasedauth.org:acr:gated' }))).toMatch(/acr_not_met/);
    // …and marked as such for one that does not.
    expect((await signIn()).id_token).toMatchObject({ acr: 'urn:devicebasedauth.org:acr:gated-timeout', amr: ['session'], dba_gates: [{ by: 'timeout' }] });
  });

  it('lets a site require sign-in gates', async () => {
    const changed = await call(env, 'PATCH', '/api/v1/audiences/cronly.org', { auth: 'operator', body: { sign_in_gates: { require: true, kinds: ['totp', 'webauthn'] } } });
    expect(changed.status).toBe(200);
    t += 61000;
    expect(error(await signIn())).toMatch(/requires a sign-in gate/);
    const { gate } = await phoneGate();
    await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body: { default: [{ any: [gate] }] } });
    expect(error(await signIn())).toMatch(/other kinds/);
  });
});

describe('loosening sign-in gates (G6, finished in G9)', () => {
  const put = body => call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: 'alice', body });

  it('tightens at once, but loosening waits for the current gates, which may refuse', async () => {
    const { gate, as } = await phoneGate();
    const { gate: other } = await phoneGate('alice', 'Tablet');
    // Adding gates, or narrowing them, is never a loosening.
    expect((await put({ default: [{ any: [gate, other], timeout_s: 120, on_timeout: 'allow' }] })).status).toBe(200);
    expect((await put({ default: [{ any: [gate], timeout_s: 120 }] })).status).toBe(200);
    // Switching them off waits for the phone, for exactly this change.
    const off = await put({ default: null });
    expect(off.status).toBe(202);
    expect(off.body).toMatchObject({ status: 'pending', code: 'gate_pending', gate_request: { purpose: 'settings', action: 'sign_in_gates', retry_after: expect.any(Number) } });
    expect((await call(env, 'GET', '/api/v1/settings/sign-in-gates', { auth: 'alice' })).body.default[0].any).toEqual([gate]);
    // Another loosening is a different request, so approving one never approves the other.
    const wider = await put({ default: [{ any: [gate, other], timeout_s: 120 }] });
    expect(wider.status).toBe(202);
    expect(wider.body.gate_request.id).not.toBe(off.body.gate_request.id);
    expect((await put({ default: null })).body.gate_request.id).toBe(off.body.gate_request.id);
    const [mine] = (await as('GET', '/api/v1/gate-requests')).body.items.filter(r => r.id === off.body.gate_request.id);
    expect((await as('POST', `/api/v1/gate-requests/${mine.id}/answer`, { ...mine.answer_as[0], decision: 'allow' })).body.status).toBe('allowed');
    expect((await put({ default: null })).status).toBe(200);
    expect((await call(env, 'GET', '/api/v1/settings/sign-in-gates', { auth: 'alice' })).body.default).toBeNull();
    expect(await audit('alice')).toContain('sign_in_gates.changed');
    // The other change is still waiting; refused, it is 403.
    await as('POST', `/api/v1/gate-requests/${wider.body.gate_request.id}/answer`, { gate, decision: 'deny' });
  });

  it('refuses a loosening the gates turn down, and never lets silence or an API key switch them off', async () => {
    const { gate, as } = await phoneGate();
    expect((await put({ default: [{ any: [gate], timeout_s: 30, on_timeout: 'allow' }] })).status).toBe(200);
    const off = await put({ default: null });
    expect(off.status).toBe(202);
    // Even an allow-on-timeout entry does not pass a loosening by silence.
    t += 31000;
    expect(await put({ default: null })).toMatchObject({ status: 403, body: { code: 'by_timeout_refused' } });
    t += 5 * 60000;
    const again = await put({ default: null });
    await as('POST', `/api/v1/gate-requests/${again.body.gate_request.id}/answer`, { gate, decision: 'deny' });
    expect(await put({ default: null })).toMatchObject({ status: 403, body: { code: 'gate_denied' } });
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k', scopes: ['gates:read', 'gates:write'] } })).body.secret;
    expect(await call(env, 'PUT', '/api/v1/settings/sign-in-gates', { auth: `ApiKey ${key}`, body: { default: null } })).toMatchObject({ status: 403, body: { code: 'session_required' } });
  });
});

describe('dashboard sign-in gate and recovery codes (G6)', () => {
  // "LocalDev alice <session>" names a local browser session.
  const as = (session, method, path, body) => call(env, method, path, { auth: `alice ${session}`, body });

  it('needs recovery codes before a deny-on-timeout dashboard gate', async () => {
    const { gate } = await phoneGate();
    expect((await as('a', 'PUT', '/api/v1/settings/sign-in-gates', { dashboard: [{ any: [gate] }] })).body.code).toBe('recovery_codes_required');
    expect((await as('a', 'PUT', '/api/v1/settings/sign-in-gates', { dashboard: [{ any: [gate], on_timeout: 'allow' }] })).status).toBe(200);
  });

  it('locks other sessions until the gate confirms them, but never revocation', async () => {
    const { gate, as: phone } = await phoneGate();
    const codes = (await as('a', 'POST', '/api/v1/settings/recovery-codes')).body.codes;
    expect(codes).toHaveLength(10);
    expect((await as('a', 'PUT', '/api/v1/settings/sign-in-gates', { dashboard: [{ any: [gate], timeout_s: 120 }] })).status).toBe(200);
    // Session "a" made the change; it too is now held, like every session (a recent sign-in is no bypass).
    expect((await as('b', 'GET', '/api/v1/account')).body.code).toBe('sign_in_gate_required');
    expect((await as('b', 'GET', '/api/v1/session')).body).toMatchObject({ dashboard: 'locked', recovery_codes_left: 10 });
    expect((await as('b', 'GET', '/api/v1/whoami')).status).toBe(200);
    const pending = (await as('b', 'POST', '/api/v1/session/confirm', {})).body;
    expect(pending).toMatchObject({ status: 'pending', gate_request: { purpose: 'dashboard', number: expect.stringMatching(/^\d\d$/) } });
    // A locked session cannot answer gate requests (it might approve someone's step-up).
    expect((await as('b', 'POST', `/api/v1/gate-requests/${pending.gate_request.id}/answer`, { gate: 'owner', decision: 'allow' })).body.code).toBe('sign_in_gate_required');
    await phone('POST', `/api/v1/gate-requests/${pending.gate_request.id}/answer`, { gate, decision: 'allow', number: pending.gate_request.number });
    expect((await as('b', 'POST', '/api/v1/session/confirm', {})).body.status).toBe('confirmed');
    expect((await as('b', 'GET', '/api/v1/account')).status).toBe(200);
    // Another session is still locked, and can still revoke (the panic button always works).
    const cid = inspectCredential((await enroll(env, 'alice b', await newDevice())).approve.body.credential).payload.cid;
    expect((await as('c', 'GET', '/api/v1/credentials')).body.code).toBe('sign_in_gate_required');
    expect((await as('c', 'DELETE', `/api/v1/credentials/${cid}`)).status).toBe(200);
    expect((await as('c', 'POST', '/api/v1/revoke-all', { confirm: 'revoke-all' })).status).toBe(200);
  });

  it('opens with a recovery code, once per code, and tells every browser', async () => {
    const { gate } = await phoneGate();
    const codes = (await as('a', 'POST', '/api/v1/settings/recovery-codes')).body.codes;
    await as('a', 'PUT', '/api/v1/settings/sign-in-gates', { dashboard: [{ any: [gate] }] });
    expect((await as('b', 'POST', '/api/v1/session/recover', { code: 'AAAA-BBBB-CCCC' })).body.code).toBe('invalid_recovery_code');
    expect((await as('b', 'POST', '/api/v1/session/recover', { code: codes[3].toLowerCase() })).body).toMatchObject({ status: 'confirmed', recovery_codes_left: 9 });
    expect((await as('b', 'GET', '/api/v1/account')).status).toBe(200);
    expect((await as('c', 'POST', '/api/v1/session/recover', { code: codes[3] })).body.code).toBe('invalid_recovery_code');
    expect(await audit('alice b')).toContain('recovery_code.used');
  });
});
