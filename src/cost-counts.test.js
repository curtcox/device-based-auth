import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { testEnv, call, newDevice, enroll, meter, ORIGIN } from '../test-utils/env.js';
import { inspectCredential, createProof, signJws, sha256b64u, b64u } from '../packages/verify/src/index.js';
import { OPERATIONS } from './utils/cost-policy.js';
import { hotp } from './services/totp.js';

// The worst cases in src/utils/cost-policy.js are what prices are floored on (AGENTS.md: every
// price must pass the price-floor test). These tests measure what the code really does, so a
// handler that starts making another Durable Object request or writing another row fails here
// instead of quietly selling below cost.

const DAY = 86400000;
let env; let m; const realNow = Date.now; let t;
beforeEach(async () => {
  t = realNow(); Date.now = () => t;
  env = await testEnv(); m = meter(env);
  for (const who of ['alice', 'operator']) await call(env, 'POST', '/api/v1/dev/deposit', { auth: who, body: { amount_microdollars: 1_000_000 } });
});
afterEach(() => { Date.now = realNow; });

/** Run `op` once to warm up, move to the next day (so the measured run flushes yesterday's aggregate row), measure it. */
async function measured(op) {
  await op();
  t += DAY; m.reset();
  const result = await op();
  return { ...m.read(), result };
}

describe('cost policy matches the code', () => {
  /**
   * Within the counted worst case: `later` is what the operation prepays but does after this
   * request (pruning and compaction deletes, alarm wake-ups, revocation and its webhooks).
   */
  const within = (op, got, later = { doRequests: 0, rowWrites: 0 }) => {
    expect(got.doRequests + later.doRequests, `${op} DO requests: ${got.ops.join(' ')}`).toBeLessThanOrEqual(OPERATIONS[op].doRequests);
    expect(got.rowWrites + later.rowWrites, `${op} rows written`).toBeLessThanOrEqual(OPERATIONS[op].rowWrites);
  };
  const later = (doRequests, rowWrites) => ({ doRequests, rowWrites });
  // A request that does two priced things (a decision that opens a gate request) fits their sum.
  const withinSum = (ops, got, after = { doRequests: 0, rowWrites: 0 }) => {
    const sum = key => ops.reduce((n, op) => n + OPERATIONS[op][key], 0);
    expect(got.doRequests + after.doRequests, `${ops.join('+')} DO requests: ${got.ops.join(' ')}`).toBeLessThanOrEqual(sum('doRequests'));
    expect(got.rowWrites + after.rowWrites, `${ops.join('+')} rows written`).toBeLessThanOrEqual(sum('rowWrites'));
  };

  it('metered read (worst case: two handler calls), also through MCP', async () => {
    const { approve } = await enroll(env, 'alice', await newDevice());
    const cid = inspectCredential(approve.body.credential).payload.cid;
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k', scopes: ['credentials:read'] } })).body.secret;
    within('read', await measured(() => call(env, 'GET', `/api/v1/credentials/${cid}/decisions`, { auth: `ApiKey ${key}` })));
    // Through MCP: the tool call reuses the /mcp request's authentication and rate limit.
    const mcp = await measured(() => call(env, 'POST', '/mcp', { auth: `ApiKey ${key}`, body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_credential', arguments: { cid } } } }));
    expect(mcp.result.body.result.isError).toBeFalsy();
    within('read', mcp);
    const op = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'k', scopes: ['audiences:read', 'audiences:write'] } })).body.secret;
    within('read', await measured(() => call(env, 'GET', '/api/v1/audiences/hashbin.org/usage', { auth: `ApiKey ${op}` })));
    within('read', await measured(() => call(env, 'POST', '/api/v1/audiences?dry_run=1', { auth: `ApiKey ${op}`, body: {} })));
  });

  it('token and certificate', async () => {
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device)).approve.body.credential;
    const ask = async (path, body) => call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body });
    within('token', await measured(() => ask('/api/v1/token', { audience: 'hashbin.org' })));
    within('token', await measured(() => ask('/api/v1/certificate', {})));
  });

  it('renew and rotate', async () => {
    const device = await newDevice();
    let credential = (await enroll(env, 'alice', device)).approve.body.credential;
    const { cid } = inspectCredential(credential).payload;
    const path = `/api/v1/credentials/${cid}/renew`;
    within('renew', await measured(async () => { const r = await call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body: {} }); credential = r.body.credential; return r; }), later(0, 3));
    let holder = device;
    within('issue', await measured(async () => {
      const next = await newDevice();
      const keyProof = await signJws({ typ: 'dba-rotate+jwt', jwk: next.publicJwk }, { cid, iat: Math.floor(t / 1000) }, next.privateKey);
      const r = await call(env, 'POST', path, { headers: await holder.headers('POST', path, credential), body: { new_key_proof: keyProof } });
      credential = r.body.credential; holder = next; return r;
      // Rotation revokes the old key's status entry now: that revocation (shard request, ~5 rows) was
      // prepaid by the issue it replaces, so it is credited here; the new entry prepays its own.
    }), later(11 - 1, 16 - 5));
  });

  it('issue', async () => {
    within('issue', await measured(() => enroll(env, 'alice', newDeviceSync())), later(11, 16));
    within('issue', await measured(async () => { const d = await newDevice(); return call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk: d.publicJwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }] } }); }), later(11, 16));
    const token = (await call(env, 'POST', '/api/v1/enrollment-tokens', { auth: 'alice', body: { name: 'f', aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], max_uses: 10, expires_in_days: 5 } })).body.token;
    within('issue', await measured(async () => { const d = await newDevice(); return call(env, 'POST', '/api/v1/enrollments/redeem', { body: { enrollment_token: token, request: await d.enrollRequest({ device: { name: 'a', kind: 'agent' } }) } }); }), later(11, 16));
  });

  it('issue by completing a paid sign-up (B9)', async () => {
    Object.assign(env, { STRIPE_SECRET_KEY: 'sk_test', STRIPE_FETCH: async () => new Response(JSON.stringify({ id: 'cs_test_1', url: 'https://checkout.stripe.com/c/pay/cs_test_1' }), { headers: { 'Content-Type': 'application/json' } }) });
    const device = await newDevice();
    const { ticket } = (await call(env, 'POST', '/api/v1/signup', { body: { request: await device.enrollRequest({ device: { name: 'a' } }), credit_cents: 500, accept_terms: true } })).body;
    await call(env, 'POST', '/api/v1/dev/signup-paid', { body: { ticket } });
    // The audience registry seeds itself once per deployment, not per sign-up.
    await enroll(env, 'alice', await newDevice());
    m.reset();
    const proof = await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url: `${ORIGIN}/api/v1/signup/complete`, credential: ticket });
    expect((await call(env, 'POST', '/api/v1/signup/complete', { body: { ticket }, headers: { DPoP: proof } })).body.status).toBe('complete');
    within('issue', m.read(), later(11, 16));
  });

  it('re-verifying a dashboard device through a gate is one gate (B9)', async () => {
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:session'] }] })).approve.body.credential;
    const created = (await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'totp', label: 'App' } })).body;
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0; let value = 0; const secret = [];
    for (const c of created.setup.secret) { value = (value << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { secret.push((value >>> (bits - 8)) & 255); bits -= 8; } }
    const code = () => hotp(new Uint8Array(secret), Math.floor(t / 30000));
    await call(env, 'POST', `/api/v1/gates/${created.id}/activate`, { auth: 'alice', body: { code: await code() } });
    t += 60000;
    const path = '/api/v1/session/reverify';
    const reverify = async body => call(env, 'POST', path, { headers: await device.headers('POST', path, credential), body });
    // Asking is a free dashboard request (like confirming the dashboard sign-in gate); what it
    // writes (the charge and the request row) and the answer are the gate's.
    m.reset();
    expect((await reverify({})).body.status).toBe('pending');
    const opened = m.read(); m.reset();
    expect((await reverify({ gate: created.id, totp: { code: await code() } })).body.status).toBe('reverified');
    const answered = m.read();
    within('gate', { doRequests: answered.doRequests, rowWrites: opened.rowWrites + answered.rowWrites, ops: [...opened.ops, ...answered.ops] }, later(0, 1));
  });

  it('recovery onto a new device: an issue, given free and bounded by the codes (B9)', async () => {
    const { codes } = (await call(env, 'POST', '/api/v1/settings/recovery-codes', { auth: 'alice' })).body;
    await enroll(env, 'alice', await newDevice()); // the registry seeds itself once per deployment
    const recover = async code => { const d = await newDevice(); return call(env, 'POST', '/api/v1/recover', { body: { account: 'alice', code, request: await d.enrollRequest({ device: { name: 'p' } }) } }); };
    within('issue', await measured(async () => { const r = await recover(codes.shift()); expect(r.body.status).toBe('recovered'); return r; }), later(11, 16));
  });

  it('decision', async () => {
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'v', scopes: ['authorize'] } })).body.secret;
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { grants: [{ actions: ['hashbin:content:write'], limits: { uses: { count: 5, per: 'day' } } }, { actions: ['hashbin:content:delete'], require: { step_up: true } }] })).approve.body.credential;
    const url = 'https://hashbin.org/api/content';
    const ask = async action => call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key}`, body: { credential, proof: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }), request: { method: 'POST', url }, audience: 'hashbin.org', action } });
    within('decision', await measured(() => ask('hashbin:content:write')), later(0, 2));
    // Asking for a step-up opens a gate request, paid by the gates' owner (alice) as one gate.
    withinSum(['decision', 'gate'], await measured(async () => { const r = await ask('hashbin:content:delete'); t += 11 * 60000; return r; }), later(0, 2));
  });

  it('gate answer and settlement by timeout', async () => {
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'v', scopes: ['authorize'] } })).body.secret;
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { grants: [{ actions: ['hashbin:content:delete'], require: { gates: [{ any: ['owner'], timeout_s: 60, on_timeout: 'allow' }] } }] })).approve.body.credential;
    const url = 'https://hashbin.org/api/content';
    const ask = async () => call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key}`, body: { credential, proof: await createProof({ privateKey: device.privateKey, publicJwk: device.publicJwk, method: 'POST', url, credential }), request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:delete' } });
    // The answer: its own request; the decision that spends the approval deletes the row (later).
    within('gate', await measured(async () => {
      const pending = (await ask()).body.gate_request;
      m.reset();
      return call(env, 'POST', `/api/v1/gate-requests/${pending.id}/answer`, { auth: 'alice', body: { gate: 'owner', decision: 'allow' } });
    }), later(1, 2 + 1));
    // A TOTP answer on the approval page (no authentication request; it rewrites the gate row).
    const created = (await call(env, 'POST', '/api/v1/gates', { auth: 'alice', body: { kind: 'totp', label: 'App' } })).body;
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0; let value = 0; const secret = [];
    for (const c of created.setup.secret) { value = (value << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { secret.push((value >>> (bits - 8)) & 255); bits -= 8; } }
    const code = () => hotp(new Uint8Array(secret), Math.floor(t / 30000));
    await call(env, 'POST', `/api/v1/gates/${created.id}/activate`, { auth: 'alice', body: { code: await code() } });
    const totpDevice = await newDevice();
    const totpCredential = (await enroll(env, 'alice', totpDevice, { grants: [{ actions: ['hashbin:content:write'], require: { gates: [{ any: [created.id] }] } }] })).approve.body.credential;
    const askTotp = async () => call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${key}`, body: { credential: totpCredential, proof: await createProof({ privateKey: totpDevice.privateKey, publicJwk: totpDevice.publicJwk, method: 'POST', url, credential: totpCredential }), request: { method: 'POST', url }, audience: 'hashbin.org', action: 'hashbin:content:write' } });
    within('gate', await measured(async () => {
      t += 30000;
      const link = (await askTotp()).body.gate_request.approve_url.split('#')[1];
      m.reset();
      return call(env, 'POST', `/api/v1/gate-links/${link}/answer`, { body: { gate: created.id, decision: 'allow', totp: { code: await code() } } });
    }), later(1, 2 + 1));
    // Settling by timeout inside a decision: the decision's own rows plus the gate's settlement.
    withinSum(['decision', 'gate'], await measured(async () => { await ask(); t += 61000; m.reset(); return ask(); }), later(0, 2));
  });

  it('login', async () => {
    const verifier = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const challenge = await sha256b64u(verifier);
    const redirect_uri = 'https://cronly.org/auth/dba/callback';
    within('login', await measured(async () => {
      const approved = await call(env, 'POST', '/oauth/authorize', { auth: 'alice', body: { client_id: 'cronly.org', redirect_uri, response_type: 'code', scope: 'openid', code_challenge: challenge, code_challenge_method: 'S256', approve: true } });
      const form = new URLSearchParams({ grant_type: 'authorization_code', code: new URL(approved.body.redirect).searchParams.get('code'), redirect_uri, client_id: 'cronly.org', code_verifier: verifier });
      return call(env, 'POST', '/oauth/token', { body: form.toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    }), later(1, 1));
  });

  it('audience change', async () => {
    let n = 0;
    within('audience', await measured(() => call(env, 'PATCH', '/api/v1/audiences/hashbin.org', { auth: 'operator', body: { description: `v${n++}` } })), later(0, 3));
  });
});

function newDeviceSync() { return newDevicePromise; }
let newDevicePromise;
beforeEach(async () => { newDevicePromise = await newDevice(); });

describe('MCP tool calls as a device', () => {
  it('work with a device credential: the forwarded call reuses the /mcp proof instead of replaying it', async () => {
    const device = await newDevice();
    const credential = (await enroll(env, 'alice', device, { aud: ['devicebasedauth.org'], grants: [{ actions: ['dba:credentials:read'] }] })).approve.body.credential;
    const { cid } = inspectCredential(credential).payload;
    const res = await call(env, 'POST', '/mcp', { headers: await device.headers('POST', '/mcp', credential), body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_credential', arguments: { cid } } } });
    expect(res.body.result.isError).toBeFalsy();
    expect(JSON.parse(res.body.result.content[0].text).cid).toBe(cid);
    // Grants still apply: this device may not read the balance.
    const denied = await call(env, 'POST', '/mcp', { headers: await device.headers('POST', '/mcp', credential), body: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'balance', arguments: {} } } });
    expect(denied.body.result.isError).toBe(true);
  });
});

describe('day rollover', () => {
  it('writes yesterday\'s aggregate rows once, however often the account is read', async () => {
    const key = (await call(env, 'POST', '/api/v1/keys', { auth: 'alice', body: { name: 'k', scopes: ['credentials:read'] } })).body.secret;
    await call(env, 'GET', '/api/v1/credentials', { auth: `ApiKey ${key}` }); // a metered read: yesterday's aggregate
    t += DAY; m.reset();
    await call(env, 'GET', '/api/v1/account', { auth: 'alice' });
    const first = m.read().rowWrites;
    expect(first).toBe(2); // the aggregate ledger row and the rolled balance row
    m.reset();
    for (let i = 0; i < 3; i++) await call(env, 'GET', '/api/v1/account', { auth: 'alice' });
    expect(m.read().rowWrites).toBe(0);
    const ledger = (await call(env, 'GET', '/api/v1/transactions', { auth: 'alice' })).body.items;
    expect(ledger.filter(r => r.aggregate)).toHaveLength(1);
  });
});
