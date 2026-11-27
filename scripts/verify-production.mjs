// Post-deploy checks against the live site. No sign-in, no spending.
import { FIRST_PARTY } from '../src/services/first-party.js';

const origin = process.env.DBA_ORIGIN || 'https://devicebasedauth.org';
const failures = [];
const check = async (name, fn) => { try { await fn(); console.log(`ok   ${name}`); } catch (error) { failures.push(name); console.error(`FAIL ${name}: ${error.message}`); } };
const json = async path => { const r = await fetch(`${origin}${path}`); if (!r.ok) throw new Error(`${path} → ${r.status}`); return r.json(); };
await check('health and deployed commit', async () => { const h = await json('/health'); if (process.env.EXPECTED_GIT_SHA && h.git_sha !== process.env.EXPECTED_GIT_SHA) throw new Error(`git_sha ${h.git_sha}`); });
await check('JWKS publishes only public keys', async () => { const j = await json('/.well-known/jwks.json'); if (!j.keys?.length || j.keys.some(k => k.d)) throw new Error('bad JWKS'); });
await check('OpenID configuration', async () => { const c = await json('/.well-known/openid-configuration'); if (c.issuer !== origin) throw new Error(c.issuer); });
for (const expected of FIRST_PARTY) await check(`audience ${expected.name}`, async () => {
  const audience = await json(`/api/v1/audiences/${expected.name}`);
  if (!audience.first_party || audience.namespace !== expected.namespace) throw new Error('wrong first-party namespace');
  const actions = new Set(audience.catalog?.map(entry => entry.action));
  for (const entry of expected.catalog) if (!actions.has(entry.action)) throw new Error(`missing action ${entry.action}`);
  for (const uri of expected.redirect_uris) if (!audience.redirect_uris?.includes(uri)) throw new Error(`missing redirect ${uri}`);
});
await check('quote', async () => { const q = await json('/api/v1/quote?op=issue'); if (!Number.isSafeInteger(q.quote_microdollars)) throw new Error('no quote'); });
await check('status list', async () => { const r = await fetch(`${origin}/status/v1/lists/0`); if (!r.ok || !(await r.text()).startsWith('ey')) throw new Error(String(r.status)); });
await check('local auth refused', async () => { const r = await fetch(`${origin}/api/v1/account`, { headers: { Authorization: 'LocalDev x' } }); if (r.status !== 401) throw new Error(String(r.status)); });
await check('home page', async () => { const r = await fetch(origin); if (!r.ok) throw new Error(String(r.status)); });
if (failures.length) process.exit(1);
