import { it, expect } from 'vitest';
import { generateKeyPair, exportPublicJwk, signJws, verifyEvent, validateEventPayload, EVENT_TYP } from './index.js';

const ISS = 'https://devicebasedauth.org';
async function issuer() {
  const pair = await generateKeyPair(true);
  const jwk = { ...(await exportPublicJwk(pair.publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' };
  return { jwks: { keys: [jwk] }, sign: (payload, header = {}) => signJws({ typ: EVENT_TYP, kid: 'k1', ...header }, payload, pair.privateKey) };
}
const now = 1795000000;
const revoked = { iss: ISS, aud: 'hashbin.org', iat: now, jti: 'evt_1', type: 'credentials.revoked', credentials: [{ cid: 'crd_1', jti: 'crd_1.1', exp: now + 3600, revoked_at: now, status: { idx: 7, uri: 'https://status.devicebasedauth.org/v1/lists/0' } }] };

it('verifies a signed revocation event for its audience', async () => {
  const { jwks, sign } = await issuer();
  const { payload } = await verifyEvent(await sign(revoked), { jwks, audience: 'hashbin.org', now });
  expect(payload.credentials[0].status.idx).toBe(7);
});

it('refuses the wrong audience, type, issuer, age, key and shape', async () => {
  const { jwks, sign } = await issuer();
  const other = await issuer();
  const cases = [
    [await sign(revoked), { audience: 'cronly.org' }, 'wrong_audience'],
    [await sign(revoked, { typ: 'dba-device+jwt' }), {}, 'wrong_type'],
    [await sign({ ...revoked, iss: 'https://evil.example' }), {}, 'wrong_issuer'],
    [await sign({ ...revoked, iat: now - 601 }), {}, 'stale_event'],
    [await sign({ ...revoked, iat: now + 120 }), {}, 'stale_event'],
    [await other.sign(revoked), {}, 'invalid_signature'],
    [await sign(revoked, { kid: 'k2' }), {}, 'unknown_kid'],
    [await sign({ ...revoked, credentials: [] }), {}, 'invalid_claims'],
    [await sign({ ...revoked, type: 'credentials.deleted' }), {}, 'invalid_claims'],
    ['not a jws', {}, 'invalid_format']
  ];
  for (const [jws, options, code] of cases) {
    await expect(verifyEvent(jws, { jwks, audience: 'hashbin.org', now, ...options }), code).rejects.toMatchObject({ code });
  }
});

it('describes every problem in a malformed payload', () => {
  expect(validateEventPayload(revoked)).toEqual([]);
  expect(validateEventPayload({ ...revoked, aud: ['hashbin.org'], credentials: [{ cid: 1, status: { idx: -1 } }] })).toHaveLength(4);
  expect(validateEventPayload({ iss: ISS, aud: 'a', iat: now, jti: 'e', type: 'webhook.test' })).toEqual([]);
});
