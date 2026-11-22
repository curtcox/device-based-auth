import { describe, it, expect } from 'vitest';
import { createRttChallenger, rttChallengeNeeded, RTT_NONCE_PREFIX } from './rtt.js';
import { generateKeyPair, exportPublicJwk, jwkThumbprint } from './jose.js';
import { createProof, verifyProof } from './credential.js';

const SECRET = 'a test secret that is at least 32 characters long';

describe('RTT challenges', () => {
  it('times the round trip on the verifier\'s own clock', async () => {
    let ms = 1_795_017_600_000;
    const rtt = createRttChallenger({ secret: SECRET, now: () => ms });
    const bind = { jkt: 'jkt-1', peer: '203.0.113.9' };
    const nonce = await rtt.issue(bind);
    expect(nonce.startsWith(RTT_NONCE_PREFIX)).toBe(true);
    ms += 37;
    expect(await rtt.check(nonce, bind)).toEqual({ rtt_ms: 37, samples: 1 });
  });

  it('binds the nonce to the key, the peer address and the secret', async () => {
    let ms = 1000;
    const rtt = createRttChallenger({ secret: SECRET, now: () => ms });
    const nonce = await rtt.issue({ jkt: 'jkt-1', peer: '203.0.113.9' });
    ms += 5;
    expect(await rtt.check(nonce, { jkt: 'jkt-2', peer: '203.0.113.9' })).toBe(null);
    expect(await rtt.check(nonce, { jkt: 'jkt-1', peer: '203.0.113.10' })).toBe(null);
    expect(await createRttChallenger({ secret: `${SECRET}!`, now: () => ms }).check(nonce, { jkt: 'jkt-1', peer: '203.0.113.9' })).toBe(null);
    const at = RTT_NONCE_PREFIX.length + 20; // inside the sealed body, not the last character's spare bits
    const forged = nonce.slice(0, at) + (nonce[at] === 'A' ? 'B' : 'A') + nonce.slice(at + 1);
    expect(await rtt.check(forged, { jkt: 'jkt-1', peer: '203.0.113.9' })).toBe(null);
    expect(await rtt.check('dpn_epochnonce', { jkt: 'jkt-1' })).toBe(null);
    expect(await rtt.check(`${RTT_NONCE_PREFIX}!!`, { jkt: 'jkt-1' })).toBe(null);
  });

  it('is no measurement once older than ten seconds', async () => {
    let ms = 1000;
    const rtt = createRttChallenger({ secret: SECRET, now: () => ms });
    const nonce = await rtt.issue({ jkt: 'k' });
    ms += 10_001;
    expect(await rtt.check(nonce, { jkt: 'k' })).toBe(null);
  });

  it('keeps the best of several samples in the nonce', async () => {
    let ms = 1000;
    const rtt = createRttChallenger({ secret: SECRET, now: () => ms });
    const first = await rtt.issue({ jkt: 'k' }); ms += 80;
    const one = await rtt.check(first, { jkt: 'k' });
    const second = await rtt.issue({ jkt: 'k', samples: one.samples, best_ms: one.rtt_ms }); ms += 30;
    const two = await rtt.check(second, { jkt: 'k' });
    const third = await rtt.issue({ jkt: 'k', samples: two.samples, best_ms: two.rtt_ms }); ms += 120;
    expect(await rtt.check(third, { jkt: 'k' })).toEqual({ rtt_ms: 30, samples: 3 });
  });

  it('refuses a short secret', () => {
    expect(() => createRttChallenger({ secret: 'short' })).toThrow(/32 bytes/);
  });

  it('challenges only when latency alone stands in the way, while samples remain', () => {
    const grants = [{ actions: ['a:b'], net: { client: { latency: { max_rtt_ms: 40, samples: 3 } } } }, { actions: ['a:c'] }];
    expect(rttChallengeNeeded(grants, [['rtt_required'], ['action_not_granted']], null)).toEqual({ samples_left: 3 });
    expect(rttChallengeNeeded(grants, [['rtt_exceeded'], ['action_not_granted']], { samples: 2 })).toEqual({ samples_left: 1 });
    expect(rttChallengeNeeded(grants, [['rtt_exceeded'], ['action_not_granted']], { samples: 3 })).toBe(null);
    expect(rttChallengeNeeded(grants, [['address_not_allowed', 'rtt_required'], ['action_not_granted']], null)).toBe(null);
  });

  it('verifyProof takes a nonce check and reports only its measurement', async () => {
    const pair = await generateKeyPair(); const publicJwk = await exportPublicJwk(pair.publicKey);
    const url = 'https://hashbin.org/api/content';
    const proof = await createProof({ privateKey: pair.privateKey, publicJwk, method: 'POST', url, nonce: 'n-1' });
    const options = { method: 'POST', url, jkt: await jwkThumbprint(publicJwk) };
    expect((await verifyProof(proof, { ...options, nonce: value => ({ ok: value === 'n-1', rtt_ms: 12 }) })).rtt_ms).toBe(12);
    await expect(verifyProof(proof, { ...options, nonce: () => ({ ok: false }) })).rejects.toMatchObject({ code: 'use_dpop_nonce' });
    expect((await verifyProof(proof, options)).rtt_ms).toBe(undefined);
  });
});
