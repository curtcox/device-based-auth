import { it, expect } from 'vitest';
import { ReplayCacheDO, durableReplayCache, REPLAY_TTL, createVerifier, createProof, generateKeyPair, exportPublicJwk, verifyProof } from './index.js';

/** Minimal Durable Object storage and namespace stand-ins. */
function memoryNamespace() {
  const objects = new Map(); let calls = 0;
  const storageFor = () => {
    const rows = new Map(); let alarm = null;
    return { rows, get: async k => rows.get(k), put: async (k, v) => { rows.set(k, v); }, delete: async keys => { for (const k of [].concat(keys)) rows.delete(k); },
      list: async ({ prefix = '', limit = Infinity }) => new Map([...rows].filter(([k]) => k.startsWith(prefix)).slice(0, limit)), getAlarm: async () => alarm, setAlarm: async t => { alarm = t; } };
  };
  return {
    objects, get calls() { return calls; },
    idFromName: name => name,
    get(id) {
      if (!objects.has(id)) objects.set(id, new ReplayCacheDO({ storage: storageFor() }));
      const object = objects.get(id);
      return { fetch: (url, init) => { calls++; return object.fetch(new Request(url, init)); } };
    }
  };
}

it('claims each proof id once across isolates', async () => {
  const ns = memoryNamespace();
  const isolateA = durableReplayCache(ns, { shards: 4 }); const isolateB = durableReplayCache(ns, { shards: 4 });
  const now = 1795000000;
  expect(await isolateA.check('jkt:1', now)).toBe(true);
  expect(await isolateB.check('jkt:1', now)).toBe(false); // the other isolate sees it
  expect(await isolateA.check('jkt:1', now)).toBe(false); // answered locally
  expect(ns.calls).toBe(2);
  expect(await isolateB.check('jkt:2', now)).toBe(true);
  expect(await isolateA.check('jkt:1', now + REPLAY_TTL + 1)).toBe(true); // forgotten after the TTL
});

it('fails closed when the object is unreachable, unless failOpen', async () => {
  const broken = { idFromName: n => n, get: () => ({ fetch: async () => { throw new Error('down'); } }) };
  expect(await durableReplayCache(broken).check('k', 1)).toBe(false);
  expect(await durableReplayCache(broken, { failOpen: true }).check('k', 1)).toBe(true);
  expect(() => durableReplayCache({})).toThrow();
});

it('validates requests and prunes expired ids by alarm', async () => {
  const ns = memoryNamespace();
  const stub = ns.get('x'); const object = ns.objects.get('x');
  expect((await stub.fetch('https://r/', { method: 'POST', body: '{"keys":[]}' })).status).toBe(400);
  const now = Math.floor(Date.now() / 1000);
  const answer = await (await stub.fetch('https://r/', { method: 'POST', body: JSON.stringify({ keys: ['a', 'b', 'a'], now: now - REPLAY_TTL - 5 }) })).json();
  expect(answer.fresh).toEqual([true, true, false]);
  expect(object.storage.rows.size).toBe(2);
  await object.alarm();
  expect(object.storage.rows.size).toBe(0);
});

it('plugs into createVerifier and verifyProof', async () => {
  const pair = await generateKeyPair(false);
  const publicJwk = await exportPublicJwk(pair.publicKey);
  const url = 'https://example.com/x';
  const proof = await createProof({ privateKey: pair.privateKey, publicJwk, method: 'POST', url });
  const replay = durableReplayCache(memoryNamespace());
  await verifyProof(proof, { method: 'POST', url, replay });
  await expect(verifyProof(proof, { method: 'POST', url, replay: durableReplayCache(memoryNamespace()) })).resolves.toBeTruthy();
  await expect(verifyProof(proof, { method: 'POST', url, replay })).rejects.toMatchObject({ code: 'replayed_proof' });
  expect(() => createVerifier({ audience: 'example.com', replay })).not.toThrow();
});
