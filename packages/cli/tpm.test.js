import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseTpmPublic, tpmPublicJwk, parseTpmSignature, createTpmKey, tpmSigner, tpmAttestation, tpmAvailable, TpmError } from './tpm.js';
import { nodeTpmSessions } from './tpm-node.js';
import { tpmKeyFile, loadDeviceKey, keyStoreOption, enrollmentPayload, signEnrollmentRequest, rotationProof, createClient, pollEnrollment, credentialMatchesKey, describeCredential } from './lib.js';
import { verifyJws, verifyProof, createProof, inspectCredential, jwkThumbprint, b64u } from '../verify/src/index.js';
import { testEnv, call, worker, ORIGIN } from '../../test-utils/env.js';

const hex = text => Uint8Array.from(text.match(/../g), byte => parseInt(byte, 16));
// TPM2B_PUBLIC of a key made by swtpm with tpm2_create -G ecc256:ecdsa-sha256 (tpm.js's template).
const KEY_PUB = hex('00580023000b00040072000000100018000b000300100020121af154b553e5403689538447703a72b1cff88c39fa5928becfbe069f74c8720020d02925144c8e4680cd66b435257c8a8b1fdeaf519ebe1aa5b1b9385efb6ddfdd');

/** A session whose tools are scripted: `tools[name](args, files)` returns { code, stderr } and may write files. */
function fakeTpm(tools = {}) {
  const calls = [];
  const open = async () => {
    const files = new Map();
    return {
      run: async (name, args) => { calls.push([name, ...args]); return (tools[name] ?? (() => ({ code: 0, stderr: '' })))(args, files); },
      write: async (name, bytes) => { files.set(name, bytes); },
      read: async name => files.get(name) ?? null,
      close: async () => { calls.push(['close']); }
    };
  };
  return { open, calls };
}

describe('TPM structures', () => {
  it('reads the P-256 point and attributes of a TPM2B_PUBLIC', () => {
    const parsed = parseTpmPublic(KEY_PUB);
    expect(parsed.attributes).toBe(0x00040072); // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign
    expect(tpmPublicJwk(KEY_PUB)).toEqual({
      kty: 'EC', crv: 'P-256',
      x: b64u(hex('121af154b553e5403689538447703a72b1cff88c39fa5928becfbe069f74c872')),
      y: b64u(hex('d02925144c8e4680cd66b435257c8a8b1fdeaf519ebe1aa5b1b9385efb6ddfdd'))
    });
    expect(tpmPublicJwk(KEY_PUB.subarray(2))).toEqual(tpmPublicJwk(KEY_PUB)); // bare TPMT_PUBLIC
  });

  it('refuses areas that are not P-256 keys, or truncated', () => {
    const rsa = KEY_PUB.slice(); rsa[3] = 0x01;
    expect(() => parseTpmPublic(rsa)).toThrow(/not an ECC key/);
    const p384 = KEY_PUB.slice(); p384[19] = 0x04;
    expect(() => parseTpmPublic(p384)).toThrow(/not a P-256 key/);
    expect(() => parseTpmPublic(KEY_PUB.subarray(0, 40))).toThrow(TpmError);
  });

  it('turns a TPMT_SIGNATURE into r ‖ s, padding short integers', () => {
    const r = new Uint8Array(31).fill(1); const s = new Uint8Array(32).fill(2);
    const sig = new Uint8Array([0x00, 0x18, 0x00, 0x0b, 0x00, 31, ...r, 0x00, 32, ...s]);
    const raw = parseTpmSignature(sig);
    expect(raw).toHaveLength(64);
    expect(raw[0]).toBe(0);
    expect(raw.subarray(1, 32)).toEqual(r);
    expect(raw.subarray(32)).toEqual(s);
    expect(() => parseTpmSignature(new Uint8Array([0x00, 0x14, 0, 0, 0, 0, 0, 0]))).toThrow(/ECDSA/);
  });
});

describe('TPM commands (scripted tpm2-tools)', () => {
  it('signs the SHA-256 digest with -d, flushing transient objects, and closes the session', async () => {
    const r = new Uint8Array(32).fill(7); const s = new Uint8Array(32).fill(9);
    const { open, calls } = fakeTpm({
      tpm2_sign: (args, files) => { files.set(args.at(-2) === 'sig.bin' ? 'sig.bin' : args[args.indexOf('-o') + 1], new Uint8Array([0x00, 0x18, 0x00, 0x0b, 0x00, 32, ...r, 0x00, 32, ...s])); return { code: 0, stderr: '' }; }
    });
    const signature = await tpmSigner(open, { public: b64u(KEY_PUB), private: 'AAAA' }).sign(new TextEncoder().encode('abc'));
    expect(signature.subarray(0, 32)).toEqual(r);
    const sign = calls.find(c => c[0] === 'tpm2_sign');
    expect(sign).toEqual(['tpm2_sign', '-c', 'key.ctx', '-g', 'sha256', '-s', 'ecdsa', '-d', '-o', 'sig.bin', 'digest.bin']);
    expect(calls.map(c => c[0])).toEqual(['tpm2_createprimary', 'tpm2_flushcontext', 'tpm2_load', 'tpm2_flushcontext', 'tpm2_sign', 'tpm2_flushcontext', 'close']);
  });

  it('reports the tool\'s own error, and a missing tpm2-tools', async () => {
    const failing = fakeTpm({ tpm2_createprimary: () => ({ code: 1, stderr: 'WARNING: noise\nERROR: Esys_CreatePrimary(0x9A2) - tpm:session(1):authorization failure\n' }) });
    await expect(createTpmKey(failing.open)).rejects.toThrow(/tpm2_createprimary failed: .*authorization failure/);
    expect(failing.calls.at(-1)).toEqual(['close']);
    const missing = fakeTpm({ tpm2_createprimary: () => ({ code: null, stderr: '' }) });
    await expect(createTpmKey(missing.open)).rejects.toThrow(/is tpm2-tools installed/);
    expect(await tpmAvailable(fakeTpm({ tpm2_getcap: () => ({ code: null }) }).open)).toBe(false);
    expect(await tpmAvailable(fakeTpm().open)).toBe(true);
  });

  it('gives up on attestation when the TPM has no EK certificate, before asking the server', async () => {
    const posts = [];
    const { open } = fakeTpm({ tpm2_nvread: () => ({ code: 1, stderr: 'ERROR: index not defined' }) });
    await expect(tpmAttestation(open, { public: b64u(KEY_PUB), private: 'AAAA' }, { post: async path => { posts.push(path); return {}; } })).rejects.toThrow(/no RSA EK certificate/);
    expect(posts).toEqual([]);
  });

  it('loads key.json for a TPM key only when its blob matches public_jwk', async () => {
    const tpm = { open: fakeTpm().open };
    const file = tpmKeyFile({ publicJwk: tpmPublicJwk(KEY_PUB), blobs: { public: b64u(KEY_PUB), private: 'AAAA' } });
    expect(file).toMatchObject({ key_store: 'tpm', key_protection: 'tpm', tpm_parent: 'srk-ecc-p256' });
    expect(file.private_jwk).toBeUndefined();
    const key = await loadDeviceKey(file, { tpm });
    expect(key.publicJwk).toEqual(tpmPublicJwk(KEY_PUB));
    expect(key.privateJwk).toBeNull();
    expect(typeof key.privateKey.sign).toBe('function');
    await expect(loadDeviceKey(file, {})).rejects.toThrow(/needs tpm2-tools/);
    await expect(loadDeviceKey({ ...file, public_jwk: { ...file.public_jwk, x: file.public_jwk.y } }, { tpm })).rejects.toThrow(/does not match/);
    await expect(loadDeviceKey({ ...file, tpm_parent: 'srk-rsa' }, { tpm })).rejects.toThrow(/cannot load/);
    expect(keyStoreOption({ flag: 'TPM' })).toBe('tpm');
  });

  it('describes a credential\'s attestation', () => {
    const lines = describeCredential({ cid: 'crd_1', device: { name: 'pc', kind: 'desktop', key_protection: 'tpm', attestation: { format: 'tpm', security_level: 'tpm', tpm_manufacturer: 'id:4E544300\u001b[2J' } }, grants: [] });
    expect(lines).toContain('Attested:  tpm key (tpm, TPM manufacturer id:4E544300[2J)');
  });
});

// A real (software) TPM, where swtpm and tpm2-tools are installed, as in CI.
const hasSwtpm = ['swtpm', 'tpm2_createprimary', 'tpm2_sign'].every(tool => spawnSync('sh', ['-c', `command -v ${tool}`]).status === 0);

async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise(resolve => server.close(resolve));
  return port;
}

describe.runIf(hasSwtpm)('TPM keys on a software TPM (swtpm)', () => {
  let dir; let swtpm; let open; let env; let client;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'dba-swtpm-'));
    // Another process may take the port (or port + 1) first; try a few, each with time to start.
    for (let attempt = 0; attempt < 3 && !open; attempt++) {
      const port = await freePort(); // the swtpm TCTI finds the control channel at port + 1
      swtpm = spawn('swtpm', ['socket', '--tpm2', '--tpmstate', `dir=${dir}`, '--server', `type=tcp,port=${port}`, '--ctrl', `type=tcp,port=${port + 1}`, '--flags', 'not-need-init,startup-clear'], { stdio: 'ignore' });
      const candidate = nodeTpmSessions({ env: { TPM2TOOLS_TCTI: `swtpm:host=127.0.0.1,port=${port}` } });
      for (let i = 0; i < 40 && swtpm.exitCode === null; i++) {
        if (await tpmAvailable(candidate)) { open = candidate; break; }
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      if (!open) swtpm.kill();
    }
    if (!open) throw new Error('swtpm did not start');
  }, 60_000);
  afterAll(async () => { swtpm?.kill(); await rm(dir, { recursive: true, force: true }); });
  beforeEach(async () => {
    env = await testEnv();
    await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
    client = createClient({ origin: ORIGIN, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
  });

  it('makes a key that cannot leave the TPM and signs JWS that verify', async () => {
    const made = await createTpmKey(open);
    expect(parseTpmPublic(Uint8Array.from(atob(made.blobs.public.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0))).attributes & 0x72).toBe(0x72);
    const key = await loadDeviceKey(tpmKeyFile(made), { tpm: { open } });
    const proof = await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method: 'POST', url: 'https://hashbin.org/x' });
    expect(await verifyProof(proof, { method: 'POST', url: 'https://hashbin.org/x', jkt: await jwkThumbprint(key.publicJwk) })).toMatchObject({ htm: 'POST' });
    // The blob reloads under a re-created SRK: the same key every time.
    const again = await loadDeviceKey(tpmKeyFile(made), { tpm: { open } });
    expect(await verifyJws(await signEnrollmentRequest(again, { iat: 1 }), key.publicJwk)).not.toBeNull();
  }, 30_000);

  it('enrolls, calls the API and rotates to a new TPM key', async () => {
    const key = await loadDeviceKey(tpmKeyFile(await createTpmKey(open)), { tpm: { open } });
    const request = await signEnrollmentRequest(key, enrollmentPayload({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], name: 'TPM test', kind: 'desktop', keyProtection: 'tpm' }));
    const start = await client.request('POST', '/api/v1/enrollments', { body: { request } });
    await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.request } });
    const { credential } = await pollEnrollment(client, start, { sleep: async () => {} });
    expect(inspectCredential(credential).payload.device).toMatchObject({ key_protection: 'tpm' });
    expect(await client.request('GET', '/api/v1/whoami', { device: { key, credential } })).toMatchObject({ account: 'alice', kind: 'device' });

    const { cid } = inspectCredential(credential).payload;
    const next = await loadDeviceKey(tpmKeyFile(await createTpmKey(open)), { tpm: { open } });
    const renewed = await client.request('POST', `/api/v1/credentials/${cid}/renew`, { device: { key, credential }, body: { new_key_proof: await rotationProof(next, cid) } });
    expect(renewed).toMatchObject({ rotated: true });
    expect(await credentialMatchesKey(renewed.credential, next)).toBe(true);
    expect(await client.request('GET', '/api/v1/whoami', { device: { key: next, credential: renewed.credential } })).toMatchObject({ account: 'alice' });
  }, 60_000);
});
