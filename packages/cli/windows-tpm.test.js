import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { windowsTpm, pcpScript, eccPublicBlob, eccPublicBlobJwk, newKeyName, WindowsTpmError, WINDOWS_TPM_BACKEND } from './windows-tpm.js';
import { powershellEncoded } from './powershell.js';
import { windowsTpmKeyFile, loadDeviceKey, forgetDeviceKey, enrollmentPayload, signEnrollmentRequest, rotationProof, createClient, pollEnrollment, credentialMatchesKey, UsageError } from './lib.js';
import { verifyJws, verifyProof, createProof, inspectCredential, jwkThumbprint, exportPublicJwk } from '../verify/src/index.js';
import { testEnv, call, worker, ORIGIN } from '../../test-utils/env.js';

const toBase64 = bytes => btoa(String.fromCharCode(...bytes));
const fromBase64 = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
/** -EncodedCommand back to the script. */
const decodeScript = encoded => { const bytes = fromBase64(encoded); let s = ''; for (let i = 0; i < bytes.length; i += 2) s += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8)); return s; };

/**
 * A stand-in for powershell.exe with the Platform Crypto Provider behind it: it accepts only
 * the exact scripts pcpScript makes (so the data must come on stdin), and keeps non-extractable
 * WebCrypto keys by name, as the provider keeps TPM keys.
 */
function fakePowershell({ refuse } = {}) {
  const keys = new Map(); const calls = [];
  const run = async (command, args, input) => {
    calls.push({ command, args, input });
    expect(command).toBe('powershell.exe');
    expect(args.slice(0, 4)).toEqual(['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']);
    const script = decodeScript(args[4]);
    const name = script.match(/'(dba-[0-9a-f]{32})'/)?.[1];
    const mode = ['create', 'sign', 'delete'].find(m => script === pcpScript(m, name));
    expect(mode).toBeDefined();
    if (refuse) return { code: 1, stdout: `error:${refuse}` };
    if (mode === 'create') {
      if (keys.has(name)) return { code: 1, stdout: 'error:The key already exists.' };
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      keys.set(name, pair);
      return { code: 0, stdout: `${toBase64(eccPublicBlob(await exportPublicJwk(pair.publicKey)))}\r\n` };
    }
    const pair = keys.get(name);
    if (!pair) return { code: 1, stdout: 'error:Keyset does not exist' };
    if (mode === 'delete') { keys.delete(name); return { code: 0, stdout: '' }; }
    const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, fromBase64(input)));
    return { code: 0, stdout: `${toBase64(eccPublicBlob(await exportPublicJwk(pair.publicKey)))}.${toBase64(signature)}` };
  };
  return { run, keys, calls };
}

describe('Windows TPM keys (Platform Crypto Provider through PowerShell)', () => {
  it('makes a key the provider keeps and signs JWS and DPoP proofs that verify', async () => {
    const ps = fakePowershell();
    const tpm = windowsTpm({ run: ps.run });
    const made = await tpm.create();
    expect(made.keyName).toMatch(/^dba-[0-9a-f]{32}$/);
    const file = windowsTpmKeyFile(made, new Date(0));
    expect(file).toEqual({ public_jwk: made.publicJwk, key_protection: 'tpm', key_store: WINDOWS_TPM_BACKEND, key_name: made.keyName, created_at: '1970-01-01T00:00:00.000Z' });
    const key = await loadDeviceKey(file, { tpm });
    expect(key.privateJwk).toBeNull();
    const proof = await createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method: 'POST', url: 'https://hashbin.org/x' });
    expect(await verifyProof(proof, { method: 'POST', url: 'https://hashbin.org/x', jkt: await jwkThumbprint(key.publicJwk) })).toMatchObject({ htm: 'POST' });
    expect(await verifyJws(await signEnrollmentRequest(key, { iat: 1 }), made.publicJwk)).not.toBeNull();
    // Data goes on stdin; no command line carries anything but the fixed script.
    for (const call of ps.calls.slice(1)) expect(call.input).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
  });

  it('refuses a key replaced under the same name, and reports the provider\'s own error', async () => {
    const ps = fakePowershell();
    const tpm = windowsTpm({ run: ps.run });
    const made = await tpm.create();
    const key = await loadDeviceKey(windowsTpmKeyFile(made), { tpm });
    ps.keys.set(made.keyName, await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']));
    await expect(createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method: 'GET', url: 'https://x.test/' })).rejects.toThrow(/does not match key\.json/);
    ps.keys.delete(made.keyName);
    await expect(createProof({ privateKey: key.privateKey, publicJwk: key.publicJwk, method: 'GET', url: 'https://x.test/' })).rejects.toThrow('the Platform Crypto Provider refused: Keyset does not exist');
    await expect(windowsTpm({ run: fakePowershell({ refuse: 'The TPM is not ready.' }).run }).create()).rejects.toThrow('refused: The TPM is not ready.');
    await expect(windowsTpm({ run: async () => ({ code: null, stdout: '' }) }).create()).rejects.toThrow(WindowsTpmError);
    await expect(windowsTpm({ run: async () => ({ code: 0, stdout: 'not base64!' }) }).create()).rejects.toThrow('no public key');
  });

  it('deletes the key when the profile forgets it, and only for its own backend', async () => {
    const ps = fakePowershell();
    const tpm = windowsTpm({ run: ps.run });
    const made = await tpm.create();
    const file = windowsTpmKeyFile(made);
    await forgetDeviceKey(file, { secrets: null });
    expect(ps.keys.has(made.keyName)).toBe(true);
    await forgetDeviceKey(file, { tpm });
    expect(ps.keys.has(made.keyName)).toBe(false);
    await forgetDeviceKey(file, { tpm }); // already gone: never throws
    await expect(loadDeviceKey(file, { tpm: { backend: 'tpm' } })).rejects.toThrow(UsageError);
    await expect(loadDeviceKey({ ...file, key_name: 7 }, { tpm })).rejects.toThrow(/cannot load/);
  });

  it('reads only P-256 public blobs and puts only checked names in scripts', () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' };
    expect(eccPublicBlobJwk(eccPublicBlob(jwk))).toEqual(jwk);
    const p384 = eccPublicBlob(jwk); new DataView(p384.buffer).setUint32(0, 0x33534345, true);
    expect(() => eccPublicBlobJwk(p384)).toThrow(/not a P-256/);
    expect(() => eccPublicBlobJwk(eccPublicBlob(jwk).subarray(0, 71))).toThrow(/not a P-256/);
    expect(() => pcpScript('sign', "dba-x');Remove-Item C:\\")).toThrow(WindowsTpmError);
    expect(() => pcpScript('export', newKeyName())).toThrow(WindowsTpmError);
    const name = newKeyName();
    expect(pcpScript('create', name)).toContain('CngExportPolicies]::None');
    expect(pcpScript('create', name)).toContain("CngProvider('Microsoft Platform Crypto Provider')");
    expect(powershellEncoded(pcpScript('sign', name)).length).toBeLessThan(8000); // command-line limit is 32,767
  });

  describe('against the Worker', () => {
    let env; let client;
    beforeEach(async () => {
      env = await testEnv();
      await call(env, 'POST', '/api/v1/dev/deposit', { auth: 'alice', body: { amount_microdollars: 1_000_000 } });
      client = createClient({ origin: ORIGIN, fetch: (url, init) => worker.fetch(new Request(url, init), env) });
    });

    it('enrolls, calls the API and rotates to a new key in the provider', async () => {
      const tpm = windowsTpm({ run: fakePowershell().run });
      const key = await loadDeviceKey(windowsTpmKeyFile(await tpm.create()), { tpm });
      const request = await signEnrollmentRequest(key, enrollmentPayload({ aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], name: 'Windows TPM test', kind: 'desktop', keyProtection: 'tpm' }));
      const start = await client.request('POST', '/api/v1/enrollments', { body: { request } });
      await call(env, 'POST', '/api/v1/enrollments/approve', { auth: 'alice', body: { request: start.request } });
      const { credential } = await pollEnrollment(client, start, { sleep: async () => {} });
      expect(inspectCredential(credential).payload.device).toMatchObject({ key_protection: 'tpm' });
      expect(inspectCredential(credential).payload.device.attestation).toBeUndefined();
      expect(await client.request('GET', '/api/v1/whoami', { device: { key, credential } })).toMatchObject({ account: 'alice', kind: 'device' });

      const { cid } = inspectCredential(credential).payload;
      const next = await loadDeviceKey(windowsTpmKeyFile(await tpm.create()), { tpm });
      const renewed = await client.request('POST', `/api/v1/credentials/${cid}/renew`, { device: { key, credential }, body: { new_key_proof: await rotationProof(next, cid) } });
      expect(renewed).toMatchObject({ rotated: true });
      expect(await credentialMatchesKey(renewed.credential, next)).toBe(true);
    });
  });
});

describe('the CLI package', () => {
  it('packs every module the CLI imports', () => {
    const { files } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));
    const modules = readdirSync(new URL('.', import.meta.url)).filter(name => name.endsWith('.js') && !name.endsWith('.test.js'));
    expect(modules.filter(name => !files.includes(name))).toEqual([]);
    expect(files).toContain('commands/');
  });
});
