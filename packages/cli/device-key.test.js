import { describe, it, expect } from 'vitest';
import { UsageError } from './errors.js';
import { newDeviceKey, loadDeviceKey, keyStoreOption, osSecretStore, powershellEncoded, dpapiScript, saveDeviceKey, forgetDeviceKey, SECRET_SERVICE } from './device-key.js';
import { rotationProof } from './enrollment.js';
import { verifyJws, jwkThumbprint } from '../verify/src/index.js';

/** A secret store backed by a Map, standing in for osSecretStore. */
function memoryStore({ saves = true, reads = true } = {}) {
  const entries = new Map();
  return {
    entries, backend: 'secret-service', name: 'the test keyring', removed: [],
    async save(account, secret) { if (saves) entries.set(account, secret); return true; },
    async load(account) { return reads ? entries.get(account) ?? null : null; },
    async remove(account) { this.removed.push(account); entries.delete(account); }
  };
}

describe('OS secret store', () => {
  function recorder(results = {}) {
    const calls = [];
    return { calls, run: async (command, args, input) => { calls.push({ command, args, input }); return results[args[0]] ?? { code: 0, stdout: '' }; } };
  }

  it('keeps the secret off the command line on macOS (security -i reads it from stdin)', async () => {
    const { calls, run } = recorder({ 'find-generic-password': { code: 0, stdout: 'c2VjcmV0\n' } });
    const store = osSecretStore({ platform: 'darwin', run });
    const account = 'A'.repeat(43);
    expect(await store.save(account, 'c2VjcmV0')).toBe(true);
    expect(await store.load(account)).toBe('c2VjcmV0');
    await store.remove(account);
    expect(calls[0]).toEqual({ command: 'security', args: ['-i'], input: `add-generic-password -U -s ${SECRET_SERVICE} -a ${account} -l dba-cli-device-key -w c2VjcmV0\n` });
    expect(calls[1].args).toEqual(['find-generic-password', '-s', SECRET_SERVICE, '-a', account, '-w']);
    expect(calls[2].args).toEqual(['delete-generic-password', '-s', SECRET_SERVICE, '-a', account]);
    for (const call of calls) expect(call.args.join(' ')).not.toContain('c2VjcmV0');
  });

  it('uses secret-tool on Linux, with the secret on stdin', async () => {
    const { calls, run } = recorder({ lookup: { code: 0, stdout: 'c2VjcmV0' } });
    const store = osSecretStore({ platform: 'linux', run });
    const account = 'B'.repeat(43);
    await store.save(account, 'c2VjcmV0');
    expect(await store.load(account)).toBe('c2VjcmV0');
    await store.remove(account);
    expect(calls.map(call => [call.command, ...call.args])).toEqual([
      ['secret-tool', 'store', '--label=dba CLI device key', 'service', SECRET_SERVICE, 'account', account],
      ['secret-tool', 'lookup', 'service', SECRET_SERVICE, 'account', account],
      ['secret-tool', 'clear', 'service', SECRET_SERVICE, 'account', account]
    ]);
    expect(calls[0].input).toBe('c2VjcmV0');
  });

  it('reports a missing or failing program as no entry, and has no store on Windows', async () => {
    const store = osSecretStore({ platform: 'linux', run: async () => ({ code: null, stdout: '' }) });
    expect(await store.save('C'.repeat(43), 'abc')).toBe(false);
    expect(await store.load('C'.repeat(43))).toBeNull();
    expect(osSecretStore({ platform: 'win32', run: async () => ({ code: 0, stdout: '' }) })).toBeNull();
    expect(osSecretStore({ platform: 'aix', run: async () => ({ code: 0, stdout: '' }), files: {}, dir: '/x' })).toBeNull();
  });

  it('refuses entry names and secrets that would need quoting', async () => {
    const store = osSecretStore({ platform: 'darwin', run: async () => ({ code: 0, stdout: '' }) });
    await expect(store.save('x -w y', 'abc')).rejects.toThrow(/thumbprint/);
    await expect(store.save('D'.repeat(43), 'a b\nadd-generic-password')).rejects.toThrow(/base64url/);
  });

  it('chooses the store from --key-store, then DBA_KEY_STORE, then auto', () => {
    expect(keyStoreOption({})).toBe('auto');
    expect(keyStoreOption({ env: { DBA_KEY_STORE: 'file' } })).toBe('file');
    expect(keyStoreOption({ flag: 'OS', env: { DBA_KEY_STORE: 'file' } })).toBe('os');
    expect(() => keyStoreOption({ flag: 'hsm' })).toThrow(UsageError);
  });

  it('keeps only the public key in key.json when the store works, and loads it back', async () => {
    const secrets = memoryStore();
    const key = await newDeviceKey();
    const saved = await saveDeviceKey(key, { secrets, now: new Date(0) });
    const account = await jwkThumbprint(key.publicJwk);
    expect(saved.keyProtection).toBe('os-keychain');
    expect(saved.file).toEqual({ public_jwk: key.publicJwk, key_protection: 'os-keychain', key_store: 'secret-service', key_store_account: account, created_at: '1970-01-01T00:00:00.000Z' });
    expect(JSON.stringify(saved.file)).not.toContain(key.privateJwk.d);
    expect(secrets.entries.get(account)).toBe(key.privateJwk.d);

    const loaded = await loadDeviceKey(saved.file, { secrets });
    const proof = await rotationProof(loaded, 'crd_ABCDEFGH', 1800000000);
    expect((await verifyJws(proof, key.publicJwk)).payload.cid).toBe('crd_ABCDEFGH');
    expect(loaded.privateJwk.d).toBe(key.privateJwk.d);

    await expect(loadDeviceKey(saved.file)).rejects.toThrow(/cannot reach/);
    await expect(loadDeviceKey(saved.file, { secrets: { ...secrets, backend: 'macos-keychain' } })).rejects.toThrow(/cannot reach/);
    const other = await newDeviceKey();
    secrets.entries.set(account, other.privateJwk.d);
    await expect(loadDeviceKey(saved.file, { secrets })).rejects.toThrow(/does not belong/);
    await forgetDeviceKey(saved.file, { secrets });
    expect(secrets.entries.has(account)).toBe(false);
    await expect(loadDeviceKey(saved.file, { secrets })).rejects.toThrow(/missing from the Secret Service/);
  });

  it('falls back to the file when the store cannot keep the key, unless told not to', async () => {
    const key = await newDeviceKey();
    const silent = memoryStore({ reads: false }); // reports success, keeps nothing (a locked keyring)
    const fallback = await saveDeviceKey(key, { secrets: silent });
    expect(fallback.keyProtection).toBe('software');
    expect(fallback.file.private_jwk.d).toBe(key.privateJwk.d);
    expect(silent.removed).toEqual([await jwkThumbprint(key.publicJwk)]);
    expect((await saveDeviceKey(key, { secrets: null })).keyProtection).toBe('software');
    await expect(saveDeviceKey(key, { mode: 'os', secrets: silent })).rejects.toThrow(/Could not keep the key in the test keyring/);
    await expect(saveDeviceKey(key, { mode: 'os', secrets: null })).rejects.toThrow(/no OS secret store/);
    const unused = memoryStore();
    expect((await saveDeviceKey(key, { mode: 'file', secrets: unused })).keyProtection).toBe('software');
    expect(unused.entries.size).toBe(0);
    await forgetDeviceKey(fallback.file, { secrets: unused }); // a file key: nothing to remove
    expect(unused.removed).toEqual([]);
  });

  /**
   * A stand-in for powershell.exe that checks the -EncodedCommand is one of the two DPAPI scripts
   * and "seals" by tagging the input with the entry's entropy, so a blob only unseals for its entry.
   */
  function fakePowershell({ code = 0 } = {}) {
    const calls = [];
    const run = async (command, args, input) => {
      calls.push({ command, args, input });
      const script = new TextDecoder('utf-16le').decode(Uint8Array.from(atob(args.at(-1)), c => c.charCodeAt(0)));
      const entropy = /GetBytes\('([^']+)'\)/.exec(script)[1];
      if (code !== 0) return { code, stdout: '' };
      if (script === dpapiScript('protect', entropy.split('/')[1])) return { code: 0, stdout: `${btoa(`${entropy}|${input}`)}\r\n` };
      if (script === dpapiScript('unprotect', entropy.split('/')[1])) {
        const [tag, secret] = atob(input).split('|');
        return tag === entropy ? { code: 0, stdout: secret } : { code: 1, stdout: '' };
      }
      return { code: 1, stdout: '' };
    };
    return { calls, run };
  }
  function memoryFiles() {
    const map = new Map();
    return { map, read: async path => map.get(path) ?? null, write: async (path, text) => { map.set(path, text); }, remove: async path => { map.delete(path); } };
  }

  it('seals with DPAPI on Windows, blob in the profile directory, secret and blob on stdin', async () => {
    const { calls, run } = fakePowershell();
    const files = memoryFiles();
    const store = osSecretStore({ platform: 'win32', run, files, dir: 'C:/Users/me/.config/dba/default' });
    expect(store.backend).toBe('windows-dpapi');
    const account = 'E'.repeat(43);
    expect(await store.save(account, 'c2VjcmV0')).toBe(true);
    const path = `C:/Users/me/.config/dba/default/${account}.dpapi`;
    expect([...files.map.keys()]).toEqual([path]);
    expect(files.map.get(path)).not.toContain('\n');
    expect(await store.load(account)).toBe('c2VjcmV0');
    for (const call of calls) {
      expect(call.command).toBe('powershell.exe');
      expect(call.args.slice(0, -1)).toEqual(['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand']);
      expect(call.args.join(' ')).not.toContain('c2VjcmV0');
    }
    expect(calls[0].input).toBe('c2VjcmV0');
    expect(calls[1].input).toBe(files.map.get(path));
    // A blob moved to another entry's name does not unseal there (the entropy names the entry).
    const other = 'F'.repeat(43);
    files.map.set(`C:/Users/me/.config/dba/default/${other}.dpapi`, files.map.get(path));
    expect(await store.load(other)).toBeNull();
    await store.remove(account);
    expect(files.map.has(path)).toBe(false);
    expect(await store.load(account)).toBeNull();
  });

  it('reports DPAPI failures as no entry and writes nothing', async () => {
    const files = memoryFiles();
    const store = osSecretStore({ platform: 'win32', run: fakePowershell({ code: 1 }).run, files, dir: 'C:/d' });
    expect(await store.save('G'.repeat(43), 'abc')).toBe(false);
    expect(files.map.size).toBe(0);
    files.map.set(`C:/d/${'G'.repeat(43)}.dpapi`, 'not base64!');
    expect(await store.load('G'.repeat(43))).toBeNull();
    await expect(store.save('x y', 'abc')).rejects.toThrow(/thumbprint/);
  });

  it('encodes PowerShell commands as base64 UTF-16LE', () => {
    expect(powershellEncoded('dir')).toBe('ZABpAHIA');
    expect(dpapiScript('protect', 'H'.repeat(43))).toContain(`'${SECRET_SERVICE}/${'H'.repeat(43)}'`);
    expect(dpapiScript('protect', 'x')).toContain('Protect(');
    expect(dpapiScript('unprotect', 'x')).toContain('Unprotect(');
  });
});
