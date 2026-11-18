import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, readFile, readdir, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { inspectCredential, jwkThumbprint } from '../verify/src/index.js';

const run = promisify(execFile);
const DBA = new URL('./dba.js', import.meta.url).pathname;

// A stand-in for secret-tool that keeps each secret in a file named by its account, so the test
// exercises dba.js's real process handling (stdin, exit codes) without a desktop keyring.
const FAKE_SECRET_TOOL = `#!/bin/sh
dir="$FAKE_KEYRING"
cmd="$1"; shift
[ "$FAKE_KEYRING_BROKEN" = 1 ] && exit 1
while [ $# -gt 0 ]; do case "$1" in account) account="$2"; shift 2;; *) shift;; esac; done
case "$cmd" in
  store) cat > "$dir/$account" ;;
  lookup) [ -f "$dir/$account" ] && cat "$dir/$account" ;;
  clear) rm -f "$dir/$account" ;;
esac
`;

async function setup() {
  const root = await mkdtemp(join(tmpdir(), 'dba-cli-'));
  const bin = join(root, 'bin'); const keyring = join(root, 'keyring'); const home = join(root, 'home');
  await run('mkdir', ['-p', bin, keyring, home]);
  await writeFile(join(bin, 'secret-tool'), FAKE_SECRET_TOOL);
  await chmod(join(bin, 'secret-tool'), 0o755);
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, DBA_HOME: home, FAKE_KEYRING: keyring, DBA_ORIGIN: 'http://127.0.0.1:9' };
  delete env.DBA_KEY_STORE;
  const dba = (args, extra = {}) => run(process.execPath, [DBA, ...args], { env: { ...env, ...extra } });
  return { root, keyring, home, dba, cleanup: () => rm(root, { recursive: true, force: true }) };
}

const request = ['enroll', '--aud', 'hashbin.org', '--action', 'hashbin:content:write', '--print-request'];

describe.runIf(process.platform === 'linux')('dba enroll with the OS secret store (fake secret-tool)', () => {
  it('keeps the private key in the keyring, says os-keychain, and clears the old entry on --force', async () => {
    const t = await setup();
    try {
      const first = await t.dba(request);
      const { header, payload } = inspectCredential(first.stdout.trim());
      expect(payload.device.key_protection).toBe('os-keychain');
      expect(first.stderr).toContain('Secret Service');
      const file = JSON.parse(await readFile(join(t.home, 'default', 'key.json'), 'utf8'));
      const account = await jwkThumbprint(header.jwk);
      expect(file).toMatchObject({ key_store: 'secret-service', key_store_account: account, public_jwk: header.jwk });
      expect(file.private_jwk).toBeUndefined();
      expect(await readdir(t.keyring)).toEqual([account]);

      await t.dba([...request, '--force']);
      const entries = await readdir(t.keyring);
      expect(entries).toHaveLength(1);
      expect(entries[0]).not.toBe(account);
    } finally { await t.cleanup(); }
  });

  it('falls back to a 0600 file when the keyring fails, and refuses with --key-store os', async () => {
    const t = await setup();
    try {
      const fallback = await t.dba(request, { FAKE_KEYRING_BROKEN: '1' });
      expect(inspectCredential(fallback.stdout.trim()).payload.device.key_protection).toBe('software');
      expect(fallback.stderr).toContain('is not available');
      const file = JSON.parse(await readFile(join(t.home, 'default', 'key.json'), 'utf8'));
      expect(file.private_jwk.d).toBeTruthy();
      await expect(t.dba([...request, '--force', '--key-store', 'os'], { FAKE_KEYRING_BROKEN: '1' })).rejects.toMatchObject({ stderr: expect.stringContaining('Could not keep the key') });
      const file2 = await t.dba([...request, '--force', '--key-store', 'file']);
      expect(inspectCredential(file2.stdout.trim()).payload.device.key_protection).toBe('software');
      expect(await readdir(t.keyring)).toEqual([]);
    } finally { await t.cleanup(); }
  });
});
