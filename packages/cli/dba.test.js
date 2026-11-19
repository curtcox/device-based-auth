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

describe.runIf(process.platform === 'linux')('dba curl --dba-wait (STATUS B7 G9)', () => {
  it('sends the request again with a fresh proof while the site answers gate_pending, until the owner approves', async () => {
    const { testEnv, call } = await import('../../test-utils/env.js');
    const { createServer } = await import('node:http');
    const env = await testEnv();
    for (const who of ['alice', 'operator']) await call(env, 'POST', '/api/v1/dev/deposit', { auth: who, body: { amount_microdollars: 1_000_000 } });
    const apiKey = (await call(env, 'POST', '/api/v1/keys', { auth: 'operator', body: { name: 'verifier', scopes: ['authorize'] } })).body.secret;

    const t = await setup();
    const fileStore = { DBA_KEY_STORE: 'file' };
    // A site whose deletes need the owner's approval each time, checked online.
    const proofs = []; let approved = false; let server;
    try {
      await t.dba(['enroll', '--aud', 'hashbin.org', '--action', 'hashbin:content:delete', '--print-request'], fileStore);
      const { public_jwk } = JSON.parse(await readFile(join(t.home, 'default', 'key.json'), 'utf8'));
      const issued = await call(env, 'POST', '/api/v1/credentials', { auth: 'alice', body: { public_jwk, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:delete'], require: { gates: [{ any: ['owner'], timeout_s: 120 }] } }] } });
      expect(issued.status).toBe(200);
      await t.dba(['import', issued.body.credential], fileStore);

      server = createServer(async (req, res) => {
        const url = `http://127.0.0.1:${server.address().port}${req.url}`;
        proofs.push(req.headers.dpop);
        const decision = (await call(env, 'POST', '/api/v1/authorize', { auth: `ApiKey ${apiKey}`, body: { credential: req.headers.authorization.slice(4), proof: req.headers.dpop, request: { method: req.method, url }, audience: 'hashbin.org', action: 'hashbin:content:delete', resource: 'abc' } })).body;
        if (decision.code === 'gate_pending' && !approved) {
          // The owner sees it and approves from the dashboard, after the first refusal.
          approved = true;
          setTimeout(() => call(env, 'POST', `/api/v1/gate-requests/${decision.gate_request.id}/answer`, { auth: 'alice', body: { gate: 'owner', decision: 'allow' } }), 200);
        }
        res.writeHead(decision.allow ? 200 : 403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(decision.allow ? { deleted: 'abc' } : { error: 'Not yet', code: decision.code, gate_request: decision.gate_request }));
      });
      await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
      const target = `http://127.0.0.1:${server.address().port}/api/content/abc`;

      const result = await t.dba(['--no-renew', 'curl', '-X', 'DELETE', '--dba-wait=30', target], fileStore);
      expect(JSON.parse(result.stdout)).toEqual({ deleted: 'abc' });
      expect(result.stderr).toMatch(/waiting for this request's gates \(request gtr_/);
      expect(proofs.length).toBeGreaterThanOrEqual(2);
      expect(new Set(proofs).size).toBe(proofs.length); // a fresh proof each time

      // Without --dba-wait, curl shows the site's answer once.
      const once = await t.dba(['--no-renew', 'curl', '-sS', '-X', 'DELETE', target], fileStore);
      expect(once.stdout).toContain('gate_pending');
      // Options that would hide the answer from dba are refused.
      await expect(t.dba(['--no-renew', 'curl', '-sSf', '--dba-wait', target], fileStore)).rejects.toMatchObject({ stderr: expect.stringContaining('drop -f') });
    } finally {
      server?.close();
      await t.cleanup();
    }
  }, 30000);
});
