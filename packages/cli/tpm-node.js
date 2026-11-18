/**
 * The Node side of tpm.js: each session is a fresh 0700 directory under the system temp dir where
 * tpm2-tools read and write their files, removed on close. Commands run without a shell, with
 * the directory as their working directory, and inherit TPM2TOOLS_TCTI from the environment.
 */
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SAFE_NAME = /^[a-z][a-z0-9.]*$/;

/** Run one command in `cwd`; resolves to { code, stderr }, code null when it could not start or timed out. */
function runIn(cwd, command, args, { env = process.env, timeoutMs = 60_000 } = {}) {
  return new Promise(resolve => {
    let child;
    try { child = spawn(command, args, { cwd, env, stdio: ['ignore', 'ignore', 'pipe'] }); } catch { resolve({ code: null, stderr: '' }); return; }
    let stderr = '';
    let done = false;
    const finish = code => { if (!done) { done = true; clearTimeout(timer); resolve({ code, stderr }); } };
    const timer = setTimeout(() => { child.kill(); finish(null); }, timeoutMs);
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', chunk => { if (stderr.length < 8192) stderr += chunk; });
    child.on('error', () => finish(null));
    child.on('close', code => finish(code));
  });
}

/** An `open` for tpm.js. `env` overrides the environment (tests point TPM2TOOLS_TCTI at a swtpm). */
export function nodeTpmSessions({ env } = {}) {
  return async () => {
    const dir = await mkdtemp(join(tmpdir(), 'dba-tpm-'));
    const path = name => { if (!SAFE_NAME.test(name)) throw new Error(`bad TPM work file name ${name}`); return join(dir, name); };
    return {
      run: (tool, args) => runIn(dir, tool, args, env ? { env: { ...process.env, ...env } } : {}),
      write: (name, bytes) => writeFile(path(name), bytes, { mode: 0o600 }),
      read: async name => { try { return new Uint8Array(await readFile(path(name))); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } },
      close: () => rm(dir, { recursive: true, force: true })
    };
  };
}
