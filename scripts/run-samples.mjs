// Run every docs sample against a fresh local server (`npm run test:samples`).
//
// Starts `wrangler dev` in local mode on port 8788 with its own storage directory, funds the
// account "sample-owner", then runs each sample. Samples print the approval link a real user
// would open; this harness approves it as sample-owner (LocalDev auth, local mode only), so the
// samples themselves contain no test hooks. Each sample must exit 0 and print what it promises.
//
// A sample whose toolchain is missing (python3 with cryptography + requests, go, a JDK; swtpm and
// tpm2-tools for the TPM sample) is skipped, unless DBA_SAMPLES_STRICT=1, when it fails.
//
// The TPM sample runs on a software TPM whose EK certificate comes from a throwaway CA made here;
// the server trusts that CA through TPM_EK_TEST_CA, which only a local server reads.
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { enrollDevice, signedRequest } from '../docs/samples/device.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PORT = Number(process.env.DBA_SAMPLES_PORT || 8788);
const ORIGIN = `http://localhost:${PORT}`;
const OWNER = 'sample-owner';
const STRICT = process.env.DBA_SAMPLES_STRICT === '1';
const SAMPLE_TIMEOUT_MS = 120_000;
const APPROVAL_LINK = /\/approve\.html#(enr_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/g;

const has = (command, args) => spawnSync(command, args, { stdio: 'ignore' }).status === 0;
const TPM_TOOLS = ['swtpm', 'swtpm_setup', 'swtpm_localca', 'tpm2_createek', 'tpm2_activatecredential', 'jq', 'openssl'];
const hasTpmTools = () => TPM_TOOLS.every(tool => has('sh', ['-c', `command -v ${tool}`]));
let tpmCaDir = null;

/**
 * Each sample: a command to run (or an in-process function), the toolchain it needs, and the
 * output that shows it worked. Output patterns are checked against stdout + stderr.
 */
const SAMPLES = [
  {
    name: 'enroll-and-call.sh', command: ['bash', 'docs/samples/enroll-and-call.sh'],
    expect: [/^Approved\. Saved the credential\./m, /^Authorization: DBA ey[\w-]+\.[\w-]+\.[\w-]+$/m, /^DPoP: ey[\w-]+\.[\w-]+\.[\w-]+$/m, /"kind":"device"/, /^Type: +dba-access\+jwt$/m, /^Verdict: +valid$/m]
  },
  {
    name: 'verify-request.mjs', command: ['node', 'docs/samples/verify-request.mjs'],
    expect: [/^ALLOW publish: hashbin:content:write by account sample-owner/m, /^DENY {2}replayed request: 401 replayed_proof/m, /^DENY {2}delete: 403 forbidden \[\["action_not_granted"\]\]/m, /^DENY {2}anonymous: 401 credential_required/m]
  },
  { name: 'worker-middleware.mjs', run: workerMiddleware },
  {
    name: 'python_device.py', command: ['python3', 'docs/samples/python_device.py'],
    needs: () => has('python3', ['-c', 'import cryptography, requests']) || 'python3 with cryptography and requests',
    expect: [/^Approved\. Credential id: crd_\w+$/m, /^whoami: account sample-owner, device dev_\w+$/m, /^ - May "hashbin:content:write", on any resource\.$/m]
  },
  {
    name: 'android', command: ['bash', 'docs/samples/android/run.sh'],
    needs: () => has('javac', ['--version']) || 'a JDK (javac 17+)',
    expect: [/^Attestation challenge: [\w-]{43}$/m, /^Approved\. Credential id: crd_\w+$/m, /^whoami: account sample-owner, device dev_\w+$/m, /^ - May "hashbin:content:write", on any resource\.$/m, /^Renewed: crd_\w+\.2$/m]
  },
  {
    name: 'tpm', command: ['bash', 'docs/samples/tpm/swtpm.sh'], env: () => ({ DBA_SAMPLE_TPM_CA: tpmCaDir }),
    needs: () => (hasTpmTools() && !!tpmCaDir) || 'swtpm, swtpm-tools, tpm2-tools, jq and openssl',
    expect: [/^Attestation challenge: [\w-]{43}$/m, /^Approved\. Attested: tpm \(id:00001014\)$/m, /^whoami: account sample-owner, device dev_\w+$/m, /only with a key attested to be in secure hardware/]
  },
  {
    name: 'go_verify', command: ['go', 'run', '.'], cwd: 'docs/samples/go_verify', credential: true,
    needs: () => has('go', ['version']) || 'go',
    expect: [/^Signature: valid \(issuer key local-dev-1\)$/m, /^Device: dev_\w+$/m, /^Grant 1: \{"actions":\["hashbin:content:write"\]\}$/m]
  }
];

/** POST/GET the local server as the sample owner. */
async function api(method, path, body, as = OWNER) {
  const response = await fetch(`${ORIGIN}${path}`, { method, headers: { Authorization: `LocalDev ${as}`, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });
  const json = await response.json();
  if (!response.ok) throw new Error(`${method} ${path}: ${json.error} (${json.code})`);
  return json;
}

/** What the account owner does on the approval page. */
const approve = request => api('POST', '/api/v1/enrollments/approve', { request });

/** A throwaway EK CA for the TPM sample's swtpm; returns its certificate (DER, base64) or null. */
async function makeTpmCa(dir) {
  const made = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'ca.key'), '-out', join(dir, 'ca.crt'), '-subj', '/CN=DBA sample EK CA', '-days', '2',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], { stdio: 'ignore' });
  if (made.status !== 0) return null;
  const pem = await readFile(join(dir, 'ca.crt'), 'utf8');
  return pem.replace(/-----[A-Z ]+-----|\s/g, '');
}

function startServer(persistDir, extraVars = {}) {
  const args = ['wrangler', 'dev', '--config', 'wrangler.local.toml', '--local', '--port', String(PORT), '--persist-to', persistDir,
    '--var', `APP_ORIGIN:${ORIGIN}`, '--var', `ISSUER:${ORIGIN}`, '--var', `STATUS_ORIGIN:${ORIGIN}/status`,
    ...Object.entries(extraVars).flatMap(([name, value]) => ['--var', `${name}:${value}`])];
  // Its own process group, so stopping it also stops workerd underneath npx and wrangler.
  const child = spawn('npx', args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  const log = [];
  child.stdout.on('data', d => log.push(d)); child.stderr.on('data', d => log.push(d));
  const stop = () => { try { process.kill(-child.pid, 'SIGTERM'); } catch { /* already gone */ } };
  return { child, stop, log: () => Buffer.concat(log).toString() };
}

async function waitForHealth(server, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (server.child.exitCode !== null) throw new Error(`wrangler exited (${server.child.exitCode})`);
    try { if ((await fetch(`${ORIGIN}/health`)).ok) return; } catch { /* not up yet */ }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error('wrangler did not answer /health in time');
}

/** Run one command-line sample, approving any enrollment link it prints. */
function runCommand(sample, env) {
  return new Promise(resolve => {
    const [command, ...args] = sample.command;
    const child = spawn(command, args, { cwd: join(ROOT, sample.cwd || '.'), env, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; const approved = new Set(); const approvals = [];
    const watch = data => {
      output += data;
      for (const [, ticket] of output.matchAll(APPROVAL_LINK)) {
        if (approved.has(ticket)) continue;
        approved.add(ticket);
        approvals.push(approve(ticket).catch(error => { output += `\n[harness] approval failed: ${error.message}\n`; }));
      }
    };
    child.stdout.on('data', watch); child.stderr.on('data', watch);
    const timer = setTimeout(() => { output += `\n[harness] timed out after ${SAMPLE_TIMEOUT_MS / 1000}s\n`; child.kill('SIGKILL'); }, SAMPLE_TIMEOUT_MS);
    child.on('error', error => { output += `\n[harness] ${error.message}\n`; });
    child.on('close', async code => { clearTimeout(timer); await Promise.all(approvals); resolve({ code, output }); });
  });
}

/** The Worker sample runs in-process: import it and call fetch() like the runtime would. */
async function workerMiddleware() {
  const { default: worker } = await import('../docs/samples/worker-middleware.mjs');
  const env = { DBA_ISSUER: ORIGIN, DBA_AUDIENCE: 'hashbin.org' };
  const device = await enrollDevice({ origin: ORIGIN, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], name: 'worker sample', onApprovalUrl: url => approve(new URL(url).hash.slice(1)) });
  const lines = []; let ok = true;
  const expect = async (label, request, status, code) => {
    const response = await worker.fetch(request, env);
    const body = await response.json();
    const pass = response.status === status && (code === undefined || body.code === code);
    ok &&= pass;
    lines.push(`${pass ? 'ok  ' : 'FAIL'} ${label}: ${response.status} ${JSON.stringify(body)}`);
  };
  const publish = await signedRequest(device, 'POST', 'https://hashbin.org/api/content');
  await expect('publish with a credential', publish, 200);
  await expect('the same proof again', publish, 401, 'replayed_proof');
  await expect('delete (not granted)', await signedRequest(device, 'DELETE', 'https://hashbin.org/api/content/abc'), 403, 'forbidden');
  await expect('no credential', new Request('https://hashbin.org/api/content', { method: 'POST' }), 401, 'credential_required');
  await expect('unknown route', new Request('https://hashbin.org/nope'), 404, 'not_found');

  // Revocation webhook: point hashbin.org's webhook (the local operator owns it) at a small HTTP
  // server that hands requests to the sample Worker, revoke the credential, and wait for the event.
  const received = [];
  const hook = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const response = await worker.fetch(new Request(`http://localhost${req.url}`, { method: req.method, headers: { 'Content-Type': req.headers['content-type'] || '' }, body: Buffer.concat(chunks) }), env);
    const text = await response.text();
    received.push(`${response.status} ${text}`);
    res.writeHead(response.status, { 'Content-Type': 'application/json' }).end(text);
  });
  await new Promise(resolve => hook.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://localhost:${hook.address().port}/webhooks/devicebasedauth`;
    await api('POST', '/api/v1/dev/deposit', { amount_microdollars: 1_000_000 }, 'operator');
    await api('PATCH', '/api/v1/audiences/hashbin.org', { revocation_webhook: url }, 'operator');
    const cid = JSON.parse(Buffer.from(device.credential.split('.')[1], 'base64url')).cid;
    await api('DELETE', `/api/v1/credentials/${cid}`);
    const deadline = Date.now() + 30_000;
    while (!received.length && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 200));
    const delivered = received[0]?.startsWith('200 ') && received[0].includes('credentials.revoked');
    ok &&= !!delivered;
    lines.push(`${delivered ? 'ok  ' : 'FAIL'} revocation webhook: ${received[0] ?? 'nothing arrived'}`);
    await expect('publish after the pushed revocation', await signedRequest(device, 'POST', 'https://hashbin.org/api/content'), 401, 'revoked');
    await api('PATCH', '/api/v1/audiences/hashbin.org', { revocation_webhook: null }, 'operator');
  } finally { hook.close(); }
  return { code: ok ? 0 : 1, output: `${lines.join('\n')}\n` };
}

async function main() {
  try { await fetch(`${ORIGIN}/health`); console.error(`Something is already listening on ${ORIGIN}; stop it or set DBA_SAMPLES_PORT.`); return 1; } catch { /* free */ }
  const persistDir = await mkdtemp(join(tmpdir(), 'dba-samples-'));
  const extraVars = {};
  if (hasTpmTools()) {
    const dir = await mkdtemp(join(persistDir, 'tpm-ca-'));
    const ca = await makeTpmCa(dir);
    if (ca) { tpmCaDir = dir; extraVars.TPM_EK_TEST_CA = ca; }
  }
  const server = startServer(persistDir, extraVars);
  const stopAll = () => { server.stop(); };
  process.on('SIGINT', () => { stopAll(); process.exit(130); });
  const failures = []; const skipped = [];
  try {
    await waitForHealth(server);
    await api('POST', '/api/v1/dev/deposit', { amount_microdollars: 1_000_000 });
    let credential;
    for (const sample of SAMPLES) {
      const missing = sample.needs?.();
      if (typeof missing === 'string') {
        console.log(`${STRICT ? 'FAIL' : 'skip'} ${sample.name}: needs ${missing}`);
        (STRICT ? failures : skipped).push(sample.name);
        continue;
      }
      const started = Date.now();
      let result;
      if (sample.run) result = await sample.run().catch(error => ({ code: 1, output: `${error.stack}\n` }));
      else {
        const env = { ...process.env, DBA_ORIGIN: ORIGIN, DBA_HOME: await mkdtemp(join(persistDir, 'home-')), ...sample.env?.() };
        if (sample.credential) {
          credential ??= (await enrollDevice({ origin: ORIGIN, aud: ['hashbin.org'], grants: [{ actions: ['hashbin:content:write'] }], onApprovalUrl: url => approve(new URL(url).hash.slice(1)) })).credential;
          env.DBA_CREDENTIAL = credential;
        }
        result = await runCommand(sample, env);
      }
      const missed = (sample.expect || []).filter(pattern => !pattern.test(result.output));
      const passed = result.code === 0 && !missed.length;
      console.log(`${passed ? 'ok  ' : 'FAIL'} ${sample.name} (${((Date.now() - started) / 1000).toFixed(1)}s)`);
      if (!passed) {
        failures.push(sample.name);
        console.log(`---- output (exit ${result.code}) ----\n${result.output}----`);
        for (const pattern of missed) console.log(`missing: ${pattern}`);
      } else if (process.env.DBA_SAMPLES_VERBOSE) console.log(result.output);
    }
  } catch (error) {
    failures.push('harness');
    console.error(`FAIL harness: ${error.message}\n---- wrangler log ----\n${server.log()}`);
  } finally {
    stopAll();
    await new Promise(resolve => { if (server.child.exitCode !== null) resolve(); else { server.child.on('exit', resolve); setTimeout(resolve, 5000); } });
    await rm(persistDir, { recursive: true, force: true });
  }
  console.log(`\n${SAMPLES.length - failures.length - skipped.length} passed, ${failures.length} failed, ${skipped.length} skipped`);
  return failures.length ? 1 : 0;
}

process.exitCode = await main();
