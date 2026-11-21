#!/usr/bin/env node
/**
 * dba: enroll this machine as a device on devicebasedauth.org, then use its credential.
 * Node 22+, no dependencies beyond @devicebasedauth/verify. The logic lives in lib.js; the
 * commands in commands/ only touch files, stdin/stdout and child processes. This file parses
 * the command line, runs the command and reports errors.
 */
import { UsageError, ApiError } from './errors.js';
import { parseArgs, splitCommand } from './args.js';
import { HELP } from './commands/help.js';
import { out, note, loadProfile } from './commands/profile.js';
import { enroll, importCredential, renew, revoke } from './commands/enroll.js';
import { status, inspect, headers, sign, curl, token, certificate, list } from './commands/credential.js';
import { confirm, gatesCommand, approvals } from './commands/gates.js';
import { signup, recover } from './commands/account.js';

const COMMANDS = {
  enroll: { values: ['name', 'kind', 'lifetime', 'wait', 'token', 'key-store'], repeatable: ['aud', 'grant', 'action'], booleans: ['print-request', 'force'] },
  signup: { values: ['deposit', 'name', 'kind', 'wait', 'key-store'], booleans: ['accept-terms', 'force', 'resume', 'no-recovery-codes'] },
  recover: { values: ['account', 'code', 'email', 'via', 'name', 'kind', 'wait', 'key-store'], booleans: ['force', 'resume'] },
  status: { booleans: ['online', 'json'] },
  whoami: { booleans: ['online', 'json'] },
  inspect: { booleans: ['json'] },
  import: {},
  headers: {},
  sign: {},
  token: { values: ['aud'] },
  certificate: { values: ['lifetime'] },
  renew: { booleans: ['rotate', 'if-due'] },
  revoke: {},
  list: { values: ['status', 'audience', 'device'], booleans: ['all', 'json'] },
  confirm: { values: ['wait'] },
  approvals: { values: ['entry', 'number'], booleans: ['watch', 'json'] },
  gates: { values: ['kind', 'label', 'device', 'url', 'public-jwk'], booleans: ['json'] },
  help: {}
};
const GLOBAL = { values: ['profile', 'origin'], booleans: ['help', 'no-renew'] };

// `dba status | head -2` closes the pipe early; that is the reader's choice, not an error.
process.stdout.on('error', error => { if (error.code === 'EPIPE') process.exit(process.exitCode ?? 0); else throw error; });

const HANDLERS = { list, confirm, approvals, gates: gatesCommand, enroll, signup, recover, status, whoami: status, inspect, import: importCredential, headers, sign, token, certificate, renew, revoke };

async function main(argv) {
  const { globals, command, rest } = splitCommand(argv);
  if (!command || command === 'help' || (globals.help && command !== 'curl')) { out(HELP); return 0; }
  if (command === 'curl') return curl(await loadProfile(globals), rest);
  const spec = COMMANDS[command];
  if (!spec) throw new UsageError(`Unknown command "${command}"`);
  const parsed = parseArgs(rest, { values: [...(spec.values || []), ...GLOBAL.values], booleans: [...(spec.booleans || []), ...GLOBAL.booleans], repeatable: spec.repeatable || [] });
  if (parsed.options.help) { out(HELP); return 0; }
  for (const name of [...GLOBAL.values, 'no-renew']) if (parsed.options[name] !== undefined) globals[name] = parsed.options[name];
  await HANDLERS[command](await loadProfile(globals), parsed);
  return 0;
}

main(process.argv.slice(2)).then(code => { process.exitCode = code; }, error => {
  if (error instanceof UsageError) note(`dba: ${error.message}\nRun \`dba help\` for usage.`);
  else if (error instanceof ApiError) note(`dba: ${error.message}${error.code ? ` (${error.code})` : ''}`);
  else note(`dba: ${error.stack || error.message}`);
  process.exitCode = 1;
});
