/**
 * Command-line parsing and where a profile lives: options, global options, whole seconds, the
 * profile directory and the server origin.
 */
import { UsageError } from './errors.js';

export const DEFAULT_ORIGIN = 'https://devicebasedauth.org';

/**
 * Parse options after a command. `spec` lists the options the command takes:
 * { values: [...], booleans: [...], repeatable: [...] } (repeatable options are also values).
 * Accepts `--name value`, `--name=value`, `-h`, and `--` to end options. Unknown options throw,
 * because a mistyped `--grant` silently ignored would enroll a device with the wrong grants.
 * Returns { options, positionals }.
 */
export function parseArgs(argv, { values = [], booleans = [], repeatable = [] } = {}) {
  const options = {}; const positionals = [];
  for (const name of repeatable) options[name] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--') { positionals.push(...argv.slice(i + 1)); break; }
    if (arg === '-h') { options.help = true; continue; }
    if (!arg.startsWith('--') || arg === '-') { positionals.push(arg); continue; }
    const eq = arg.indexOf('=');
    const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
    if (booleans.includes(name)) {
      if (eq !== -1) throw new UsageError(`--${name} does not take a value`);
      options[name] = true; continue;
    }
    if (!values.includes(name) && !repeatable.includes(name)) throw new UsageError(`Unknown option --${name}`);
    let value;
    if (eq !== -1) value = arg.slice(eq + 1);
    else { if (i + 1 >= argv.length) throw new UsageError(`--${name} needs a value`); value = argv[++i]; }
    if (repeatable.includes(name)) options[name].push(value); else options[name] = value;
  }
  return { options, positionals };
}

/**
 * Split the global options (--profile, --origin, --no-renew, --help) that come before the command from the
 * command and its arguments. `dba curl` passes everything after the command straight to curl,
 * so global options for it must come first; other commands also accept them later.
 */
export function splitCommand(argv) {
  const globals = {}; let i = 0;
  for (; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { globals.help = true; continue; }
    if (arg === '--no-renew') { globals['no-renew'] = true; continue; }
    const match = arg.match(/^--(profile|origin)(?:=(.*))?$/);
    if (!match) break;
    if (match[2] !== undefined) globals[match[1]] = match[2];
    else { if (i + 1 >= argv.length) throw new UsageError(`--${match[1]} needs a value`); globals[match[1]] = argv[++i]; }
  }
  return { globals, command: argv[i], rest: argv.slice(i + 1) };
}

/**
 * Where a profile's files live: $DBA_HOME/<profile>, else $XDG_CONFIG_HOME/dba/<profile>, else
 * ~/.config/dba/<profile>. Profiles let one machine hold several devices (say, work and home).
 */
export function configPaths({ env = {}, home, profile = 'default' }) {
  if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$/.test(profile)) throw new UsageError('--profile must be 1–64 letters, digits, ".", "_" or "-"');
  const base = env.DBA_HOME || `${env.XDG_CONFIG_HOME || `${home}/.config`}/dba`;
  const dir = `${base.replace(/\/+$/, '')}/${profile}`;
  return { dir, key: `${dir}/key.json`, credential: `${dir}/credential.jwt`, config: `${dir}/config.json`, confirmation: `${dir}/confirmation.jwt`, certificate: `${dir}/client.crt`, certificateKey: `${dir}/client.key`, ca: `${dir}/ca.crt` };
}

/**
 * The server to talk to: --origin, then $DBA_ORIGIN, then the origin the profile enrolled with
 * (so a device enrolled against a local server keeps using it), then devicebasedauth.org.
 */
export function resolveOrigin({ flag, env = {}, saved } = {}) {
  const value = flag || env.DBA_ORIGIN || saved || DEFAULT_ORIGIN;
  let url;
  try { url = new URL(value); } catch { throw new UsageError(`Not a URL: ${value}`); }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new UsageError(`The origin must be http(s): ${value}`);
  return url.origin;
}

/** Parse a whole number of seconds from an option. */
export function secondsOption(value, name) {
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) <= 0) throw new UsageError(`--${name} must be a whole number of seconds`);
  return Number(value);
}
