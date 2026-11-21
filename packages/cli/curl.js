/**
 * `dba curl`: the method and URL a curl command line will use (the DPoP proof must name them),
 * the header file that keeps the credential off the command line, and dba's own --dba-wait.
 */
import { UsageError } from './errors.js';
import { secondsOption } from './args.js';

// curl options whose value is the next argument, so it is never mistaken for the URL.
const CURL_VALUE_OPTIONS = new Set(['-X', '--request', '-H', '--header', '-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json',
  '-F', '--form', '--form-string', '-o', '--output', '-u', '--user', '-A', '--user-agent', '-e', '--referer', '-b', '--cookie', '-c', '--cookie-jar', '-T', '--upload-file',
  '-w', '--write-out', '-x', '--proxy', '-m', '--max-time', '--connect-timeout', '-r', '--range', '-E', '--cert', '--key', '--cacert', '--resolve', '--retry', '-K', '--config', '--url']);
const CURL_SHORT_WITH_VALUE = new Set(['X', 'H', 'd', 'F', 'o', 'u', 'A', 'e', 'b', 'c', 'T', 'w', 'x', 'm', 'r', 'E', 'K']);

/**
 * Work out the method and URL a curl command line will use, which the DPoP proof must name.
 * Method: -X/--request; else HEAD for -I, PUT for -T, POST for -d/--data*, --json or -F, unless
 * -G sends the data as a query; else GET. URL: --url, or the first http(s):// argument.
 */
export function curlRequest(args) {
  let method; let url; let data = false; let get = false; let head = false; let upload = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    let name = arg; let value;
    if (arg.startsWith('--') && arg.includes('=')) { name = arg.slice(0, arg.indexOf('=')); value = arg.slice(arg.indexOf('=') + 1); }
    else if (/^-[A-Za-z]./.test(arg) && CURL_SHORT_WITH_VALUE.has(arg[1])) { name = arg.slice(0, 2); value = arg.slice(2); }
    else if (CURL_VALUE_OPTIONS.has(arg)) { value = args[++i]; }
    if (name === '-X' || name === '--request') method = value;
    else if (name === '--url') url ??= value;
    else if (name === '-d' || name.startsWith('--data') || name === '--json' || name === '-F' || name.startsWith('--form')) data = true;
    else if (name === '-T' || name === '--upload-file') upload = true;
    else if (name === '-G' || name === '--get') get = true;
    else if (name === '-I' || name === '--head') head = true;
    else if (value === undefined && !arg.startsWith('-') && /^https?:\/\//i.test(arg)) url ??= arg;
  }
  if (!url) throw new UsageError('dba curl needs an http(s):// URL');
  method ||= head ? 'HEAD' : upload ? 'PUT' : data && !get ? 'POST' : 'GET';
  return { method: method.toUpperCase(), url };
}

/**
 * curl arguments that read the credential headers from a file (`-H @file`, curl 7.55+) in front of
 * the caller's own. Never on the command line: any local user can read another's arguments (ps,
 * /proc), and DPoP does not sign the body, so a proof seen there could be raced to the same URL
 * with another body before curl sends it.
 */
export function curlArgs(args, headerFile) {
  return ['-H', `@${headerFile}`, ...args];
}

/** The contents of that header file: one "Name: value" line per header. */
export function curlHeaderFile(headers) {
  return Object.entries(headers).map(([name, value]) => `${name}: ${value}\n`).join('');
}


// curl options that would send the response somewhere `dba curl --dba-wait` cannot read it, or
// (--fail) make curl drop the body that says gate_pending. Short letters among them too.
const WAIT_CONFLICTS = new Set(['-o', '--output', '-O', '--remote-name', '--remote-name-all', '-J', '--remote-header-name', '-D', '--dump-header', '-w', '--write-out', '-i', '--include', '-f', '--fail', '--fail-with-body', '--output-dir']);
const WAIT_CONFLICT_LETTERS = new Set(['o', 'O', 'J', 'D', 'w', 'i', 'f']);

/**
 * Take dba's own `--dba-wait[=SECONDS]` out of `dba curl`'s arguments (a name curl will never
 * use). Returns { args, waitSeconds } with waitSeconds null when it was not given (default 300).
 * While waiting, dba reads the response itself, so options that redirect it are refused.
 */
export function curlWaitOption(args) {
  let waitSeconds = null;
  const rest = [];
  for (const arg of args) {
    if (arg === '--dba-wait') waitSeconds = 300;
    else if (arg.startsWith('--dba-wait=')) waitSeconds = secondsOption(arg.slice('--dba-wait='.length), 'dba-wait');
    else rest.push(arg);
  }
  if (waitSeconds === null) return { args: rest, waitSeconds };
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    const name = arg.startsWith('--') && arg.includes('=') ? arg.slice(0, arg.indexOf('=')) : arg;
    let clash = WAIT_CONFLICTS.has(name) ? name : null;
    if (!clash && /^-[A-Za-z]{2,}/.test(arg)) {
      // A cluster such as -sSf: letters up to the first one that takes a value.
      for (const letter of arg.slice(1)) {
        if (WAIT_CONFLICT_LETTERS.has(letter)) { clash = `-${letter}`; break; }
        if (CURL_SHORT_WITH_VALUE.has(letter)) break;
      }
    }
    if (clash) throw new UsageError(`dba curl --dba-wait reads the response itself and prints the body; drop ${clash}`);
    if (CURL_VALUE_OPTIONS.has(arg)) i++;
  }
  return { args: rest, waitSeconds };
}
