/**
 * Credential export for the dashboard (master plan §5.2): the list API's records as JSON or CSV.
 * Pure functions, so they are unit-tested in Node (src/credential-export.test.js).
 */

const COLUMNS = [
  ['cid', c => c.cid], ['version', c => c.version], ['state', c => c.state],
  ['device_id', c => c.device_id], ['device_name', c => c.device?.name], ['device_kind', c => c.device?.kind], ['key_protection', c => c.device?.key_protection],
  ['audiences', c => (c.aud || []).join(' ')], ['actions', c => [...new Set((c.grants || []).flatMap(g => g.actions || []))].join(' ')],
  ['grants_json', c => JSON.stringify(c.grants || [])],
  ['issued_at', c => iso(c.iat)], ['expires_at', c => iso(c.exp)], ['revoked_at', c => isoMs(c.revoked_at)], ['revoked_reason', c => c.revoked_reason],
  ['parent_cid', c => c.parent_cid], ['key_thumbprint', c => c.jkt]
];

const iso = seconds => (Number.isFinite(seconds) ? new Date(seconds * 1000).toISOString() : '');
const isoMs = ms => (Number.isFinite(ms) ? new Date(ms).toISOString() : '');

/**
 * One CSV field (RFC 4180). Device names and reasons are typed by people and devices, so a value
 * starting with = + - @ (or a tab/CR) is prefixed with ' to keep spreadsheets from running it
 * as a formula (CSV injection).
 */
export function csvField(value) {
  let text = value === undefined || value === null ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/** Credentials as CSV text with a header row and CRLF line ends. */
export function credentialsCsv(items) {
  const lines = [COLUMNS.map(([name]) => name).join(',')];
  for (const item of items) lines.push(COLUMNS.map(([, get]) => csvField(get(item))).join(','));
  return `${lines.join('\r\n')}\r\n`;
}

/** Credentials as pretty JSON, with when and how it was exported. */
export function credentialsJson(items, { account, filter = {}, now = Date.now() } = {}) {
  return `${JSON.stringify({ exported_at: new Date(now).toISOString(), account, filter, count: items.length, items }, null, 2)}\n`;
}
