/**
 * Credentials once issued: describing them in plain English, listing the account's, and
 * renewing them when two thirds of the lifetime has passed or the issuer key was withdrawn.
 */
import { inspectCredential, describeGrant } from '@devicebasedauth/verify';
import { UsageError } from './errors.js';

/** "in 3 days", "2 hours ago": enough precision to decide whether to renew. */
export function relativeTime(seconds, now = Math.floor(Date.now() / 1000)) {
  const delta = seconds - now; const abs = Math.abs(delta);
  const [n, unit] = abs >= 86400 * 2 ? [Math.round(abs / 86400), 'day'] : abs >= 7200 ? [Math.round(abs / 3600), 'hour'] : abs >= 120 ? [Math.round(abs / 60), 'minute'] : [abs, 'second'];
  const text = `${n} ${unit}${n === 1 ? '' : 's'}`;
  return delta >= 0 ? `in ${text}` : `${text} ago`;
}

const iso = seconds => new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');

/**
 * A plain-English summary of a decoded credential (or access token) payload: who, what, until
 * when. Decoding proves nothing; callers say so when the signature has not been checked.
 */
export function describeCredential(payload, now = Math.floor(Date.now() / 1000)) {
  const lines = [];
  const device = payload.device ? `"${payload.device.name}" (${payload.device.kind}, key: ${payload.device.key_protection})` : '';
  // Access tokens carry the credential's cid but their own jti, and no key binding.
  const version = typeof payload.jti === 'string' && payload.jti.startsWith(`${payload.cid}.`) ? ` (version ${payload.jti.slice(payload.cid.length + 1)})` : '';
  lines.push(payload.cnf ? `Credential ${payload.cid ?? '?'}${version}` : `Access token for credential ${payload.cid ?? '?'} (bearer: anyone holding it can use it)`);
  lines.push(`Device:    ${payload.sub ?? '?'} ${device}`.trimEnd());
  const attestation = payload.device?.attestation;
  if (attestation && typeof attestation === 'object') {
    const clean = text => String(text).replace(/[\p{Cc}\p{Cf}]/gu, '');
    const details = [attestation.format, attestation.tpm_manufacturer && `TPM manufacturer ${attestation.tpm_manufacturer}`, attestation.app_id && `app ${attestation.app_id}`].filter(Boolean).map(clean);
    lines.push(`Attested:  ${clean(attestation.security_level ?? '?')} key (${details.join(', ')})`);
  }
  lines.push(`Account:   ${payload.acct ?? '?'}`);
  lines.push(`Sites:     ${Array.isArray(payload.aud) ? payload.aud.join(', ') : '?'}`);
  if (Number.isSafeInteger(payload.exp)) lines.push(`${payload.exp > now ? 'Expires' : 'Expired'}:   ${iso(payload.exp)} (${relativeTime(payload.exp, now)})`);
  lines.push('Grants:');
  const grants = Array.isArray(payload.grants) ? payload.grants : [];
  grants.forEach((grant, i) => lines.push(`  ${i + 1}. ${describeGrant(grant)}`));
  if (!grants.length) lines.push('  (none)');
  return lines;
}

export const CREDENTIAL_STATES = ['active', 'expired', 'revoked'];

/** The query string for GET /api/v1/credentials from `dba list` options. */
export function listQuery({ status, audience, device, cursor } = {}) {
  if (status !== undefined && !CREDENTIAL_STATES.includes(status)) throw new UsageError(`--status must be one of ${CREDENTIAL_STATES.join(', ')}`);
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries({ status, audience, device, cursor })) if (value !== undefined) params.set(name, value);
  const query = params.toString();
  return `/api/v1/credentials${query ? `?${query}` : ''}`;
}

/**
 * One line per credential for `dba list`: id, state, device name, sites and expiry. Device names
 * are the owner's text; control characters are dropped so a name cannot rewrite the terminal.
 */
export function formatCredentialList(items, now = Math.floor(Date.now() / 1000)) {
  if (!items.length) return ['No credentials.'];
  const clean = text => String(text ?? '').replace(/[\p{Cc}\p{Cf}]/gu, '');
  const rows = items.map(c => [clean(c.cid), clean(c.state), clean(c.device?.name || c.device_id), (c.aud || []).map(clean).join(','), Number.isSafeInteger(c.exp) ? `${c.exp > now ? 'expires' : 'expired'} ${relativeTime(c.exp, now)}` : '']);
  const header = ['CREDENTIAL', 'STATE', 'DEVICE', 'SITES', 'EXPIRY'];
  const widths = header.map((h, i) => Math.min(40, Math.max(h.length, ...rows.map(r => r[i].length))));
  const fit = (text, width) => (text.length > width ? `${text.slice(0, width - 1)}…` : text).padEnd(width);
  return [header, ...rows].map(row => row.map((cell, i) => (i === row.length - 1 ? cell : fit(cell, widths[i]))).join('  ').trimEnd());
}

/** True once two thirds of the lifetime has passed: the point the plan says devices renew. */
export function shouldRenew(payload, now = Math.floor(Date.now() / 1000)) {
  return Number.isSafeInteger(payload.iat) && Number.isSafeInteger(payload.exp) && now >= payload.iat + ((payload.exp - payload.iat) * 2) / 3;
}

export const JWKS_CACHE_SECONDS = 3600;

/**
 * True when the issuer no longer publishes the key that signed this credential: after an issuer key
 * is withdrawn (compromised), relying parties refuse the credential, and the device must renew it
 * (free) to get one signed by the current key. The JWKS is fetched at most once an hour through
 * `cache` ({ read(): {fetched_at, kids} | null, write(entry) }), and again early when the cached copy
 * lacks the kid. Any failure to fetch answers false: never renew on a guess.
 */
export async function issuerKeyWithdrawn({ client, credential, cache, now = Math.floor(Date.now() / 1000) }) {
  const { header } = inspectCredential(credential);
  const cached = await cache.read().catch(() => null);
  if (cached && Array.isArray(cached.kids) && now - cached.fetched_at < JWKS_CACHE_SECONDS && cached.kids.includes(header.kid)) return false;
  let kids;
  try { kids = (await client.request('GET', '/.well-known/jwks.json')).keys.map(k => k.kid); } catch { return false; }
  if (!kids.length) return false;
  await cache.write({ fetched_at: now, kids }).catch(() => {});
  return !kids.includes(header.kid);
}

/**
 * Whether commands that present the credential renew it first when it is due. On by default (the
 * browser SDK does the same); `--no-renew` or DBA_AUTO_RENEW=0 turns it off, for example on a
 * machine whose account owner wants every renewal (25 µ$) to be deliberate.
 */
export function autoRenewEnabled({ flag, env = {} } = {}) {
  if (flag) return false;
  return !['0', 'false', 'no', 'off'].includes(String(env.DBA_AUTO_RENEW ?? '').trim().toLowerCase());
}

/**
 * Renew the device's credential if two thirds of its lifetime have passed and it has not expired.
 * Returns { renewed: false, reason } or { renewed: true, result } after `save(result)` stored the
 * new credential. A failure never stops the caller from using the still-valid credential: it comes
 * back as { renewed: false, reason: 'failed', error } for the caller to warn about. `superseded`
 * means another process renewed first; the caller should re-read its credential file.
 */
export async function renewIfDue({ client, device, save, withdrawn = false, now = Math.floor(Date.now() / 1000) }) {
  const { payload } = inspectCredential(device.credential);
  if (!Number.isSafeInteger(payload.exp) || payload.exp <= now) return { renewed: false, reason: 'expired' };
  if (!withdrawn && !shouldRenew(payload, now)) return { renewed: false, reason: 'not_due' };
  let result;
  try {
    result = await client.request('POST', `/api/v1/credentials/${encodeURIComponent(payload.cid)}/renew`, { device, body: {} });
  } catch (error) {
    if (error.code === 'superseded') return { renewed: false, reason: 'superseded' };
    return { renewed: false, reason: 'failed', error };
  }
  await save(result);
  return { renewed: true, result };
}
