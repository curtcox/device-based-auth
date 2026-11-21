/**
 * Security email (STATUS S8, D9; master plan §10) through Amazon SES's v2 HTTP API, signed with
 * AWS Signature Version 4 in WebCrypto (no SDK in the Worker).
 *
 * Configured by EMAIL_PROVIDER=ses, SES_REGION, EMAIL_FROM and the secrets SES_ACCESS_KEY_ID and
 * SES_SECRET_ACCESS_KEY. Without them no email is queued or charged. env.EMAIL_FETCH replaces
 * fetch in tests.
 */

const te = new TextEncoder();
const hex = bytes => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');

async function sha256Hex(data) {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? te.encode(data) : data)));
}

async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', typeof key === 'string' ? te.encode(key) : key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, te.encode(data)));
}

// RFC 3986 unreserved characters stay as they are; everything else is %XX (SigV4's rule).
const awsEncode = s => encodeURIComponent(s).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/**
 * Sign a request with AWS Signature Version 4. Returns the headers to send: the given ones plus
 * x-amz-date and authorization (host is signed but left for fetch to set).
 * @param {{ method: string, url: string, headers?: Record<string,string>, body?: string, region: string, service: string, accessKeyId: string, secretAccessKey: string, now?: number }} request
 */
export async function signAwsV4({ method, url, headers = {}, body = '', region, service, accessKeyId, secretAccessKey, now = Date.now() }) {
  const u = new URL(url);
  const amzDate = new Date(now).toISOString().replace(/[-:]|\.\d{3}/g, '');
  const day = amzDate.slice(0, 8);
  const all = { host: u.host, 'x-amz-date': amzDate };
  for (const [name, value] of Object.entries(headers)) all[name.toLowerCase()] = String(value);
  const names = Object.keys(all).sort();
  const canonicalHeaders = names.map(n => `${n}:${all[n].trim().replace(/\s+/g, ' ')}\n`).join('');
  const query = [...u.searchParams].map(([k, v]) => [awsEncode(k), awsEncode(v)]).sort(([a, x], [b, y]) => a < b ? -1 : a > b ? 1 : x < y ? -1 : x > y ? 1 : 0).map(([k, v]) => `${k}=${v}`).join('&');
  const path = u.pathname.split('/').map(segment => awsEncode(decodeURIComponent(segment))).join('/') || '/';
  const canonical = [method, path, query, canonicalHeaders, names.join(';'), await sha256Hex(body)].join('\n');
  const scope = `${day}/${region}/${service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, await sha256Hex(canonical)].join('\n');
  let key = await hmac(`AWS4${secretAccessKey}`, day);
  for (const part of [region, service, 'aws4_request']) key = await hmac(key, part);
  const signature = hex(await hmac(key, toSign));
  return { ...headers, 'x-amz-date': amzDate, authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}` };
}

/** True when this server can send security email. */
export function emailConfigured(env) {
  return env.EMAIL_PROVIDER === 'ses' && !!(env.SES_REGION && env.SES_ACCESS_KEY_ID && env.SES_SECRET_ACCESS_KEY && env.EMAIL_FROM);
}

/** A plausible single mailbox (what Clerk verified), or null. Never a list or a header. */
export function cleanEmailAddress(value) {
  if (typeof value !== 'string') return null;
  const address = value.trim();
  return address.length <= 254 && /^[^\s@<>()",;:\\[\]]+@[^\s@<>()",;:\\[\]]+\.[^\s@<>()",;:\\[\]]+$/.test(address) ? address : null;
}

/** Strip control characters (a subject must stay one line) and cap the length. */
export function emailLine(value, max = 120) {
  return String(value ?? '').replace(/[\p{Cc}\p{Cf}]/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

/**
 * Send one plain-text email. Resolves to { ok, status, retry, error }: `retry` is true only when
 * SES answered that it did not take the message (throttled or a server error), so a retry cannot
 * send (and bill) it twice. A network error is not retried for the same reason.
 */
export async function sendEmail(env, { to, subject, text }, now = Date.now()) {
  if (!emailConfigured(env)) return { ok: false, retry: false, error: 'email is not configured' };
  const url = `https://email.${env.SES_REGION}.amazonaws.com/v2/email/outbound-emails`;
  const body = JSON.stringify({
    FromEmailAddress: env.EMAIL_FROM,
    Destination: { ToAddresses: [to] },
    Content: { Simple: { Subject: { Data: emailLine(subject, 200), Charset: 'UTF-8' }, Body: { Text: { Data: text, Charset: 'UTF-8' } } } }
  });
  const headers = await signAwsV4({ method: 'POST', url, headers: { 'content-type': 'application/json' }, body, region: env.SES_REGION, service: 'ses', accessKeyId: env.SES_ACCESS_KEY_ID, secretAccessKey: env.SES_SECRET_ACCESS_KEY, now });
  try {
    const response = await (env.EMAIL_FETCH || fetch)(url, { method: 'POST', headers, body });
    if (response.ok) return { ok: true, status: response.status, retry: false };
    return { ok: false, status: response.status, retry: response.status === 429 || response.status >= 500, error: (await response.text().catch(() => '')).slice(0, 200) };
  } catch (error) {
    return { ok: false, retry: false, error: String(error?.message || error).slice(0, 200) };
  }
}
