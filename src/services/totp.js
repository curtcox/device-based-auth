/**
 * TOTP (RFC 6238 over RFC 4226 HOTP): HMAC-SHA1, 6 digits, 30-second steps, the parameters every
 * authenticator app (Google Authenticator, Authy, 1Password, Microsoft Authenticator…) supports.
 */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const TOTP = Object.freeze({ digits: 6, period: 30, window: 1 });

/** RFC 4648 base32 without padding (what otpauth:// URIs carry). */
export function base32(bytes) {
  let bits = 0; let value = 0; let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** The HOTP value for a counter (RFC 4226 §5.3), as a zero-padded string. */
export async function hotp(secret, counter, digits = TOTP.digits) {
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
  const offset = mac[19] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** The time step of an instant (milliseconds). */
export const stepAt = nowMs => Math.floor(nowMs / 1000 / TOTP.period);

/**
 * Which step (within ±window of now) a code is for, or null. Callers refuse steps at or below the
 * last one they accepted for the gate, so each code works once.
 */
export async function matchStep(secret, code, nowMs, afterStep = -1) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return null;
  const now = stepAt(nowMs);
  for (let step = now - TOTP.window; step <= now + TOTP.window; step++) {
    if (step <= afterStep) continue;
    if (await hotp(secret, step) === code) return step;
  }
  return null;
}

/** An otpauth:// URI for authenticator apps (and QR codes). */
export function otpauthUri({ secret, label, issuer = 'devicebasedauth.org' }) {
  const name = encodeURIComponent(`${issuer}:${label}`);
  return `otpauth://totp/${name}?secret=${base32(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP.digits}&period=${TOTP.period}`;
}
