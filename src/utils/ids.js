const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** A random id like "crd_7Q2M9X4K1BZ0R3P5" (Crockford base32, 80 bits). */
export function randomId(prefix, length = 16) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return `${prefix}_${[...bytes].map(b => ALPHABET[b & 31]).join('')}`;
}

/** A deterministic id derived from inputs (used for device ids: one per account and key). */
export async function derivedId(prefix, ...parts) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(parts.join('\n'))));
  return `${prefix}_${[...digest.slice(0, 16)].map(b => ALPHABET[b & 31]).join('')}`;
}
