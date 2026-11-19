// Minimal CBOR (RFC 8949) decoder for Apple App Attest attestation objects (attestation.js):
// unsigned and negative integers, byte and text strings, arrays, maps, false/true/null.
// Definite lengths only, no tags or floats, bounded depth and size: anything else throws.
// Maps become JS Maps keyed by their (string or number) keys.

const MAX_DEPTH = 16;
const MAX_ITEMS = 1024;

/**
 * Decode one CBOR item filling the whole buffer.
 * @param {Uint8Array} bytes
 * @returns {*}
 */
export function decodeCbor(bytes) {
  const { value, length } = decodeCborPrefix(bytes);
  if (length !== bytes.length) throw new Error('malformed CBOR: trailing bytes');
  return value;
}

/**
 * Decode the CBOR item at the start of a buffer, returning it and the bytes it took (WebAuthn
 * authenticator data puts a COSE key in the middle of other bytes).
 * @param {Uint8Array} bytes
 * @returns {{ value: *, length: number }}
 */
export function decodeCborPrefix(bytes) {
  let at = 0;
  const fail = message => { throw new Error(`malformed CBOR: ${message}`); };
  const take = n => {
    if (n > bytes.length - at) fail('truncated');
    const out = bytes.subarray(at, at + n); at += n; return out;
  };
  const argument = info => {
    if (info < 24) return info;
    if (info === 24) return take(1)[0];
    if (info === 25) { const b = take(2); return b[0] * 256 + b[1]; }
    if (info === 26) { const b = take(4); return ((b[0] * 256 + b[1]) * 256 + b[2]) * 256 + b[3]; }
    if (info === 27) {
      const b = take(8); let n = 0;
      for (const byte of b) n = n * 256 + byte;
      if (n > Number.MAX_SAFE_INTEGER) fail('integer too large');
      return n;
    }
    return fail('indefinite lengths are not supported');
  };
  const item = depth => {
    if (depth > MAX_DEPTH) fail('nested too deeply');
    const first = take(1)[0];
    const major = first >> 5; const info = first & 0x1f;
    if (major === 7) {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      return fail('unsupported simple value');
    }
    const n = argument(info);
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: return take(n).slice();
      case 3: return new TextDecoder('utf-8', { fatal: true }).decode(take(n));
      case 4: {
        if (n > MAX_ITEMS) fail('array too long');
        const out = [];
        for (let i = 0; i < n; i++) out.push(item(depth + 1));
        return out;
      }
      case 5: {
        if (n > MAX_ITEMS) fail('map too long');
        const out = new Map();
        for (let i = 0; i < n; i++) {
          const key = item(depth + 1);
          if (typeof key !== 'string' && typeof key !== 'number') fail('map keys must be strings or integers');
          if (out.has(key)) fail('duplicate map key');
          out.set(key, item(depth + 1));
        }
        return out;
      }
      default: return fail('tags are not supported');
    }
  };
  const value = item(0);
  return { value, length: at };
}
