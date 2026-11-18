// Minimal DER (X.690) encoding and decoding: enough to build the X.509 certificates in x509.js
// and to read the certificate chains devices send as key attestation (attestation.js).
const enc = new TextEncoder();

export const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };

function length(n) {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes = []; while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

/** One TLV with a single-byte tag. */
export const tlv = (tag, ...content) => { const body = concat(...content); return concat(Uint8Array.of(tag), length(body.length), body); };

/** A context-specific EXPLICIT tag of any number (multi-byte for numbers ≥ 31, as Android uses). */
export function contextTag(number, ...content) {
  if (number < 31) return tlv(0xa0 | number, ...content);
  const n = [number & 0x7f]; let rest = number >> 7;
  while (rest > 0) { n.unshift(0x80 | (rest & 0x7f)); rest >>= 7; }
  const body = concat(...content);
  return concat(Uint8Array.of(0xbf, ...n), length(body.length), body);
}

export const seq = (...items) => tlv(0x30, ...items);
export const set = (...items) => tlv(0x31, ...items);
export const octets = bytes => tlv(0x04, bytes);
export const bits = bytes => tlv(0x03, Uint8Array.of(0), bytes);
export const utf8 = text => tlv(0x0c, enc.encode(text));
export const bool = value => tlv(0x01, Uint8Array.of(value ? 0xff : 0));
export const explicit = (n, ...items) => tlv(0xa0 | n, ...items);

/** A non-negative DER INTEGER from big-endian bytes. */
export function integer(bytes) {
  let i = 0; while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const trimmed = bytes.slice(i);
  return tlv(0x02, trimmed[0] & 0x80 ? concat(Uint8Array.of(0), trimmed) : trimmed);
}

/** A small non-negative INTEGER (or ENUMERATED with tag 0x0a). */
export function smallInt(n, tag = 0x02) {
  const bytes = []; do { bytes.unshift(n & 0xff); n = Math.floor(n / 256); } while (n > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(tag, Uint8Array.from(bytes));
}

export function oid(dotted) {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const out = [40 * a + b];
  for (let n of rest) { const chunk = [n & 0x7f]; while ((n >>= 7) > 0) chunk.unshift(0x80 | (n & 0x7f)); out.push(...chunk); }
  return tlv(0x06, Uint8Array.from(out));
}

/** UTCTime before 2050, GeneralizedTime after (RFC 5280 §4.1.2.5). */
export function time(ms) {
  const d = new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/[-:T]/g, '').replace('.000', '');
  return d.startsWith('20') && Number(d.slice(0, 4)) < 2050 ? tlv(0x17, enc.encode(d.slice(2))) : tlv(0x18, enc.encode(d));
}

// ---- Decoding ----

const MAX_DEPTH = 32;

/**
 * Read one DER element at `offset`. Returns { cls, constructed, tag, header, start, end,
 * content, raw }: `tag` is the tag number (multi-byte numbers decoded), `content` the value
 * bytes, `raw` the whole element. Throws on anything malformed, indefinite or truncated.
 */
export function readElement(bytes, offset = 0) {
  const fail = () => { throw new Error('malformed DER'); };
  if (offset + 2 > bytes.length) fail();
  const first = bytes[offset];
  const cls = first >> 6; const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f; let at = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    for (let i = 0; ; i++) {
      if (at >= bytes.length || i > 3) fail();
      const b = bytes[at++]; tag = tag * 128 + (b & 0x7f);
      if (!(b & 0x80)) break;
    }
  }
  if (at >= bytes.length) fail();
  let len = bytes[at++];
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count === 0 || count > 4 || at + count > bytes.length) fail();
    len = 0; for (let i = 0; i < count; i++) len = len * 256 + bytes[at++];
  }
  const end = at + len;
  if (end > bytes.length) fail();
  return { cls, constructed, tag, header: at - offset, start: at, end, content: bytes.subarray(at, end), raw: bytes.subarray(offset, end) };
}

/** The elements inside a constructed element (or a whole buffer). */
export function children(element, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error('DER nested too deeply');
  const bytes = element.content ?? element; const out = []; let at = 0;
  while (at < bytes.length) { const child = readElement(bytes, at); out.push(child); at = child.end; }
  return out;
}

/** Parse a buffer that must hold exactly one element. */
export function parseOne(bytes) {
  const element = readElement(bytes, 0);
  if (element.end !== bytes.length) throw new Error('trailing bytes after DER element');
  return element;
}

/** Universal-class element with this tag, or throw. */
export function expectTag(element, tag, what = 'element') {
  if (!element || element.cls !== 0 || element.tag !== tag) throw new Error(`expected ${what}`);
  return element;
}

export function decodeOid(element) {
  const b = expectTag(element, 6, 'OBJECT IDENTIFIER').content;
  if (!b.length) throw new Error('empty OID');
  const out = [Math.min(2, Math.floor(b[0] / 40)), b[0] - 40 * Math.min(2, Math.floor(b[0] / 40))];
  let n = 0;
  for (let i = 1; i < b.length; i++) { n = n * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { out.push(n); n = 0; } }
  return out.join('.');
}

/** INTEGER or ENUMERATED as a Number (throws past 2^53) — for versions, enums and tags. */
export function decodeSmallInt(element) {
  if (!element || element.cls !== 0 || (element.tag !== 2 && element.tag !== 10)) throw new Error('expected INTEGER');
  const b = element.content;
  if (!b.length || b[0] & 0x80) throw new Error('negative or empty INTEGER');
  let n = 0; for (const byte of b) { n = n * 256 + byte; if (n > Number.MAX_SAFE_INTEGER) throw new Error('INTEGER too large'); }
  return n;
}

/** INTEGER bytes as lowercase hex without leading zeros (how certificate serials are listed). */
export function integerHex(element) {
  const hex = [...expectTag(element, 2, 'INTEGER').content].map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.replace(/^0+(?=.)/, '');
}

/** UTCTime / GeneralizedTime (Z only) to milliseconds. */
export function decodeTime(element) {
  const s = new TextDecoder().decode(element.content);
  let m;
  if (element.tag === 0x17 && (m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) {
    const yy = Number(m[1]);
    return Date.UTC(yy < 50 ? 2000 + yy : 1900 + yy, m[2] - 1, m[3], m[4], m[5], m[6]);
  }
  if (element.tag === 0x18 && (m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s))) return Date.UTC(Number(m[1]), m[2] - 1, m[3], m[4], m[5], m[6]);
  throw new Error('unsupported time');
}
