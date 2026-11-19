import { describe, it, expect } from 'vitest';
import { qrEncode, byteCapacity, alignmentPositions, formatBits, versionBits } from '../frontend/js/qr.js';

// The dashboard's QR encoder (frontend/js/qr.js, STATUS B7 G9) checked against constants from
// ISO/IEC 18004 and by a reader written separately here: it finds the mask from the format bits,
// unmasks, reads the zigzag, de-interleaves with the standard's block table, checks every
// Reed–Solomon block's syndromes are zero, and parses the byte segment back to text.

// Format bits for level M, masks 0–7 (ISO/IEC 18004 Table C.1).
const FORMAT_M = ['101010000010010', '101000100100101', '101111001111100', '101101101001011', '100010111111001', '100000011001110', '100111110010111', '100101010100000'];

// Level M block layouts (ISO/IEC 18004 Table 9): [count, data codewords] groups, ecc per block.
const LAYOUT = {
  1: { groups: [[1, 16]], ecc: 10 },
  2: { groups: [[1, 28]], ecc: 16 },
  5: { groups: [[2, 43]], ecc: 24 },
  7: { groups: [[4, 31]], ecc: 18 },
  9: { groups: [[3, 36], [2, 37]], ecc: 22 },
  10: { groups: [[4, 43], [1, 44]], ecc: 26 },
  15: { groups: [[5, 41], [5, 42]], ecc: 24 }
};

// GF(256) by log tables, unlike the encoder's bitwise multiply.
const EXP = new Array(512); const LOG = new Array(256);
for (let i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 256) x ^= 0x11D; }
for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

function syndromesZero(block, ecc) {
  for (let i = 0; i < ecc; i++) {
    let s = 0;
    for (const c of block) s = mul(s, EXP[i]) ^ c; // Horner at α^i
    if (s !== 0) return false;
  }
  return true;
}

// Mask conditions as the standard writes them: i = row, j = column.
const MASK = [
  (i, j) => (i + j) % 2 === 0, (i) => i % 2 === 0, (i, j) => j % 3 === 0, (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0, (i, j) => (i * j) % 2 + (i * j) % 3 === 0,
  (i, j) => ((i * j) % 2 + (i * j) % 3) % 2 === 0, (i, j) => ((i * j) % 3 + (i + j) % 2) % 2 === 0
];

function read(m) {
  const size = m.length;
  const version = (size - 17) / 4;
  const reserved = Array.from({ length: size }, () => new Array(size).fill(false));
  const box = (r0, c0, r1, c1) => { for (let r = r0; r <= r1; r++) for (let c = c0; c <= c1; c++) if (r >= 0 && c >= 0 && r < size && c < size) reserved[r][c] = true; };
  box(0, 0, 8, 8); box(0, size - 8, 8, size - 1); box(size - 8, 0, size - 1, 8); // finders, separators, format
  box(6, 0, 6, size - 1); box(0, 6, size - 1, 6); // timing
  const a = alignmentPositions(version);
  const corner = (r, c) => (r < 9 && c < 9) || (r < 9 && c > size - 9) || (r > size - 9 && c < 9);
  for (const r of a) for (const c of a) if (!corner(r, c)) box(r - 2, c - 2, r + 2, c + 2);
  if (version >= 7) { box(0, size - 11, 5, size - 9); box(size - 11, 0, size - 9, 5); }

  // Format bits, both copies (bit 14 first).
  const bit = (r, c) => (m[r][c] ? '1' : '0');
  const first = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]].map(([r, c]) => bit(r, c)).join('');
  const second = [...Array(7)].map((_, k) => bit(size - 1 - k, 8)).join('') + [...Array(8)].map((_, k) => bit(8, size - 8 + k)).join('');
  expect(second).toBe(first);
  expect(m[size - 8][8]).toBe(true); // the dark module
  const mask = FORMAT_M.indexOf(first);
  expect(mask).toBeGreaterThanOrEqual(0);

  // Zigzag, upward first, skipping the vertical timing column.
  const bits = [];
  let up = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let k = 0; k < size; k++) {
      const r = up ? size - 1 - k : k;
      for (const c of [col, col - 1]) if (!reserved[r][c]) bits.push(m[r][c] !== MASK[mask](r, c) ? 1 : 0);
    }
    up = !up;
  }
  const codewords = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) codewords.push(parseInt(bits.slice(i, i + 8).join(''), 2));

  // De-interleave: data columns across blocks, then ecc columns.
  const { groups, ecc } = LAYOUT[version];
  const lens = groups.flatMap(([n, len]) => Array(n).fill(len));
  const blocks = lens.map(() => []);
  let p = 0;
  for (let i = 0; i < Math.max(...lens); i++) lens.forEach((len, b) => { if (i < len) blocks[b].push(codewords[p++]); });
  for (let i = 0; i < ecc; i++) blocks.forEach(b => b.push(codewords[p++]));
  for (const b of blocks) expect(syndromesZero(b, ecc)).toBe(true);
  const data = blocks.flatMap((b, i) => b.slice(0, lens[i]));

  // Byte segment.
  const stream = data.flatMap(c => [...c.toString(2).padStart(8, '0')].map(Number));
  const take = n => parseInt(stream.splice(0, n).join(''), 2);
  expect(take(4)).toBe(4);
  const length = take(version <= 9 ? 8 : 16);
  return { mask, text: new TextDecoder().decode(new Uint8Array([...Array(length)].map(() => take(8)))) };
}

describe('QR encoder (TOTP setup, STATUS B7 G9)', () => {
  it('matches the standard\'s capacities, alignment positions, format and version bits', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 40].map(byteCapacity)).toEqual([14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 666, 2331]);
    expect(alignmentPositions(2)).toEqual([6, 18]);
    expect(alignmentPositions(7)).toEqual([6, 22, 38]);
    expect(alignmentPositions(14)).toEqual([6, 26, 46, 66]);
    expect(alignmentPositions(32)).toEqual([6, 34, 60, 86, 112, 138]);
    expect(alignmentPositions(40)).toEqual([6, 30, 58, 86, 114, 142, 170]);
    expect([0, 1, 2, 3, 4, 5, 6, 7].map(m => formatBits(m).toString(2).padStart(15, '0'))).toEqual(FORMAT_M);
    expect(versionBits(7).toString(2).padStart(18, '0')).toBe('000111110010010100');
    expect(versionBits(8).toString(2).padStart(18, '0')).toBe('001000010110111100');
  });

  it('round-trips through the reader at several versions and every mask', () => {
    const uri = 'otpauth://totp/devicebasedauth.org:Pixel%20authenticator?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=devicebasedauth.org&algorithm=SHA1&digits=6&period=30';
    for (const [text, version] of [['HELLO', 1], ['a'.repeat(26), 2], ['é'.repeat(40), 5], [uri, 9], ['y'.repeat(200), 10], ['x'.repeat(400), 15]]) {
      const auto = qrEncode(text);
      expect(auto.version).toBe(version);
      expect(read(auto.modules).text).toBe(text);
      for (let mask = 0; mask < 8; mask++) {
        const forced = qrEncode(text, { mask });
        expect(read(forced.modules)).toEqual({ mask, text });
      }
    }
    expect(qrEncode('x', { minVersion: 7 }).version).toBe(7);
    expect(read(qrEncode('x'.repeat(100), { minVersion: 7 }).modules).text).toBe('x'.repeat(100));
  });

  it('the reader notices a flipped module', () => {
    const { modules } = qrEncode('HELLO', { mask: 3 });
    modules[20][20] = !modules[20][20];
    expect(() => read(modules)).toThrow();
  });

  it('refuses text too long for any version', () => {
    expect(() => qrEncode('x'.repeat(2332))).toThrow(RangeError);
  });
});
