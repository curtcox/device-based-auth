/**
 * A small QR code encoder (ISO/IEC 18004), written here so the TOTP setup page can show its
 * otpauth: URI as a code without shipping third-party code to every visitor (STATUS B7 G9).
 *
 * Only what that needs: byte mode, error correction level M (15% damage), versions 1–40, mask
 * chosen by the standard penalty rules. No dependencies and no DOM except in qrSvg().
 */

// Level M per version (index = version): error correction codewords per block, and blocks.
const ECC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28];
const BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49];
const LEVEL_M_BITS = 0; // the format field's two bits for level M

/** Modules left for data and error correction once the function patterns are drawn. */
function rawModules(version) {
  let n = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const align = Math.floor(version / 7) + 2;
    n -= (25 * align - 10) * align - 55;
    if (version >= 7) n -= 36;
  }
  return n;
}

/** Data codewords a version holds at level M. */
export function dataCodewords(version) {
  return Math.floor(rawModules(version) / 8) - ECC_PER_BLOCK[version] * BLOCKS[version];
}

/** Bytes a version holds in byte mode at level M (4 mode bits and the length field included). */
export function byteCapacity(version) {
  return Math.floor((dataCodewords(version) * 8 - 4 - (version <= 9 ? 8 : 16)) / 8);
}

/** Centers of the alignment patterns along each axis. */
export function alignmentPositions(version) {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < count; pos -= step) result.splice(1, 0, pos);
  return result;
}

/** The 15 format bits for level M and a mask (BCH(15,5), XOR 0x5412). */
export function formatBits(mask) {
  const data = (LEVEL_M_BITS << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

/** The 18 version bits for versions 7 and up (BCH(18,6)). */
export function versionBits(version) {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
  return (version << 12) | rem;
}

// Reed–Solomon over GF(2^8) with the polynomial 0x11D.
function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11D);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function rsDivisor(degree) {
  const result = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = gfMul(root, 2);
  }
  return result;
}

function rsRemainder(data, divisor) {
  const result = new Array(divisor.length).fill(0);
  for (const b of data) {
    const factor = b ^ result.shift();
    result.push(0);
    for (let i = 0; i < divisor.length; i++) result[i] ^= gfMul(divisor[i], factor);
  }
  return result;
}

/** Split data into blocks, add each block's error correction, and interleave (§7.6). */
function withErrorCorrection(data, version) {
  const blocks = BLOCKS[version];
  const eccLen = ECC_PER_BLOCK[version];
  const raw = Math.floor(rawModules(version) / 8);
  const shortBlocks = blocks - (raw % blocks);
  const shortLen = Math.floor(raw / blocks);
  const divisor = rsDivisor(eccLen);
  const parts = [];
  for (let i = 0, k = 0; i < blocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < shortBlocks ? 0 : 1));
    k += dat.length;
    const ecc = rsRemainder(dat, divisor);
    if (i < shortBlocks) dat.push(0); // a gap so every block is as long; skipped below
    parts.push(dat.concat(ecc));
  }
  const out = [];
  for (let i = 0; i < parts[0].length; i++) {
    for (let j = 0; j < parts.length; j++) if (i !== shortLen - eccLen || j >= shortBlocks) out.push(parts[j][i]);
  }
  return out;
}

const MASKS = [
  (x, y) => (x + y) % 2 === 0,
  (x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => (x * y) % 2 + (x * y) % 3 === 0,
  (x, y) => ((x * y) % 2 + (x * y) % 3) % 2 === 0,
  (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0
];

/** Penalty score of a finished symbol (§7.8.3), used to pick the mask. */
function penalty(m) {
  const size = m.length;
  let score = 0;
  const line = get => {
    let s = 0;
    let run = 1;
    for (let i = 1; i <= size; i++) {
      if (i < size && get(i) === get(i - 1)) { run++; continue; }
      if (run >= 5) s += 3 + run - 5;
      run = 1;
    }
    // Finder-like 1:1:3:1:1 with four light modules on either side.
    for (let i = 0; i + 11 <= size; i++) {
      const p = [];
      for (let k = 0; k < 11; k++) p.push(get(i + k) ? 1 : 0);
      const t = p.join('');
      if (t === '10111010000' || t === '00001011101') s += 40;
    }
    return s;
  };
  for (let y = 0; y < size; y++) score += line(x => m[y][x]);
  for (let x = 0; x < size; x++) score += line(y => m[y][x]);
  let dark = 0;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (m[y][x]) dark++;
      if (x + 1 < size && y + 1 < size && m[y][x] === m[y][x + 1] && m[y][x] === m[y + 1][x] && m[y][x] === m[y + 1][x + 1]) score += 3;
    }
  }
  const total = size * size;
  score += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
  return score;
}

/**
 * Encode text (UTF-8, byte mode, level M) as a QR code.
 * @param {string} text
 * @param {{ mask?: number, minVersion?: number }} [options] mask 0–7 forces a mask (tests)
 * @returns {{ version: number, mask: number, size: number, modules: boolean[][] }} modules[y][x], true = dark
 */
export function qrEncode(text, { mask: forcedMask, minVersion = 1 } = {}) {
  const bytes = [...new TextEncoder().encode(String(text))];
  let version = minVersion;
  while (version <= 40 && byteCapacity(version) < bytes.length) version++;
  if (version > 40) throw new RangeError('Text is too long for a QR code');

  // Bit stream: mode 0100, length, bytes, terminator, pad to bytes, pad codewords.
  const bits = [];
  const put = (value, n) => { for (let i = n - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
  put(4, 4);
  put(bytes.length, version <= 9 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  const capacity = dataCodewords(version) * 8;
  put(0, Math.min(4, capacity - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xEC; bits.length < capacity; pad ^= 0xEC ^ 0x11) put(pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(''), 2));

  const size = version * 4 + 17;
  const modules = Array.from({ length: size }, () => new Array(size).fill(false));
  const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { modules[y][x] = dark; fixed[y][x] = true; };

  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx; const y = cy + dy;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4);
      }
    }
  }
  const align = alignmentPositions(version);
  const last = align.length - 1;
  for (let i = 0; i <= last; i++) {
    for (let j = 0; j <= last; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(align[i] + dx, align[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
  const drawFormat = mask => {
    const f = formatBits(mask);
    const bit = i => ((f >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true); // the dark module
  };
  drawFormat(0);
  if (version >= 7) {
    const v = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const dark = ((v >>> i) & 1) === 1;
      const a = size - 11 + (i % 3); const b = Math.floor(i / 3);
      set(a, b, dark); set(b, a, dark);
    }
  }

  // Codewords in the two-column zigzag from the bottom right (§7.7.3).
  const codewords = withErrorCorrection(data, version);
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const y = ((right + 1) & 2) === 0 ? size - 1 - vert : vert;
        if (fixed[y][x] || i >= codewords.length * 8) continue;
        modules[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
        i++;
      }
    }
  }

  const apply = mask => {
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!fixed[y][x] && MASKS[mask](x, y)) modules[y][x] = !modules[y][x];
  };
  let mask = forcedMask;
  if (mask === undefined) {
    let best = Infinity;
    for (let m = 0; m < 8; m++) {
      apply(m); drawFormat(m);
      const p = penalty(modules);
      if (p < best) { best = p; mask = m; }
      apply(m); // masking twice undoes it
    }
  }
  apply(mask); drawFormat(mask);
  return { version, mask, size, modules };
}

/**
 * The code as an SVG element (dark modules as one path, a 4-module quiet zone). Only numbers go
 * into its markup, never the text.
 * @param {string} text
 * @param {{ label?: string, doc?: Document }} [options]
 * @returns {SVGSVGElement}
 */
export function qrSvg(text, { label = 'QR code', doc = document } = {}) {
  const { size, modules } = qrEncode(text);
  const ns = 'http://www.w3.org/2000/svg';
  const total = size + 8;
  const svg = doc.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', `0 0 ${total} ${total}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', label);
  svg.setAttribute('shape-rendering', 'crispEdges');
  svg.setAttribute('class', 'qr');
  const bg = doc.createElementNS(ns, 'rect');
  bg.setAttribute('width', String(total)); bg.setAttribute('height', String(total)); bg.setAttribute('fill', '#fff');
  const path = doc.createElementNS(ns, 'path');
  let d = '';
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (modules[y][x]) d += `M${x + 4} ${y + 4}h1v1h-1z`;
  path.setAttribute('d', d); path.setAttribute('fill', '#000');
  svg.append(bg, path);
  return svg;
}
