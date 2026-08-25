//
// HEATDEATH - offline BIP-39 / EVM seed generator
// Copyright (C) 2026 ILIA MAKSIMENKA
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details. You should have received a copy of it along with this
// program; if not, see <https://www.gnu.org/licenses/>.
//
// Third-party material embedded here is under its own terms - see NOTICE.md.
//
//
// QR Code encoder — byte mode, ECC levels L and M, versions 1-40.
// ISO/IEC 18004.
//
// WHAT THIS IS FOR, STATED NARROWLY
// ---------------------------------
// Putting the derived ADDRESS LIST on a second screen so it can be compared
// without retyping 42 hex characters eleven times. Transcription error is the
// dominant real-world failure of this whole workflow, and comparing addresses
// by eye across two devices is exactly where it strikes.
//
// WHAT IT IS NOT
// --------------
// It is NOT independent verification. Verifying a derivation independently
// requires the second device to DERIVE the addresses, which requires the seed
// there. Moving the addresses moves the OUTPUT of the computation under test,
// so it cannot check itself. For real independent verification see
// docs/en/COMPARISON.md, "Сверка с третьими инструментами".
//
// WHAT IT MUST NEVER CARRY
// ------------------------
// Mnemonic, entropy, seed, private keys, SLIP-39 shares — and NOT the account
// extended public key either. docs/en/ENTROPY.md explains why the hardened
// `account` scheme exists: one leaked account xpub exposes the public keys of
// every address under it, including ones that have never spent, collapsing
// their 160-bit hash barrier against a future quantum attack. A photographed
// QR is machine-readable in a way a photographed address list is not, so an
// xpub export would be a convenient way to do the exact thing this project
// warns against. The public entry point takes an ARRAY OF ADDRESS STRINGS and
// nothing else, by construction rather than by discipline.
//
// VALIDATION
// ----------
// Two oracles, both external, run in the self-test of the parent tool:
//   1. OpenCV's QR detector decodes this encoder's output back to the exact
//      input string. That is validity as a phone experiences it.
//   2. With the mask index pinned on both sides, the module matrix is
//      identical to Python's `qrcode` library. (Unpinned, two conformant
//      encoders may legitimately pick different masks and agree on nothing.)
//
import assert from "node:assert/strict";

// ---------------------------------------------------------------------------
// GF(256) FOR REED-SOLOMON
//
// QR uses primitive polynomial 0x11D. This is NOT the 0x11B used by AES and
// by the Shamir code in slip39.mjs. Mixing them up yields tables that look
// plausible, pass a self-consistent round-trip, and are wrong — the same
// shape of bug that a doubling-vs-(x+1) generator already caused in this
// project once. The self-test pins two published products.
// ---------------------------------------------------------------------------

export const QR_PRIMITIVE_POLYNOMIAL = 0x11d;

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= QR_PRIMITIVE_POLYNOMIAL;
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255];
}

export const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

/** Generator polynomial for `degree` error-correction codewords. */
function rsGenerator(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data, ecLength) {
  const gen = rsGenerator(ecLength);
  const remainder = new Uint8Array(ecLength);
  for (const byte of data) {
    const factor = byte ^ remainder[0];
    remainder.copyWithin(0, 1);
    remainder[ecLength - 1] = 0;
    for (let i = 0; i < ecLength; i += 1) remainder[i] ^= gfMul(gen[i + 1], factor);
  }
  return remainder;
}

// ---------------------------------------------------------------------------
// SPECIFICATION TABLES
//
// Transcribed programmatically from the reference `qrcode` Python package
// (BSD, Copyright (c) 2011 Lincoln Loop - see NOTICE.md) rather than typed by
// hand; typing 320 block-structure numbers by eye is a guaranteed source of
// silent corruption. The values themselves are data defined by ISO/IEC 18004.
//
// EC_BLOCKS[level][version] = [ecCodewordsPerBlock, [[blockCount, dataWords], ...]]
// ALIGN[version] = alignment pattern centre coordinates
// ---------------------------------------------------------------------------

const EC_BLOCKS = {
  L: {
    1: [7, [[1, 19]]],
    2: [10, [[1, 34]]],
    3: [15, [[1, 55]]],
    4: [20, [[1, 80]]],
    5: [26, [[1, 108]]],
    6: [18, [[2, 68]]],
    7: [20, [[2, 78]]],
    8: [24, [[2, 97]]],
    9: [30, [[2, 116]]],
    10: [18, [[2, 68], [2, 69]]],
    11: [20, [[4, 81]]],
    12: [24, [[2, 92], [2, 93]]],
    13: [26, [[4, 107]]],
    14: [30, [[3, 115], [1, 116]]],
    15: [22, [[5, 87], [1, 88]]],
    16: [24, [[5, 98], [1, 99]]],
    17: [28, [[1, 107], [5, 108]]],
    18: [30, [[5, 120], [1, 121]]],
    19: [28, [[3, 113], [4, 114]]],
    20: [28, [[3, 107], [5, 108]]],
    21: [28, [[4, 116], [4, 117]]],
    22: [28, [[2, 111], [7, 112]]],
    23: [30, [[4, 121], [5, 122]]],
    24: [30, [[6, 117], [4, 118]]],
    25: [26, [[8, 106], [4, 107]]],
    26: [28, [[10, 114], [2, 115]]],
    27: [30, [[8, 122], [4, 123]]],
    28: [30, [[3, 117], [10, 118]]],
    29: [30, [[7, 116], [7, 117]]],
    30: [30, [[5, 115], [10, 116]]],
    31: [30, [[13, 115], [3, 116]]],
    32: [30, [[17, 115]]],
    33: [30, [[17, 115], [1, 116]]],
    34: [30, [[13, 115], [6, 116]]],
    35: [30, [[12, 121], [7, 122]]],
    36: [30, [[6, 121], [14, 122]]],
    37: [30, [[17, 122], [4, 123]]],
    38: [30, [[4, 122], [18, 123]]],
    39: [30, [[20, 117], [4, 118]]],
    40: [30, [[19, 118], [6, 119]]],
  },
  M: {
    1: [10, [[1, 16]]],
    2: [16, [[1, 28]]],
    3: [26, [[1, 44]]],
    4: [18, [[2, 32]]],
    5: [24, [[2, 43]]],
    6: [16, [[4, 27]]],
    7: [18, [[4, 31]]],
    8: [22, [[2, 38], [2, 39]]],
    9: [22, [[3, 36], [2, 37]]],
    10: [26, [[4, 43], [1, 44]]],
    11: [30, [[1, 50], [4, 51]]],
    12: [22, [[6, 36], [2, 37]]],
    13: [22, [[8, 37], [1, 38]]],
    14: [24, [[4, 40], [5, 41]]],
    15: [24, [[5, 41], [5, 42]]],
    16: [28, [[7, 45], [3, 46]]],
    17: [28, [[10, 46], [1, 47]]],
    18: [26, [[9, 43], [4, 44]]],
    19: [26, [[3, 44], [11, 45]]],
    20: [26, [[3, 41], [13, 42]]],
    21: [26, [[17, 42]]],
    22: [28, [[17, 46]]],
    23: [28, [[4, 47], [14, 48]]],
    24: [28, [[6, 45], [14, 46]]],
    25: [28, [[8, 47], [13, 48]]],
    26: [28, [[19, 46], [4, 47]]],
    27: [28, [[22, 45], [3, 46]]],
    28: [28, [[3, 45], [23, 46]]],
    29: [28, [[21, 45], [7, 46]]],
    30: [28, [[19, 47], [10, 48]]],
    31: [28, [[2, 46], [29, 47]]],
    32: [28, [[10, 46], [23, 47]]],
    33: [28, [[14, 46], [21, 47]]],
    34: [28, [[14, 46], [23, 47]]],
    35: [28, [[12, 47], [26, 48]]],
    36: [28, [[6, 47], [34, 48]]],
    37: [28, [[29, 46], [14, 47]]],
    38: [28, [[13, 46], [32, 47]]],
    39: [28, [[40, 47], [7, 48]]],
    40: [28, [[18, 47], [31, 48]]],
  },
};
const ALIGN = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
  11: [6, 30, 54],
  12: [6, 32, 58],
  13: [6, 34, 62],
  14: [6, 26, 46, 66],
  15: [6, 26, 48, 70],
  16: [6, 26, 50, 74],
  17: [6, 30, 54, 78],
  18: [6, 30, 56, 82],
  19: [6, 30, 58, 86],
  20: [6, 34, 62, 90],
  21: [6, 28, 50, 72, 94],
  22: [6, 26, 50, 74, 98],
  23: [6, 30, 54, 78, 102],
  24: [6, 28, 54, 80, 106],
  25: [6, 32, 58, 84, 110],
  26: [6, 30, 58, 86, 114],
  27: [6, 34, 62, 90, 118],
  28: [6, 26, 50, 74, 98, 122],
  29: [6, 30, 54, 78, 102, 126],
  30: [6, 26, 52, 78, 104, 130],
  31: [6, 30, 56, 82, 108, 134],
  32: [6, 34, 60, 86, 112, 138],
  33: [6, 30, 58, 86, 114, 142],
  34: [6, 34, 62, 90, 118, 146],
  35: [6, 30, 54, 78, 102, 126, 150],
  36: [6, 24, 50, 76, 102, 128, 154],
  37: [6, 28, 54, 80, 106, 132, 158],
  38: [6, 32, 58, 84, 110, 136, 162],
  39: [6, 26, 54, 82, 110, 138, 166],
  40: [6, 30, 58, 86, 114, 142, 170],
};

// Format-info error-correction level bits (NOT the same order as the names).
const ECC_BITS = { L: 0b01, M: 0b00 };

// ---------------------------------------------------------------------------
// DATA ENCODING
// ---------------------------------------------------------------------------

const charCountBits = (version) => (version <= 9 ? 8 : 16);

function totalDataCodewords(version, ecc) {
  const [, groups] = EC_BLOCKS[ecc][version];
  return groups.reduce((sum, [count, words]) => sum + count * words, 0);
}

function chooseVersion(byteLength, ecc) {
  for (let version = 1; version <= 40; version += 1) {
    const capacityBits = totalDataCodewords(version, ecc) * 8;
    const needed = 4 + charCountBits(version) + byteLength * 8;
    if (needed <= capacityBits) return version;
  }
  assert.fail(
    `${byteLength} bytes does not fit in any QR version at ECC level ${ecc}`,
  );
}

function buildCodewords(bytes, version, ecc) {
  const bits = [];
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i -= 1) bits.push((value >> i) & 1);
  };

  push(0b0100, 4); // byte mode
  push(bytes.length, charCountBits(version));
  for (const b of bytes) push(b, 8);

  const capacity = totalDataCodewords(version, ecc) * 8;
  assert.ok(bits.length <= capacity, "data exceeds chosen version capacity");
  for (let i = 0; i < 4 && bits.length < capacity; i += 1) bits.push(0); // terminator
  while (bits.length % 8 !== 0) bits.push(0);

  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    data.push(bits.slice(i, i + 8).reduce((v, b) => (v << 1) | b, 0));
  }
  // Alternating pad codewords, per spec.
  const PAD = [0xec, 0x11];
  for (let i = 0; data.length < capacity / 8; i += 1) data.push(PAD[i % 2]);
  return data;
}

/** Split into blocks, RS-encode each, then interleave data and EC codewords. */
function interleave(data, version, ecc) {
  const [ecPerBlock, groups] = EC_BLOCKS[ecc][version];
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (const [count, words] of groups) {
    for (let i = 0; i < count; i += 1) {
      const block = data.slice(offset, offset + words);
      offset += words;
      dataBlocks.push(block);
      ecBlocks.push(rsEncode(block, ecPerBlock));
    }
  }
  assert.equal(offset, data.length, "block split did not consume all data");

  const out = [];
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxData; i += 1) {
    for (const block of dataBlocks) if (i < block.length) out.push(block[i]);
  }
  for (let i = 0; i < ecPerBlock; i += 1) {
    for (const block of ecBlocks) out.push(block[i]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// MATRIX CONSTRUCTION
// ---------------------------------------------------------------------------

const FORMAT_GENERATOR = 0x537;
const FORMAT_MASK = 0x5412;
const VERSION_GENERATOR = 0x1f25;

function bch(value, generator, degree) {
  let rest = value << degree;
  const genBits = 32 - Math.clz32(generator);
  while (32 - Math.clz32(rest) >= genBits) {
    rest ^= generator << (32 - Math.clz32(rest) - genBits);
  }
  return (value << degree) | rest;
}

const formatBits = (ecc, mask) =>
  bch((ECC_BITS[ecc] << 3) | mask, FORMAT_GENERATOR, 10) ^ FORMAT_MASK;

const versionBits = (version) => bch(version, VERSION_GENERATOR, 12);

const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function blankMatrix(size) {
  return {
    size,
    modules: new Uint8Array(size * size),
    reserved: new Uint8Array(size * size),
  };
}

const setModule = (m, r, c, dark, reserve = true) => {
  m.modules[r * m.size + c] = dark ? 1 : 0;
  if (reserve) m.reserved[r * m.size + c] = 1;
};

function placeFunctionPatterns(m, version) {
  const size = m.size;

  const finder = (row, col) => {
    for (let r = -1; r <= 7; r += 1) {
      for (let c = -1; c <= 7; c += 1) {
        const rr = row + r;
        const cc = col + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const outer = r >= 0 && r <= 6 && (c === 0 || c === 6);
        const side = c >= 0 && c <= 6 && (r === 0 || r === 6);
        const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        setModule(m, rr, cc, outer || side || core);
      }
    }
  };
  finder(0, 0);
  finder(0, size - 7);
  finder(size - 7, 0);

  for (const centre of ALIGN[version]) {
    for (const other of ALIGN[version]) {
      // Skip the three that would sit on top of a finder pattern.
      const nearFinder =
        (centre <= 8 && other <= 8) ||
        (centre <= 8 && other >= size - 9) ||
        (centre >= size - 9 && other <= 8);
      if (nearFinder) continue;
      for (let r = -2; r <= 2; r += 1) {
        for (let c = -2; c <= 2; c += 1) {
          setModule(m, centre + r, other + c, Math.max(Math.abs(r), Math.abs(c)) !== 1);
        }
      }
    }
  }

  for (let i = 8; i < size - 8; i += 1) {
    setModule(m, 6, i, i % 2 === 0);
    setModule(m, i, 6, i % 2 === 0);
  }

  // Reserve the format-information areas; contents written after masking.
  // The bounds here must match writeFormat exactly: copy 2 occupies row 8 for
  // eight columns from the right edge, but only SEVEN rows up column 8 from
  // the bottom. Reserving eight would clear the always-dark module below,
  // which is a one-module error that no scanner tolerates and that leaves
  // every other module correct - so nothing points at it.
  for (let i = 0; i < 9; i += 1) {
    if (i !== 6) setModule(m, i, 8, false);
    if (i !== 6) setModule(m, 8, i, false);
  }
  for (let i = 0; i < 8; i += 1) setModule(m, 8, size - 1 - i, false);
  for (let i = 0; i < 7; i += 1) setModule(m, size - 1 - i, 8, false);

  setModule(m, size - 8, 8, true); // the always-dark module

  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i += 1) {
      const bit = ((bits >> i) & 1) === 1;
      setModule(m, Math.floor(i / 3), size - 11 + (i % 3), bit);
      setModule(m, size - 11 + (i % 3), Math.floor(i / 3), bit);
    }
  }
}

function placeData(m, codewords) {
  const size = m.size;
  let bitIndex = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    const col = right <= 6 ? right - 1 : right; // column 6 is the timing pattern
    for (let i = 0; i < size; i += 1) {
      const row = upward ? size - 1 - i : i;
      for (const c of [col, col - 1]) {
        if (m.reserved[row * m.size + c]) continue;
        const byte = codewords[bitIndex >> 3];
        const bit = byte === undefined ? 0 : (byte >> (7 - (bitIndex & 7))) & 1;
        m.modules[row * m.size + c] = bit;
        bitIndex += 1;
      }
    }
    upward = !upward;
  }
}

function applyMask(m, maskIndex) {
  const fn = MASKS[maskIndex];
  const out = { size: m.size, modules: Uint8Array.from(m.modules), reserved: m.reserved };
  for (let r = 0; r < m.size; r += 1) {
    for (let c = 0; c < m.size; c += 1) {
      if (m.reserved[r * m.size + c]) continue;
      if (fn(r, c)) out.modules[r * m.size + c] ^= 1;
    }
  }
  return out;
}

function writeFormat(m, ecc, maskIndex) {
  const bits = formatBits(ecc, maskIndex);
  const size = m.size;
  // Coordinates are (row, column). Getting these two strips transposed still
  // produces a well-formed-looking symbol that no scanner can read, because
  // every module outside the format area is correct - so the failure gives no
  // hint where it is. Copy 1 runs DOWN column 8 then LEFT along row 8; copy 2
  // runs LEFT along row 8 from the right edge, then UP column 8 from the
  // bottom, skipping the always-dark module at (size - 8, 8).
  for (let i = 0; i < 15; i += 1) {
    const bit = ((bits >> i) & 1) === 1;

    if (i < 6) setModule(m, i, 8, bit);
    else if (i === 6) setModule(m, 7, 8, bit);
    else if (i === 7) setModule(m, 8, 8, bit);
    else if (i === 8) setModule(m, 8, 7, bit);
    else setModule(m, 8, 14 - i, bit);

    if (i < 8) setModule(m, 8, size - 1 - i, bit);
    else setModule(m, size - 15 + i, 8, bit);
  }
}

/** ISO/IEC 18004 penalty rules; the lowest-scoring mask is chosen. */
function penalty(m) {
  const size = m.size;
  const at = (r, c) => m.modules[r * size + c];
  let score = 0;

  for (const transposed of [false, true]) {
    for (let a = 0; a < size; a += 1) {
      let run = 1;
      for (let b = 1; b < size; b += 1) {
        const prev = transposed ? at(b - 1, a) : at(a, b - 1);
        const cur = transposed ? at(b, a) : at(a, b);
        if (cur === prev) {
          run += 1;
          if (run === 5) score += 3;
          else if (run > 5) score += 1;
        } else {
          run = 1;
        }
      }
    }
  }

  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const v = at(r, c);
      if (v === at(r, c + 1) && v === at(r + 1, c) && v === at(r + 1, c + 1)) score += 3;
    }
  }

  const FINDER = [1, 0, 1, 1, 1, 0, 1];
  const matches = (get, i) => {
    for (let k = 0; k < 7; k += 1) if (get(i + k) !== FINDER[k]) return false;
    return true;
  };
  const clearRun = (get, from, to) => {
    for (let k = from; k < to; k += 1) if (get(k) !== 0) return false;
    return true;
  };
  for (const transposed of [false, true]) {
    for (let a = 0; a < size; a += 1) {
      const get = (i) =>
        i < 0 || i >= size ? 0 : transposed ? at(i, a) : at(a, i);
      for (let i = 0; i <= size - 7; i += 1) {
        if (!matches(get, i)) continue;
        if (clearRun(get, i - 4, i) || clearRun(get, i + 7, i + 11)) score += 40;
      }
    }
  }

  let dark = 0;
  for (let i = 0; i < size * size; i += 1) dark += m.modules[i];
  const percent = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;
  return score;
}

// ---------------------------------------------------------------------------
// PUBLIC API
// ---------------------------------------------------------------------------

/**
 * Encode text as a QR symbol.
 *
 * @param {string} text
 * @param {{ecc?: "L"|"M", mask?: number}} options `mask` forces a mask index
 *   instead of choosing by penalty score; used only to compare against another
 *   encoder, since two conformant encoders may legitimately pick different
 *   masks and then agree on no module at all.
 * @returns {{size: number, version: number, mask: number, modules: Uint8Array}}
 */
export function encodeQR(text, { ecc = "M", mask = null } = {}) {
  assert.ok(ecc === "L" || ecc === "M", `unsupported ECC level ${ecc}`);
  const bytes = Buffer.from(String(text), "utf8");
  const version = chooseVersion(bytes.length, ecc);
  const codewords = interleave(buildCodewords(bytes, version, ecc), version, ecc);

  const size = version * 4 + 17;
  const base = blankMatrix(size);
  placeFunctionPatterns(base, version);
  placeData(base, codewords);

  let best = null;
  const candidates = mask === null ? [0, 1, 2, 3, 4, 5, 6, 7] : [mask];
  for (const index of candidates) {
    const masked = applyMask(base, index);
    writeFormat(masked, ecc, index);
    const score = mask === null ? penalty(masked) : 0;
    if (best === null || score < best.score) best = { score, index, masked };
  }

  return { size, version, mask: best.index, modules: best.masked.modules };
}

/**
 * Render a symbol for a terminal, two rows per line using half-block glyphs.
 * The quiet zone is not decoration: scanners need it to find the symbol.
 */
export function renderQR({ size, modules }, { quiet = 4 } = {}) {
  const total = size + quiet * 2;
  const dark = (r, c) =>
    r >= quiet && c >= quiet && r < quiet + size && c < quiet + size &&
    modules[(r - quiet) * size + (c - quiet)] === 1;

  // Half-block glyphs: one character cell holds TWO module rows. A terminal
  // cell is roughly one unit wide and two tall, so ONE character per module
  // column keeps the symbol square. Emitting two characters per module - the
  // obvious-looking choice - stretches it 2:1 horizontally and doubles the
  // width, which pushes anything past v8 off an 80-column terminal.
  const GLYPHS = [" ", "\u2584", "\u2580", "\u2588"]; // none, lower, upper, full
  const lines = [];
  for (let r = 0; r < total; r += 2) {
    let line = "";
    for (let c = 0; c < total; c += 1) {
      const top = dark(r, c) ? 2 : 0;
      const bottom = r + 1 < total && dark(r + 1, c) ? 1 : 0;
      line += GLYPHS[top | bottom];
    }
    lines.push(line);
  }
  return lines.join("\n");
}

export const MAX_SCANNABLE_VERSION = 12;

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

/**
 * Encode a list of EVM addresses as one or more scannable symbols.
 *
 * THE INPUT TYPE IS THE SAFETY PROPERTY. This takes an array of address
 * strings and validates each against EVM_ADDRESS before encoding. A mnemonic,
 * a private key, an entropy hex blob or an extended public key cannot pass
 * that check, so the "never QR a secret" rule is enforced structurally here
 * rather than by remembering it at every call site.
 *
 * @param {string[]} addresses
 * @returns {{label: string, text: string, symbol: object}[]}
 */
export function encodeAddressQRs(addresses, { ecc = "L" } = {}) {
  assert.ok(Array.isArray(addresses) && addresses.length > 0, "no addresses given");
  addresses.forEach((address, i) => {
    assert.match(
      String(address), EVM_ADDRESS,
      `entry ${i} is not an EVM address. This encoder accepts addresses only - ` +
        "it must never be handed a mnemonic, key, share or extended public key.",
    );
  });

  const lines = addresses.map((a, i) => `${i} ${a}`);

  // The fit probe must include the "part i/n" header, because the final
  // encode does. Sizing without it produces chunks that individually fit and
  // then tip over the version cap once the header is prepended - a bug that
  // only appears at the exact list length where a chunk sits on the boundary.
  // A fixed worst-case header keeps the probe conservative.
  const HEADER_PROBE = "part 99/99\n";
  const chunks = [];
  let current = [];
  for (const line of lines) {
    const candidate = [...current, line];
    const { version } = encodeQR(HEADER_PROBE + candidate.join("\n"), { ecc, mask: 0 });
    if (version > MAX_SCANNABLE_VERSION && current.length > 0) {
      chunks.push(current);
      current = [line];
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) chunks.push(current);
  assert.ok(
    chunks.every((c) => c.length > 0),
    "a single address does not fit the version cap",
  );

  return chunks.map((chunk, i) => {
    const header = chunks.length > 1 ? `part ${i + 1}/${chunks.length}\n` : "";
    const text = header + chunk.join("\n");
    return { label: `addresses ${chunk[0].split(" ")[0]}-${chunk[chunk.length - 1].split(" ")[0]}`,
             text, symbol: encodeQR(text, { ecc }) };
  });
}

export const QR_LIMITS = { maxVersion: 40, levels: ["L", "M"], maxScannable: MAX_SCANNABLE_VERSION };

/** Spot-checks that fail loudly if the GF(256) tables ever drift to 0x11B. */
export function qrSelfTest({ log = () => {} }) {
  assert.equal(QR_PRIMITIVE_POLYNOMIAL, 0x11d, "QR must use primitive polynomial 0x11D");
  // Products over GF(2^8)/0x11D, computed independently by long
  // multiplication rather than read out of these tables.
  //
  // The middle one is the discriminator: 0x57 * 0x83 is 0x31 under QR's
  // 0x11D and 0xC1 under AES's 0x11B. Since slip39.mjs legitimately uses
  // 0x11B a few files away, this single assertion is what stops the two
  // polynomials being swapped - a mistake that yields tables which look
  // reasonable and are silently wrong for most products.
  assert.equal(gfMul(3, 7), 0x09);
  assert.equal(gfMul(0x57, 0x83), 0x31, "GF tables are not using 0x11D");
  assert.equal(gfMul(0x02, 0x8e), 0x01, "0x02 and 0x8E are inverses mod 0x11D");
  assert.equal(new Set(EXP.slice(0, 255)).size, 255, "generator is not primitive");
  log("QR GF(256)/0x11D arithmetic matches published values");

  // End-to-end shape check across a version boundary and a character-count
  // boundary. Byte-identity against an external encoder is verified out of
  // band; see docs/en/VERIFY.md.
  for (const [text, expectVersion] of [["test", 1], ["x".repeat(120), 7]]) {
    const q = encodeQR(text, { ecc: "M" });
    assert.equal(q.version, expectVersion, `unexpected version for ${text.length} bytes`);
    assert.equal(q.size, q.version * 4 + 17);
    assert.equal(q.modules.length, q.size * q.size);
  }
  const qrs = encodeAddressQRs(Array.from({ length: 11 }, () => "0x" + "aB".repeat(20)));
  for (const { symbol } of qrs) {
    assert.ok(symbol.version <= MAX_SCANNABLE_VERSION, "emitted an unscannable version");
  }
  assert.throws(
    () => encodeAddressQRs(["abandon abandon abandon"]),
    /not an EVM address/, "address encoder accepted non-address input",
  );
  log(`QR address encoding: ${qrs.length} symbol(s), all within v${MAX_SCANNABLE_VERSION}`);
}
