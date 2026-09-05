#!/usr/bin/env node

// generate.mjs
import assert4 from "node:assert/strict";
import os2 from "node:os";
import fs from "node:fs";
import path from "node:path";
import process3 from "node:process";
import {
  createHash as createHash2,
  createHmac as createHmac2,
  pbkdf2Sync as pbkdf2Sync2,
  randomBytes as randomBytes4,
  timingSafeEqual
} from "node:crypto";

// node_modules/@noble/hashes/_u64.js
var U32_MASK64 = /* @__PURE__ */ (() => BigInt(2 ** 32 - 1))();
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var fromNumH = (n) => n / 2 ** 32 | 0;
var fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE2) {
  const h = fromNumH(n);
  const l = fromNumL(n);
  view.setUint32(byteOffset, isLE2 ? l : h, isLE2);
  view.setUint32(byteOffset + 4, isLE2 ? h : l, isLE2);
}
var shrSH = (h, _l, s) => h >>> s;
var shrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrSH = (h, l, s) => h >>> s | l << 32 - s;
var rotrSL = (h, l, s) => h << 32 - s | l >>> s;
var rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
var rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
function add(Ah, Al, Bh, Bl) {
  const l = (Al >>> 0) + (Bl >>> 0);
  return { h: Ah + Bh + (l / 2 ** 32 | 0) | 0, l: l | 0 };
}
var add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
var add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
var add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
var add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
var add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
var add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;

// node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abool(value, title = "") {
  if (typeof value !== "boolean")
    throw new TypeError(atitle(title) + "expected boolean, got type=" + typeof value);
  return value;
}
function abytes(value, length, title = "") {
  if (isBytes(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new TypeError("expected hash wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
  if (h.outputLen < 1 || h.blockLen < 1)
    throw new Error("hash blockLen / outputLen must be >= 1");
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function rotl(word, shift) {
  return word << shift | word >>> 32 - shift >>> 0;
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
function asciiToBase16(ch) {
  return ch >= 48 && ch <= 57 ? ch - 48 : ch >= 65 && ch <= 70 ? ch - (65 - 10) : ch >= 97 && ch <= 102 ? ch - (97 - 10) : void 0;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new TypeError("hex string expected, got " + typeof hex);
  if (hasHexBuiltin) {
    try {
      return Uint8Array.fromHex(hex);
    } catch (error) {
      if (error instanceof SyntaxError)
        throw new RangeError(error.message);
      throw error;
    }
  }
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new RangeError("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new TypeError("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function kdfInputToBytes(data, errorTitle = "") {
  if (typeof data === "string")
    return utf8ToBytes(data);
  return abytes(data, void 0, errorTitle);
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function checkOpts(defaults, opts, title = "opts") {
  aobject(defaults, "defaults");
  if (opts !== void 0)
    aobject(opts, title);
  const merged = Object.assign(defaults, opts);
  return merged;
}
function createHasher(hashCons, info = {}) {
  if (typeof hashCons !== "function")
    throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
  info = checkOpts({}, info, "info");
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes(bytesLength = 32) {
  anumber(bytesLength, "bytesLength");
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  if (bytesLength > 65536)
    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// node_modules/@noble/hashes/_md.js
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class {
  blockLen;
  outputLen;
  canXOF = false;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE2) {
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let processed = false;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        processed = true;
        continue;
      }
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
        processed = true;
      }
    }
    this.length += data.length;
    if (processed)
      this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    buffer.fill(0, pos);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      buffer.fill(0);
    }
    setU64FromNum(view, blockLen - 8, this.length * 8, isLE2);
    this.process(view, 0);
    this.roundClean();
    const oview = out === buffer ? view : createView(out);
    const len = this.outputLen;
    const outLen = len / 4;
    const state = this.get();
    if (len % 4 || outLen > state.length)
      throw new Error("invalid outputLen");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneIntoMeta(to) {
    const { buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (pos)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);
var SHA512_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  4089235720,
  3144134277,
  2227873595,
  1013904242,
  4271175723,
  2773480762,
  1595750129,
  1359893119,
  2917565137,
  2600822924,
  725511199,
  528734635,
  4215389547,
  1541459225,
  327033209
]);

// node_modules/@noble/hashes/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA2_32B = class extends HashMD {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // Numeric initializers matter: starting the fields as `undefined` changes
  // V8's field representation and makes sha256 3x slower (measured).
  A = 0;
  B = 0;
  C = 0;
  D = 0;
  E = 0;
  F = 0;
  G = 0;
  H = 0;
  constructor(outputLen, IV) {
    super(64, outputLen, 8, false);
    this.A = IV[0] | 0;
    this.B = IV[1] | 0;
    this.C = IV[2] | 0;
    this.D = IV[3] | 0;
    this.E = IV[4] | 0;
    this.F = IV[5] | 0;
    this.G = IV[6] | 0;
    this.H = IV[7] | 0;
  }
  get() {
    const { A, B: B2, C, D, E, F, G, H } = this;
    return [A, B2, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B2, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B2 | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  _cloneInto(to) {
    (to ||= new this.constructor()).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B: B2, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B2, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B2;
      B2 = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B2 = B2 + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B2, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var _SHA256 = class extends SHA2_32B {
  constructor() {
    super(32, SHA256_IV);
  }
};
var K512 = /* @__PURE__ */ (() => split([
  "0x428a2f98d728ae22",
  "0x7137449123ef65cd",
  "0xb5c0fbcfec4d3b2f",
  "0xe9b5dba58189dbbc",
  "0x3956c25bf348b538",
  "0x59f111f1b605d019",
  "0x923f82a4af194f9b",
  "0xab1c5ed5da6d8118",
  "0xd807aa98a3030242",
  "0x12835b0145706fbe",
  "0x243185be4ee4b28c",
  "0x550c7dc3d5ffb4e2",
  "0x72be5d74f27b896f",
  "0x80deb1fe3b1696b1",
  "0x9bdc06a725c71235",
  "0xc19bf174cf692694",
  "0xe49b69c19ef14ad2",
  "0xefbe4786384f25e3",
  "0x0fc19dc68b8cd5b5",
  "0x240ca1cc77ac9c65",
  "0x2de92c6f592b0275",
  "0x4a7484aa6ea6e483",
  "0x5cb0a9dcbd41fbd4",
  "0x76f988da831153b5",
  "0x983e5152ee66dfab",
  "0xa831c66d2db43210",
  "0xb00327c898fb213f",
  "0xbf597fc7beef0ee4",
  "0xc6e00bf33da88fc2",
  "0xd5a79147930aa725",
  "0x06ca6351e003826f",
  "0x142929670a0e6e70",
  "0x27b70a8546d22ffc",
  "0x2e1b21385c26c926",
  "0x4d2c6dfc5ac42aed",
  "0x53380d139d95b3df",
  "0x650a73548baf63de",
  "0x766a0abb3c77b2a8",
  "0x81c2c92e47edaee6",
  "0x92722c851482353b",
  "0xa2bfe8a14cf10364",
  "0xa81a664bbc423001",
  "0xc24b8b70d0f89791",
  "0xc76c51a30654be30",
  "0xd192e819d6ef5218",
  "0xd69906245565a910",
  "0xf40e35855771202a",
  "0x106aa07032bbd1b8",
  "0x19a4c116b8d2d0c8",
  "0x1e376c085141ab53",
  "0x2748774cdf8eeb99",
  "0x34b0bcb5e19b48a8",
  "0x391c0cb3c5c95a63",
  "0x4ed8aa4ae3418acb",
  "0x5b9cca4f7763e373",
  "0x682e6ff3d6b2b8a3",
  "0x748f82ee5defb2fc",
  "0x78a5636f43172f60",
  "0x84c87814a1f0ab72",
  "0x8cc702081a6439ec",
  "0x90befffa23631e28",
  "0xa4506cebde82bde9",
  "0xbef9a3f7b2c67915",
  "0xc67178f2e372532b",
  "0xca273eceea26619c",
  "0xd186b8c721c0c207",
  "0xeada7dd6cde0eb1e",
  "0xf57d4f7fee6ed178",
  "0x06f067aa72176fba",
  "0x0a637dc5a2c898a6",
  "0x113f9804bef90dae",
  "0x1b710b35131c471b",
  "0x28db77f523047d84",
  "0x32caab7b40c72493",
  "0x3c9ebe0a15c9bebc",
  "0x431d67c49c100d4c",
  "0x4cc5d4becb3e42b6",
  "0x597f299cfc657e2a",
  "0x5fcb6fab3ad6faec",
  "0x6c44198c4a475817"
].map((n) => BigInt(n))))();
var SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
var SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
var SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
var SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
var SHA2_64B = class extends HashMD {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // h -- high 32 bits, l -- low 32 bits
  // Numeric initializers matter: starting the fields as `undefined` changes
  // V8's field representation and slows hashing down (measured on sha256).
  Ah = 0;
  Al = 0;
  Bh = 0;
  Bl = 0;
  Ch = 0;
  Cl = 0;
  Dh = 0;
  Dl = 0;
  Eh = 0;
  El = 0;
  Fh = 0;
  Fl = 0;
  Gh = 0;
  Gl = 0;
  Hh = 0;
  Hl = 0;
  constructor(outputLen, IV) {
    super(128, outputLen, 16, false);
    this.Ah = IV[0] | 0;
    this.Al = IV[1] | 0;
    this.Bh = IV[2] | 0;
    this.Bl = IV[3] | 0;
    this.Ch = IV[4] | 0;
    this.Cl = IV[5] | 0;
    this.Dh = IV[6] | 0;
    this.Dl = IV[7] | 0;
    this.Eh = IV[8] | 0;
    this.El = IV[9] | 0;
    this.Fh = IV[10] | 0;
    this.Fl = IV[11] | 0;
    this.Gh = IV[12] | 0;
    this.Gl = IV[13] | 0;
    this.Hh = IV[14] | 0;
    this.Hl = IV[15] | 0;
  }
  // prettier-ignore
  get() {
    const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
  }
  // prettier-ignore
  set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
    this.Ah = Ah | 0;
    this.Al = Al | 0;
    this.Bh = Bh | 0;
    this.Bl = Bl | 0;
    this.Ch = Ch | 0;
    this.Cl = Cl | 0;
    this.Dh = Dh | 0;
    this.Dl = Dl | 0;
    this.Eh = Eh | 0;
    this.El = El | 0;
    this.Fh = Fh | 0;
    this.Fl = Fl | 0;
    this.Gh = Gh | 0;
    this.Gl = Gl | 0;
    this.Hh = Hh | 0;
    this.Hl = Hl | 0;
  }
  _cloneInto(to) {
    (to ||= new this.constructor()).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4) {
      SHA512_W_H[i] = view.getUint32(offset);
      SHA512_W_L[i] = view.getUint32(offset += 4);
    }
    for (let i = 16; i < 80; i++) {
      const W15h = SHA512_W_H[i - 15] | 0;
      const W15l = SHA512_W_L[i - 15] | 0;
      const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
      const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
      const W2h = SHA512_W_H[i - 2] | 0;
      const W2l = SHA512_W_L[i - 2] | 0;
      const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
      const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
      const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
      const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
      SHA512_W_H[i] = SUMh | 0;
      SHA512_W_L[i] = SUMl | 0;
    }
    let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
    for (let i = 0; i < 80; i++) {
      const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
      const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
      const CHIh = Eh & Fh ^ ~Eh & Gh;
      const CHIl = El & Fl ^ ~El & Gl;
      const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
      const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
      const T1l = T1ll | 0;
      const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
      const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
      const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
      const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
      Hh = Gh | 0;
      Hl = Gl | 0;
      Gh = Fh | 0;
      Gl = Fl | 0;
      Fh = Eh | 0;
      Fl = El | 0;
      ({ h: Eh, l: El } = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
      Dh = Ch | 0;
      Dl = Cl | 0;
      Ch = Bh | 0;
      Cl = Bl | 0;
      Bh = Ah | 0;
      Bl = Al | 0;
      const All = add3L(T1l, sigma0l, MAJl);
      Ah = add3H(All, T1h, sigma0h, MAJh);
      Al = All | 0;
    }
    ({ h: Ah, l: Al } = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
    ({ h: Bh, l: Bl } = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
    ({ h: Ch, l: Cl } = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
    ({ h: Dh, l: Dl } = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
    ({ h: Eh, l: El } = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
    ({ h: Fh, l: Fl } = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
    ({ h: Gh, l: Gl } = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
    ({ h: Hh, l: Hl } = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
    this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
  }
  roundClean() {
    clean(SHA512_W_H, SHA512_W_L);
  }
  destroy() {
    this.destroyed = true;
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  }
};
var _SHA512 = class extends SHA2_64B {
  constructor() {
    super(64, SHA512_IV);
  }
};
var sha256 = /* @__PURE__ */ createHasher(
  () => new _SHA256(),
  /* @__PURE__ */ oidNist(1)
);
var sha512 = /* @__PURE__ */ createHasher(
  () => new _SHA512(),
  /* @__PURE__ */ oidNist(3)
);

// node_modules/@noble/curves/utils.js
function aarray(item, title, inner = () => {
}) {
  if (!Array.isArray(item))
    throw new TypeError(`"${title}" expected array, got type=${typeof item}`);
  for (let i = 0; i < item.length; i++)
    inner(item[i], `${title}[${i}]`);
  return item;
}
var abytes2 = (value, length, title) => abytes(value, length, title);
var anumber2 = anumber;
function astring(value, title = "") {
  if (typeof value !== "string") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected string, got type=" + typeof value);
  }
  return value;
}
function aobject2(value, title = "object") {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError(title === "object" ? "expected valid options object" : `"${title}" expected object, got type=${typeof value}`);
  return value;
}
function afunction(value, title) {
  if (typeof value !== "function")
    throw new TypeError(`"${title}" is invalid: expected function, got ${typeof value}`);
  return value;
}
var bytesToHex2 = bytesToHex;
var concatBytes2 = (...arrays) => concatBytes(...arrays);
var hexToBytes2 = (hex) => hexToBytes(hex);
var isBytes2 = isBytes;
var randomBytes2 = (bytesLength) => randomBytes(bytesLength);
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
var atitle2 = (title) => title ? `"${title}" ` : "";
function abool2(value, title = "") {
  if (typeof value !== "boolean")
    throw new TypeError(atitle2(title) + "expected boolean, got type=" + typeof value);
  return value;
}
function abignumber(n) {
  if (typeof n === "bigint") {
    if (!isPosBig(n))
      throw new RangeError("positive bigint expected, got " + n);
  } else
    anumber2(n);
  return n;
}
function asafenumber(value, title = "") {
  if (typeof value !== "number") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected number, got type=" + typeof value);
  }
  if (!Number.isSafeInteger(value)) {
    const prefix = title && `"${title}" `;
    throw new RangeError(prefix + "expected safe integer, got " + value);
  }
}
function numberToHexUnpadded(num) {
  const hex = abignumber(num).toString(16);
  return hex.length & 1 ? "0" + hex : hex;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new TypeError("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  return hexToNumber(bytesToHex(copyBytes(abytes(bytes)).reverse()));
}
function numberToBytesBE(n, len) {
  anumber(len);
  if (len === 0)
    throw new Error("zero output length is invalid");
  n = abignumber(n);
  const expectedLen = len * 2;
  const hex = n.toString(16);
  if (hex.length > expectedLen)
    throw new RangeError("number is too large");
  return hexToBytes(hex.padStart(expectedLen, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes2(bytes));
}
function isPosBig(n) {
  return typeof n === "bigint" && _0n <= n;
}
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new RangeError("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  if (n < _0n)
    throw new Error("expected non-negative bigint, got " + n);
  return n === _0n ? 0 : n.toString(2).length;
}
var bitMask = (n) => {
  asafenumber(n, "n");
  return (_1n << BigInt(n)) - _1n;
};
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
  anumber(hashLen, "hashLen");
  anumber(qByteLen, "qByteLen");
  if (typeof hmacFn !== "function")
    throw new TypeError("hmacFn must be a function");
  const u8n = (len) => new Uint8Array(len);
  const NULL = Uint8Array.of();
  const byte0 = Uint8Array.of(0);
  const byte1 = Uint8Array.of(1);
  const _maxDrbgIters = 1e3;
  let v = u8n(hashLen);
  let k = u8n(hashLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...msgs) => hmacFn(k, concatBytes2(v, ...msgs));
  const reseed = (seed = NULL) => {
    k = h(byte0, seed);
    v = h();
    if (seed.length === 0)
      return;
    k = h(byte1, seed);
    v = h();
  };
  const gen = () => {
    if (i++ >= _maxDrbgIters)
      throw new Error("drbg: tried max amount of iterations");
    let len = 0;
    const out = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes2(...out);
  };
  const genUntil = (seed, pred) => {
    reset();
    reseed(seed);
    let res = void 0;
    while ((res = pred(gen())) === void 0)
      reseed();
    reset();
    return res;
  };
  return genUntil;
}
function validateObject(object, fields = {}, optFields = {}, title = "object") {
  aobject2(object, title);
  aobject2(fields, "fields");
  aobject2(optFields, "optFields");
  function checkField(fieldName, expectedType, isOpt) {
    const label = title === "object" ? `param "${String(fieldName)}"` : `"${title}.${String(fieldName)}"`;
    const val = object[fieldName];
    if (!Object.hasOwn(object, fieldName) && (isOpt ? val !== void 0 : expectedType !== "function")) {
      throw new TypeError(`${label} is invalid: expected own property`);
    }
    if (isOpt && val === void 0)
      return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new TypeError(`${label} is invalid: expected ${expectedType}, got ${current}`);
  }
  const iter = (f, isOpt) => Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
  iter(fields, false);
  iter(optFields, true);
}

// node_modules/@noble/curves/abstract/modular.js
var _0n2 = /* @__PURE__ */ BigInt(0);
var _1n2 = /* @__PURE__ */ BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _7n = /* @__PURE__ */ BigInt(7);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _15n = /* @__PURE__ */ BigInt(15);
var _16n = /* @__PURE__ */ BigInt(16);
var POW_WINDOWED_MIN = /* @__PURE__ */ BigInt("0x10000000000000000");
function mod(a, b) {
  if (b <= _0n2)
    throw new Error("mod: expected positive modulus, got " + b);
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow(num, power, modulo) {
  if (modulo <= _1n2)
    throw new Error("pow: expected modulus > 1, got " + modulo);
  if (typeof power !== "bigint")
    throw new TypeError("invalid exponent: expected bigint, got " + typeof power);
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return _1n2;
  if (power === _1n2)
    return num;
  let d = num % modulo;
  if (d < _0n2)
    d += modulo;
  if (power < POW_WINDOWED_MIN) {
    let p2 = _1n2;
    while (power > _0n2) {
      if (power & _1n2)
        p2 = p2 * d % modulo;
      d = d * d % modulo;
      power >>= _1n2;
    }
    return p2;
  }
  const digits = [];
  while (power > _0n2) {
    digits.push(Number(power & _15n));
    power >>= _4n;
  }
  const table = new Array(16);
  table[0] = _1n2;
  table[1] = d;
  for (let i = 2; i < 16; i++)
    table[i] = table[i - 1] * d % modulo;
  let p = table[digits[digits.length - 1]];
  for (let w = digits.length - 2; w >= 0; w--) {
    p = p * p % modulo;
    p = p * p % modulo;
    p = p * p % modulo;
    p = p * p % modulo;
    const digit = digits[w];
    if (digit !== 0)
      p = p * table[digit] % modulo;
  }
  return p;
}
function pow2(x, power, modulo) {
  if (modulo <= _1n2)
    throw new Error("pow2: expected modulus > 1, got " + modulo);
  if (power < _0n2)
    throw new Error("pow2: expected non-negative exponent, got " + power);
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _1n2)
    throw new Error("invert: expected modulus > 1, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n2, u = _1n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b - a * q;
    const m = x - u * q;
    b = a, a = r, x = u, u = m;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function invertCt(a, prime) {
  if (prime <= _1n2)
    throw new Error("invertCt: expected prime modulus > 1, got " + prime);
  const an = mod(a, prime);
  if (an === _0n2)
    throw new Error("invertCt: expected non-zero number");
  const inverse = pow(an, prime - _2n, prime);
  if (mod(an * inverse, prime) !== _1n2)
    throw new Error("invertCt: does not exist");
  return inverse;
}
function assertIsSquare(Fp, root, n) {
  const F = Fp;
  if (!F.eql(F.sqr(root), n))
    throw new Error("Cannot find square root");
}
function aoddModulus(order, fnName) {
  if ((order & _1n2) === _0n2)
    throw new Error(fnName + ": expected odd modulus, got " + order);
}
function sqrt3mod4(Fp, n) {
  const F = Fp;
  const p1div4 = (F.ORDER + _1n2) / _4n;
  const root = F.pow(n, p1div4);
  assertIsSquare(F, root, n);
  return root;
}
function sqrt5mod8(Fp, n) {
  const F = Fp;
  const p5div8 = (F.ORDER - _5n) / _8n;
  const n2 = F.mul(n, _2n);
  const v = F.pow(n2, p5div8);
  const nv = F.mul(n, v);
  const i = F.mul(F.mul(nv, _2n), v);
  const root = F.mul(nv, F.sub(i, F.ONE));
  assertIsSquare(F, root, n);
  return root;
}
function sqrt9mod16(P) {
  const Fp_ = Field(P);
  const tn = tonelliShanks(P);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P + _7n) / _16n;
  return ((Fp, n) => {
    const F = Fp;
    let tv1 = F.pow(n, c4);
    let tv2 = F.mul(tv1, c1);
    const tv3 = F.mul(tv1, c2);
    const tv4 = F.mul(tv1, c3);
    const e1 = F.eql(F.sqr(tv2), n);
    const e2 = F.eql(F.sqr(tv3), n);
    tv1 = F.cmov(tv1, tv2, e1);
    tv2 = F.cmov(tv4, tv3, e2);
    const e3 = F.eql(F.sqr(tv2), n);
    const root = F.cmov(tv1, tv2, e3);
    assertIsSquare(F, root, n);
    return root;
  });
}
function tonelliShanks(P) {
  if (P < _3n)
    throw new Error("sqrt is not defined for small field");
  aoddModulus(P, "tonelliShanks");
  let Q = P - _1n2;
  let S = 0;
  while (Q % _2n === _0n2) {
    Q /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n2) / _2n;
  return function tonelliSlow(Fp, n) {
    const F = Fp;
    if (F.is0(n))
      return n;
    if (FpLegendre(F, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = F.mul(F.ONE, cc);
    let t = F.pow(n, Q);
    let R = F.pow(n, Q1div2);
    while (!F.eql(t, F.ONE)) {
      if (F.is0(t))
        throw new Error("Cannot find square root: probably non-prime P");
      let i = 1;
      let t_tmp = F.sqr(t);
      while (!F.eql(t_tmp, F.ONE)) {
        i++;
        t_tmp = F.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n2 << BigInt(M - i - 1);
      const b = F.pow(c, exponent);
      M = i;
      c = F.sqr(b);
      t = F.mul(t, c);
      R = F.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  aoddModulus(P, "Fp.sqrt");
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  if (P % _16n === _9n)
    return sqrt9mod16(P);
  return tonelliShanks(P);
}
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  aobject2(field, "field");
  if (typeof field.ORDER !== "bigint")
    throw new TypeError('param "ORDER" is invalid: expected bigint, got ' + typeof field.ORDER);
  asafenumber(field.BYTES, "BYTES");
  asafenumber(field.BITS, "BITS");
  for (const name of FIELD_FIELDS)
    afunction(field[name], "field." + name);
  if (field.BYTES < 1 || field.BITS < 1)
    throw new Error("invalid field: expected BYTES/BITS > 0");
  if (field.ORDER <= _1n2)
    throw new Error("invalid field: expected ORDER > 1, got " + field.ORDER);
  return field;
}
function FpInvertBatch(Fp, nums, passZero = false) {
  validateField(Fp);
  aarray(nums, "nums");
  abool2(passZero, "passZero");
  const F = Fp;
  const inverted = new Array(nums.length).fill(passZero ? F.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (F.is0(num))
      return acc;
    inverted[i] = acc;
    return F.mul(acc, num);
  }, F.ONE);
  const invertedAcc = F.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (F.is0(num))
      return acc;
    inverted[i] = F.mul(acc, inverted[i]);
    return F.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp, n) {
  validateField(Fp);
  const F = Fp;
  aoddModulus(F.ORDER, "FpLegendre");
  const p1mod2 = (F.ORDER - _1n2) / _2n;
  const powered = F.pow(n, p1mod2);
  const yes = F.eql(powered, F.ONE);
  const zero = F.eql(powered, F.ZERO);
  const no = F.eql(powered, F.neg(F.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber2(nBitLength);
  if (n <= _0n2)
    throw new Error("invalid n length: expected positive n, got " + n);
  if (nBitLength !== void 0 && nBitLength < 1)
    throw new Error("invalid n length: expected positive bit length, got " + nBitLength);
  const bits = bitLen(n);
  if (nBitLength !== void 0 && nBitLength < bits)
    throw new Error(`invalid n length: expected nBitLength (${nBitLength}) >= bitLen(n) (${bits})`);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : bits;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
var FIELD_SQRT = /* @__PURE__ */ new WeakMap();
var _Field = class {
  ORDER;
  BITS;
  BYTES;
  isLE;
  ZERO = _0n2;
  ONE = _1n2;
  _lengths;
  _mod;
  constructor(ORDER, opts = {}) {
    if (ORDER <= _1n2)
      throw new Error("invalid field: expected ORDER > 1, got " + ORDER);
    let _nbitLength = void 0;
    this.isLE = false;
    if (opts != null && typeof opts === "object") {
      if (typeof opts.BITS === "number")
        _nbitLength = opts.BITS;
      if (typeof opts.sqrt === "function")
        Object.defineProperty(this, "sqrt", { value: opts.sqrt, enumerable: true });
      if (typeof opts.isLE === "boolean")
        this.isLE = opts.isLE;
      if (opts.allowedLengths)
        this._lengths = Object.freeze(opts.allowedLengths.slice());
      if (typeof opts.modFromBytes === "boolean")
        this._mod = opts.modFromBytes;
    }
    const { nBitLength, nByteLength } = nLength(ORDER, _nbitLength);
    if (nByteLength > 2048)
      throw new Error("invalid field: expected ORDER of <= 2048 bytes");
    this.ORDER = ORDER;
    this.BITS = nBitLength;
    this.BYTES = nByteLength;
    Object.freeze(this);
  }
  create(num) {
    return mod(num, this.ORDER);
  }
  isValid(num) {
    if (typeof num !== "bigint")
      throw new TypeError("invalid field element: expected bigint, got " + typeof num);
    return _0n2 <= num && num < this.ORDER;
  }
  is0(num) {
    return num === _0n2;
  }
  // is valid and invertible
  isValidNot0(num) {
    return !this.is0(num) && this.isValid(num);
  }
  isOdd(num) {
    return (num & _1n2) === _1n2;
  }
  neg(num) {
    return mod(-num, this.ORDER);
  }
  eql(lhs, rhs) {
    return lhs === rhs;
  }
  sqr(num) {
    return mod(num * num, this.ORDER);
  }
  add(lhs, rhs) {
    return mod(lhs + rhs, this.ORDER);
  }
  sub(lhs, rhs) {
    return mod(lhs - rhs, this.ORDER);
  }
  mul(lhs, rhs) {
    return mod(lhs * rhs, this.ORDER);
  }
  pow(num, power) {
    return pow(num, power, this.ORDER);
  }
  div(lhs, rhs) {
    return mod(lhs * invert(rhs, this.ORDER), this.ORDER);
  }
  // Same as above, but doesn't normalize
  sqrN(num) {
    return num * num;
  }
  addN(lhs, rhs) {
    return lhs + rhs;
  }
  subN(lhs, rhs) {
    return lhs - rhs;
  }
  mulN(lhs, rhs) {
    return lhs * rhs;
  }
  inv(num) {
    return invert(num, this.ORDER);
  }
  sqrt(num) {
    let sqrt = FIELD_SQRT.get(this);
    if (!sqrt)
      FIELD_SQRT.set(this, sqrt = FpSqrt(this.ORDER));
    return sqrt(this, num);
  }
  toBytes(num) {
    return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
  }
  fromBytes(bytes, skipValidation = false) {
    abytes2(bytes);
    const { _lengths: allowedLengths, BYTES, isLE: isLE2, ORDER, _mod: modFromBytes } = this;
    if (allowedLengths) {
      if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
        throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
      }
      const padded = new Uint8Array(BYTES);
      padded.set(bytes, isLE2 ? 0 : padded.length - bytes.length);
      bytes = padded;
    }
    if (bytes.length !== BYTES)
      throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
    let scalar = isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    if (modFromBytes)
      scalar = mod(scalar, ORDER);
    if (!skipValidation) {
      if (!this.isValid(scalar))
        throw new Error("invalid field element: outside of range 0..ORDER");
    }
    return scalar;
  }
  // TODO: we don't need it here, move out to separate fn
  invertBatch(lst) {
    return FpInvertBatch(this, lst, true);
  }
  // We can't move this out because Fp6, Fp12 implement it
  // and it's unclear what to return in there.
  cmov(a, b, condition) {
    abool2(condition, "condition");
    return condition ? b : a;
  }
};
function Field(ORDER, opts = {}) {
  Object.freeze(_Field.prototype);
  return new _Field(ORDER, opts);
}
function getFieldBytesLength(fieldOrder) {
  if (typeof fieldOrder !== "bigint")
    throw new Error("field order must be bigint");
  if (fieldOrder <= _1n2)
    throw new Error("field order must be greater than 1");
  const bitLength = bitLen(fieldOrder - _1n2);
  return Math.ceil(bitLength / 8);
}
function getMinHashLength(fieldOrder) {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}
function mapHashToField(key, fieldOrder, isLE2 = false) {
  abytes2(key);
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = Math.max(getMinHashLength(fieldOrder), 16);
  if (len < minLen || len > 1024)
    throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
  const num = isLE2 ? bytesToNumberLE(key) : bytesToNumberBE(key);
  const reduced = mod(num, fieldOrder - _1n2) + _1n2;
  return isLE2 ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}

// node_modules/@noble/curves/abstract/curve.js
var _0n3 = /* @__PURE__ */ BigInt(0);
var _1n3 = /* @__PURE__ */ BigInt(1);
var _4n2 = /* @__PURE__ */ BigInt(4);
var BLIND_BYTES = 16;
var BLIND_BITS = 128;
var FW_WINDOW = 5;
var TABLE_BYTES_MAX = /* @__PURE__ */ (() => 2 ** 31)();
function validatePointCons(Point2) {
  const pc = Point2;
  if (typeof pc !== "function")
    throw new TypeError('"Point" expected constructor, got type=' + typeof Point2);
  afunction(pc.fromAffine, "Point.fromAffine");
  afunction(pc.fromBytes, "Point.fromBytes");
  afunction(pc.fromHex, "Point.fromHex");
  aobject2(pc.BASE, "Point.BASE");
  aobject2(pc.ZERO, "Point.ZERO");
  validateField(pc.Fp);
  validateField(pc.Fn);
}
function normalizeZ(c, points) {
  validatePointCons(c);
  validateMSMPoints(points, c);
  const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}
function validateW(W, bits, min = 1) {
  if (!Number.isSafeInteger(W) || W < min || W > bits)
    throw new Error("invalid window size, expected [" + min + ".." + bits + "], got W=" + W);
}
function validateTableBytes(numPoints, fpBytes) {
  const bytes = numPoints * (4 * fpBytes + 128);
  if (bytes > TABLE_BYTES_MAX)
    throw new Error("invalid window size: table would need ~" + Math.ceil(bytes / 2 ** 20) + " MiB, max " + TABLE_BYTES_MAX / 2 ** 20 + " MiB");
}
function probeRandomBytes(randomBytes5, length) {
  if (randomBytes5 === void 0)
    return void 0;
  afunction(randomBytes5, "randomBytes");
  try {
    const probe = randomBytes5(length);
    if (!isBytes2(probe) || probe.length !== length)
      return void 0;
  } catch {
    return void 0;
  }
  return randomBytes5;
}
function validateMSMPoints(points, c) {
  aarray(points, "points");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field, maxScalar) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    const ok = maxScalar === void 0 ? field.isValid(s) : isPosBig(s) && s < maxScalar;
    if (!ok)
      throw new Error("invalid scalar at index " + i);
  });
}
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getWindowSize(P) {
  return pointWindowSizes.get(P) || 1;
}
function oddMultiples(p, size) {
  const dbl = p.double();
  const t = [p];
  for (let j = 1; j < size; j++)
    t.push(t[j - 1].add(dbl));
  return t;
}
function wnafDigits(n, W) {
  const size = 2 ** W;
  const half = size / 2;
  const mask = BigInt(size - 1);
  const d = [];
  while (n > _0n3) {
    let w = 0;
    if (n & _1n3) {
      w = Number(n & mask);
      if (w >= half)
        w -= size;
      n -= BigInt(w);
    }
    d.push(w);
    n >>= _1n3;
  }
  return d;
}
function signedWindowDigits(n, W, windows) {
  const size = 2 ** W;
  const half = size / 2;
  const mask = BigInt(size - 1);
  const shiftBy = BigInt(W);
  const d = [];
  for (let w = 0; w < windows; w++) {
    let v = Number(n & mask);
    n >>= shiftBy;
    if (v > half) {
      v -= size;
      n += _1n3;
    }
    d.push(v);
  }
  if (n !== _0n3)
    throw new Error("invalid wnaf");
  return d;
}
function wnafWalk(zero, tables, digits) {
  let max = 0;
  for (const d of digits)
    max = Math.max(max, d.length);
  let acc = zero;
  for (let bit = max - 1; bit >= 0; bit--) {
    if (bit !== max - 1)
      acc = acc.double();
    for (let i = 0; i < digits.length; i++) {
      const w = digits[i][bit];
      if (w) {
        const item = tables[i][Math.abs(w) - 1 >> 1];
        acc = acc.add(w < 0 ? item.negate() : item);
      }
    }
  }
  return acc;
}
var ScalarMultiplier = class {
  Point;
  BASE;
  ZERO;
  randomBytes;
  wnafPrecomputes = /* @__PURE__ */ new WeakMap();
  baseCanBeBlinded;
  bits;
  // Parametrized with a given Point class (not individual point)
  constructor(Point2, randomBytes5) {
    validatePointCons(Point2);
    this.randomBytes = probeRandomBytes(randomBytes5, BLIND_BYTES);
    this.Point = Point2;
    this.BASE = Point2.BASE;
    this.ZERO = Point2.ZERO;
    this.bits = Point2.Fn.BITS;
  }
  /**
   * Creates a signed fixed-window wNAF precomputation table: for every window w, the
   * multiples `[1..2^(W−1)]⋅2^(w⋅W)⋅P`, flattened. All doublings are baked into the table,
   * so cached multiplication is additions-only. `windows = ceil(bits/W) + 1`: the extra
   * window absorbs the final carry of signed-digit recoding.
   * For a 256-bit curve and W=6, the table is 44⋅32 = 1408 points.
   * @param point - Point instance
   * @param W - window size
   * @param bits - scalar bitlength the table must cover
   */
  buildWnafTable(point, W, bits) {
    const windows = Math.ceil(bits / W) + 1;
    const half = 2 ** (W - 1);
    const comp = [];
    let base = point;
    for (let w = 0; w < windows; w++) {
      let acc = base;
      for (let i = 0; i < half; i++) {
        comp.push(acc);
        acc = acc.add(base);
      }
      base = comp[comp.length - 1].double();
    }
    return { W, bits, windows, comp };
  }
  /**
   * Implements ec multiplication using precomputed signed fixed-window wNAF tables.
   * Constant-time: fixed window count with one table addition per window — zero digits feed
   * the fake accumulator — and no doublings; the lookup scans the whole window slice.
   * Scalar bounds are validated by the public entry points ({@link ScalarMultiplier.mulCT},
   * {@link ScalarMultiplier.mulCTBlinded}, {@link ScalarMultiplier.mulUnsafe});
   * signedWindowDigits throws if `n` exceeds the table.
   * @returns real and fake (for const-time) points
   */
  wnafCachedCT(precomputes, n) {
    const { W, windows, comp } = precomputes;
    const half = 2 ** (W - 1);
    const digits = signedWindowDigits(n, W, windows);
    let p = this.ZERO;
    let f = this.BASE;
    for (let w = 0; w < windows; w++) {
      const digit = digits[w];
      const start = w * half;
      const idx = Math.abs(digit) - 1;
      let sel = comp[start];
      for (let i = 1; i < half; i++)
        sel = i === idx ? comp[start + i] : sel;
      const neg = sel.negate();
      if (digit === 0)
        f = f.add(comp[start]);
      else
        p = p.add(digit < 0 ? neg : sel);
    }
    return { p, f };
  }
  // Cache key is point identity plus (W, bits); at most two entries exist per point (public-width
  // `Fn.BITS` and blinded `Fn.BITS + BLIND_BITS`). Callers must not reuse the same point with
  // incompatible `transform(...)` layouts and expect a separate cache entry.
  getWnafPrecomputes(W, point, bits, transform) {
    let entries = this.wnafPrecomputes.get(point);
    let comp = entries?.find((entry) => entry.W === W && entry.bits === bits);
    if (!comp) {
      comp = this.buildWnafTable(point, W, bits);
      if (typeof transform === "function")
        comp = { ...comp, comp: transform(comp.comp) };
      if (!entries) {
        entries = [];
        this.wnafPrecomputes.set(point, entries);
      }
      entries.push(comp);
    }
    return comp;
  }
  assertPoint(point) {
    if (!(point instanceof this.Point))
      throw new TypeError('"point" expected Point instance, got type=' + typeof point);
  }
  // Shared prologue of the constant-time entry points. Rejects scalar 0: in key/signature-style
  // callers a zero scalar means broken upstream plumbing, and concrete Points already reject it.
  // Uses inRange instead of Fn.isValidNot0: validateField() only certifies the arithmetic subset.
  validateMulInput(point, scalar) {
    this.assertPoint(point);
    if (!inRange(scalar, _1n3, this.Point.Fn.ORDER))
      throw new Error("invalid scalar");
  }
  // Constant-time dispatch shared by mulCT / mulCTBlinded. Un-precomputed points (W===1, e.g.
  // ECDH peer keys) skip building a throwaway cached table in favor of a small fixed-window
  // multiply. `n` must be < 2^bits.
  runCT(point, n, bits, transform) {
    const W = getWindowSize(point);
    if (W === 1)
      return this.fixedWindowCT(point, n, bits);
    return this.wnafCachedCT(this.getWnafPrecomputes(W, point, bits, transform), n);
  }
  mulCT(point, scalar, transform) {
    this.validateMulInput(point, scalar);
    return this.runCT(point, scalar, this.bits, transform);
  }
  mulCTBlinded(point, scalar, transform) {
    this.validateMulInput(point, scalar);
    if (this.randomBytes === void 0)
      throw new Error("randomBytes is required for scalar blinding");
    const bits = this.Point.Fn.BITS + BLIND_BITS;
    const blind = this.randomBytes(BLIND_BYTES);
    if (!isBytes2(blind) || blind.length !== BLIND_BYTES)
      throw new Error("randomBytes returned invalid byte array");
    blind[0] = blind[0] & 63 | 128;
    const n = scalar + bytesToNumberBE(blind) * this.Point.Fn.ORDER;
    return this.runCT(point, n, bits, transform);
  }
  /**
   * Constant-time multiplication `n*point` for an un-precomputed point, via a small fixed window.
   * A cached wNAF table only pays off when reused; a flat 2^FW_WINDOW table (`size-1` adds) is
   * far cheaper to build for a single use. The point-operation sequence is independent of `n`:
   * build the table, then per window exactly FW_WINDOW doublings, a data-oblivious scan over
   * every table entry, and one addition (adds the identity when the window digit is 0 — never
   * skipped).
   *
   * `n` must be `< 2^bits`. Assumes complete addition (adding the identity costs the same as any
   * add), which holds for the Weierstrass/Edwards point types used here. The table is left in
   * projective form (no normalizeZ): normalizing this small a table costs more than the
   * mixed-add savings it would buy for a single multiply.
   * @returns real point `p`; `f` duplicates it only to match {@link wnafCachedCT}'s return shape
   * (this path needs no fake accumulator — its op-count is already scalar-independent).
   */
  fixedWindowCT(point, n, bits) {
    const W = FW_WINDOW;
    const size = 1 << W;
    const mask = bitMask(W);
    const table = new Array(size);
    table[0] = this.ZERO;
    for (let i = 1; i < size; i++)
      table[i] = table[i - 1].add(point);
    const windows = Math.ceil(bits / W);
    let acc = this.ZERO;
    for (let window = windows - 1; window >= 0; window--) {
      if (window !== windows - 1)
        for (let d = 0; d < W; d++)
          acc = acc.double();
      const digit = Number(n >> BigInt(window * W) & mask);
      let sel = table[0];
      for (let i = 1; i < size; i++)
        sel = i === digit ? table[i] : sel;
      acc = acc.add(sel);
    }
    return { p: acc, f: acc };
  }
  shouldBlind(point, cofactor) {
    if (this.randomBytes === void 0)
      return false;
    if (cofactor === _1n3)
      return true;
    if (point !== this.BASE)
      return false;
    if (this.baseCanBeBlinded === void 0)
      this.baseCanBeBlinded = this.mulUnsafe(this.BASE, this.Point.Fn.ORDER).is0();
    return this.baseCanBeBlinded;
  }
  mulSecret(point, scalar, cofactor, transform) {
    return this.shouldBlind(point, cofactor) ? this.mulCTBlinded(point, scalar, transform) : this.mulCT(point, scalar, transform);
  }
  mulUnsafe(point, scalar, transform) {
    this.assertPoint(point);
    if (!isPosBig(scalar))
      throw new Error("invalid scalar");
    const W = getWindowSize(point);
    if (W === 1 || scalar >= this.Point.Fn.ORDER)
      return mulAddUnsafe(this.Point, [point], [scalar], true);
    const precomputes = this.getWnafPrecomputes(W, point, this.bits, transform);
    return this.wnafCachedCT(precomputes, scalar).p;
  }
  // Remembers the window size used for precomputed wNAF multiplication of the given point
  // and drops any previously built tables. Usually only the base point is precomputed.
  // W=1 resets the point to the un-precomputed (table-less) paths.
  // W is additionally capped so tables stay under ~2 GiB ({@link TABLE_BYTES_MAX}).
  setWindowSize(point, W) {
    this.assertPoint(point);
    validateW(W, this.bits);
    const windows = Math.ceil((this.bits + BLIND_BITS) / W) + 1;
    validateTableBytes(windows * 2 ** (W - 1), this.Point.Fp.BYTES);
    pointWindowSizes.set(point, W);
    this.wnafPrecomputes.delete(point);
  }
  // True when a window size is set: tables themselves are built lazily on first multiply.
  hasWindowSize(point) {
    return getWindowSize(point) !== 1;
  }
};
function mulAddUnsafe(c, points, scalars, allowOversized = false) {
  validatePointCons(c);
  validateMSMPoints(points, c);
  abool2(allowOversized, "allowOversized");
  validateMSMScalars(scalars, c.Fn, allowOversized ? c.Fn.ORDER ** _4n2 : void 0);
  if (points.length !== scalars.length)
    throw new Error("arrays of points and scalars must have equal length");
  const tables = points.map((p) => oddMultiples(p, 4));
  const digits = scalars.map((n) => wnafDigits(n, 4));
  return wnafWalk(c.ZERO, tables, digits);
}
function createField(order, field, isLE2) {
  if (field) {
    if (field.ORDER !== order)
      throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
    validateField(field);
    return field;
  } else {
    return Field(order, { isLE: isLE2 });
  }
}
function createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
  if (type !== "weierstrass" && type !== "edwards")
    throw new Error('expected curve type "weierstrass" or "edwards"');
  if (FpFnLE === void 0)
    FpFnLE = type === "edwards";
  if (!CURVE || typeof CURVE !== "object")
    throw new Error(`expected valid ${type} CURVE object`);
  validateObject(curveOpts);
  for (const p of ["p", "n", "h"]) {
    const val = CURVE[p];
    if (!(isPosBig(val) && val !== _0n3))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn2 = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b = type === "weierstrass" ? "b" : "d";
  const params = ["Gx", "Gy", "a", _b];
  for (const p of params) {
    if (!Fp.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp, Fn: Fn2 };
}
function createKeygen(randomSecretKey, getPublicKey) {
  return function keygen(seed) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  };
}

// node_modules/@noble/hashes/hmac.js
var _HMAC = class {
  oHash;
  iHash;
  blockLen;
  outputLen;
  canXOF = false;
  finished = false;
  destroyed = false;
  constructor(hash, key) {
    ahash(hash);
    abytes(key, void 0, "key");
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("expected Hash instance");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad = new Uint8Array(blockLen);
    pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54;
    this.iHash.update(pad);
    this.oHash = hash.create();
    for (let i = 0; i < pad.length; i++)
      pad[i] ^= 54 ^ 92;
    this.oHash.update(pad);
    clean(pad);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const buf = out.subarray(0, this.outputLen);
    this.iHash.digestInto(buf);
    this.oHash.update(buf);
    this.oHash.digestInto(buf);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.canXOF = canXOF;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = /* @__PURE__ */ (() => {
  const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
  hmac_.create = (hash, key) => new _HMAC(hash, key);
  return hmac_;
})();

// node_modules/@noble/curves/abstract/der.js
var _0n4 = /* @__PURE__ */ BigInt(0);
var DERErr = class extends Error {
  constructor(m = "") {
    super(m);
  }
};
var _DER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag, data) => {
      const { Err: E } = _DER;
      asafenumber(tag, "tag");
      if (tag < 0 || tag > 255)
        throw new E("tlv.encode: wrong tag");
      astring(data, "data");
      if (data.length & 1)
        throw new E("tlv.encode: unpadded data");
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if (len.length / 2 & 128)
        throw new E("tlv.encode: long form length too big");
      const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag, data) {
      const { Err: E } = _DER;
      data = abytes2(data, void 0, "DER data");
      let pos = 0;
      if (tag < 0 || tag > 255)
        throw new E("tlv.decode: wrong tag");
      if (data.length < 2 || data[pos++] !== tag)
        throw new E("tlv.decode: wrong tlv");
      const first = data[pos++];
      const isLong = !!(first & 128);
      let length = 0;
      if (!isLong)
        length = first;
      else {
        const lenLen = first & 127;
        if (!lenLen)
          throw new E("tlv.decode(long): indefinite length not supported");
        if (lenLen > 4)
          throw new E("tlv.decode(long): byte length is too big");
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen)
          throw new E("tlv.decode: length bytes not complete");
        if (lengthBytes[0] === 0)
          throw new E("tlv.decode(long): zero leftmost byte");
        for (const b of lengthBytes)
          length = length << 8 | b;
        pos += lenLen;
        if (length < 128)
          throw new E("tlv.decode(long): not minimal encoding");
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length)
        throw new E("tlv.decode: wrong value length");
      return { v, l: data.subarray(pos + length) };
    }
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num) {
      const { Err: E } = _DER;
      abignumber(num);
      if (num < _0n4)
        throw new E("integer: negative integers are not allowed");
      let hex = numberToHexUnpadded(num);
      if (Number.parseInt(hex[0], 16) & 8)
        hex = "00" + hex;
      if (hex.length & 1)
        throw new E("unexpected DER parsing assertion: unpadded hex");
      return hex;
    },
    decode(data) {
      const { Err: E } = _DER;
      if (data.length < 1)
        throw new E("invalid signature integer: empty");
      if (data[0] & 128)
        throw new E("invalid signature integer: negative");
      if (data.length > 1 && data[0] === 0 && !(data[1] & 128))
        throw new E("invalid signature integer: unnecessary leading zero");
      return bytesToNumberBE(data);
    }
  },
  toSig(bytes) {
    const { Err: E, _int: int, _tlv: tlv } = _DER;
    const data = abytes2(bytes, void 0, "signature");
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
    if (seqLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
    if (sLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig) {
    const { _tlv: tlv, _int: int } = _DER;
    validateObject(sig, { r: "bigint", s: "bigint" }, {}, "sig");
    const rs = tlv.encode(2, int.encode(sig.r));
    const ss = tlv.encode(2, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(48, seq);
  }
};
var DER = /* @__PURE__ */ (() => {
  Object.freeze(_DER._tlv);
  Object.freeze(_DER._int);
  return Object.freeze(_DER);
})();

// node_modules/@noble/curves/abstract/weierstrass.js
var divNearest = (num, den) => (num + (num >= 0 ? den : -den) / _2n2) / den;
function _splitEndoScalar(k, basis, n) {
  aInRange("scalar", k, _0n5, n);
  const [[a1, b1], [a2, b2]] = basis;
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);
  let k1 = k - c1 * a1 - c2 * a2;
  let k2 = -c1 * b1 - c2 * b2;
  const k1neg = k1 < _0n5;
  const k2neg = k2 < _0n5;
  if (k1neg)
    k1 = -k1;
  if (k2neg)
    k2 = -k2;
  const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n4;
  if (k1 < _0n5 || k1 >= MAX_NUM || k2 < _0n5 || k2 >= MAX_NUM) {
    throw new Error("splitScalar (endomorphism): failed for k");
  }
  return { k1neg, k1, k2neg, k2 };
}
function validateSigFormat(format) {
  if (!["compact", "recovered", "der"].includes(format))
    throw new Error('Signature format must be "compact", "recovered", or "der"');
  return format;
}
function validateSigOpts(opts, def) {
  validateObject(opts);
  const optsn = {};
  for (let optName of Object.keys(def)) {
    optsn[optName] = opts[optName] === void 0 ? def[optName] : opts[optName];
  }
  abool2(optsn.lowS, "lowS");
  abool2(optsn.prehash, "prehash");
  if (optsn.format !== void 0)
    validateSigFormat(optsn.format);
  return optsn;
}
var _0n5 = /* @__PURE__ */ BigInt(0);
var _1n4 = /* @__PURE__ */ BigInt(1);
var _2n2 = /* @__PURE__ */ BigInt(2);
var _3n2 = /* @__PURE__ */ BigInt(3);
var _4n3 = /* @__PURE__ */ BigInt(4);
function weierstrass(params, extraOpts = {}) {
  const validated = createCurveFields("weierstrass", params, extraOpts);
  const Fp = validated.Fp;
  const Fn2 = validated.Fn;
  let CURVE = validated.CURVE;
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  validateObject(extraOpts, {}, {
    allowInfinityPoint: "boolean",
    clearCofactor: "function",
    isTorsionFree: "function",
    fromBytes: "function",
    toBytes: "function",
    endo: "object",
    randomBytes: "function"
  });
  const { endo, allowInfinityPoint } = extraOpts;
  const randomBytes5 = extraOpts.randomBytes === void 0 ? randomBytes2 : extraOpts.randomBytes;
  if (endo) {
    if (!Fp.is0(CURVE.a) || typeof endo.beta !== "bigint" || !Array.isArray(endo.basises)) {
      throw new Error('invalid endo: expected "beta": bigint and "basises": array');
    }
  }
  const lengths = getWLengths(Fp, Fn2);
  function assertCompressionIsSupported() {
    if (!Fp.isOdd)
      throw new Error("compression is not supported: Field does not have .isOdd()");
  }
  function pointToBytes(_c, point, isCompressed) {
    if (allowInfinityPoint && point.is0())
      return Uint8Array.of(0);
    const { x, y } = point.toAffine();
    const bx = Fp.toBytes(x);
    abool2(isCompressed, "isCompressed");
    if (isCompressed) {
      assertCompressionIsSupported();
      const hasEvenY = !Fp.isOdd(y);
      return concatBytes2(pprefix(hasEvenY), bx);
    } else {
      return concatBytes2(Uint8Array.of(4), bx, Fp.toBytes(y));
    }
  }
  function pointFromBytes(bytes) {
    abytes2(bytes, void 0, "Point");
    const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    if (allowInfinityPoint && length === 1 && head === 0)
      return { x: Fp.ZERO, y: Fp.ZERO };
    if (length === comp && (head === 2 || head === 3)) {
      const x = Fp.fromBytes(tail);
      if (!Fp.isValid(x))
        throw new Error("bad point: is not on curve, wrong x");
      const y2 = weierstrassEquation(x);
      let y;
      try {
        y = Fp.sqrt(y2);
      } catch (sqrtError) {
        const err = sqrtError instanceof Error ? ": " + sqrtError.message : "";
        throw new Error("bad point: is not on curve, sqrt error" + err);
      }
      assertCompressionIsSupported();
      const evenY = Fp.isOdd(y);
      const evenH = (head & 1) === 1;
      if (evenH !== evenY)
        y = Fp.neg(y);
      return { x, y };
    } else if (length === uncomp && head === 4) {
      const L = Fp.BYTES;
      const x = Fp.fromBytes(tail.subarray(0, L));
      const y = Fp.fromBytes(tail.subarray(L, L * 2));
      if (!isValidXY(x, y))
        throw new Error("bad point: is not on curve");
      return { x, y };
    } else {
      throw new Error(`bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`);
    }
  }
  const encodePoint = extraOpts.toBytes === void 0 ? pointToBytes : extraOpts.toBytes;
  const decodePoint = extraOpts.fromBytes === void 0 ? pointFromBytes : extraOpts.fromBytes;
  const b3 = Fp.mul(CURVE.b, _3n2);
  const mulA = Fp.is0(CURVE.a) ? (_) => Fp.ZERO : (x) => Fp.mul(CURVE.a, x);
  function weierstrassEquation(x) {
    const x2 = Fp.sqr(x);
    const x3 = Fp.mul(x2, x);
    return Fp.add(Fp.add(x3, Fp.mul(x, CURVE.a)), CURVE.b);
  }
  function isValidXY(x, y) {
    const left = Fp.sqr(y);
    const right = weierstrassEquation(x);
    return Fp.eql(left, right);
  }
  if (!isValidXY(CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n2), _4n3);
  const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
  if (Fp.is0(Fp.add(_4a3, _27b2)))
    throw new Error("bad curve params: a or b");
  function acoord(title, n, banZero = false) {
    if (!Fp.isValid(n) || banZero && Fp.is0(n))
      throw new Error(`bad point coordinate ${title}`);
    return n;
  }
  function aprjpoint(other) {
    if (!(other instanceof Point2))
      throw new Error("Weierstrass Point expected");
  }
  function splitEndoScalarN(k) {
    if (!endo || !endo.basises)
      throw new Error("no endo");
    return _splitEndoScalar(k, endo.basises, Fn2.ORDER);
  }
  function pushWnafPair(points, scalars, p, k) {
    if (!Fn2.isValid(k))
      throw new RangeError("invalid scalar: out of range");
    if (endo) {
      const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(k);
      const psi = new Point2(Fp.mul(p.X, endo.beta), p.Y, p.Z);
      points.push(k1neg ? p.negate() : p, k2neg ? psi.negate() : psi);
      scalars.push(k1, k2);
    } else {
      points.push(p);
      scalars.push(k);
    }
  }
  const validityCache = /* @__PURE__ */ new WeakSet();
  class Point2 {
    static BASE = new Point2(CURVE.Gx, CURVE.Gy, Fp.ONE);
    static ZERO = new Point2(Fp.ZERO, Fp.ONE, Fp.ZERO);
    static Fp = Fp;
    static Fn = Fn2;
    X;
    Y;
    Z;
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    constructor(X, Y, Z) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y, true);
      this.Z = acoord("z", Z);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    static fromAffine(p) {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point2)
        throw new Error("projective point not allowed");
      if (Fp.is0(x) && Fp.is0(y))
        return Point2.ZERO;
      return new Point2(x, y, Fp.ONE);
    }
    static fromBytes(bytes) {
      const P = Point2.fromAffine(decodePoint(abytes2(bytes, void 0, "point")));
      P.assertValidity();
      return P;
    }
    static fromHex(hex) {
      return Point2.fromBytes(hexToBytes2(hex));
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /**
     * @param isLazy - true will defer table computation until the first multiplication
     */
    precompute(windowSize = 6, isLazy = true) {
      wnaf.setWindowSize(this, windowSize);
      if (!isLazy)
        this.multiply(_3n2);
      return this;
    }
    // TODO: return `this`
    /** A point on curve is valid if it conforms to equation. */
    assertValidity() {
      const p = this;
      if (p.is0()) {
        if (extraOpts.allowInfinityPoint && Fp.is0(p.X) && Fp.eql(p.Y, Fp.ONE) && Fp.is0(p.Z))
          return;
        throw new Error("bad point: ZERO");
      }
      if (validityCache.has(p))
        return;
      const { x, y } = p.toAffine();
      if (!Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("bad point: x or y not field elements");
      if (!isValidXY(x, y))
        throw new Error("bad point: equation left != right");
      if (!p.isTorsionFree())
        throw new Error("bad point: not in prime-order subgroup");
      validityCache.add(p);
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (!Fp.isOdd)
        throw new Error("Field doesn't support isOdd");
      return !Fp.isOdd(y);
    }
    /** Compare one point to another. */
    equals(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }
    /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
    negate() {
      return new Point2(this.X, Fp.neg(this.Y), this.Z);
    }
    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
      let t0 = Fp.mul(X1, X1);
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3);
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = mulA(Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3);
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3);
      t2 = mulA(t2);
      t3 = Fp.sub(t0, t2);
      t3 = mulA(t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0);
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1);
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3);
      Z3 = Fp.add(Z3, Z3);
      return new Point2(X3, Y3, Z3);
    }
    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
      let t0 = Fp.mul(X1, X2);
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2);
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2);
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2);
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = mulA(t4);
      X3 = Fp.mul(b3, t2);
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0);
      t1 = Fp.add(t1, t0);
      t2 = mulA(t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2);
      t2 = mulA(t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4);
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0);
      return new Point2(X3, Y3, Z3);
    }
    subtract(other) {
      aprjpoint(other);
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point2.ZERO);
    }
    /**
     * Constant time multiplication.
     * Uses precomputed tables (signed fixed-window wNAF) when available.
     * Uses scalar blinding and avoids endomorphism splitting in the secret-scalar path.
     * @param scalar - by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar) {
      if (!Fn2.isValidNot0(scalar))
        throw new RangeError("invalid scalar: out of range");
      const { p, f } = wnaf.mulSecret(this, scalar, cofactor, normalize2);
      return normalize2([p, f])[0];
    }
    /**
     * Non-constant-time multiplication. Uses width-4 wNAF with GLV endomorphism splitting
     * when available (two half-width scalars sharing one halved doubling chain).
     * It's faster, but should only be used when you don't care about
     * an exposed secret key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(scalar) {
      const p = this;
      const sc = scalar;
      if (!Fn2.isValid(sc))
        throw new RangeError("invalid scalar: out of range");
      if (sc === _0n5 || p.is0())
        return Point2.ZERO;
      if (sc === _1n4)
        return p;
      if (wnaf.hasWindowSize(this))
        return wnaf.mulUnsafe(p, sc, normalize2);
      const points = [];
      const scalars = [];
      pushWnafPair(points, scalars, p, sc);
      return mulAddUnsafe(Point2, points, scalars);
    }
    /**
     * Non-constant-time double-scalar multiplication `a⋅this + b⋅other` (Strauss–Shamir).
     * Both walks share one doubling chain via {@link mulAddUnsafe}, and GLV endomorphism
     * (when available) halves the chain again by splitting each scalar into two half-width
     * parts. Used by ECDSA verification and public-key recovery for `R = u1⋅G + u2⋅P`.
     * Only for public scalars.
     */
    mulAddUnsafe(a, other, b) {
      aprjpoint(other);
      const points = [];
      const scalars = [];
      pushWnafPair(points, scalars, this, a);
      pushWnafPair(points, scalars, other, b);
      return mulAddUnsafe(Point2, points, scalars);
    }
    /**
     * Converts Projective point to affine (x, y) coordinates.
     * (X, Y, Z) ∋ (x=X/Z, y=Y/Z).
     * @param invertedZ - Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
     */
    toAffine(invertedZ) {
      const p = this;
      let iz = invertedZ;
      if (iz != null && !Fp.isValid(iz))
        throw new RangeError('"invertedZ" expected valid field element');
      const { X, Y, Z } = p;
      if (Fp.eql(Z, Fp.ONE))
        return { x: X, y: Y };
      const is0 = p.is0();
      if (iz == null)
        iz = is0 ? Fp.ONE : Fp.inv(Z);
      const x = Fp.mul(X, iz);
      const y = Fp.mul(Y, iz);
      const zz = Fp.mul(Z, iz);
      if (is0)
        return { x: Fp.ZERO, y: Fp.ZERO };
      if (!Fp.eql(zz, Fp.ONE))
        throw new Error("invZ was invalid");
      return { x, y };
    }
    /**
     * Checks whether Point is free of torsion elements (is in prime subgroup).
     * Always torsion-free for cofactor=1 curves.
     */
    isTorsionFree() {
      const { isTorsionFree } = extraOpts;
      if (cofactor === _1n4)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point2, this);
      return wnaf.mulUnsafe(this, CURVE_ORDER).is0();
    }
    clearCofactor() {
      const { clearCofactor } = extraOpts;
      if (cofactor === _1n4)
        return this;
      if (clearCofactor)
        return clearCofactor(Point2, this);
      return this.multiplyUnsafe(cofactor);
    }
    isSmallOrder() {
      if (cofactor === _1n4)
        return this.is0();
      return this.clearCofactor().is0();
    }
    toBytes(isCompressed = true) {
      abool2(isCompressed, "isCompressed");
      this.assertValidity();
      return encodePoint(Point2, this, isCompressed);
    }
    toHex(isCompressed = true) {
      return bytesToHex2(this.toBytes(isCompressed));
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
  }
  const normalize2 = (points) => normalizeZ(Point2, points);
  const wnaf = new ScalarMultiplier(Point2, randomBytes5);
  if (wnaf.bits >= 6)
    Point2.BASE.precompute(6);
  Object.freeze(Point2.prototype);
  Object.freeze(Point2);
  return Point2;
}
function pprefix(hasEvenY) {
  return Uint8Array.of(hasEvenY ? 2 : 3);
}
function getWLengths(Fp, Fn2) {
  return {
    secretKey: Fn2.BYTES,
    publicKey: 1 + Fp.BYTES,
    publicKeyUncompressed: 1 + 2 * Fp.BYTES,
    publicKeyHasPrefix: true,
    // Raw compact `(r || s)` signature width; DER and recovered signatures use
    // different lengths outside this helper.
    signature: 2 * Fn2.BYTES
  };
}
function ecdh(Point2, ecdhOpts = {}) {
  validatePointCons(Point2);
  const { Fn: Fn2 } = Point2;
  const randomBytes_ = ecdhOpts.randomBytes === void 0 ? randomBytes2 : ecdhOpts.randomBytes;
  const lengths = Object.assign(getWLengths(Point2.Fp, Fn2), {
    seed: Math.max(getMinHashLength(Fn2.ORDER), 16)
  });
  function isValidSecretKey(secretKey) {
    try {
      const num = Fn2.fromBytes(secretKey);
      return Fn2.isValidNot0(num);
    } catch (error) {
      return false;
    }
  }
  function isValidPublicKey(publicKey, isCompressed) {
    const { publicKey: comp, publicKeyUncompressed } = lengths;
    try {
      const l = publicKey.length;
      if (isCompressed === true && l !== comp)
        return false;
      if (isCompressed === false && l !== publicKeyUncompressed)
        return false;
      return !!Point2.fromBytes(publicKey);
    } catch (error) {
      return false;
    }
  }
  function randomSecretKey(seed) {
    seed = seed === void 0 ? randomBytes_(lengths.seed) : seed;
    return mapHashToField(abytes2(seed, lengths.seed, "seed"), Fn2.ORDER);
  }
  function getPublicKey(secretKey, isCompressed = true) {
    return Point2.BASE.multiply(Fn2.fromBytes(secretKey)).toBytes(isCompressed);
  }
  function isProbPub(item) {
    const { secretKey, publicKey, publicKeyUncompressed } = lengths;
    const allowedLengths = Fn2._lengths;
    if (!isBytes2(item))
      return void 0;
    const l = abytes2(item, void 0, "key").length;
    const isPub = l === publicKey || l === publicKeyUncompressed;
    const isSec = l === secretKey || !!allowedLengths?.includes(l);
    if (isPub && isSec)
      return void 0;
    return isPub;
  }
  function getSharedSecret(secretKeyA, publicKeyB, isCompressed = true) {
    if (isProbPub(secretKeyA) === true)
      throw new Error("first arg must be private key");
    if (isProbPub(publicKeyB) === false)
      throw new Error("second arg must be public key");
    const s = Fn2.fromBytes(secretKeyA);
    const b = Point2.fromBytes(publicKeyB);
    return b.multiply(s).toBytes(isCompressed);
  }
  const utils = {
    isValidSecretKey,
    isValidPublicKey,
    randomSecretKey
  };
  const keygen = createKeygen(randomSecretKey, getPublicKey);
  Object.freeze(utils);
  Object.freeze(lengths);
  return Object.freeze({ getPublicKey, getSharedSecret, keygen, Point: Point2, utils, lengths });
}
function ecdsa(Point2, hash, ecdsaOpts = {}) {
  validatePointCons(Point2);
  const hash_ = hash;
  ahash(hash_);
  validateObject(ecdsaOpts, {}, {
    hmac: "function",
    lowS: "boolean",
    randomBytes: "function",
    bits2int: "function",
    bits2int_modN: "function"
  });
  const opts = Object.assign({}, ecdsaOpts);
  const randomBytes5 = opts.randomBytes === void 0 ? randomBytes2 : opts.randomBytes;
  const hmac2 = opts.hmac === void 0 ? (key, msg) => hmac(hash_, key, msg) : opts.hmac;
  const { Fp, Fn: Fn2 } = Point2;
  const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn2;
  const blindLength = getMinHashLength(CURVE_ORDER);
  const csprng = probeRandomBytes(randomBytes5, blindLength);
  const { keygen, getPublicKey, getSharedSecret, utils, lengths } = ecdh(Point2, opts);
  const defaultSigOpts = {
    prehash: true,
    lowS: typeof opts.lowS === "boolean" ? opts.lowS : true,
    format: "compact",
    extraEntropy: false
  };
  const hasLargeRecoveryLifts = CURVE_ORDER * _2n2 + _1n4 < Fp.ORDER;
  function isBiggerThanHalfOrder(number) {
    const HALF = CURVE_ORDER >> _1n4;
    return number > HALF;
  }
  function validateRS(title, num) {
    if (!Fn2.isValidNot0(num))
      throw new Error(`invalid signature ${title}: out of range 1..Point.Fn.ORDER`);
    return num;
  }
  function assertFieldSignIsSupported() {
    if (!Fp.isOdd)
      throw new Error("Field doesn't support isOdd");
  }
  function getRecoveryBit(x, y, r) {
    assertFieldSignIsSupported();
    return (x === r ? 0 : 2) | Number(Fp.isOdd(y));
  }
  function assertRecoverableCurve() {
    if (hasLargeRecoveryLifts)
      throw new Error('"recovered" sig type is not supported for cofactor >2 curves');
  }
  function validateSigLength(bytes, format) {
    validateSigFormat(format);
    const size = lengths.signature;
    const sizer = format === "compact" ? size : format === "recovered" ? size + 1 : void 0;
    return abytes2(bytes, sizer);
  }
  class Signature {
    r;
    s;
    recovery;
    constructor(r, s, recovery) {
      this.r = validateRS("r", r);
      this.s = validateRS("s", s);
      if (recovery != null) {
        assertRecoverableCurve();
        if (![0, 1, 2, 3].includes(recovery))
          throw new Error("invalid recovery id");
        this.recovery = recovery;
      }
      Object.freeze(this);
    }
    static fromBytes(bytes, format = defaultSigOpts.format) {
      validateSigLength(bytes, format);
      let recid;
      if (format === "der") {
        const { r: r2, s: s2 } = DER.toSig(abytes2(bytes));
        return new Signature(r2, s2);
      }
      if (format === "recovered") {
        recid = bytes[0];
        format = "compact";
        bytes = bytes.subarray(1);
      }
      const L = lengths.signature / 2;
      const r = bytes.subarray(0, L);
      const s = bytes.subarray(L, L * 2);
      return new Signature(Fn2.fromBytes(r), Fn2.fromBytes(s), recid);
    }
    static fromHex(hex, format) {
      return this.fromBytes(hexToBytes2(hex), format);
    }
    assertRecovery() {
      const { recovery } = this;
      if (recovery == null)
        throw new Error("invalid recovery id: must be present");
      return recovery;
    }
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    // Unlike the top-level helper below, this method expects a digest that has
    // already been hashed to the curve's message representative.
    recoverPublicKey(messageHash) {
      const { r, s } = this;
      const recovery = this.assertRecovery();
      const radj = recovery === 2 || recovery === 3 ? r + CURVE_ORDER : r;
      if (!Fp.isValid(radj))
        throw new Error("invalid recovery id: sig.r+curve.n != R.x");
      const x = Fp.toBytes(radj);
      const R = Point2.fromBytes(concatBytes2(pprefix((recovery & 1) === 0), x));
      const ir = Fn2.inv(radj);
      const h = bits2int_modN(abytes2(messageHash, void 0, "msgHash"));
      const u1 = Fn2.create(-h * ir);
      const u2 = Fn2.create(s * ir);
      const Q = Point2.BASE.mulAddUnsafe(u1, R, u2);
      if (Q.is0())
        throw new Error("invalid recovery: point at infinify");
      Q.assertValidity();
      return Q;
    }
    // Signatures should be low-s, to prevent malleability.
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    toBytes(format = defaultSigOpts.format) {
      validateSigFormat(format);
      if (format === "der")
        return hexToBytes2(DER.hexFromSig(this));
      const { r, s } = this;
      const rb = Fn2.toBytes(r);
      const sb = Fn2.toBytes(s);
      if (format === "recovered") {
        assertRecoverableCurve();
        return concatBytes2(Uint8Array.of(this.assertRecovery()), rb, sb);
      }
      return concatBytes2(rb, sb);
    }
    toHex(format) {
      return bytesToHex2(this.toBytes(format));
    }
  }
  Object.freeze(Signature.prototype);
  Object.freeze(Signature);
  const bits2int = opts.bits2int === void 0 ? function bits2int_def(bytes) {
    if (bytes.length > 8192)
      throw new Error("input is too large");
    const num = bytesToNumberBE(bytes);
    const delta = bytes.length * 8 - fnBits;
    return delta > 0 ? num >> BigInt(delta) : num;
  } : opts.bits2int;
  const bits2int_modN = opts.bits2int_modN === void 0 ? function bits2int_modN_def(bytes) {
    return Fn2.create(bits2int(bytes));
  } : opts.bits2int_modN;
  const ORDER_MASK = bitMask(fnBits);
  function int2octets(num) {
    aInRange("num < 2^" + fnBits, num, _0n5, ORDER_MASK);
    return Fn2.toBytes(num);
  }
  function validateMsgAndHash(message, prehash) {
    abytes2(message, void 0, "message");
    return prehash ? abytes2(hash_(message), void 0, "prehashed message") : message;
  }
  function prepSig(message, secretKey, opts2) {
    const { lowS, prehash, extraEntropy } = validateSigOpts(opts2, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    const h1int = bits2int_modN(message);
    const d = Fn2.fromBytes(secretKey);
    if (!Fn2.isValidNot0(d))
      throw new Error("invalid private key");
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (extraEntropy != null && extraEntropy !== false) {
      const e = extraEntropy === true ? randomBytes5(lengths.secretKey) : extraEntropy;
      seedArgs.push(abytes2(e, void 0, "extraEntropy"));
    }
    const seed = concatBytes2(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!Fn2.isValidNot0(k))
        return;
      const q = Point2.BASE.multiply(k).toAffine();
      const r = Fn2.create(q.x);
      if (r === _0n5)
        return;
      let s;
      if (csprng !== void 0) {
        const b = bytesToNumberBE(mapHashToField(csprng(blindLength), CURVE_ORDER));
        const ibk = Fn2.inv(Fn2.mul(b, k));
        const bm = Fn2.mul(b, m);
        const bd = Fn2.mul(b, d);
        s = Fn2.create(ibk * Fn2.create(bm + bd * r));
      } else {
        const ik = invertCt(k, CURVE_ORDER);
        s = Fn2.create(ik * Fn2.create(m + r * d));
      }
      if (s === _0n5)
        return;
      let recovery = getRecoveryBit(q.x, q.y, r);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = Fn2.neg(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, hasLargeRecoveryLifts ? void 0 : recovery);
    }
    return { seed, k2sig };
  }
  function sign(message, secretKey, opts2 = {}) {
    const { seed, k2sig } = prepSig(message, secretKey, opts2);
    const drbg = createHmacDrbg(hash_.outputLen, Fn2.BYTES, hmac2);
    const sig = drbg(seed, k2sig);
    return sig.toBytes(opts2.format);
  }
  function verify2(signature, message, publicKey, opts2 = {}) {
    const { lowS, prehash, format } = validateSigOpts(opts2, defaultSigOpts);
    publicKey = abytes2(publicKey, void 0, "publicKey");
    message = validateMsgAndHash(message, prehash);
    if (!isBytes2(signature)) {
      const end = signature instanceof Signature ? ", use sig.toBytes()" : "";
      throw new Error("verify expects Uint8Array signature" + end);
    }
    validateSigLength(signature, format);
    try {
      const sig = Signature.fromBytes(signature, format);
      const P = Point2.fromBytes(publicKey);
      if (lowS && sig.hasHighS())
        return false;
      const { r, s } = sig;
      const h = bits2int_modN(message);
      const is = Fn2.inv(s);
      const u1 = Fn2.create(h * is);
      const u2 = Fn2.create(r * is);
      const R = Point2.BASE.mulAddUnsafe(u1, P, u2);
      if (R.is0())
        return false;
      const q = R.toAffine();
      const v = Fn2.create(q.x);
      if (v !== r)
        return false;
      if (format === "recovered" && sig.recovery !== getRecoveryBit(q.x, q.y, r))
        return false;
      return true;
    } catch (e) {
      return false;
    }
  }
  function recoverPublicKey(signature, message, opts2 = {}) {
    const { prehash } = validateSigOpts(opts2, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    return Signature.fromBytes(signature, "recovered").recoverPublicKey(message).toBytes();
  }
  return Object.freeze({
    keygen,
    getPublicKey,
    getSharedSecret,
    utils,
    lengths,
    Point: Point2,
    sign,
    verify: verify2,
    recoverPublicKey,
    Signature,
    hash: hash_
  });
}

// node_modules/@noble/curves/secp256k1.js
var secp256k1_CURVE = {
  p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
  n: BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
  Gy: BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
};
var secp256k1_ENDO = {
  beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
  basises: [
    [BigInt("0x3086d221a7d46bcde86c90e49284eb15"), -BigInt("0xe4437ed6010e88286f547fa90abfe4c3")],
    [BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8"), BigInt("0x3086d221a7d46bcde86c90e49284eb15")]
  ]
};
var _2n3 = /* @__PURE__ */ BigInt(2);
function sqrtMod(y) {
  const P = secp256k1_CURVE.p;
  const _3n3 = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
  const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
  const b2 = y * y * y % P;
  const b3 = b2 * b2 * y % P;
  const b6 = pow2(b3, _3n3, P) * b3 % P;
  const b9 = pow2(b6, _3n3, P) * b3 % P;
  const b11 = pow2(b9, _2n3, P) * b2 % P;
  const b22 = pow2(b11, _11n, P) * b11 % P;
  const b44 = pow2(b22, _22n, P) * b22 % P;
  const b88 = pow2(b44, _44n, P) * b44 % P;
  const b176 = pow2(b88, _88n, P) * b88 % P;
  const b220 = pow2(b176, _44n, P) * b44 % P;
  const b223 = pow2(b220, _3n3, P) * b3 % P;
  const t1 = pow2(b223, _23n, P) * b22 % P;
  const t2 = pow2(t1, _6n, P) * b2 % P;
  const root = pow2(t2, _2n3, P);
  if (!Fpk1.eql(Fpk1.sqr(root), y))
    throw new Error("Cannot find square root");
  return root;
}
var Fpk1 = /* @__PURE__ */ Field(secp256k1_CURVE.p, { sqrt: sqrtMod });
var Pointk1 = /* @__PURE__ */ weierstrass(secp256k1_CURVE, {
  Fp: Fpk1,
  endo: secp256k1_ENDO
});
var secp256k1 = /* @__PURE__ */ ecdsa(Pointk1, sha256);

// node_modules/@noble/hashes/sha3.js
var _0n6 = BigInt(0);
var _1n5 = BigInt(1);
var _2n4 = BigInt(2);
var _7n2 = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n5, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n6;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n5 ^ (R >> _7n2) * _0x71n) % _256n;
    if (R & _2n4)
      t ^= _1n5 << (_1n5 << BigInt(j)) - _1n5;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
var B = new Uint32Array(5 * 2);
function keccakP(s, rounds = 24) {
  if (!(s instanceof Uint32Array))
    throw new TypeError('"s" expected Uint32Array(50), got type=' + typeof s);
  if (s.length !== 50)
    throw new RangeError('"s" expected Uint32Array(50), got length=' + s.length);
  anumber(rounds, "rounds");
  if (rounds < 1 || rounds > 24)
    throw new Error('"rounds" expected integer 1..24');
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
      s[y] ^= ~s[y + 2] & s[y + 4];
      s[y + 1] ^= ~s[y + 3] & s[y + 5];
      s[y + 2] ^= ~s[y + 4] & s[y + 6];
      s[y + 3] ^= ~s[y + 5] & s[y + 7];
      s[y + 4] ^= ~s[y + 6] & s[y + 8];
      s[y + 5] ^= ~s[y + 7] & s[y + 9];
      s[y + 6] ^= ~s[y + 8] & b0;
      s[y + 7] ^= ~s[y + 9] & b1;
      s[y + 8] ^= ~b0 & b2;
      s[y + 9] ^= ~b1 & b3;
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var Keccak = class _Keccak {
  state;
  pos = 0;
  posOut = 0;
  finished = false;
  state32;
  destroyed = false;
  blockLen;
  suffix;
  outputLen;
  canXOF;
  enableXOF = false;
  rounds;
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    anumber(blockLen, "blockLen");
    anumber(suffix, "suffix");
    anumber(rounds, "rounds");
    abool(enableXOF, "enableXOF");
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.canXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen, "outputLen");
    if (!(0 < blockLen && blockLen < 200))
      throw new Error('"blockLen" must be 1..199');
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { blockLen, state, state32 } = this;
    const len = data.length;
    const canUseU32 = blockLen % 4 === 0 && data.byteOffset % 4 === 0;
    const blockLen32 = blockLen / 4;
    const data32 = canUseU32 && len >= blockLen ? u32(data) : void 0;
    for (let pos = 0; pos < len; ) {
      if (data32 !== void 0 && this.pos === 0 && pos % 4 === 0 && len - pos >= blockLen) {
        for (let i = 0, o = pos / 4; i < blockLen32; i++)
          state32[i] ^= data32[o + i];
        pos += blockLen;
        this.pos = blockLen;
        this.keccak();
        continue;
      }
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not enabled");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out.length === this.outputLen ? out : out.subarray(0, this.outputLen));
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.outputLen);
    this.digestInto(out);
    return out;
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.blockLen = blockLen;
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.canXOF = this.canXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
var keccak_256 = /* @__PURE__ */ genKeccak(1, 136, 32);

// node_modules/@noble/hashes/legacy.js
var Rho160 = /* @__PURE__ */ Uint8Array.from([
  7,
  4,
  13,
  1,
  10,
  6,
  15,
  3,
  12,
  0,
  9,
  5,
  2,
  14,
  11,
  8
]);
var Id160 = /* @__PURE__ */ (() => Uint8Array.from(new Array(16).fill(0).map((_, i) => i)))();
var Pi160 = /* @__PURE__ */ (() => Id160.map((i) => (9 * i + 5) % 16))();
var idxLR = /* @__PURE__ */ (() => {
  const L = [Id160];
  const R = [Pi160];
  const res = [L, R];
  for (let i = 0; i < 4; i++)
    for (let j of res)
      j.push(j[i].map((k) => Rho160[k]));
  return res;
})();
var idxL = /* @__PURE__ */ (() => idxLR[0])();
var idxR = /* @__PURE__ */ (() => idxLR[1])();
var shifts160 = /* @__PURE__ */ [
  [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
  [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
  [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
  [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
  [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5]
].map((i) => Uint8Array.from(i));
var shiftsL160 = /* @__PURE__ */ idxL.map((idx, i) => idx.map((j) => shifts160[i][j]));
var shiftsR160 = /* @__PURE__ */ idxR.map((idx, i) => idx.map((j) => shifts160[i][j]));
var Kl160 = /* @__PURE__ */ Uint32Array.from([
  0,
  1518500249,
  1859775393,
  2400959708,
  2840853838
]);
var Kr160 = /* @__PURE__ */ Uint32Array.from([
  1352829926,
  1548603684,
  1836072691,
  2053994217,
  0
]);
function ripemd_f(group, x, y, z) {
  if (group === 0)
    return x ^ y ^ z;
  if (group === 1)
    return x & y | ~x & z;
  if (group === 2)
    return (x | ~y) ^ z;
  if (group === 3)
    return x & z | y & ~z;
  return x ^ (y | ~z);
}
var BUF_160 = /* @__PURE__ */ new Uint32Array(16);
var _RIPEMD160 = class extends HashMD {
  h0 = 1732584193 | 0;
  h1 = 4023233417 | 0;
  h2 = 2562383102 | 0;
  h3 = 271733878 | 0;
  h4 = 3285377520 | 0;
  constructor() {
    super(64, 20, 8, true);
  }
  get() {
    const { h0, h1, h2, h3, h4 } = this;
    return [h0, h1, h2, h3, h4];
  }
  set(h0, h1, h2, h3, h4) {
    this.h0 = h0 | 0;
    this.h1 = h1 | 0;
    this.h2 = h2 | 0;
    this.h3 = h3 | 0;
    this.h4 = h4 | 0;
  }
  _cloneInto(to) {
    (to ||= new this.constructor()).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      BUF_160[i] = view.getUint32(offset, true);
    let al = this.h0 | 0, ar = al, bl = this.h1 | 0, br = bl, cl = this.h2 | 0, cr = cl, dl = this.h3 | 0, dr = dl, el = this.h4 | 0, er = el;
    for (let group = 0; group < 5; group++) {
      const rGroup = 4 - group;
      const hbl = Kl160[group], hbr = Kr160[group];
      const rl = idxL[group], rr = idxR[group];
      const sl = shiftsL160[group], sr = shiftsR160[group];
      for (let i = 0; i < 16; i++) {
        const tl = rotl(al + ripemd_f(group, bl, cl, dl) + BUF_160[rl[i]] + hbl, sl[i]) + el | 0;
        al = el, el = dl, dl = rotl(cl, 10) | 0, cl = bl, bl = tl;
      }
      for (let i = 0; i < 16; i++) {
        const tr = rotl(ar + ripemd_f(rGroup, br, cr, dr) + BUF_160[rr[i]] + hbr, sr[i]) + er | 0;
        ar = er, er = dr, dr = rotl(cr, 10) | 0, cr = br, br = tr;
      }
    }
    this.set(this.h1 + cl + dr | 0, this.h2 + dl + er | 0, this.h3 + el + ar | 0, this.h4 + al + br | 0, this.h0 + bl + cr | 0);
  }
  roundClean() {
    clean(BUF_160);
  }
  destroy() {
    this.destroyed = true;
    clean(this.buffer);
    this.set(0, 0, 0, 0, 0);
  }
};
var ripemd160 = /* @__PURE__ */ createHasher(() => new _RIPEMD160());

// node_modules/@scure/base/index.js
var freeze = (fn) => Object.freeze(fn());
function isBytes3(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
function abytes3(b) {
  if (!isBytes3(b))
    throw new TypeError("Uint8Array expected");
}
function afn(input) {
  if (typeof input !== "function")
    throw new TypeError("function expected");
  return true;
}
function astr(label, input) {
  if (typeof input !== "string")
    throw new TypeError(`${label}: string expected`);
  return true;
}
function anumber3(n, title = "number") {
  if (typeof n !== "number")
    throw new TypeError(`${title}: expected number, got ${typeof n}`);
  if (!Number.isSafeInteger(n))
    throw new RangeError(`${title}: expected safe integer, got ${n}`);
}
function chain(...args) {
  const id = (a) => a;
  const wrap = (a, b) => (c) => a(b(c));
  const encode = args.map((x) => x.encode).reduceRight(wrap, id);
  const decode = args.map((x) => x.decode).reduce(wrap, id);
  return { encode, decode };
}
var asciiDecoder = /* @__PURE__ */ (() => {
  try {
    const decoder = new TextDecoder();
    return decoder.decode(Uint8Array.of(65, 48, 43, 127)) === "A0+\x7F" ? decoder : void 0;
  } catch (e) {
    return void 0;
  }
})();
var B2S_CHUNK = 8192;
function charcodesToString(codes) {
  const len = codes.length;
  if (asciiDecoder !== void 0 && len >= 12)
    return asciiDecoder.decode(codes);
  if (len <= B2S_CHUNK)
    return String.fromCharCode.apply(null, codes);
  let res = "";
  for (let i = 0; i < len; i += B2S_CHUNK)
    res += String.fromCharCode.apply(null, codes.subarray(i, i + B2S_CHUNK));
  return res;
}
function alphabet(letters, aliases) {
  const len = letters.length;
  if (len > 128)
    throw new Error("alphabet: max 128 letters");
  const encTable = new Uint8Array(len);
  const decTable = new Int8Array(128).fill(-1);
  for (let i = 0; i < len; i++) {
    const code = letters.charCodeAt(i);
    if (letters.codePointAt(i) !== code || code > 127)
      throw new Error("alphabet: single-char ASCII letters only");
    encTable[i] = code;
    decTable[code] = i;
  }
  if (aliases !== void 0) {
    for (const alias of Object.keys(aliases)) {
      const code = alias.charCodeAt(0);
      const target = decTable[aliases[alias].charCodeAt(0)];
      if (alias.length !== 1 || code > 127 || target === void 0 || target === -1)
        throw new Error(`alphabet: invalid alias ${alias}`);
      decTable[code] = target;
    }
  }
  return {
    encode: (digits) => {
      const codes = new Uint8Array(digits.length);
      for (let i = 0; i < digits.length; i++) {
        const d = digits[i];
        const code = encTable[d];
        if (code === void 0)
          throw new Error(`alphabet.encode: invalid digit ${d}`);
        codes[i] = code;
      }
      return charcodesToString(codes);
    },
    decode: (input) => {
      astr("decode", input);
      const slen = input.length;
      const digits = new Uint8Array(slen);
      for (let i = 0; i < slen; i++) {
        const code = input.charCodeAt(i);
        const digit = code < 128 ? decTable[code] : -1;
        if (digit === -1)
          throw new Error(`Unknown letter "${input[i]}". Allowed: ${letters}`);
        digits[i] = digit;
      }
      return digits;
    }
  };
}
function checksum(len, fn) {
  anumber3(len);
  if (len <= 0)
    throw new RangeError(`checksum length must be positive: ${len}`);
  afn(fn);
  const _fn = fn;
  return {
    encode(data) {
      abytes3(data);
      const sum = _fn(data).slice(0, len);
      const res = new Uint8Array(data.length + len);
      res.set(data);
      res.set(sum, data.length);
      return res;
    },
    decode(data) {
      abytes3(data);
      const payload = data.slice(0, -len);
      const oldChecksum = data.slice(-len);
      const newChecksum = _fn(payload).slice(0, len);
      for (let i = 0; i < len; i++)
        if (newChecksum[i] !== oldChecksum[i])
          throw new Error("Invalid checksum");
      return payload;
    }
  };
}
var B58_GROUP = 656356768;
var radix58 = {
  encode: (bytes) => {
    abytes3(bytes);
    const blen = bytes.length;
    if (blen === 0)
      return new Uint8Array(0);
    let zeros = 0;
    while (zeros < blen - 1 && bytes[zeros] === 0)
      zeros++;
    const nlimbs = Math.ceil(blen / 2);
    const limbs = new Uint16Array(nlimbs);
    const odd = blen & 1;
    if (odd)
      limbs[0] = bytes[0];
    for (let i = odd, j2 = odd; i < blen; i += 2, j2++)
      limbs[j2] = bytes[i] << 8 | bytes[i + 1];
    const groups = [];
    let pos = 0;
    while (pos < nlimbs) {
      let carry = 0;
      for (let i = pos; i < nlimbs; i++) {
        const cur = carry * 65536 + limbs[i];
        const q = Math.floor(cur / B58_GROUP);
        carry = cur - q * B58_GROUP;
        limbs[i] = q;
        if (q === 0 && i === pos)
          pos++;
      }
      groups.push(carry);
    }
    const top = groups.length - 1;
    let sig = top * 5;
    for (let v = groups[top]; ; v = Math.floor(v / 58)) {
      sig++;
      if (v < 58)
        break;
    }
    const res = new Uint8Array(zeros + sig);
    let j = res.length - 1;
    for (let g = 0; g < top; g++) {
      let v = groups[g];
      for (let k = 0; k < 5; k++) {
        res[j--] = v % 58;
        v = Math.floor(v / 58);
      }
    }
    for (let v = groups[top]; j >= zeros; v = Math.floor(v / 58))
      res[j--] = v % 58;
    return res;
  },
  decode: (digits) => {
    abytes3(digits);
    const dlen = digits.length;
    if (dlen === 0)
      return new Uint8Array(0);
    if (dlen >= 65536)
      throw new Error("invalid length");
    let zeros = 0;
    while (zeros < dlen - 1 && digits[zeros] === 0)
      zeros++;
    const limbs = new Uint16Array(Math.ceil(dlen * 6 / 16) + 1);
    let used = 0;
    let i = 0;
    let group = dlen % 5 || 5;
    while (i < dlen) {
      let gval = 0;
      let factor = 1;
      for (const end = i + group; i < end; i++) {
        const d = digits[i];
        if (d >= 58)
          throw new Error(`invalid integer: ${d}`);
        gval = gval * 58 + d;
        factor *= 58;
      }
      group = 5;
      let carry = gval;
      for (let k = 0; k < used; k++) {
        const cur = limbs[k] * factor + carry;
        carry = Math.floor(cur / 65536);
        limbs[k] = cur - carry * 65536;
      }
      for (; carry > 0; carry = Math.floor(carry / 65536))
        limbs[used++] = carry % 65536;
    }
    const valueBytes = used === 0 ? 1 : used * 2 - (limbs[used - 1] < 256 ? 1 : 0);
    const res = new Uint8Array(zeros + valueBytes);
    let j = res.length - 1;
    for (let k = 0; k < used; k++) {
      const limb = limbs[k];
      res[j--] = limb & 255;
      if (j >= zeros)
        res[j--] = limb >> 8;
    }
    return res;
  }
};
var genBase58 = (abc) => chain(radix58, alphabet(abc));
var base58 = /* @__PURE__ */ freeze(() => genBase58("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"));
var createBase58check = (sha2563) => {
  afn(sha2563);
  const _sha256 = sha2563;
  return chain(checksum(4, (data) => _sha256(_sha256(data))), base58);
};

// node_modules/@scure/bip32/index.js
var Point = /* @__PURE__ */ (() => secp256k1.Point)();
var Fn = /* @__PURE__ */ (() => Point.Fn)();
var base58check = /* @__PURE__ */ createBase58check(sha256);
var MASTER_SECRET = /* @__PURE__ */ (() => {
  return Uint8Array.from("Bitcoin seed".split(""), (char) => char.charCodeAt(0));
})();
var BITCOIN_VERSIONS = { private: 76066276, public: 76067358 };
var HARDENED_OFFSET = 2147483648;
var hash160 = (data) => ripemd160(sha256(data));
var fromU32 = (data) => createView(data).getUint32(0, false);
var toU32 = (n, title = "number") => {
  if (typeof n !== "number")
    throw new TypeError(`"${title}" expected number, got type=${typeof n}`);
  if (!Number.isSafeInteger(n) || n < 0 || n > 2 ** 32 - 1)
    throw new RangeError(`"${title}" expected integer in range 0..2**32-1, got ${n}`);
  const buf = new Uint8Array(4);
  createView(buf).setUint32(0, n, false);
  return buf;
};
var validateVersions = (versions, title = "versions") => {
  if (!(typeof versions === "object" && versions !== null))
    throw new Error("versions must be an object");
  toU32(versions.private, `${title}.private`);
  toU32(versions.public, `${title}.public`);
  return versions;
};
var HDKey = class _HDKey {
  get fingerprint() {
    if (!this.pubHash) {
      throw new Error("No publicKey set!");
    }
    return fromU32(this.pubHash);
  }
  get identifier() {
    return this.pubHash;
  }
  get pubKeyHash() {
    return this.pubHash;
  }
  // Returns the live private key buffer for this instance.
  // Copy it first if you need an immutable snapshot.
  get privateKey() {
    return this._privateKey || null;
  }
  get publicKey() {
    return this._publicKey || null;
  }
  get privateExtendedKey() {
    const priv = this._privateKey;
    if (!priv) {
      throw new Error("No private key");
    }
    return base58check.encode(this.serialize(this.versions.private, concatBytes(Uint8Array.of(0), priv)));
  }
  get publicExtendedKey() {
    if (!this._publicKey) {
      throw new Error("No public key");
    }
    return base58check.encode(this.serialize(this.versions.public, this._publicKey));
  }
  static fromMasterSeed(seed, versions = BITCOIN_VERSIONS) {
    abytes(seed);
    versions = validateVersions(versions);
    if (8 * seed.length < 128 || 8 * seed.length > 512) {
      throw new RangeError("HDKey: seed length must be between 128 and 512 bits; 256 bits is advised, got " + seed.length);
    }
    const I = hmac(sha512, MASTER_SECRET, seed);
    const privateKey = I.slice(0, 32);
    const chainCode = I.slice(32);
    return new _HDKey({ versions, chainCode, privateKey });
  }
  static fromExtendedKey(base58key, versions = BITCOIN_VERSIONS) {
    versions = validateVersions(versions);
    const keyBuffer = base58check.decode(base58key);
    const keyView = createView(keyBuffer);
    const version = keyView.getUint32(0, false);
    const opt = {
      versions,
      depth: keyBuffer[4],
      parentFingerprint: keyView.getUint32(5, false),
      index: keyView.getUint32(9, false),
      chainCode: keyBuffer.slice(13, 45)
    };
    const key = keyBuffer.slice(45);
    const isPriv = key[0] === 0;
    if (version !== versions[isPriv ? "private" : "public"]) {
      throw new Error("Version mismatch");
    }
    if (isPriv) {
      return new _HDKey({ ...opt, privateKey: key.slice(1) });
    } else {
      return new _HDKey({ ...opt, publicKey: key });
    }
  }
  static fromJSON(json) {
    return _HDKey.fromExtendedKey(json.xpriv);
  }
  versions;
  depth = 0;
  index = 0;
  chainCode = null;
  parentFingerprint = 0;
  _privateKey;
  _publicKey;
  pubHash;
  constructor(opt) {
    if (!opt || typeof opt !== "object") {
      throw new Error("HDKey.constructor must not be called directly");
    }
    this.versions = opt.versions ? validateVersions(opt.versions) : BITCOIN_VERSIONS;
    this.depth = opt.depth || 0;
    this.chainCode = opt.chainCode ? Uint8Array.from(opt.chainCode) : null;
    this.index = opt.index || 0;
    this.parentFingerprint = opt.parentFingerprint || 0;
    if (!this.depth) {
      if (this.parentFingerprint || this.index) {
        throw new Error("HDKey: zero depth with non-zero index/parent fingerprint");
      }
    }
    if (this.depth > 255) {
      throw new Error("HDKey: depth exceeds the serializable value 255");
    }
    if (opt.publicKey && opt.privateKey) {
      throw new Error("HDKey: publicKey and privateKey at same time.");
    }
    if (opt.privateKey) {
      if (!secp256k1.utils.isValidSecretKey(opt.privateKey))
        throw new Error("Invalid private key");
      this._privateKey = Uint8Array.from(opt.privateKey);
      this._publicKey = secp256k1.getPublicKey(this._privateKey, true);
    } else if (opt.publicKey) {
      this._publicKey = Point.fromBytes(opt.publicKey).toBytes(true);
    } else {
      throw new Error("HDKey: no public or private key provided");
    }
    this.pubHash = hash160(this._publicKey);
  }
  derive(path2) {
    if (!/^[mM]'?/.test(path2)) {
      throw new Error('Path must start with "m" or "M"');
    }
    if (/^[mM]'?$/.test(path2)) {
      return this;
    }
    const parts = path2.replace(/^[mM]'?\//, "").split("/");
    let child = this;
    for (const c of parts) {
      const m = /^(\d+)('?)$/.exec(c);
      const m1 = m && m[1];
      if (!m || m.length !== 3 || typeof m1 !== "string")
        throw new Error("invalid child index: " + c);
      let idx = +m1;
      if (!Number.isSafeInteger(idx) || idx >= HARDENED_OFFSET) {
        throw new Error("Invalid index");
      }
      if (m[2] === "'") {
        idx += HARDENED_OFFSET;
      }
      child = child.deriveChild(idx);
    }
    return child;
  }
  /**
   * @param _I - Test-only override for the 64-byte HMAC-SHA512 output; normal callers must omit it.
   */
  deriveChild(index, _I) {
    if (!this._publicKey || !this.chainCode) {
      throw new Error("No publicKey or chainCode set");
    }
    let data = toU32(index, "index");
    if (index >= HARDENED_OFFSET) {
      const priv = this._privateKey;
      if (!priv) {
        throw new Error("Could not derive hardened child key");
      }
      data = concatBytes(Uint8Array.of(0), priv, data);
    } else {
      data = concatBytes(this._publicKey, data);
    }
    const out = _I || hmac(sha512, this.chainCode, data);
    abytes(out, 64);
    const childTweak = out.slice(0, 32);
    const chainCode = out.slice(32);
    const opt = {
      versions: this.versions,
      chainCode,
      depth: this.depth + 1,
      parentFingerprint: this.fingerprint,
      index
    };
    if (opt.depth > 255) {
      throw new Error("HDKey: depth exceeds the serializable value 255");
    }
    try {
      const ctweak = Fn.fromBytes(childTweak);
      if (this._privateKey) {
        const added = Fn.create(Fn.fromBytes(this._privateKey) + ctweak);
        if (!Fn.isValidNot0(added)) {
          throw new Error("The tweak was out of range or the resulted private key is invalid");
        }
        opt.privateKey = Fn.toBytes(added);
      } else {
        const point = Point.fromBytes(this._publicKey);
        const added = ctweak === 0n ? point : point.add(Point.BASE.multiply(ctweak));
        if (added.equals(Point.ZERO)) {
          throw new Error("The tweak was equal to negative P, which made the result key invalid");
        }
        opt.publicKey = added.toBytes(true);
      }
      return new _HDKey(opt);
    } catch (err) {
      return this.deriveChild(index + 1);
    }
  }
  sign(hash) {
    if (!this._privateKey) {
      throw new Error("No privateKey set!");
    }
    abytes(hash, 32);
    return secp256k1.sign(hash, this._privateKey, { prehash: false });
  }
  verify(hash, signature) {
    abytes(hash, 32);
    abytes(signature, 64);
    if (!this._publicKey) {
      throw new Error("No publicKey set!");
    }
    return secp256k1.verify(signature, hash, this._publicKey, { prehash: false });
  }
  wipePrivateData() {
    if (this._privateKey) {
      this._privateKey.fill(0);
      this._privateKey = void 0;
    }
    return this;
  }
  toJSON() {
    return {
      xpriv: this.privateExtendedKey,
      xpub: this.publicExtendedKey
    };
  }
  serialize(version, key) {
    if (!this.chainCode) {
      throw new Error("No chainCode set");
    }
    abytes(key, 33);
    return concatBytes(toU32(version, "version"), new Uint8Array([this.depth]), toU32(this.parentFingerprint, "parentFingerprint"), toU32(this.index, "index"), this.chainCode, key);
  }
};

// node_modules/@noble/hashes/pbkdf2.js
function pbkdf2Init(hash, _password, _salt, _opts) {
  ahash(hash);
  const opts = checkOpts({ dkLen: 32, asyncTick: 10 }, _opts);
  const { c, dkLen, asyncTick } = opts;
  anumber(c, "c");
  anumber(dkLen, "dkLen");
  anumber(asyncTick, "asyncTick");
  if (c < 1)
    throw new Error('"c" (iterations) must be >= 1');
  if (dkLen < 1)
    throw new Error('"dkLen" must be >= 1');
  if (dkLen > (2 ** 32 - 1) * hash.outputLen)
    throw new Error("derived key too long");
  const p = kdfInputToBytes(_password, "password");
  const s = kdfInputToBytes(_salt, "salt");
  const DK = new Uint8Array(dkLen);
  const { iHash, oHash, outputLen } = hmac.create(hash, p);
  const u = new Uint8Array(outputLen);
  const eng = pbkdf2Engine(iHash, oHash, s, u);
  return { c, dkLen, asyncTick, DK, outputLen, eng };
}
function pbkdf2Engine(iHash, oHash, salt, u) {
  const counter = new Uint8Array(4);
  const view = createView(counter);
  const salted = iHash._cloneInto().update(salt);
  const work = oHash._cloneInto();
  const iClone = iHash._cloneInto;
  const oClone = oHash._cloneInto;
  return {
    u1: (ti, Ti) => {
      view.setInt32(0, ti, false);
      salted._cloneInto(work).update(counter).digestInto(u);
      oHash._cloneInto(work).update(u).digestInto(u);
      Ti.set(u.subarray(0, Ti.length));
    },
    // Whole `F` inner loop for the sync variant: one optimized function owns the hot loop.
    rounds: (c, Ti) => {
      for (let ui = 1; ui < c; ui++) {
        iClone.call(iHash, work).update(u).digestInto(u);
        oClone.call(oHash, work).update(u).digestInto(u);
        for (let i = 0; i < Ti.length; i++)
          Ti[i] ^= u[i];
      }
    },
    output: (DK) => {
      iHash.destroy();
      oHash.destroy();
      salted.destroy();
      work.destroy();
      clean(u);
      return DK;
    }
  };
}
function pbkdf2(hash, password, salt, opts) {
  const { c, dkLen, DK, outputLen, eng } = pbkdf2Init(hash, password, salt, opts);
  for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += outputLen) {
    const Ti = DK.subarray(pos, pos + outputLen);
    eng.u1(ti, Ti);
    eng.rounds(c, Ti);
  }
  return eng.output(DK);
}

// node_modules/@scure/bip39/index.js
var isJapanese = (wordlist2) => wordlist2[0] === "\u3042\u3044\u3053\u304F\u3057\u3093";
function nfkd(str) {
  if (typeof str !== "string")
    throw new TypeError("invalid mnemonic type: " + typeof str);
  return str.normalize("NFKD");
}
function normalize(str) {
  const norm = nfkd(str);
  const words = norm.split(" ");
  if (![12, 15, 18, 21, 24].includes(words.length))
    throw new Error("Invalid mnemonic");
  return { nfkd: norm, words };
}
function aentropy(ent) {
  abytes(ent);
  if (![16, 20, 24, 28, 32].includes(ent.length))
    throw new RangeError("invalid entropy length");
}
var calcChecksum = (entropy) => {
  const bitsLeft = 8 - entropy.length / 4;
  return sha256(entropy)[0] >> bitsLeft << bitsLeft;
};
function awordlist(wordlist2) {
  if (!Array.isArray(wordlist2) || wordlist2.length !== 2048 || typeof wordlist2[0] !== "string")
    throw new TypeError("Wordlist: expected array of 2048 strings");
  wordlist2.forEach((i) => {
    if (typeof i !== "string")
      throw new TypeError("wordlist: non-string element: " + i);
  });
}
function encodeWords(entropy, wordlist2) {
  awordlist(wordlist2);
  const bytes = new Uint8Array(entropy.length + 1);
  bytes.set(entropy);
  bytes[entropy.length] = calcChecksum(entropy);
  const words = [];
  let carry = 0;
  let bits = 0;
  for (const byte of bytes) {
    carry = carry << 8 | byte;
    bits += 8;
    if (bits >= 11) {
      bits -= 11;
      words.push(wordlist2[carry >>> bits & 2047]);
      carry &= (1 << bits) - 1;
    }
  }
  return words;
}
function decodeWords(words, wordlist2) {
  awordlist(wordlist2);
  const entLen = words.length / 3 * 4;
  const bytes = new Uint8Array(entLen + 1);
  let carry = 0;
  let bits = 0;
  let pos = 0;
  for (const word of words) {
    const index = wordlist2.indexOf(word);
    if (index === -1)
      throw new Error("Unknown word: " + word);
    carry = carry << 11 | index;
    bits += 11;
    while (bits >= 8) {
      bits -= 8;
      bytes[pos++] = carry >>> bits & 255;
    }
    carry &= (1 << bits) - 1;
  }
  if (bits > 0)
    bytes[pos] = carry << 8 - bits;
  const entropy = bytes.subarray(0, entLen);
  if (bytes[entLen] !== calcChecksum(entropy))
    throw new Error("Invalid checksum");
  return Uint8Array.from(entropy);
}
function mnemonicToEntropy(mnemonic, wordlist2) {
  const { words } = normalize(mnemonic);
  const entropy = decodeWords(words, wordlist2);
  aentropy(entropy);
  return entropy;
}
function entropyToMnemonic(entropy, wordlist2) {
  aentropy(entropy);
  const words = encodeWords(entropy, wordlist2);
  return words.join(isJapanese(wordlist2) ? "\u3000" : " ");
}
function validateMnemonic(mnemonic, wordlist2) {
  try {
    mnemonicToEntropy(mnemonic, wordlist2);
  } catch (e) {
    return false;
  }
  return true;
}
var psalt = (passphrase) => {
  if (typeof passphrase !== "string")
    throw new TypeError("invalid passphrase type: " + typeof passphrase);
  return nfkd("mnemonic" + passphrase);
};
function mnemonicToSeedSync(mnemonic, passphrase = "") {
  return pbkdf2(sha512, normalize(mnemonic).nfkd, psalt(passphrase), {
    c: 2048,
    dkLen: 64
  });
}

// node_modules/@scure/bip39/wordlists/english.js
var wordlist = /* @__PURE__ */ Object.freeze(`abandon
ability
able
about
above
absent
absorb
abstract
absurd
abuse
access
accident
account
accuse
achieve
acid
acoustic
acquire
across
act
action
actor
actress
actual
adapt
add
addict
address
adjust
admit
adult
advance
advice
aerobic
affair
afford
afraid
again
age
agent
agree
ahead
aim
air
airport
aisle
alarm
album
alcohol
alert
alien
all
alley
allow
almost
alone
alpha
already
also
alter
always
amateur
amazing
among
amount
amused
analyst
anchor
ancient
anger
angle
angry
animal
ankle
announce
annual
another
answer
antenna
antique
anxiety
any
apart
apology
appear
apple
approve
april
arch
arctic
area
arena
argue
arm
armed
armor
army
around
arrange
arrest
arrive
arrow
art
artefact
artist
artwork
ask
aspect
assault
asset
assist
assume
asthma
athlete
atom
attack
attend
attitude
attract
auction
audit
august
aunt
author
auto
autumn
average
avocado
avoid
awake
aware
away
awesome
awful
awkward
axis
baby
bachelor
bacon
badge
bag
balance
balcony
ball
bamboo
banana
banner
bar
barely
bargain
barrel
base
basic
basket
battle
beach
bean
beauty
because
become
beef
before
begin
behave
behind
believe
below
belt
bench
benefit
best
betray
better
between
beyond
bicycle
bid
bike
bind
biology
bird
birth
bitter
black
blade
blame
blanket
blast
bleak
bless
blind
blood
blossom
blouse
blue
blur
blush
board
boat
body
boil
bomb
bone
bonus
book
boost
border
boring
borrow
boss
bottom
bounce
box
boy
bracket
brain
brand
brass
brave
bread
breeze
brick
bridge
brief
bright
bring
brisk
broccoli
broken
bronze
broom
brother
brown
brush
bubble
buddy
budget
buffalo
build
bulb
bulk
bullet
bundle
bunker
burden
burger
burst
bus
business
busy
butter
buyer
buzz
cabbage
cabin
cable
cactus
cage
cake
call
calm
camera
camp
can
canal
cancel
candy
cannon
canoe
canvas
canyon
capable
capital
captain
car
carbon
card
cargo
carpet
carry
cart
case
cash
casino
castle
casual
cat
catalog
catch
category
cattle
caught
cause
caution
cave
ceiling
celery
cement
census
century
cereal
certain
chair
chalk
champion
change
chaos
chapter
charge
chase
chat
cheap
check
cheese
chef
cherry
chest
chicken
chief
child
chimney
choice
choose
chronic
chuckle
chunk
churn
cigar
cinnamon
circle
citizen
city
civil
claim
clap
clarify
claw
clay
clean
clerk
clever
click
client
cliff
climb
clinic
clip
clock
clog
close
cloth
cloud
clown
club
clump
cluster
clutch
coach
coast
coconut
code
coffee
coil
coin
collect
color
column
combine
come
comfort
comic
common
company
concert
conduct
confirm
congress
connect
consider
control
convince
cook
cool
copper
copy
coral
core
corn
correct
cost
cotton
couch
country
couple
course
cousin
cover
coyote
crack
cradle
craft
cram
crane
crash
crater
crawl
crazy
cream
credit
creek
crew
cricket
crime
crisp
critic
crop
cross
crouch
crowd
crucial
cruel
cruise
crumble
crunch
crush
cry
crystal
cube
culture
cup
cupboard
curious
current
curtain
curve
cushion
custom
cute
cycle
dad
damage
damp
dance
danger
daring
dash
daughter
dawn
day
deal
debate
debris
decade
december
decide
decline
decorate
decrease
deer
defense
define
defy
degree
delay
deliver
demand
demise
denial
dentist
deny
depart
depend
deposit
depth
deputy
derive
describe
desert
design
desk
despair
destroy
detail
detect
develop
device
devote
diagram
dial
diamond
diary
dice
diesel
diet
differ
digital
dignity
dilemma
dinner
dinosaur
direct
dirt
disagree
discover
disease
dish
dismiss
disorder
display
distance
divert
divide
divorce
dizzy
doctor
document
dog
doll
dolphin
domain
donate
donkey
donor
door
dose
double
dove
draft
dragon
drama
drastic
draw
dream
dress
drift
drill
drink
drip
drive
drop
drum
dry
duck
dumb
dune
during
dust
dutch
duty
dwarf
dynamic
eager
eagle
early
earn
earth
easily
east
easy
echo
ecology
economy
edge
edit
educate
effort
egg
eight
either
elbow
elder
electric
elegant
element
elephant
elevator
elite
else
embark
embody
embrace
emerge
emotion
employ
empower
empty
enable
enact
end
endless
endorse
enemy
energy
enforce
engage
engine
enhance
enjoy
enlist
enough
enrich
enroll
ensure
enter
entire
entry
envelope
episode
equal
equip
era
erase
erode
erosion
error
erupt
escape
essay
essence
estate
eternal
ethics
evidence
evil
evoke
evolve
exact
example
excess
exchange
excite
exclude
excuse
execute
exercise
exhaust
exhibit
exile
exist
exit
exotic
expand
expect
expire
explain
expose
express
extend
extra
eye
eyebrow
fabric
face
faculty
fade
faint
faith
fall
false
fame
family
famous
fan
fancy
fantasy
farm
fashion
fat
fatal
father
fatigue
fault
favorite
feature
february
federal
fee
feed
feel
female
fence
festival
fetch
fever
few
fiber
fiction
field
figure
file
film
filter
final
find
fine
finger
finish
fire
firm
first
fiscal
fish
fit
fitness
fix
flag
flame
flash
flat
flavor
flee
flight
flip
float
flock
floor
flower
fluid
flush
fly
foam
focus
fog
foil
fold
follow
food
foot
force
forest
forget
fork
fortune
forum
forward
fossil
foster
found
fox
fragile
frame
frequent
fresh
friend
fringe
frog
front
frost
frown
frozen
fruit
fuel
fun
funny
furnace
fury
future
gadget
gain
galaxy
gallery
game
gap
garage
garbage
garden
garlic
garment
gas
gasp
gate
gather
gauge
gaze
general
genius
genre
gentle
genuine
gesture
ghost
giant
gift
giggle
ginger
giraffe
girl
give
glad
glance
glare
glass
glide
glimpse
globe
gloom
glory
glove
glow
glue
goat
goddess
gold
good
goose
gorilla
gospel
gossip
govern
gown
grab
grace
grain
grant
grape
grass
gravity
great
green
grid
grief
grit
grocery
group
grow
grunt
guard
guess
guide
guilt
guitar
gun
gym
habit
hair
half
hammer
hamster
hand
happy
harbor
hard
harsh
harvest
hat
have
hawk
hazard
head
health
heart
heavy
hedgehog
height
hello
helmet
help
hen
hero
hidden
high
hill
hint
hip
hire
history
hobby
hockey
hold
hole
holiday
hollow
home
honey
hood
hope
horn
horror
horse
hospital
host
hotel
hour
hover
hub
huge
human
humble
humor
hundred
hungry
hunt
hurdle
hurry
hurt
husband
hybrid
ice
icon
idea
identify
idle
ignore
ill
illegal
illness
image
imitate
immense
immune
impact
impose
improve
impulse
inch
include
income
increase
index
indicate
indoor
industry
infant
inflict
inform
inhale
inherit
initial
inject
injury
inmate
inner
innocent
input
inquiry
insane
insect
inside
inspire
install
intact
interest
into
invest
invite
involve
iron
island
isolate
issue
item
ivory
jacket
jaguar
jar
jazz
jealous
jeans
jelly
jewel
job
join
joke
journey
joy
judge
juice
jump
jungle
junior
junk
just
kangaroo
keen
keep
ketchup
key
kick
kid
kidney
kind
kingdom
kiss
kit
kitchen
kite
kitten
kiwi
knee
knife
knock
know
lab
label
labor
ladder
lady
lake
lamp
language
laptop
large
later
latin
laugh
laundry
lava
law
lawn
lawsuit
layer
lazy
leader
leaf
learn
leave
lecture
left
leg
legal
legend
leisure
lemon
lend
length
lens
leopard
lesson
letter
level
liar
liberty
library
license
life
lift
light
like
limb
limit
link
lion
liquid
list
little
live
lizard
load
loan
lobster
local
lock
logic
lonely
long
loop
lottery
loud
lounge
love
loyal
lucky
luggage
lumber
lunar
lunch
luxury
lyrics
machine
mad
magic
magnet
maid
mail
main
major
make
mammal
man
manage
mandate
mango
mansion
manual
maple
marble
march
margin
marine
market
marriage
mask
mass
master
match
material
math
matrix
matter
maximum
maze
meadow
mean
measure
meat
mechanic
medal
media
melody
melt
member
memory
mention
menu
mercy
merge
merit
merry
mesh
message
metal
method
middle
midnight
milk
million
mimic
mind
minimum
minor
minute
miracle
mirror
misery
miss
mistake
mix
mixed
mixture
mobile
model
modify
mom
moment
monitor
monkey
monster
month
moon
moral
more
morning
mosquito
mother
motion
motor
mountain
mouse
move
movie
much
muffin
mule
multiply
muscle
museum
mushroom
music
must
mutual
myself
mystery
myth
naive
name
napkin
narrow
nasty
nation
nature
near
neck
need
negative
neglect
neither
nephew
nerve
nest
net
network
neutral
never
news
next
nice
night
noble
noise
nominee
noodle
normal
north
nose
notable
note
nothing
notice
novel
now
nuclear
number
nurse
nut
oak
obey
object
oblige
obscure
observe
obtain
obvious
occur
ocean
october
odor
off
offer
office
often
oil
okay
old
olive
olympic
omit
once
one
onion
online
only
open
opera
opinion
oppose
option
orange
orbit
orchard
order
ordinary
organ
orient
original
orphan
ostrich
other
outdoor
outer
output
outside
oval
oven
over
own
owner
oxygen
oyster
ozone
pact
paddle
page
pair
palace
palm
panda
panel
panic
panther
paper
parade
parent
park
parrot
party
pass
patch
path
patient
patrol
pattern
pause
pave
payment
peace
peanut
pear
peasant
pelican
pen
penalty
pencil
people
pepper
perfect
permit
person
pet
phone
photo
phrase
physical
piano
picnic
picture
piece
pig
pigeon
pill
pilot
pink
pioneer
pipe
pistol
pitch
pizza
place
planet
plastic
plate
play
please
pledge
pluck
plug
plunge
poem
poet
point
polar
pole
police
pond
pony
pool
popular
portion
position
possible
post
potato
pottery
poverty
powder
power
practice
praise
predict
prefer
prepare
present
pretty
prevent
price
pride
primary
print
priority
prison
private
prize
problem
process
produce
profit
program
project
promote
proof
property
prosper
protect
proud
provide
public
pudding
pull
pulp
pulse
pumpkin
punch
pupil
puppy
purchase
purity
purpose
purse
push
put
puzzle
pyramid
quality
quantum
quarter
question
quick
quit
quiz
quote
rabbit
raccoon
race
rack
radar
radio
rail
rain
raise
rally
ramp
ranch
random
range
rapid
rare
rate
rather
raven
raw
razor
ready
real
reason
rebel
rebuild
recall
receive
recipe
record
recycle
reduce
reflect
reform
refuse
region
regret
regular
reject
relax
release
relief
rely
remain
remember
remind
remove
render
renew
rent
reopen
repair
repeat
replace
report
require
rescue
resemble
resist
resource
response
result
retire
retreat
return
reunion
reveal
review
reward
rhythm
rib
ribbon
rice
rich
ride
ridge
rifle
right
rigid
ring
riot
ripple
risk
ritual
rival
river
road
roast
robot
robust
rocket
romance
roof
rookie
room
rose
rotate
rough
round
route
royal
rubber
rude
rug
rule
run
runway
rural
sad
saddle
sadness
safe
sail
salad
salmon
salon
salt
salute
same
sample
sand
satisfy
satoshi
sauce
sausage
save
say
scale
scan
scare
scatter
scene
scheme
school
science
scissors
scorpion
scout
scrap
screen
script
scrub
sea
search
season
seat
second
secret
section
security
seed
seek
segment
select
sell
seminar
senior
sense
sentence
series
service
session
settle
setup
seven
shadow
shaft
shallow
share
shed
shell
sheriff
shield
shift
shine
ship
shiver
shock
shoe
shoot
shop
short
shoulder
shove
shrimp
shrug
shuffle
shy
sibling
sick
side
siege
sight
sign
silent
silk
silly
silver
similar
simple
since
sing
siren
sister
situate
six
size
skate
sketch
ski
skill
skin
skirt
skull
slab
slam
sleep
slender
slice
slide
slight
slim
slogan
slot
slow
slush
small
smart
smile
smoke
smooth
snack
snake
snap
sniff
snow
soap
soccer
social
sock
soda
soft
solar
soldier
solid
solution
solve
someone
song
soon
sorry
sort
soul
sound
soup
source
south
space
spare
spatial
spawn
speak
special
speed
spell
spend
sphere
spice
spider
spike
spin
spirit
split
spoil
sponsor
spoon
sport
spot
spray
spread
spring
spy
square
squeeze
squirrel
stable
stadium
staff
stage
stairs
stamp
stand
start
state
stay
steak
steel
stem
step
stereo
stick
still
sting
stock
stomach
stone
stool
story
stove
strategy
street
strike
strong
struggle
student
stuff
stumble
style
subject
submit
subway
success
such
sudden
suffer
sugar
suggest
suit
summer
sun
sunny
sunset
super
supply
supreme
sure
surface
surge
surprise
surround
survey
suspect
sustain
swallow
swamp
swap
swarm
swear
sweet
swift
swim
swing
switch
sword
symbol
symptom
syrup
system
table
tackle
tag
tail
talent
talk
tank
tape
target
task
taste
tattoo
taxi
teach
team
tell
ten
tenant
tennis
tent
term
test
text
thank
that
theme
then
theory
there
they
thing
this
thought
three
thrive
throw
thumb
thunder
ticket
tide
tiger
tilt
timber
time
tiny
tip
tired
tissue
title
toast
tobacco
today
toddler
toe
together
toilet
token
tomato
tomorrow
tone
tongue
tonight
tool
tooth
top
topic
topple
torch
tornado
tortoise
toss
total
tourist
toward
tower
town
toy
track
trade
traffic
tragic
train
transfer
trap
trash
travel
tray
treat
tree
trend
trial
tribe
trick
trigger
trim
trip
trophy
trouble
truck
true
truly
trumpet
trust
truth
try
tube
tuition
tumble
tuna
tunnel
turkey
turn
turtle
twelve
twenty
twice
twin
twist
two
type
typical
ugly
umbrella
unable
unaware
uncle
uncover
under
undo
unfair
unfold
unhappy
uniform
unique
unit
universe
unknown
unlock
until
unusual
unveil
update
upgrade
uphold
upon
upper
upset
urban
urge
usage
use
used
useful
useless
usual
utility
vacant
vacuum
vague
valid
valley
valve
van
vanish
vapor
various
vast
vault
vehicle
velvet
vendor
venture
venue
verb
verify
version
very
vessel
veteran
viable
vibrant
vicious
victory
video
view
village
vintage
violin
virtual
virus
visa
visit
visual
vital
vivid
vocal
voice
void
volcano
volume
vote
voyage
wage
wagon
wait
walk
wall
walnut
want
warfare
warm
warrior
wash
wasp
waste
water
wave
way
wealth
weapon
wear
weasel
weather
web
wedding
weekend
weird
welcome
west
wet
whale
what
wheat
wheel
when
where
whip
whisper
wide
width
wife
wild
will
win
window
wine
wing
wink
winner
winter
wire
wisdom
wise
wish
witness
wolf
woman
wonder
wood
wool
word
work
world
worry
worth
wrap
wreck
wrestle
wrist
write
wrong
yard
year
yellow
you
young
youth
zebra
zero
zone
zoo`.split("\n"));

// slip39.mjs
import assert from "node:assert/strict";
import { createHash, createHmac, pbkdf2Sync, randomBytes as randomBytes3 } from "node:crypto";
var RADIX_BITS = 10;
var ID_LENGTH_BITS = 15;
var EXTENDABLE_FLAG_LENGTH_BITS = 1;
var ITERATION_EXP_LENGTH_BITS = 4;
var ID_EXP_LENGTH_WORDS = 2;
var CHECKSUM_LENGTH_WORDS = 3;
var DIGEST_LENGTH_BYTES = 4;
var METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS;
var MIN_STRENGTH_BITS = 128;
var MAX_SHARE_COUNT = 16;
var SECRET_INDEX = 255;
var DIGEST_INDEX = 254;
var BASE_ITERATION_COUNT = 1e4;
var ROUND_COUNT = 4;
var CUSTOMIZATION_STRING_ORIG = Buffer.from("shamir", "utf8");
var CUSTOMIZATION_STRING_EXTENDABLE = Buffer.from("shamir_extendable", "utf8");
var SLIP39_WORDLIST_SHA256 = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3";
var SLIP39_WORDLIST = "academic acid acne acquire acrobat activity actress adapt adequate adjust admit adorn adult advance advocate afraid again agency agree aide aircraft airline airport ajar alarm album alcohol alien alive alpha already alto aluminum always amazing ambition amount amuse analysis anatomy ancestor ancient angel angry animal answer antenna anxiety apart aquatic arcade arena argue armed artist artwork aspect auction august aunt average aviation avoid award away axis axle beam beard beaver become bedroom behavior being believe belong benefit best beyond bike biology birthday bishop black blanket blessing blimp blind blue body bolt boring born both boundary bracelet branch brave breathe briefing broken brother browser bucket budget building bulb bulge bumpy bundle burden burning busy buyer cage calcium camera campus canyon capacity capital capture carbon cards careful cargo carpet carve category cause ceiling center ceramic champion change charity check chemical chest chew chubby cinema civil class clay cleanup client climate clinic clock clogs closet clothes club cluster coal coastal coding column company corner costume counter course cover cowboy cradle craft crazy credit cricket criminal crisis critical crowd crucial crunch crush crystal cubic cultural curious curly custody cylinder daisy damage dance darkness database daughter deadline deal debris debut decent decision declare decorate decrease deliver demand density deny depart depend depict deploy describe desert desire desktop destroy detailed detect device devote diagnose dictate diet dilemma diminish dining diploma disaster discuss disease dish dismiss display distance dive divorce document domain domestic dominant dough downtown dragon dramatic dream dress drift drink drove drug dryer duckling duke duration dwarf dynamic early earth easel easy echo eclipse ecology edge editor educate either elbow elder election elegant element elephant elevator elite else email emerald emission emperor emphasis employer empty ending endless endorse enemy energy enforce engage enjoy enlarge entrance envelope envy epidemic episode equation equip eraser erode escape estate estimate evaluate evening evidence evil evoke exact example exceed exchange exclude excuse execute exercise exhaust exotic expand expect explain express extend extra eyebrow facility fact failure faint fake false family famous fancy fangs fantasy fatal fatigue favorite fawn fiber fiction filter finance findings finger firefly firm fiscal fishing fitness flame flash flavor flea flexible flip float floral fluff focus forbid force forecast forget formal fortune forward founder fraction fragment frequent freshman friar fridge friendly frost froth frozen fumes funding furl fused galaxy game garbage garden garlic gasoline gather general genius genre genuine geology gesture glad glance glasses glen glimpse goat golden graduate grant grasp gravity gray greatest grief grill grin grocery gross group grownup grumpy guard guest guilt guitar gums hairy hamster hand hanger harvest have havoc hawk hazard headset health hearing heat helpful herald herd hesitate hobo holiday holy home hormone hospital hour huge human humidity hunting husband hush husky hybrid idea identify idle image impact imply improve impulse include income increase index indicate industry infant inform inherit injury inmate insect inside install intend intimate invasion involve iris island isolate item ivory jacket jerky jewelry join judicial juice jump junction junior junk jury justice kernel keyboard kidney kind kitchen knife knit laden ladle ladybug lair lamp language large laser laundry lawsuit leader leaf learn leaves lecture legal legend legs lend length level liberty library license lift likely lilac lily lips liquid listen literary living lizard loan lobe location losing loud loyalty luck lunar lunch lungs luxury lying lyrics machine magazine maiden mailman main makeup making mama manager mandate mansion manual marathon march market marvel mason material math maximum mayor meaning medal medical member memory mental merchant merit method metric midst mild military mineral minister miracle mixed mixture mobile modern modify moisture moment morning mortgage mother mountain mouse move much mule multiple muscle museum music mustang nail national necklace negative nervous network news nuclear numb numerous nylon oasis obesity object observe obtain ocean often olympic omit oral orange orbit order ordinary organize ounce oven overall owner paces pacific package paid painting pajamas pancake pants papa paper parcel parking party patent patrol payment payroll peaceful peanut peasant pecan penalty pencil percent perfect permit petition phantom pharmacy photo phrase physics pickup picture piece pile pink pipeline pistol pitch plains plan plastic platform playoff pleasure plot plunge practice prayer preach predator pregnant premium prepare presence prevent priest primary priority prisoner privacy prize problem process profile program promise prospect provide prune public pulse pumps punish puny pupal purchase purple python quantity quarter quick quiet race racism radar railroad rainbow raisin random ranked rapids raspy reaction realize rebound rebuild recall receiver recover regret regular reject relate remember remind remove render repair repeat replace require rescue research resident response result retailer retreat reunion revenue review reward rhyme rhythm rich rival river robin rocky romantic romp roster round royal ruin ruler rumor sack safari salary salon salt satisfy satoshi saver says scandal scared scatter scene scholar science scout scramble screw script scroll seafood season secret security segment senior shadow shaft shame shaped sharp shelter sheriff short should shrimp sidewalk silent silver similar simple single sister skin skunk slap slavery sled slice slim slow slush smart smear smell smirk smith smoking smug snake snapshot sniff society software soldier solution soul source space spark speak species spelling spend spew spider spill spine spirit spit spray sprinkle square squeeze stadium staff standard starting station stay steady step stick stilt story strategy strike style subject submit sugar suitable sunlight superior surface surprise survive sweater swimming swing switch symbolic sympathy syndrome system tackle tactics tadpole talent task taste taught taxi teacher teammate teaspoon temple tenant tendency tension terminal testify texture thank that theater theory therapy thorn threaten thumb thunder ticket tidy timber timely ting tofu together tolerate total toxic tracks traffic training transfer trash traveler treat trend trial tricycle trip triumph trouble true trust twice twin type typical ugly ultimate umbrella uncover undergo unfair unfold unhappy union universe unkind unknown unusual unwrap upgrade upstairs username usher usual valid valuable vampire vanish various vegan velvet venture verdict verify very veteran vexed victim video view vintage violence viral visitor visual vitamins vocal voice volume voter voting walnut warmth warn watch wavy wealthy weapon webcam welcome welfare western width wildlife window wine wireless wisdom withdraw wits wolf woman work worthy wrap wrist writing wrote year yelp yield yoga zero".split(" ");
var WORD_INDEX = new Map(SLIP39_WORDLIST.map((w, i) => [w, i]));
function assertSlip39WordlistIntegrity() {
  assert.equal(SLIP39_WORDLIST.length, 1024, "SLIP-39 wordlist must have 1024 words");
  const digest = createHash("sha256").update(`${SLIP39_WORDLIST.join("\n")}
`).digest("hex");
  assert.equal(
    digest,
    SLIP39_WORDLIST_SHA256,
    "SLIP-39 wordlist does not match the published SHA-256; shares produced with it would not be readable by other implementations"
  );
}
var EXP = new Uint8Array(255);
var LOG = new Uint8Array(256);
{
  let poly = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = poly;
    LOG[poly] = i;
    poly = poly << 1 ^ poly;
    if (poly & 256) poly ^= 283;
  }
}
function interpolate(shares, x) {
  const xs = shares.map((s) => s[0]);
  assert.equal(new Set(xs).size, shares.length, "Duplicate share index");
  const lengths = new Set(shares.map((s) => s[1].length));
  assert.equal(lengths.size, 1, "Shares have inconsistent lengths");
  const direct = shares.find((s) => s[0] === x);
  if (direct) return Buffer.from(direct[1]);
  let logProd = 0;
  for (const [xi] of shares) logProd += LOG[xi ^ x];
  const result = Buffer.alloc(lengths.values().next().value);
  for (const [xi, yi] of shares) {
    let sum = 0;
    for (const xj of xs) sum += LOG[xi ^ xj];
    const basis = ((logProd - LOG[xi ^ x] - sum) % 255 + 255) % 255;
    for (let k = 0; k < result.length; k += 1) {
      const v = yi[k];
      result[k] ^= v === 0 ? 0 : EXP[(LOG[v] + basis) % 255];
    }
  }
  return result;
}
function createDigest(randomData, sharedSecret) {
  return createHmac("sha256", randomData).update(sharedSecret).digest().subarray(0, DIGEST_LENGTH_BYTES);
}
function splitSecret(threshold, shareCount, sharedSecret, rng) {
  assert.ok(threshold >= 1, "Threshold must be a positive integer");
  assert.ok(threshold <= shareCount, "Threshold exceeds the number of shares");
  assert.ok(shareCount <= MAX_SHARE_COUNT, `At most ${MAX_SHARE_COUNT} shares`);
  if (threshold === 1) {
    return Array.from({ length: shareCount }, (_, i) => [i, Buffer.from(sharedSecret)]);
  }
  const randomShareCount = threshold - 2;
  const shares = [];
  for (let i = 0; i < randomShareCount; i += 1) {
    shares.push([i, rng(sharedSecret.length)]);
  }
  const randomPart = rng(sharedSecret.length - DIGEST_LENGTH_BYTES);
  const digest = createDigest(randomPart, sharedSecret);
  const base = [
    ...shares,
    [DIGEST_INDEX, Buffer.concat([digest, randomPart])],
    [SECRET_INDEX, Buffer.from(sharedSecret)]
  ];
  for (let i = randomShareCount; i < shareCount; i += 1) {
    shares.push([i, interpolate(base, i)]);
  }
  return shares;
}
function recoverSecret(threshold, shares) {
  if (threshold === 1) return Buffer.from(shares[0][1]);
  const sharedSecret = interpolate(shares, SECRET_INDEX);
  const digestShare = interpolate(shares, DIGEST_INDEX);
  const digest = digestShare.subarray(0, DIGEST_LENGTH_BYTES);
  const randomPart = digestShare.subarray(DIGEST_LENGTH_BYTES);
  assert.ok(
    digest.equals(createDigest(randomPart, sharedSecret)),
    "Invalid digest of the shared secret: the shares do not belong together, or one of them was transcribed incorrectly"
  );
  return sharedSecret;
}
function getSalt(identifier, extendable) {
  if (extendable) return Buffer.alloc(0);
  const id = Buffer.alloc(2);
  id.writeUInt16BE(identifier, 0);
  return Buffer.concat([CUSTOMIZATION_STRING_ORIG, id]);
}
function roundFunction(i, passphrase, e, salt, r) {
  return pbkdf2Sync(
    Buffer.concat([Buffer.from([i]), passphrase]),
    Buffer.concat([salt, r]),
    (BASE_ITERATION_COUNT << e) / ROUND_COUNT,
    r.length,
    "sha256"
  );
}
function xorBytes(a, b) {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = a[i] ^ b[i];
  return out;
}
function feistel(secret, passphrase, e, identifier, extendable, reverse) {
  const half = secret.length / 2;
  let l = Buffer.from(secret.subarray(0, half));
  let r = Buffer.from(secret.subarray(half));
  const salt = getSalt(identifier, extendable);
  const order = [0, 1, 2, 3];
  if (reverse) order.reverse();
  for (const i of order) {
    const next = xorBytes(l, roundFunction(i, passphrase, e, salt, r));
    l = r;
    r = next;
  }
  return Buffer.concat([r, l]);
}
var encryptSecret = (s, p, e, id, ext) => feistel(s, p, e, id, ext, false);
var decryptSecret = (s, p, e, id, ext) => feistel(s, p, e, id, ext, true);
function encodePassphrase(passphrase) {
  const s = passphrase ?? "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    assert.ok(
      c >= 32 && c <= 126,
      "SLIP-39 passphrases must be printable ASCII (code points 32-126)"
    );
  }
  return Buffer.from(s, "utf8");
}
var RS1024_GEN = [
  14737472,
  29474944,
  58949888,
  117899776,
  235798537,
  470557714,
  940076068,
  814808136,
  565311632,
  66318624
];
function rs1024Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 20;
    chk = ((chk & 1048575) << 10 ^ v) >>> 0;
    for (let i = 0; i < 10; i += 1) {
      if (b >>> i & 1) chk = (chk ^ RS1024_GEN[i]) >>> 0;
    }
  }
  return chk >>> 0;
}
var customization = (extendable) => Array.from(extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG);
function rs1024CreateChecksum(data, extendable) {
  const values = [...customization(extendable), ...data, 0, 0, 0];
  const polymod = rs1024Polymod(values) ^ 1;
  const out = [];
  for (let i = CHECKSUM_LENGTH_WORDS - 1; i >= 0; i -= 1) {
    out.push(polymod >>> 10 * i & 1023);
  }
  return out;
}
var rs1024Verify = (data, extendable) => rs1024Polymod([...customization(extendable), ...data]) === 1;
var bitsToWords = (bits) => Math.ceil(bits / RADIX_BITS);
function encodeShare(share) {
  assert.ok(Number.isInteger(share.identifier) && share.identifier >= 0 && share.identifier < 2 ** ID_LENGTH_BITS, "identifier out of range");
  assert.ok(
    Number.isInteger(share.iterationExponent) && share.iterationExponent >= 0 && share.iterationExponent < 2 ** ITERATION_EXP_LENGTH_BITS,
    "iteration exponent out of range"
  );
  assert.ok(Number.isInteger(share.groupCount) && share.groupCount >= 1 && share.groupCount <= MAX_SHARE_COUNT, "group count out of range");
  assert.ok(Number.isInteger(share.groupIndex) && share.groupIndex >= 0 && share.groupIndex < share.groupCount, "group index must be below group count");
  assert.ok(Number.isInteger(share.groupThreshold) && share.groupThreshold >= 1 && share.groupThreshold <= share.groupCount, "group threshold out of range");
  assert.ok(Number.isInteger(share.memberIndex) && share.memberIndex >= 0 && share.memberIndex < MAX_SHARE_COUNT, "member index out of range");
  assert.ok(Number.isInteger(share.memberThreshold) && share.memberThreshold >= 1 && share.memberThreshold <= MAX_SHARE_COUNT, "member threshold out of range");
  assert.ok(
    Buffer.isBuffer(share.value) || share.value instanceof Uint8Array,
    "share value must be bytes"
  );
  assert.ok(
    share.value.length >= MIN_STRENGTH_BITS / 8 && share.value.length % 2 === 0,
    "share value must have a valid even byte length"
  );
  const valueWordCount = bitsToWords(share.value.length * 8);
  let acc = 0n;
  const push = (v, bits) => {
    acc = acc << BigInt(bits) | BigInt(v);
  };
  push(share.identifier, ID_LENGTH_BITS);
  push(share.extendable ? 1 : 0, EXTENDABLE_FLAG_LENGTH_BITS);
  push(share.iterationExponent, ITERATION_EXP_LENGTH_BITS);
  push(share.groupIndex, 4);
  push(share.groupThreshold - 1, 4);
  push(share.groupCount - 1, 4);
  push(share.memberIndex, 4);
  push(share.memberThreshold - 1, 4);
  acc = acc << BigInt(valueWordCount * RADIX_BITS) | BigInt(`0x${Buffer.from(share.value).toString("hex")}`);
  const total = ID_EXP_LENGTH_WORDS + 2 + valueWordCount;
  const data = [];
  for (let i = total - 1; i >= 0; i -= 1) {
    data.push(Number(acc >> BigInt(10 * i) & 1023n));
  }
  return [...data, ...rs1024CreateChecksum(data, share.extendable)].map((i) => SLIP39_WORDLIST[i]).join(" ");
}
function decodeShare(mnemonic) {
  assert.equal(typeof mnemonic, "string", "SLIP-39 mnemonic must be a primitive string");
  const words = mnemonic.toLowerCase().trim().split(/\s+/).filter(Boolean);
  assert.ok(
    words.length >= METADATA_LENGTH_WORDS + bitsToWords(MIN_STRENGTH_BITS),
    `A SLIP-39 share has at least ${METADATA_LENGTH_WORDS + bitsToWords(MIN_STRENGTH_BITS)} words; got ${words.length}`
  );
  const indexes = words.map((w) => {
    const i = WORD_INDEX.get(w);
    assert.ok(i !== void 0, `"${w}" is not a SLIP-39 word`);
    return i;
  });
  const extendable = Boolean((indexes[0] << 10 | indexes[1]) >>> 4 & 1);
  assert.ok(
    rs1024Verify(indexes, extendable),
    "Invalid SLIP-39 checksum: a word is wrong or out of order"
  );
  const data = indexes.slice(0, indexes.length - CHECKSUM_LENGTH_WORDS);
  const valueWordCount = data.length - ID_EXP_LENGTH_WORDS - 2;
  const paddingBits = RADIX_BITS * valueWordCount % 16;
  assert.ok(paddingBits <= 8, "Invalid SLIP-39 share length");
  let acc = 0n;
  for (const w of data) acc = acc << 10n | BigInt(w);
  const valueBits = BigInt(valueWordCount * RADIX_BITS);
  const valueInt = acc & (1n << valueBits) - 1n;
  acc >>= valueBits;
  const pull = (bits) => {
    const mask = (1n << BigInt(bits)) - 1n;
    const v = Number(acc & mask);
    acc >>= BigInt(bits);
    return v;
  };
  const memberThreshold = pull(4) + 1;
  const memberIndex = pull(4);
  const groupCount = pull(4) + 1;
  const groupThreshold = pull(4) + 1;
  const groupIndex = pull(4);
  const iterationExponent = pull(ITERATION_EXP_LENGTH_BITS);
  pull(EXTENDABLE_FLAG_LENGTH_BITS);
  const identifier = pull(ID_LENGTH_BITS);
  assert.ok(
    valueInt >> valueBits - BigInt(paddingBits) === 0n || paddingBits === 0,
    "Invalid SLIP-39 padding"
  );
  const valueBytes = Number(valueBits - BigInt(paddingBits)) / 8;
  const value = Buffer.from(
    valueInt.toString(16).padStart(valueBytes * 2, "0").slice(-valueBytes * 2),
    "hex"
  );
  assert.ok(
    groupCount >= groupThreshold,
    "Invalid SLIP-39 share: group threshold exceeds group count"
  );
  assert.ok(
    groupIndex < groupCount,
    "Invalid SLIP-39 share: group index is outside the declared group count"
  );
  return {
    identifier,
    extendable,
    iterationExponent,
    groupIndex,
    groupThreshold,
    groupCount,
    memberIndex,
    memberThreshold,
    value
  };
}
function splitSecretIntoShares({
  secret,
  passphrase = "",
  groupThreshold = 1,
  groups,
  extendable = true,
  iterationExponent = 1,
  identifier,
  rng = randomBytes3
}) {
  assert.ok(
    secret.length >= MIN_STRENGTH_BITS / 8 && secret.length % 2 === 0,
    `The secret must be at least ${MIN_STRENGTH_BITS / 8} bytes and even in length`
  );
  assert.ok(Array.isArray(groups) && groups.length >= 1, "At least one group required");
  assert.ok(groups.length <= MAX_SHARE_COUNT, `At most ${MAX_SHARE_COUNT} groups`);
  assert.ok(
    Number.isInteger(groupThreshold) && groupThreshold >= 1 && groupThreshold <= groups.length,
    "Group threshold must be between 1 and the number of groups"
  );
  for (const g of groups) {
    assert.ok(
      Number.isInteger(g.threshold) && Number.isInteger(g.count) && g.threshold >= 1 && g.threshold <= g.count && g.count <= MAX_SHARE_COUNT,
      `Invalid group ${JSON.stringify(g)}`
    );
    assert.ok(
      !(g.threshold === 1 && g.count > 1),
      "A group with threshold 1 must contain exactly one share: every share would otherwise be a full copy of the group secret"
    );
  }
  const id = identifier ?? rng(2).readUInt16BE(0) & (1 << ID_LENGTH_BITS) - 1;
  const pass = encodePassphrase(passphrase);
  const encrypted = encryptSecret(secret, pass, iterationExponent, id, extendable);
  const groupShares = splitSecret(groupThreshold, groups.length, encrypted, rng);
  return groupShares.map(([groupIndex, groupSecret], gi) => {
    const { threshold, count } = groups[gi];
    return splitSecret(threshold, count, groupSecret, rng).map(
      ([memberIndex, value]) => encodeShare({
        identifier: id,
        extendable,
        iterationExponent,
        groupIndex,
        groupThreshold,
        groupCount: groups.length,
        memberIndex,
        memberThreshold: threshold,
        value
      })
    );
  });
}
function combineShares(mnemonics, passphrase = "") {
  assert.ok(
    Array.isArray(mnemonics) && mnemonics.length > 0,
    "At least one SLIP-39 share is required"
  );
  const shares = mnemonics.map(decodeShare);
  const first = shares[0];
  for (const s of shares) {
    assert.ok(
      s.identifier === first.identifier && s.extendable === first.extendable && s.iterationExponent === first.iterationExponent && s.groupThreshold === first.groupThreshold && s.groupCount === first.groupCount,
      "These shares belong to different SLIP-39 backups"
    );
  }
  const byGroup = /* @__PURE__ */ new Map();
  for (const s of shares) {
    if (!byGroup.has(s.groupIndex)) byGroup.set(s.groupIndex, []);
    byGroup.get(s.groupIndex).push(s);
  }
  assert.equal(
    byGroup.size,
    first.groupThreshold,
    `Wrong number of groups: expected exactly ${first.groupThreshold}, got ${byGroup.size}`
  );
  const groupSecrets = [];
  for (const [groupIndex, members] of byGroup) {
    const t = members[0].memberThreshold;
    for (const m of members) {
      assert.equal(
        m.memberThreshold,
        t,
        "Shares in one group disagree about the member threshold"
      );
    }
    assert.equal(
      new Set(members.map((m) => m.memberIndex)).size,
      members.length,
      "Duplicate share within a group"
    );
    assert.equal(
      members.length,
      t,
      `Wrong number of shares in group ${groupIndex}: expected exactly ${t}, got ${members.length}`
    );
    assert.equal(
      new Set(members.map((m) => m.value.length)).size,
      1,
      "Shares in one group have inconsistent lengths"
    );
    groupSecrets.push([
      groupIndex,
      recoverSecret(t, members.map((m) => [m.memberIndex, m.value]))
    ]);
  }
  const encrypted = recoverSecret(first.groupThreshold, groupSecrets);
  assert.ok(
    encrypted.length >= MIN_STRENGTH_BITS / 8 && encrypted.length % 2 === 0,
    "Recovered secret has an invalid length"
  );
  return decryptSecret(
    encrypted,
    encodePassphrase(passphrase),
    first.iterationExponent,
    first.identifier,
    first.extendable
  );
}
function chooseBig(n, k) {
  if (k < 0 || k > n) return 0n;
  k = Math.min(k, n - k);
  let r = 1n;
  for (let i = 1; i <= k; i += 1) {
    r = r * BigInt(n - k + i) / BigInt(i);
  }
  return r;
}
function combinationsOfIndexes(n, k) {
  const out = [];
  const visit = (start, chosen) => {
    if (chosen.length === k) {
      out.push(chosen);
      return;
    }
    for (let i = start; i <= n - (k - chosen.length); i += 1) {
      visit(i + 1, [...chosen, i]);
    }
  };
  visit(0, []);
  return out;
}
function countAdmissibleSubsetsExact(groupThreshold, groups) {
  assert.ok(
    Array.isArray(groups) && groups.length >= 1 && groups.length <= MAX_SHARE_COUNT,
    "invalid group list"
  );
  assert.ok(Number.isInteger(groupThreshold) && groupThreshold >= 1 && groupThreshold <= groups.length, "invalid group threshold");
  for (const group of groups) {
    assert.ok(Number.isInteger(group.count) && Number.isInteger(group.threshold) && group.threshold >= 1 && group.threshold <= group.count && group.count <= MAX_SHARE_COUNT, "invalid group layout");
  }
  let total = 0n;
  for (const chosen of combinationsOfIndexes(groups.length, groupThreshold)) {
    let product = 1n;
    for (const gi of chosen) {
      product *= chooseBig(groups[gi].count, groups[gi].threshold);
    }
    total += product;
  }
  return total;
}
function unrankCombination(items, k, rank) {
  const out = [];
  let start = 0;
  for (let left = k; left > 0; left -= 1) {
    for (let i = start; i <= items.length - left; i += 1) {
      const block = chooseBig(items.length - i - 1, left - 1);
      if (rank < block) {
        out.push(items[i]);
        start = i + 1;
        break;
      }
      rank -= block;
    }
  }
  return out;
}
function admissibleSubsetAtRank(groupThreshold, groups, mnemonics, rank) {
  const total = countAdmissibleSubsetsExact(groupThreshold, groups);
  assert.ok(
    typeof rank === "bigint" && rank >= 0n && rank < total,
    "admissible subset rank out of range"
  );
  const groupSets = combinationsOfIndexes(groups.length, groupThreshold);
  let chosenGroups;
  for (const candidate of groupSets) {
    const weight = candidate.reduce((product, gi) => product * chooseBig(groups[gi].count, groups[gi].threshold), 1n);
    if (rank < weight) {
      chosenGroups = candidate;
      break;
    }
    rank -= weight;
  }
  assert.ok(chosenGroups, "internal admissible subset unranking failure");
  const subset = [];
  for (const gi of chosenGroups) {
    const count = chooseBig(groups[gi].count, groups[gi].threshold);
    const memberRank = rank % count;
    rank /= count;
    subset.push(...unrankCombination(mnemonics[gi], groups[gi].threshold, memberRank));
  }
  return subset;
}
function randomBigIntBelow(limit, rng) {
  assert.ok(limit > 0n);
  const bits = limit.toString(2).length;
  const bytes = Math.ceil(bits / 8);
  const mask = (1n << BigInt(bits)) - 1n;
  for (; ; ) {
    const candidate = BigInt(`0x${Buffer.from(rng(bytes)).toString("hex") || "0"}`) & mask;
    if (candidate < limit) return candidate;
  }
}
function randomAdmissibleRank(total, rng) {
  assert.ok(typeof total === "bigint" && total > 0n, "total must be a positive bigint");
  return randomBigIntBelow(total, rng);
}
function admissibleSubsets(groupThreshold, groups, mnemonics) {
  const chooseK = (arr, k) => {
    if (k === 0) return [[]];
    if (arr.length < k) return [];
    const [head, ...rest] = arr;
    return [
      ...chooseK(rest, k - 1).map((c) => [head, ...c]),
      ...chooseK(rest, k)
    ];
  };
  const groupChoices = chooseK(
    groups.map((_, i) => i),
    groupThreshold
  );
  const out = [];
  for (const chosenGroups of groupChoices) {
    let combos = [[]];
    for (const gi of chosenGroups) {
      const next = [];
      for (const memberSet of chooseK(mnemonics[gi], groups[gi].threshold)) {
        for (const prefix of combos) next.push([...prefix, ...memberSet]);
      }
      combos = next;
    }
    out.push(...combos);
  }
  return out;
}
var ROUND_TRIP_SCENARIOS = [
  { name: "1-of-1", groupThreshold: 1, groups: [{ threshold: 1, count: 1 }] },
  { name: "2-of-3", groupThreshold: 1, groups: [{ threshold: 2, count: 3 }] },
  { name: "3-of-5", groupThreshold: 1, groups: [{ threshold: 3, count: 5 }] },
  {
    name: "2 of 3 groups, 2-of-3 each",
    groupThreshold: 2,
    groups: [
      { threshold: 2, count: 3 },
      { threshold: 2, count: 3 },
      { threshold: 2, count: 3 }
    ]
  },
  {
    name: "mixed thresholds",
    groupThreshold: 2,
    groups: [
      { threshold: 1, count: 1 },
      { threshold: 3, count: 4 },
      { threshold: 2, count: 2 }
    ]
  }
];
var equalBytesLocal = (a, b) => Buffer.from(a).equals(Buffer.from(b));
function slip39SelfTest({ vectors, fixtures, log = () => {
}, rng = randomBytes3 }) {
  assertSlip39WordlistIntegrity();
  log("SLIP-39 wordlist matches the published SHA-256");
  const gfMul2 = (a, b) => a === 0 || b === 0 ? 0 : EXP[(LOG[a] + LOG[b]) % 255];
  assert.equal(gfMul2(3, 7), 9, "GF(256) multiplication is wrong");
  assert.equal(gfMul2(87, 131), 193, "GF(256) multiplication is wrong");
  assert.equal(new Set(EXP).size, 255, "GF(256) generator is not primitive");
  log("GF(256) arithmetic matches published values");
  let valid = 0;
  let rejected = 0;
  for (const [description, mnemonics, secretHex] of vectors) {
    const mustFail = !secretHex;
    let got = null;
    try {
      got = combineShares(mnemonics, "TREZOR").toString("hex");
    } catch {
      assert.ok(mustFail, `SLIP-39 vector rejected but should be valid: ${description}`);
      rejected += 1;
      continue;
    }
    assert.ok(!mustFail, `SLIP-39 vector accepted but must be rejected: ${description}`);
    assert.equal(got, secretHex, `SLIP-39 vector mismatch: ${description}`);
    valid += 1;
  }
  assert.equal(valid + rejected, vectors.length);
  assert.ok(valid > 0 && rejected > 0, "Vector file lost its positive or negative cases");
  log(`${vectors.length} official SLIP-39 vectors (${valid} decoded, ${rejected} rejected)`);
  let reencoded = 0;
  let extendableSeen = 0;
  for (const [, mnemonics] of vectors) {
    for (const mnemonic of mnemonics) {
      let share;
      try {
        share = decodeShare(mnemonic);
      } catch {
        continue;
      }
      assert.equal(
        encodeShare(share),
        mnemonic.toLowerCase().trim().split(/\s+/).join(" "),
        "encodeShare does not reproduce a reference share byte for byte"
      );
      if (share.extendable) extendableSeen += 1;
      reencoded += 1;
    }
  }
  assert.ok(reencoded > 0, "no shares were re-encoded");
  assert.ok(extendableSeen > 0, "no extendable share exercised the encode path");
  log(
    `${reencoded} reference shares re-encoded byte-identically (${extendableSeen} extendable)`
  );
  if (fixtures) {
    for (const pin of fixtures.fieldPins ?? []) {
      const share = { ...pin.fields, value: Buffer.from(pin.valueHex, "hex") };
      assert.equal(encodeShare(share), pin.mnemonic, `field pin "${pin.name}" changed`);
      const back = decodeShare(pin.mnemonic);
      for (const [key, expected] of Object.entries(pin.fields)) {
        assert.equal(back[key], expected, `field pin "${pin.name}": ${key} round-trip`);
      }
      assert.ok(back.value.equals(share.value), `field pin "${pin.name}": value round-trip`);
    }
    if (fixtures.fieldPins?.length) {
      log(`${fixtures.fieldPins.length} field pins at every packed-field extreme`);
    }
    const secret = Buffer.from(fixtures.secret, "hex");
    for (const f of fixtures.fixtures) {
      const makeRng = (seed) => {
        let counter = 0;
        return (n) => {
          const out = Buffer.alloc(n);
          for (let off = 0; off < n; off += 32) {
            const ctr = Buffer.alloc(4);
            ctr.writeUInt32BE(counter, 0);
            counter += 1;
            createHash("sha256").update(Buffer.from(seed)).update(ctr).digest().copy(out, off);
          }
          return out;
        };
      };
      const flat = splitSecretIntoShares({
        secret,
        groupThreshold: f.groupThreshold,
        groups: f.groups,
        extendable: f.extendable,
        iterationExponent: f.iterationExponent,
        identifier: f.identifier,
        // NOTE: this seed string still says "evm-seed-tool" on purpose. It is not
        // a brand string - it is the provenance anchor of these fixtures. Their
        // expected shares were produced with this exact seed and then verified
        // against the reference python-shamir-mnemonic, which recovered the secret
        // and agreed on every field. Renaming it would regenerate the expectations
        // from THIS implementation, turning externally-verified vectors into
        // self-referential ones - the exact failure mode that let the GF(256)
        // doubling bug survive until the official Trezor vectors caught it.
        // A rebrand is not a reason to give that up.
        rng: makeRng(`evm-seed-tool/slip39-fixture/${f.name}`)
      }).flat();
      assert.equal(flat.length, f.shareCount, `fixture "${f.name}": share count changed`);
      assert.equal(flat[0], f.firstShare, `fixture "${f.name}": first share changed`);
      assert.equal(flat[flat.length - 1], f.lastShare, `fixture "${f.name}": last share changed`);
      assert.equal(
        createHash("sha256").update(flat.join("\n")).digest("hex"),
        f.sha256,
        `fixture "${f.name}": encoded shares changed`
      );
    }
    const shares = fixtures.fixtures.reduce((a, f) => a + f.shareCount, 0);
    log(`${fixtures.fixtures.length} deterministic fixtures (${shares} shares) byte-identical`);
  }
  let subsetCount = 0;
  for (const bytes of [16, 32]) {
    const secret = rng(bytes);
    for (const scenario of ROUND_TRIP_SCENARIOS) {
      for (const extendable of [true, false]) {
        const shares = splitSecretIntoShares({
          secret,
          groupThreshold: scenario.groupThreshold,
          groups: scenario.groups,
          extendable,
          iterationExponent: 0,
          rng
        });
        for (const subset of admissibleSubsets(
          scenario.groupThreshold,
          scenario.groups,
          shares
        )) {
          assert.ok(
            combineShares(subset, "").equals(secret),
            `SLIP-39 round-trip failed: ${scenario.name}, ${bytes} bytes`
          );
          subsetCount += 1;
        }
      }
    }
  }
  log(`exhaustive round-trip: ${subsetCount} admissible share subsets all recovered`);
  assert.throws(
    () => splitSecretIntoShares({ secret: Buffer.alloc(8), groups: [{ threshold: 1, count: 1 }] }),
    /at least/,
    "accepted a secret below the minimum strength"
  );
  assert.throws(
    () => splitSecretIntoShares({ secret: Buffer.alloc(32), groups: [{ threshold: 1, count: 3 }] }),
    /threshold 1/,
    "allowed MEMBER threshold 1 with multiple shares"
  );
  {
    const secret = rng(32);
    const groups = [{ threshold: 2, count: 3 }, { threshold: 3, count: 5 }];
    const shares = splitSecretIntoShares({ secret, groupThreshold: 1, groups, rng });
    assert.ok(equalBytesLocal(combineShares(shares[0].slice(0, 2), ""), secret));
    assert.ok(equalBytesLocal(combineShares(shares[1].slice(0, 3), ""), secret));
  }
  assert.throws(
    () => combineShares(["not a share"]),
    /at least|not a SLIP-39 word/,
    "accepted a non-share"
  );
  log("SLIP-39 negative tests: length, threshold-1 and garbage input all rejected");
}

// slip39-vectors.json
var slip39_vectors_default = [
  [
    "1. Valid mnemonic without sharing (128 bits)",
    [
      "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"
    ],
    "bb54aac4b89dc868ba37d9cc21b2cece",
    "xprv9s21ZrQH143K4QViKpwKCpS2zVbz8GrZgpEchMDg6KME9HZtjfL7iThE9w5muQA4YPHKN1u5VM1w8D4pvnjxa2BmpGMfXr7hnRrRHZ93awZ"
  ],
  [
    "2. Mnemonic with invalid checksum (128 bits)",
    [
      "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
    ],
    "",
    ""
  ],
  [
    "3. Mnemonic with invalid padding (128 bits)",
    [
      "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
    ],
    "",
    ""
  ],
  [
    "4. Basic sharing 2-of-3 (128 bits)",
    [
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
      "shadow pistol academic acid actress prayer class unknown daughter sweater depict flip twice unkind craft early superior advocate guest smoking"
    ],
    "b43ceb7e57a0ea8766221624d01b0864",
    "xprv9s21ZrQH143K2nNuAbfWPHBtfiSCS14XQgb3otW4pX655q58EEZeC8zmjEUwucBu9dPnxdpbZLCn57yx45RBkwJHnwHFjZK4XPJ8SyeYjYg"
  ],
  [
    "5. Basic sharing 2-of-3 (128 bits)",
    [
      "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed"
    ],
    "",
    ""
  ],
  [
    "6. Mnemonics with different identifiers (128 bits)",
    [
      "adequate smoking academic acid debut wine petition glen cluster slow rhyme slow simple epidemic rumor junk tracks treat olympic tolerate",
      "adequate stay academic agency agency formal party ting frequent learn upstairs remember smear leaf damage anatomy ladle market hush corner"
    ],
    "",
    ""
  ],
  [
    "7. Mnemonics with different iteration exponents (128 bits)",
    [
      "peasant leaves academic acid desert exact olympic math alive axle trial tackle drug deny decent smear dominant desert bucket remind",
      "peasant leader academic agency cultural blessing percent network envelope medal junk primary human pumps jacket fragment payroll ticket evoke voice"
    ],
    "",
    ""
  ],
  [
    "8. Mnemonics with mismatching group thresholds (128 bits)",
    [
      "liberty category beard echo animal fawn temple briefing math username various wolf aviation fancy visual holy thunder yelp helpful payment",
      "liberty category beard email beyond should fancy romp founder easel pink holy hairy romp loyalty material victim owner toxic custody",
      "liberty category academic easy being hazard crush diminish oral lizard reaction cluster force dilemma deploy force club veteran expect photo"
    ],
    "",
    ""
  ],
  [
    "9. Mnemonics with mismatching group counts (128 bits)",
    [
      "average senior academic leaf broken teacher expect surface hour capture obesity desire negative dynamic dominant pistol mineral mailman iris aide",
      "average senior academic agency curious pants blimp spew clothes slice script dress wrap firm shaft regular slavery negative theater roster"
    ],
    "",
    ""
  ],
  [
    "10. Mnemonics with greater group threshold than group counts (128 bits)",
    [
      "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
      "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
      "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce"
    ],
    "",
    ""
  ],
  [
    "11. Mnemonics with duplicate member indices (128 bits)",
    [
      "device stay academic always dive coal antenna adult black exceed stadium herald advance soldier busy dryer daughter evaluate minister laser",
      "device stay academic always dwarf afraid robin gravity crunch adjust soul branch walnut coastal dream costume scholar mortgage mountain pumps"
    ],
    "",
    ""
  ],
  [
    "12. Mnemonics with mismatching member thresholds (128 bits)",
    [
      "hour painting academic academic device formal evoke guitar random modern justice filter withdraw trouble identify mailman insect general cover oven",
      "hour painting academic agency artist again daisy capital beaver fiber much enjoy suitable symbolic identify photo editor romp float echo"
    ],
    "",
    ""
  ],
  [
    "13. Mnemonics giving an invalid digest (128 bits)",
    [
      "guilt walnut academic acid deliver remove equip listen vampire tactics nylon rhythm failure husband fatigue alive blind enemy teaspoon rebound",
      "guilt walnut academic agency brave hamster hobo declare herd taste alpha slim criminal mild arcade formal romp branch pink ambition"
    ],
    "",
    ""
  ],
  [
    "14. Insufficient number of groups (128 bits, case 1)",
    [
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"
    ],
    "",
    ""
  ],
  [
    "15. Insufficient number of groups (128 bits, case 2)",
    [
      "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join",
      "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter"
    ],
    "",
    ""
  ],
  [
    "16. Threshold number of groups, but insufficient number of members in one group (128 bits)",
    [
      "eraser senior decision shadow artist work morning estate greatest pipeline plan ting petition forget hormone flexible general goat admit surface",
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice"
    ],
    "",
    ""
  ],
  [
    "17. Threshold number of groups and members in each group (128 bits, case 1)",
    [
      "eraser senior decision roster beard treat identify grumpy salt index fake aviation theater cubic bike cause research dragon emphasis counter",
      "eraser senior ceramic snake clay various huge numb argue hesitate auction category timber browser greatest hanger petition script leaf pickup",
      "eraser senior ceramic shaft dynamic become junior wrist silver peasant force math alto coal amazing segment yelp velvet image paces",
      "eraser senior ceramic round column hawk trust auction smug shame alive greatest sheriff living perfect corner chest sled fumes adequate",
      "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing"
    ],
    "7c3397a292a5941682d7a4ae2d898d11",
    "xprv9s21ZrQH143K3dzDLfeY3cMp23u5vDeFYftu5RPYZPucKc99mNEddU4w99GxdgUGcSfMpVDxhnR1XpJzZNXRN1m6xNgnzFS5MwMP6QyBRKV"
  ],
  [
    "18. Threshold number of groups and members in each group (128 bits, case 2)",
    [
      "eraser senior decision smug corner ruin rescue cubic angel tackle skin skunk program roster trash rumor slush angel flea amazing",
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      "eraser senior decision scared cargo theory device idea deliver modify curly include pancake both news skin realize vitamins away join"
    ],
    "7c3397a292a5941682d7a4ae2d898d11",
    "xprv9s21ZrQH143K3dzDLfeY3cMp23u5vDeFYftu5RPYZPucKc99mNEddU4w99GxdgUGcSfMpVDxhnR1XpJzZNXRN1m6xNgnzFS5MwMP6QyBRKV"
  ],
  [
    "19. Threshold number of groups and members in each group (128 bits, case 3)",
    [
      "eraser senior beard romp adorn nuclear spill corner cradle style ancient family general leader ambition exchange unusual garlic promise voice",
      "eraser senior acrobat romp bishop medical gesture pumps secret alive ultimate quarter priest subject class dictate spew material endless market"
    ],
    "7c3397a292a5941682d7a4ae2d898d11",
    "xprv9s21ZrQH143K3dzDLfeY3cMp23u5vDeFYftu5RPYZPucKc99mNEddU4w99GxdgUGcSfMpVDxhnR1XpJzZNXRN1m6xNgnzFS5MwMP6QyBRKV"
  ],
  [
    "20. Valid mnemonic without sharing (256 bits)",
    [
      "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck"
    ],
    "989baf9dcaad5b10ca33dfd8cc75e42477025dce88ae83e75a230086a0e00e92",
    "xprv9s21ZrQH143K41mrxxMT2FpiheQ9MFNmWVK4tvX2s28KLZAhuXWskJCKVRQprq9TnjzzzEYePpt764csiCxTt22xwGPiRmUjYUUdjaut8RM"
  ],
  [
    "21. Mnemonic with invalid checksum (256 bits)",
    [
      "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar"
    ],
    "",
    ""
  ],
  [
    "22. Mnemonic with invalid padding (256 bits)",
    [
      "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister"
    ],
    "",
    ""
  ],
  [
    "23. Basic sharing 2-of-3 (256 bits)",
    [
      "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap",
      "humidity disease academic agency actress jacket gross physics cylinder solution fake mortgage benefit public busy prepare sharp friar change work slow purchase ruler again tricycle involve viral wireless mixture anatomy desert cargo upgrade"
    ],
    "c938b319067687e990e05e0da0ecce1278f75ff58d9853f19dcaeed5de104aae",
    "xprv9s21ZrQH143K3a4GRMgK8WnawupkwkP6gyHxRsXnMsYPTPH21fWwNcAytijtfyftqNfiaY8LgQVdBQvHZ9FBvtwdjC7LCYxjYruJFuLzyMQ"
  ],
  [
    "24. Basic sharing 2-of-3 (256 bits)",
    [
      "humidity disease academic always aluminum jewelry energy woman receiver strategy amuse duckling lying evidence network walnut tactics forget hairy rebound impulse brother survive clothes stadium mailman rival ocean reward venture always armed unwrap"
    ],
    "",
    ""
  ],
  [
    "25. Mnemonics with different identifiers (256 bits)",
    [
      "smear husband academic acid deadline scene venture distance dive overall parking bracelet elevator justice echo burning oven chest duke nylon",
      "smear isolate academic agency alpha mandate decorate burden recover guard exercise fatal force syndrome fumes thank guest drift dramatic mule"
    ],
    "",
    ""
  ],
  [
    "26. Mnemonics with different iteration exponents (256 bits)",
    [
      "finger trash academic acid average priority dish revenue academic hospital spirit western ocean fact calcium syndrome greatest plan losing dictate",
      "finger traffic academic agency building lilac deny paces subject threaten diploma eclipse window unknown health slim piece dragon focus smirk"
    ],
    "",
    ""
  ],
  [
    "27. Mnemonics with mismatching group thresholds (256 bits)",
    [
      "flavor pink beard echo depart forbid retreat become frost helpful juice unwrap reunion credit math burning spine black capital lair",
      "flavor pink beard email diet teaspoon freshman identify document rebound cricket prune headset loyalty smell emission skin often square rebound",
      "flavor pink academic easy credit cage raisin crazy closet lobe mobile become drink human tactics valuable hand capture sympathy finger"
    ],
    "",
    ""
  ],
  [
    "28. Mnemonics with mismatching group counts (256 bits)",
    [
      "column flea academic leaf debut extra surface slow timber husky lawsuit game behavior husky swimming already paper episode tricycle scroll",
      "column flea academic agency blessing garbage party software stadium verify silent umbrella therapy decorate chemical erode dramatic eclipse replace apart"
    ],
    "",
    ""
  ],
  [
    "29. Mnemonics with greater group threshold than group counts (256 bits)",
    [
      "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
      "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
      "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful"
    ],
    "",
    ""
  ],
  [
    "30. Mnemonics with duplicate member indices (256 bits)",
    [
      "fishing recover academic always device craft trend snapshot gums skin downtown watch device sniff hour clock public maximum garlic born",
      "fishing recover academic always aircraft view software cradle fangs amazing package plastic evaluate intend penalty epidemic anatomy quarter cage apart"
    ],
    "",
    ""
  ],
  [
    "31. Mnemonics with mismatching member thresholds (256 bits)",
    [
      "evoke garden academic academic answer wolf scandal modern warmth station devote emerald market physics surface formal amazing aquatic gesture medical",
      "evoke garden academic agency deal revenue knit reunion decrease magazine flexible company goat repair alarm military facility clogs aide mandate"
    ],
    "",
    ""
  ],
  [
    "32. Mnemonics giving an invalid digest (256 bits)",
    [
      "river deal academic acid average forbid pistol peanut custody bike class aunt hairy merit valid flexible learn ajar very easel",
      "river deal academic agency camera amuse lungs numb isolate display smear piece traffic worthy year patrol crush fact fancy emission"
    ],
    "",
    ""
  ],
  [
    "33. Insufficient number of groups (256 bits, case 1)",
    [
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"
    ],
    "",
    ""
  ],
  [
    "34. Insufficient number of groups (256 bits, case 2)",
    [
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install"
    ],
    "",
    ""
  ],
  [
    "35. Threshold number of groups, but insufficient number of members in one group (256 bits)",
    [
      "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club",
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium"
    ],
    "",
    ""
  ],
  [
    "36. Threshold number of groups and members in each group (256 bits, case 1)",
    [
      "wildlife deal ceramic round aluminum pitch goat racism employer miracle percent math decision episode dramatic editor lily prospect program scene rebuild display sympathy have single mustang junction relate often chemical society wits estate",
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal ceramic scatter argue equip vampire together ruin reject literary rival distance aquatic agency teammate rebound false argue miracle stay again blessing peaceful unknown cover beard acid island language debris industry idle",
      "wildlife deal ceramic snake agree voter main lecture axis kitchen physics arcade velvet spine idea scroll promise platform firm sharp patrol divorce ancestor fantasy forbid goat ajar believe swimming cowboy symbolic plastic spelling",
      "wildlife deal decision shadow analysis adjust bulb skunk muscle mandate obesity total guitar coal gravity carve slim jacket ruin rebuild ancestor numerous hour mortgage require herd maiden public ceiling pecan pickup shadow club"
    ],
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b",
    "xprv9s21ZrQH143K2UspC9FRPfQC9NcDB4HPkx1XG9UEtuceYtpcCZ6ypNZWdgfxQ9dAFVeD1F4Zg4roY7nZm2LB7THPD6kaCege3M7EuS8v85c"
  ],
  [
    "37. Threshold number of groups and members in each group (256 bits, case 2)",
    [
      "wildlife deal decision scared acne fatal snake paces obtain election dryer dominant romp tactics railroad marvel trust helpful flip peanut theory theater photo luck install entrance taxi step oven network dictate intimate listen",
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      "wildlife deal decision smug ancestor genuine move huge cubic strategy smell game costume extend swimming false desire fake traffic vegan senior twice timber submit leader payroll fraction apart exact forward pulse tidy install"
    ],
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b",
    "xprv9s21ZrQH143K2UspC9FRPfQC9NcDB4HPkx1XG9UEtuceYtpcCZ6ypNZWdgfxQ9dAFVeD1F4Zg4roY7nZm2LB7THPD6kaCege3M7EuS8v85c"
  ],
  [
    "38. Threshold number of groups and members in each group (256 bits, case 3)",
    [
      "wildlife deal beard romp alcohol space mild usual clothes union nuclear testify course research heat listen task location thank hospital slice smell failure fawn helpful priest ambition average recover lecture process dough stadium",
      "wildlife deal acrobat romp anxiety axis starting require metric flexible geology game drove editor edge screw helpful have huge holy making pitch unknown carve holiday numb glasses survive already tenant adapt goat fangs"
    ],
    "5385577c8cfc6c1a8aa0f7f10ecde0a3318493262591e78b8c14c6686167123b",
    "xprv9s21ZrQH143K2UspC9FRPfQC9NcDB4HPkx1XG9UEtuceYtpcCZ6ypNZWdgfxQ9dAFVeD1F4Zg4roY7nZm2LB7THPD6kaCege3M7EuS8v85c"
  ],
  [
    "39. Mnemonic with insufficient length",
    [
      "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder"
    ],
    "",
    ""
  ],
  [
    "40. Mnemonic with invalid master secret length",
    [
      "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter"
    ],
    "",
    ""
  ],
  [
    "41. Valid mnemonics which can detect some errors in modular arithmetic",
    [
      "herald flea academic cage avoid space trend estate dryer hairy evoke eyebrow improve airline artwork garlic premium duration prevent oven",
      "herald flea academic client blue skunk class goat luxury deny presence impulse graduate clay join blanket bulge survive dish necklace",
      "herald flea academic acne advance fused brother frozen broken game ranked ajar already believe check install theory angry exercise adult"
    ],
    "ad6f2ad8b59bbbaa01369b9006208d9a",
    "xprv9s21ZrQH143K2R4HJxcG1eUsudvHM753BZ9vaGkpYCoeEhCQx147C5qEcupPHxcXYfdYMwJmsKXrHDhtEwutxTTvFzdDCZVQwHneeQH8ioH"
  ],
  [
    "42. Valid extendable mnemonic without sharing (128 bits)",
    [
      "testify swimming academic academic column loyalty smear include exotic bedroom exotic wrist lobe cover grief golden smart junior estimate learn"
    ],
    "1679b4516e0ee5954351d288a838f45e",
    "xprv9s21ZrQH143K2w6eTpQnB73CU8Qrhg6gN3D66Jr16n5uorwoV7CwxQ5DofRPyok5DyRg4Q3BfHfCgJFk3boNRPPt1vEW1ENj2QckzVLQFXu"
  ],
  [
    "43. Extendable basic sharing 2-of-3 (128 bits)",
    [
      "enemy favorite academic acid cowboy phrase havoc level response walnut budget painting inside trash adjust froth kitchen learn tidy punish",
      "enemy favorite academic always academic sniff script carpet romp kind promise scatter center unfair training emphasis evening belong fake enforce"
    ],
    "48b1a4b80b8c209ad42c33672bdaa428",
    "xprv9s21ZrQH143K4FS1qQdXYAFVAHiSAnjj21YAKGh2CqUPJ2yQhMmYGT4e5a2tyGLiVsRgTEvajXkxhg92zJ8zmWZas9LguQWz7WZShfJg6RS"
  ],
  [
    "44. Valid extendable mnemonic without sharing (256 bits)",
    [
      "impulse calcium academic academic alcohol sugar lyrics pajamas column facility finance tension extend space birthday rainbow swimming purple syndrome facility trial warn duration snapshot shadow hormone rhyme public spine counter easy hawk album"
    ],
    "8340611602fe91af634a5f4608377b5235fa2d757c51d720c0c7656249a3035f",
    "xprv9s21ZrQH143K2yJ7S8bXMiGqp1fySH8RLeFQKQmqfmmLTRwWmAYkpUcWz6M42oGoFMJRENmvsGQmunWTdizsi8v8fku8gpbVvYSiCYJTF1Y"
  ],
  [
    "45. Extendable basic sharing 2-of-3 (256 bits)",
    [
      "western apart academic always artist resident briefing sugar woman oven coding club ajar merit pecan answer prisoner artist fraction amount desktop mild false necklace muscle photo wealthy alpha category unwrap spew losing making",
      "western apart academic acid answer ancient auction flip image penalty oasis beaver multiple thunder problem switch alive heat inherit superior teaspoon explain blanket pencil numb lend punish endless aunt garlic humidity kidney observe"
    ],
    "8dc652d6d6cd370d8c963141f6d79ba440300f25c467302c1d966bff8f62300d",
    "xprv9s21ZrQH143K2eFW2zmu3aayWWd6MJZBG7RebW35fiKcoCZ6jFi6U5gzffB9McDdiKTecUtRqJH9GzueCXiQK1LaQXdgthS8DgWfC8Uu3z7"
  ]
];

// slip39-fixtures.json
var slip39_fixtures_default = {
  _README: [
    "Two kinds of pin for encodeShare, covering what the 45 official Trezor",
    "vectors never reach.",
    "",
    "fieldPins: encodeShare called directly on synthetic share records whose",
    "  every packed field sits at its extreme - identifier 0 and 32767,",
    "  iterationExponent 0 and 15, groupIndex/memberIndex 0 and 15,",
    "  groupThreshold/groupCount 1 and 16, extendable both ways. No key",
    "  derivation is involved, which matters: driving iterationExponent 15",
    "  through a real split costs 327,680,000 PBKDF2 iterations and 26",
    "  seconds, and the KDF is not what these pins are testing.",
    "",
    "fixtures: full 16-group x 16-member splits, which exercise the block and",
    "  interleaving structure at maximum width. iterationExponent 0 keeps them",
    "  at 7 ms.",
    "",
    "PROVENANCE. Every fieldPin mnemonic was parsed by the reference",
    "python-shamir-mnemonic, which agreed on all eight fields and on the share",
    "value at every extreme (6/6). The 16-group fixtures were likewise recovered",
    "by the reference to the exact secret. So both were externally correct when",
    "created; thereafter they are regression anchors.",
    "",
    "The externally-authoritative encode check that runs continuously is the",
    "re-encoding of all 77 reference share strings in slip39-vectors.json.",
    "",
    "secret: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    'rng: counter-mode SHA-256 over "evm-seed-tool/slip39-fixture/" + name',
    "",
    'The rng seed string above still says "evm-seed-tool" after the project',
    "was renamed to HEATDEATH. That is deliberate. It is not a brand string but",
    "the provenance anchor of these expectations: they were generated with this",
    "exact seed and then confirmed by the reference python-shamir-mnemonic.",
    "Renaming it would regenerate them from this implementation alone, turning",
    "externally-verified vectors into self-referential ones. See the note at the",
    "call site in slip39.mjs."
  ],
  secret: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  fieldPins: [
    {
      name: "all fields at maximum / 16B",
      fields: {
        identifier: 32767,
        extendable: true,
        iterationExponent: 15,
        groupIndex: 15,
        groupThreshold: 16,
        groupCount: 16,
        memberIndex: 15,
        memberThreshold: 16
      },
      valueHex: "000102030405060708090a0b0c0d0e0f",
      mnemonic: "zero zero zero zero academic acrobat aluminum debris activity alarm busy learn election animal deal snapshot likely render coding costume"
    },
    {
      name: "all fields at maximum / 32B",
      fields: {
        identifier: 32767,
        extendable: true,
        iterationExponent: 15,
        groupIndex: 15,
        groupThreshold: 16,
        groupCount: 16,
        memberIndex: 15,
        memberThreshold: 16
      },
      valueHex: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
      mnemonic: "zero zero zero zero award wine sympathy deny repeat photo lungs symbolic gray fact depart lungs away easel universe invasion similar triumph numb charity install mouse else skin ceramic easy buyer keyboard depart"
    },
    {
      name: "all fields at minimum / 16B",
      fields: {
        identifier: 0,
        extendable: false,
        iterationExponent: 0,
        groupIndex: 0,
        groupThreshold: 1,
        groupCount: 1,
        memberIndex: 0,
        memberThreshold: 1
      },
      valueHex: "000102030405060708090a0b0c0d0e0f",
      mnemonic: "academic academic academic academic academic acrobat aluminum debris activity alarm busy learn election animal deal snapshot likely elevator display endless"
    },
    {
      name: "all fields at minimum / 32B",
      fields: {
        identifier: 0,
        extendable: false,
        iterationExponent: 0,
        groupIndex: 0,
        groupThreshold: 1,
        groupCount: 1,
        memberIndex: 0,
        memberThreshold: 1
      },
      valueHex: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
      mnemonic: "academic academic academic academic award wine sympathy deny repeat photo lungs symbolic gray fact depart lungs away easel universe invasion similar triumph numb charity install mouse else skin ceramic easy deploy dive jacket"
    },
    {
      name: "alternating bit pattern / 16B",
      fields: {
        identifier: 21845,
        extendable: false,
        iterationExponent: 10,
        groupIndex: 5,
        groupThreshold: 11,
        groupCount: 12,
        memberIndex: 10,
        memberThreshold: 6
      },
      valueHex: "000102030405060708090a0b0c0d0e0f",
      mnemonic: "plot plot forget treat academic acrobat aluminum debris activity alarm busy learn election animal deal snapshot likely smart secret fact"
    },
    {
      name: "alternating bit pattern / 32B",
      fields: {
        identifier: 21845,
        extendable: false,
        iterationExponent: 10,
        groupIndex: 5,
        groupThreshold: 11,
        groupCount: 12,
        memberIndex: 10,
        memberThreshold: 6
      },
      valueHex: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
      mnemonic: "plot plot forget treat award wine sympathy deny repeat photo lungs symbolic gray fact depart lungs away easel universe invasion similar triumph numb charity install mouse else skin ceramic easy traffic axis short"
    }
  ],
  fixtures: [
    {
      name: "16 groups x 2-of-16, group threshold 16",
      groupThreshold: 16,
      groups: [
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        }
      ],
      identifier: 32767,
      extendable: false,
      iterationExponent: 0,
      shareCount: 256,
      sha256: "2ab67a208f43a85219d056c5b9f2e69cb118c24bd537ca4b2bd3c4a0967e67cc",
      firstShare: "zero walnut award roster adjust ocean tolerate username airline blue space merchant premium paid dress pleasure frequent herald space squeeze maiden surface ending nail empty junior webcam lips exhaust sniff repair engage prospect",
      lastShare: "zero walnut zero withdraw artist have criminal stadium prepare voter prize cylinder mandate recall moment closet liberty promise warmth hand fragment advance explain season acquire kitchen birthday tackle presence fawn merchant often bulge"
    },
    {
      name: "16 groups x 2-of-16, extendable",
      groupThreshold: 16,
      groups: [
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        },
        {
          threshold: 2,
          count: 16
        }
      ],
      identifier: 0,
      extendable: true,
      iterationExponent: 0,
      shareCount: 256,
      sha256: "66c803f77bf7b290085a0991218dc7a2000575f4deb242053b1fbbf14c3f69cb",
      firstShare: "academic again award roster argue carbon evening process bolt grief regular devote dwarf space says deal realize skunk declare lunch merit duration friar clogs voice minister bundle knit founder oven gasoline crisis afraid",
      lastShare: "academic again zero withdraw acne width gravity alien level writing ruler cowboy decrease volume echo tendency cover twin gums style priest preach numb perfect pulse gesture ounce wisdom debris enjoy fluff style sunlight"
    }
  ]
};

// qr.mjs
import assert2 from "node:assert/strict";
var QR_PRIMITIVE_POLYNOMIAL = 285;
var EXP2 = new Uint8Array(512);
var LOG2 = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP2[i] = x;
    LOG2[x] = i;
    x <<= 1;
    if (x & 256) x ^= QR_PRIMITIVE_POLYNOMIAL;
  }
  for (let i = 255; i < 512; i += 1) EXP2[i] = EXP2[i - 255];
}
var gfMul = (a, b) => a === 0 || b === 0 ? 0 : EXP2[LOG2[a] + LOG2[b]];
function rsGenerator(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j += 1) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP2[i]);
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
var EC_BLOCKS = {
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
    40: [30, [[19, 118], [6, 119]]]
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
    40: [28, [[18, 47], [31, 48]]]
  }
};
var ALIGN = {
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
  40: [6, 30, 58, 86, 114, 142, 170]
};
var ECC_BITS = { L: 1, M: 0 };
var charCountBits = (version) => version <= 9 ? 8 : 16;
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
  assert2.fail(
    `${byteLength} bytes does not fit in any QR version at ECC level ${ecc}`
  );
}
function buildCodewords(bytes, version, ecc) {
  const bits = [];
  const push = (value, length) => {
    for (let i = length - 1; i >= 0; i -= 1) bits.push(value >> i & 1);
  };
  push(4, 4);
  push(bytes.length, charCountBits(version));
  for (const b of bytes) push(b, 8);
  const capacity = totalDataCodewords(version, ecc) * 8;
  assert2.ok(bits.length <= capacity, "data exceeds chosen version capacity");
  for (let i = 0; i < 4 && bits.length < capacity; i += 1) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    data.push(bits.slice(i, i + 8).reduce((v, b) => v << 1 | b, 0));
  }
  const PAD = [236, 17];
  for (let i = 0; data.length < capacity / 8; i += 1) data.push(PAD[i % 2]);
  return data;
}
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
  assert2.equal(offset, data.length, "block split did not consume all data");
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
var FORMAT_GENERATOR = 1335;
var FORMAT_MASK = 21522;
var VERSION_GENERATOR = 7973;
function bch(value, generator, degree) {
  let rest = value << degree;
  const genBits = 32 - Math.clz32(generator);
  while (32 - Math.clz32(rest) >= genBits) {
    rest ^= generator << 32 - Math.clz32(rest) - genBits;
  }
  return value << degree | rest;
}
var formatBits = (ecc, mask) => bch(ECC_BITS[ecc] << 3 | mask, FORMAT_GENERATOR, 10) ^ FORMAT_MASK;
var versionBits = (version) => bch(version, VERSION_GENERATOR, 12);
var MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => r * c % 2 + r * c % 3 === 0,
  (r, c) => (r * c % 2 + r * c % 3) % 2 === 0,
  (r, c) => ((r + c) % 2 + r * c % 3) % 2 === 0
];
function blankMatrix(size) {
  return {
    size,
    modules: new Uint8Array(size * size),
    reserved: new Uint8Array(size * size)
  };
}
var setModule = (m, r, c, dark, reserve = true) => {
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
      const nearFinder = centre <= 8 && other <= 8 || centre <= 8 && other >= size - 9 || centre >= size - 9 && other <= 8;
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
  for (let i = 0; i < 9; i += 1) {
    if (i !== 6) setModule(m, i, 8, false);
    if (i !== 6) setModule(m, 8, i, false);
  }
  for (let i = 0; i < 8; i += 1) setModule(m, 8, size - 1 - i, false);
  for (let i = 0; i < 7; i += 1) setModule(m, size - 1 - i, 8, false);
  setModule(m, size - 8, 8, true);
  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i += 1) {
      const bit = (bits >> i & 1) === 1;
      setModule(m, Math.floor(i / 3), size - 11 + i % 3, bit);
      setModule(m, size - 11 + i % 3, Math.floor(i / 3), bit);
    }
  }
}
function placeData(m, codewords) {
  const size = m.size;
  let bitIndex = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    const col = right <= 6 ? right - 1 : right;
    for (let i = 0; i < size; i += 1) {
      const row = upward ? size - 1 - i : i;
      for (const c of [col, col - 1]) {
        if (m.reserved[row * m.size + c]) continue;
        const byte = codewords[bitIndex >> 3];
        const bit = byte === void 0 ? 0 : byte >> 7 - (bitIndex & 7) & 1;
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
  for (let i = 0; i < 15; i += 1) {
    const bit = (bits >> i & 1) === 1;
    if (i < 6) setModule(m, i, 8, bit);
    else if (i === 6) setModule(m, 7, 8, bit);
    else if (i === 7) setModule(m, 8, 8, bit);
    else if (i === 8) setModule(m, 8, 7, bit);
    else setModule(m, 8, 14 - i, bit);
    if (i < 8) setModule(m, 8, size - 1 - i, bit);
    else setModule(m, size - 15 + i, 8, bit);
  }
}
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
      const get = (i) => i < 0 || i >= size ? 0 : transposed ? at(i, a) : at(a, i);
      for (let i = 0; i <= size - 7; i += 1) {
        if (!matches(get, i)) continue;
        if (clearRun(get, i - 4, i) || clearRun(get, i + 7, i + 11)) score += 40;
      }
    }
  }
  let dark = 0;
  for (let i = 0; i < size * size; i += 1) dark += m.modules[i];
  const percent = dark * 100 / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;
  return score;
}
function encodeQR(text, { ecc = "M", mask = null } = {}) {
  assert2.ok(ecc === "L" || ecc === "M", `unsupported ECC level ${ecc}`);
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
function renderQR({ size, modules }, { quiet = 4 } = {}) {
  const total = size + quiet * 2;
  const dark = (r, c) => r >= quiet && c >= quiet && r < quiet + size && c < quiet + size && modules[(r - quiet) * size + (c - quiet)] === 1;
  const GLYPHS = [" ", "\u2584", "\u2580", "\u2588"];
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
var MAX_SCANNABLE_VERSION = 12;
var EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
function encodeAddressQRs(addresses, { ecc = "L" } = {}) {
  assert2.ok(Array.isArray(addresses) && addresses.length > 0, "no addresses given");
  addresses.forEach((address, i) => {
    assert2.equal(
      typeof address,
      "string",
      `entry ${i} must be a primitive string; objects are never QR-encoded`
    );
    assert2.match(
      address,
      EVM_ADDRESS,
      `entry ${i} is not an EVM address. This encoder accepts addresses only - it must never be handed a mnemonic, key, share or extended public key.`
    );
  });
  const lines = addresses.map((a, i) => `${i} ${a}`);
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
  assert2.ok(
    chunks.every((c) => c.length > 0),
    "a single address does not fit the version cap"
  );
  return chunks.map((chunk, i) => {
    const header = chunks.length > 1 ? `part ${i + 1}/${chunks.length}
` : "";
    const text = header + chunk.join("\n");
    return {
      label: `addresses ${chunk[0].split(" ")[0]}-${chunk[chunk.length - 1].split(" ")[0]}`,
      text,
      symbol: encodeQR(text, { ecc })
    };
  });
}
function qrSelfTest({ log = () => {
} }) {
  assert2.equal(QR_PRIMITIVE_POLYNOMIAL, 285, "QR must use primitive polynomial 0x11D");
  assert2.equal(gfMul(3, 7), 9);
  assert2.equal(gfMul(87, 131), 49, "GF tables are not using 0x11D");
  assert2.equal(gfMul(2, 142), 1, "0x02 and 0x8E are inverses mod 0x11D");
  assert2.equal(new Set(EXP2.slice(0, 255)).size, 255, "generator is not primitive");
  log("QR GF(256)/0x11D arithmetic matches published values");
  for (const [text, expectVersion] of [["test", 1], ["x".repeat(120), 7]]) {
    const q = encodeQR(text, { ecc: "M" });
    assert2.equal(q.version, expectVersion, `unexpected version for ${text.length} bytes`);
    assert2.equal(q.size, q.version * 4 + 17);
    assert2.equal(q.modules.length, q.size * q.size);
  }
  const qrs = encodeAddressQRs(Array.from({ length: 11 }, () => "0x" + "aB".repeat(20)));
  for (const { symbol } of qrs) {
    assert2.ok(symbol.version <= MAX_SCANNABLE_VERSION, "emitted an unscannable version");
  }
  assert2.throws(
    () => encodeAddressQRs(["abandon abandon abandon"]),
    /not an EVM address/,
    "address encoder accepted non-address input"
  );
  log(`QR address encoding: ${qrs.length} symbol(s), all within v${MAX_SCANNABLE_VERSION}`);
}

// cli.mjs
import assert3 from "node:assert/strict";
var COMMANDS = /* @__PURE__ */ new Map([
  ["--self-test", "self-test"],
  ["--doctor", "doctor"],
  ["--safe-owner", "safe-owner"],
  ["--rehearse-safe-owner", "rehearse-safe-owner"],
  ["--wizard", "wizard"],
  ["--generate", "generate"],
  ["--verify", "verify"],
  ["--split", "split"],
  ["--combine", "combine"],
  ["--op-export", "op-export"],
  ["--prove-guard", "prove-guard"],
  ["--prove-sandbox", "prove-guard"],
  ["--license", "license"]
]);
var BOOLEAN_SCOPES = /* @__PURE__ */ new Map([
  ["--dice", /* @__PURE__ */ new Set(["wizard", "generate"])],
  ["--show-public", /* @__PURE__ */ new Set(["wizard", "generate", "verify", "combine"])],
  ["--show-private", /* @__PURE__ */ new Set(["wizard", "generate", "verify", "combine"])],
  // The wizard always offers a screen wipe, so the flag is meaningless there
  // and is rejected rather than silently accepted.
  ["--wipe-screen", /* @__PURE__ */ new Set(["generate"])],
  ["--dry-run", /* @__PURE__ */ new Set(["op-export"])],
  ["--qr", /* @__PURE__ */ new Set(["wizard", "generate", "verify", "combine"])]
]);
var OPTION_SCOPES = /* @__PURE__ */ new Map([
  ["--scheme", /* @__PURE__ */ new Set(["wizard", "generate", "verify", "split", "combine", "op-export"])],
  ["--accounts", /* @__PURE__ */ new Set(["wizard", "generate", "verify", "split", "combine", "op-export"])],
  ["--shares", /* @__PURE__ */ new Set(["wizard", "split"])],
  ["--group-threshold", /* @__PURE__ */ new Set(["wizard", "split"])]
]);
function exactInteger(value, name, min, max = Number.MAX_SAFE_INTEGER) {
  assert3.match(value, /^(0|[1-9][0-9]*)$/, `${name} must be a base-10 integer`);
  const number = Number(value);
  assert3.ok(
    Number.isSafeInteger(number) && number >= min && number <= max,
    `${name} must be an integer between ${min} and ${max}`
  );
  return number;
}
function parseCli(argv, {
  defaultScheme,
  schemes,
  defaultAccounts,
  maxAccounts
} = {}) {
  if (argv.includes("--help")) {
    return { command: "help", flags: /* @__PURE__ */ new Set(["--help"]) };
  }
  const flags = /* @__PURE__ */ new Set();
  const opts = /* @__PURE__ */ new Map();
  for (const arg of argv) {
    assert3.ok(arg.startsWith("--"), `Unexpected positional argument "${arg}"`);
    const eq = arg.indexOf("=");
    if (eq === -1) {
      assert3.ok(!flags.has(arg), `Duplicate flag "${arg}"`);
      flags.add(arg);
    } else {
      const key = arg.slice(0, eq);
      assert3.ok(!opts.has(key), `Duplicate option "${key}"`);
      assert3.ok(arg.slice(eq + 1).length > 0, `${key} requires a value`);
      opts.set(key, arg.slice(eq + 1));
    }
  }
  for (const flag of flags) {
    assert3.ok(COMMANDS.has(flag) || BOOLEAN_SCOPES.has(flag), `Unknown flag "${flag}"`);
  }
  for (const key of opts.keys()) {
    assert3.ok(OPTION_SCOPES.has(key), `Unknown option "${key}"`);
  }
  const selected = [...flags].filter((flag) => COMMANDS.has(flag));
  assert3.equal(selected.length, 1, "select exactly one command (use --help for usage)");
  const command = COMMANDS.get(selected[0]);
  assert3.equal(
    selected.filter((flag) => COMMANDS.get(flag) === command).length,
    1,
    "command aliases cannot be used together"
  );
  for (const flag of flags) {
    if (BOOLEAN_SCOPES.has(flag)) {
      assert3.ok(BOOLEAN_SCOPES.get(flag).has(command), `${flag} is not valid with --${command}`);
    }
  }
  for (const key of opts.keys()) {
    assert3.ok(OPTION_SCOPES.get(key).has(command), `${key} is not valid with --${command}`);
  }
  const scheme = opts.get("--scheme") ?? defaultScheme;
  assert3.ok(
    schemes.includes(scheme),
    `Unknown --scheme "${scheme}". Available: ${schemes.join(", ")}`
  );
  const count = exactInteger(
    opts.get("--accounts") ?? String(defaultAccounts),
    "--accounts",
    1,
    maxAccounts
  );
  const groupThreshold = exactInteger(
    opts.get("--group-threshold") ?? "1",
    "--group-threshold",
    1,
    16
  );
  return {
    command,
    flags,
    scheme,
    count,
    shareSpec: opts.get("--shares") ?? "2of3",
    groupThreshold,
    showPrivate: flags.has("--show-private"),
    showPublic: flags.has("--show-public"),
    useDice: flags.has("--dice"),
    wipe: flags.has("--wipe-screen"),
    dryRun: flags.has("--dry-run"),
    qr: flags.has("--qr")
  };
}

// terminal.mjs
import process from "node:process";
var ETX = "";
var EOT = "";
var ESC = "\x1B";
var BS = "\b";
var DEL = "\x7F";
var NAK = "";
var segmenter = new Intl.Segmenter(void 0, { granularity: "grapheme" });
function dropLastGrapheme(value) {
  const segments = [...segmenter.segment(value)];
  return segments.length === 0 ? value : value.slice(0, segments.at(-1).index);
}
var graphemeCount = (value) => [...segmenter.segment(value)].length;
var TerminalInputDecoder = class {
  #value = "";
  #escape = "";
  #paste = false;
  get value() {
    return this.#value;
  }
  push(chunk) {
    let completed = false;
    let aborted = false;
    let erased = 0;
    let echo = "";
    for (const ch of chunk) {
      if (this.#escape) {
        if (ch === ETX || ch === EOT) {
          this.#escape = "";
          aborted = true;
          break;
        }
        if ((ch === "\r" || ch === "\n") && !this.#paste) {
          this.#escape = "";
          completed = true;
          break;
        }
        this.#escape += ch;
        if (this.#escape === `${ESC}[200~`) {
          this.#paste = true;
          this.#escape = "";
        } else if (this.#escape === `${ESC}[201~`) {
          this.#paste = false;
          this.#escape = "";
        } else if (this.#escape.startsWith(`${ESC}[`) && this.#escape.length >= 3 && /[@-~]$/.test(ch) || this.#escape.startsWith(`${ESC}O`) && this.#escape.length >= 3 || !this.#escape.startsWith(`${ESC}[`) && !this.#escape.startsWith(`${ESC}O`) && this.#escape.length >= 2) {
          this.#escape = "";
        } else if (this.#escape.length > 64) {
          this.#escape = "";
        }
        continue;
      }
      if (ch === ESC) {
        this.#escape = ESC;
        continue;
      }
      if (ch === "\r" || ch === "\n") {
        if (this.#paste) {
          this.#value += ch;
          echo += ch;
        } else {
          completed = true;
          break;
        }
        continue;
      }
      if (ch === ETX || ch === EOT) {
        aborted = true;
        break;
      }
      if (ch === BS || ch === DEL) {
        const next = dropLastGrapheme(this.#value);
        if (next !== this.#value) {
          this.#value = next;
          erased += 1;
        }
        continue;
      }
      if (ch === NAK && !this.#paste) {
        erased += graphemeCount(this.#value);
        this.#value = "";
        continue;
      }
      if (ch < " " && !this.#paste) continue;
      this.#value += ch;
      echo += ch;
    }
    return { completed, aborted, erased, echo };
  }
};
async function readInput(prompt, {
  echo = false,
  stdin = process.stdin,
  stdout = process.stdout
} = {}) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== "function") {
    throw new Error("stdin is not a terminal; this command needs interactive input");
  }
  const wasRaw = Boolean(stdin.isRaw);
  const decoder = new TerminalInputDecoder();
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");
  stdout.write(prompt);
  try {
    await new Promise((resolve, reject) => {
      const cleanup = () => {
        stdin.off("data", onData);
        stdin.off("error", onError);
        stdin.off("end", onEnd);
      };
      const onError = (error) => {
        cleanup();
        reject(error);
      };
      const onEnd = () => {
        cleanup();
        reject(new Error("terminal input ended unexpectedly"));
      };
      const onData = (chunk) => {
        const event = decoder.push(chunk);
        if (echo && event.echo) stdout.write(event.echo);
        if (echo && event.erased) stdout.write("\b \b".repeat(event.erased));
        if (event.aborted) {
          cleanup();
          stdout.write("\n");
          reject(new Error("aborted by user"));
        } else if (event.completed) {
          cleanup();
          stdout.write("\n");
          resolve();
        }
      };
      stdin.on("data", onData);
      stdin.once("error", onError);
      stdin.once("end", onEnd);
    });
  } finally {
    stdin.setRawMode(wasRaw);
    stdin.pause();
  }
  const value = decoder.value;
  if (!value.isWellFormed()) {
    throw new Error("input contains malformed Unicode; nothing was accepted");
  }
  return value;
}
function normalizePassphrase(value) {
  if (typeof value !== "string" || !value.isWellFormed()) {
    throw new TypeError("passphrase must be well-formed Unicode text");
  }
  return value.normalize("NFKD");
}
function validateNewWalletPassphrase(value) {
  if (value === "") return;
  if (!/^[\x20-\x7e]+$/.test(value)) {
    throw new Error(
      "new-wallet passphrases must contain printable ASCII only (space through ~)"
    );
  }
  if (value !== value.trim()) {
    throw new Error(
      "new-wallet passphrases must not start or end with a space: hidden input cannot show it, and restoring without it opens a different, empty wallet"
    );
  }
}
function passphraseCautions(value) {
  const cautions = [];
  if (/ {2,}/.test(value)) {
    cautions.push(
      "It contains two or more consecutive spaces. They count, and they are invisible on paper; a single space between words is far safer."
    );
  }
  if (looksObviouslyWeakPassphrase(value)) {
    cautions.push(
      "It has an obvious weak structure or is short. Software cannot infer how randomly a passphrase was chosen, so no honest entropy figure can be given; use independently sampled Diceware words or random characters."
    );
  }
  return cautions;
}
function looksObviouslyWeakPassphrase(value) {
  if (value.length < 16) return true;
  if (/^(.)\1+$/u.test(value)) return true;
  if (/^(.{1,8})\1+$/u.test(value)) return true;
  if (/^(password|passphrase|letmein|qwerty|123456|correct horse battery staple)/iu.test(value.trim())) return true;
  return false;
}

// op-transport.mjs
async function sendSecretPayload({
  spawn,
  shell,
  cat,
  opPath,
  vault,
  payload,
  preview = false
}) {
  const script = `exec ${cat} | "$1" item create --vault "$2" --format=json ${preview ? "--dry-run " : ""}-`;
  const child = spawn(shell, ["-c", script, "sh", opPath, vault], {
    stdio: ["pipe", "pipe", "pipe"]
  });
  let transportFailed = false;
  child.stdout.on("data", () => {
  });
  child.stderr.on("data", () => {
  });
  child.stdin.on("error", () => {
    transportFailed = true;
  });
  const result = await new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    child.on("error", () => finish({ code: -1, transportFailed: true }));
    child.on("close", (code) => finish({ code, transportFailed }));
    child.stdin.end(payload);
  });
  if (result.transportFailed && result.code === 0) result.code = -1;
  return result;
}

// runtime.mjs
import os from "node:os";
import process2 from "node:process";
function inspectorUrl(runtime) {
  try {
    return runtime.getBuiltinModule?.("node:inspector")?.url?.();
  } catch {
    return void 0;
  }
}
var FORBIDDEN_PERMISSION_SCOPES = Object.freeze([
  "net",
  "child",
  "worker",
  "fs.write",
  "addon",
  "ffi",
  "inspector",
  "wasi"
]);
var FORBIDDEN_EXEC_ARGV = Object.freeze([
  "--heapsnapshot-signal",
  "--heapsnapshot-near-heap-limit",
  "--heap-prof",
  "--cpu-prof",
  "--prof",
  "--diagnostic-dir",
  "--report-on-signal",
  "--report-on-fatalerror",
  "--report-uncaught-exception",
  "--require",
  "-r",
  "--import",
  "--loader",
  "--experimental-loader",
  "--env-file",
  "--env-file-if-exists"
]);
function forbiddenExecArgv(execArgv) {
  return execArgv.filter((argument) => FORBIDDEN_EXEC_ARGV.some((flag) => argument === flag || argument.startsWith(`${flag}=`)));
}
function supportsNetworkPermission(runtime = process2) {
  return Boolean(runtime.allowedNodeEnvironmentFlags?.has("--allow-net"));
}
function permissionFlagConcerns(runtime) {
  const concerns = [];
  const allowedReads = /* @__PURE__ */ new Set([".", runtime.cwd(), "/dev/urandom"]);
  for (const argument of runtime.execArgv ?? []) {
    if (argument === "--allow-fs-write" || argument.startsWith("--allow-fs-write=")) {
      concerns.push({
        id: "permission-fs.write-resource",
        message: `Filesystem write grant is present in execArgv (${argument}).`
      });
    }
    if (argument.startsWith("--allow-fs-read=")) {
      const resource = argument.slice("--allow-fs-read=".length);
      if (!allowedReads.has(resource)) {
        concerns.push({
          id: "permission-fs.read-resource",
          message: `Unexpected filesystem read grant is present in execArgv (${argument}).`
        });
      }
    }
  }
  return concerns;
}
function inspectRuntime({
  requireTty = true,
  requirePermission = false,
  runtime = process2,
  networkInterfaces = () => os.networkInterfaces()
} = {}) {
  const blockers = [];
  const warnings = [];
  if (runtime.env.SSH_TTY || runtime.env.SSH_CONNECTION) {
    blockers.push({
      id: "ssh",
      message: "This is an SSH session. Every character printed here crosses a network and lands in a remote terminal's scrollback. Run on the physical machine."
    });
  }
  const inspectFlags = [...runtime.execArgv, runtime.env.NODE_OPTIONS ?? ""].join(" ").match(/--inspect[\w-]*/g);
  if (inspectFlags) {
    blockers.push({
      id: "debugger",
      message: `A debugger port is enabled (${inspectFlags.join(", ")}). Anything attached to it can read the seed straight out of process memory.`
    });
  }
  const inspector = inspectorUrl(runtime);
  if (inspector) {
    blockers.push({ id: "inspector", message: `An inspector is already listening on ${inspector}.` });
  }
  const dumpFlags = forbiddenExecArgv(runtime.execArgv ?? []);
  if (dumpFlags.length > 0) {
    blockers.push({
      id: "diagnostic-flags",
      message: `Node was started with ${dumpFlags.join(", ")}. Such flags write process memory to disk or run code before this file - a heap snapshot contains the seed. Start through the provided launchers, which pass none of them.`
    });
  }
  if (requireTty && !runtime.stdout.isTTY) {
    blockers.push({
      id: "stdout-tty",
      message: "stdout is not a terminal. NOTE: this check is a convenience guard, not a security boundary - script(1), `tmux pipe-pane`, expect and terminal session logging all defeat it trivially. You remain responsible for ensuring nothing is recording this terminal."
    });
  }
  if (requireTty && !runtime.stdin?.isTTY) {
    blockers.push({
      id: "stdin-tty",
      message: "stdin is not a terminal. Secret input must come directly from the interactive terminal, never a pipe, redirected file, or automation harness."
    });
  }
  if (!runtime.permission) {
    const row = {
      id: "permission-model",
      message: "Node's trusted-code capability guard is OFF. Network, subprocesses and file writes are technically possible from this process. Use a provided source or verified launcher, which enables it."
    };
    (requirePermission ? blockers : warnings).push(row);
  } else {
    if (!supportsNetworkPermission(runtime)) {
      const row = {
        id: "permission-net-unsupported",
        message: `This Node (${runtime.version ?? "unknown version"}) has no network permission scope, so the capability guard cannot deny network or DNS access from this process. Node 25 introduced --allow-net; use Node 26 LTS.`
      };
      (requirePermission ? blockers : warnings).push(row);
    }
    for (const scope of FORBIDDEN_PERMISSION_SCOPES) {
      if (runtime.permission.has(scope)) {
        const row = { id: `permission-${scope}`, message: `Permission "${scope}" is ALLOWED.` };
        (requirePermission ? blockers : warnings).push(row);
      }
    }
    for (const row of permissionFlagConcerns(runtime)) {
      (requirePermission ? blockers : warnings).push(row);
    }
    if (runtime.permission.has("fs.read", runtime.cwd())) {
      warnings.push({
        id: "repository-read",
        message: "Repository-wide filesystem read is allowed. This is expected only in source-checkout mode; signed bundle commands need /dev/urandom only."
      });
    }
    if (!runtime.permission.has("fs.read", "/dev/urandom")) {
      blockers.push({
        id: "urandom-read",
        message: "The required /dev/urandom read capability is missing."
      });
    }
  }
  if (typeof runtime.getuid === "function" && runtime.getuid() === 0) {
    warnings.push({ id: "root", message: "Running as root. This tool needs no privileges whatsoever." });
  }
  if (runtime.env.TMUX || runtime.env.STY) {
    warnings.push({
      id: "terminal-multiplexer",
      message: "Running inside tmux/screen. These keep large scrollback buffers and can be configured to log the session to disk."
    });
  }
  if (runtime.env.NODE_OPTIONS?.trim()) {
    const row = {
      id: "node-options",
      message: `NODE_OPTIONS is set ("${runtime.env.NODE_OPTIONS}"). It can inject code or broaden resource-scoped permissions before this file runs.`
    };
    (requirePermission ? blockers : warnings).push(row);
  }
  const cwd = runtime.cwd();
  for (const dir of [
    "Library/Mobile Documents",
    "iCloud",
    "Dropbox",
    "Google Drive",
    "OneDrive",
    "Yandex.Disk",
    "pCloud",
    "MEGA"
  ]) {
    if (cwd.includes(dir)) {
      warnings.push({
        id: "cloud-directory",
        message: `Working directory looks cloud-synchronised (matched "${dir}").`
      });
      break;
    }
  }
  try {
    const live = Object.entries(networkInterfaces()).filter(([, addrs]) => (addrs ?? []).some((address) => !address.internal)).map(([name]) => name);
    if (live.length > 0) {
      const sample = live.slice(0, 3).join(", ");
      warnings.push({
        id: "network-interfaces",
        message: `${live.length} network interface(s) are up (${sample}${live.length > 3 ? ", ..." : ""}). Disable Wi-Fi, Ethernet and Bluetooth before generating.`
      });
    }
  } catch {
    warnings.push({ id: "network-unknown", message: "Network interfaces could not be inspected." });
  }
  return Object.freeze({
    blockers: Object.freeze(blockers),
    warnings: Object.freeze(warnings)
  });
}

// generate.mjs
var TOOL_ID = "heatdeath/v2";
var ENTROPY_BYTES = 32;
var DEFAULT_ACCOUNTS = 11;
var MAX_ACCOUNTS = 100;
var DICE_MIN_ROLLS = 128;
var SAFE_OWNER_SCHEME = "metamask";
var PASSPHRASE_ATTEMPTS = 5;
var REHEARSAL_ENTROPY = Buffer.alloc(ENTROPY_BYTES, 0);
var REHEARSAL_BANNER = "PUBLIC TEST DATA - NEVER FUND THIS ADDRESS";
var CURVE_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
var WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
var PATH_SCHEMES = {
  // Varies the address index. All accounts share one extended public key,
  // so anyone holding that xpub can link every address to one wallet.
  // This is what MetaMask, Rabby, Trust and Ledger "Legacy" use.
  metamask: {
    template: "m/44'/60'/0'/0/%i",
    linkable: true,
    note: "MetaMask / Rabby / Trust / Ledger Legacy. Addresses share one xpub."
  },
  // Varies the hardened account level. Each index sits behind its own
  // hardened boundary, so no single xpub links them, and a leaked child
  // key does not expose its siblings. This is what Ledger Live uses.
  // NOT validated against a published third-party vector - see README.
  account: {
    template: "m/44'/60'/%i'/0/0",
    linkable: false,
    note: "Ledger Live. Hardened per account - addresses are NOT xpub-linkable."
  }
};
var DEFAULT_SCHEME = "metamask";
var sha2562 = (...chunks) => {
  const h = createHash2("sha256");
  for (const c of chunks) h.update(c);
  return h.digest();
};
var POPCOUNT = new Uint8Array(256);
for (let i = 0; i < 256; i += 1) POPCOUNT[i] = (i & 1) + POPCOUNT[i >> 1];
function bigToBytes32(value) {
  assert4.ok(value > 0n && value < CURVE_N, "Scalar out of range");
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}
function bytesToBig(bytes) {
  return BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
}
function xorInto(target, source) {
  assert4.equal(target.length, source.length);
  for (let i = 0; i < target.length; i += 1) target[i] ^= source[i];
  return target;
}
function equalBytes(a, b) {
  return a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function parsePath(path2) {
  const parts = path2.split("/");
  assert4.equal(parts[0], "m", `Path must start with "m": ${path2}`);
  return parts.slice(1).map((part) => {
    const hardened = /['hH]$/.test(part);
    const raw = hardened ? part.slice(0, -1) : part;
    assert4.match(raw, /^[0-9]+$/, `Bad path element: ${part}`);
    const n = Number.parseInt(raw, 10);
    assert4.ok(n >= 0 && n < 2147483648, `Path element out of range: ${part}`);
    return hardened ? n + 2147483648 : n;
  });
}
var pathFor = (scheme, index) => PATH_SCHEMES[scheme].template.replace("%i", String(index));
var templateFor = (scheme) => PATH_SCHEMES[scheme].template.replace("%i", "i");
function assertRuntime({ requireTty = true, requirePermission = false } = {}) {
  const { blockers, warnings } = inspectRuntime({ requireTty, requirePermission });
  if (warnings.length > 0) {
    process3.stdout.write("\nWARNINGS\n");
    for (const row of warnings) process3.stdout.write(`  ! ${row.message}
`);
  }
  if (blockers.length > 0) {
    throw new Error(
      `refusing to continue:
${blockers.map((row) => `  x ${row.message}`).join("\n")}`
    );
  }
  return { warnings };
}
function assertWordlistIntegrity() {
  assert4.equal(wordlist.length, 2048, "Wordlist must contain exactly 2048 words");
  assert4.equal(
    sha2562(`${wordlist.join("\n")}
`).toString("hex"),
    WORDLIST_SHA256,
    "BIP-39 English wordlist does not match the published SHA-256. A phrase produced with it would not be readable by other wallets."
  );
}
function toChecksumAddress(lowercaseHex) {
  assert4.match(lowercaseHex, /^[0-9a-f]{40}$/);
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(lowercaseHex)));
  let result = "0x";
  for (let i = 0; i < lowercaseHex.length; i += 1) {
    const character = lowercaseHex[i];
    result += Number.parseInt(hash[i], 16) >= 8 ? character.toUpperCase() : character;
  }
  return result;
}
function addressFromPrivateKey(privateKey) {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  assert4.equal(publicKey.length, 65);
  assert4.equal(publicKey[0], 4);
  const digest = keccak_256(publicKey.slice(1));
  return {
    address: toChecksumAddress(bytesToHex(digest.slice(-20))),
    publicKey
  };
}
function primaryAccounts(seed, scheme, count) {
  const master = HDKey.fromMasterSeed(seed);
  const fingerprint = `0x${(master.fingerprint >>> 0).toString(16).padStart(8, "0")}`;
  const nodes = [];
  const accounts = [];
  for (let index = 0; index < count; index += 1) {
    const path2 = pathFor(scheme, index);
    const node = master.derive(path2);
    assert4.ok(node.privateKey, `No private key at ${path2}`);
    nodes.push(node);
    accounts.push({
      index,
      path: path2,
      privateKey: Buffer.from(node.privateKey),
      ...addressFromPrivateKey(node.privateKey)
    });
  }
  return {
    accounts,
    fingerprint,
    dispose: () => {
      for (const n of nodes) n.wipePrivateData();
      master.wipePrivateData();
    }
  };
}
function refEntropyToMnemonic(entropy, words) {
  const csBits = entropy.length * 8 / 32;
  assert4.ok(Number.isInteger(csBits) && csBits >= 4 && csBits <= 8);
  let bits = "";
  for (const byte of entropy) bits += byte.toString(2).padStart(8, "0");
  bits += sha2562(entropy)[0].toString(2).padStart(8, "0").slice(0, csBits);
  assert4.equal(bits.length % 11, 0);
  const out = [];
  for (let i = 0; i < bits.length; i += 11) {
    out.push(words[Number.parseInt(bits.slice(i, i + 11), 2)]);
  }
  return out.join(" ");
}
function refMnemonicToSeed(mnemonic, passphrase = "") {
  return pbkdf2Sync2(
    Buffer.from(mnemonic.normalize("NFKD"), "utf8"),
    Buffer.from(`mnemonic${passphrase.normalize("NFKD")}`, "utf8"),
    2048,
    64,
    "sha512"
  );
}
function refMaster(seed) {
  const I = createHmac2("sha512", "Bitcoin seed").update(seed).digest();
  const k = bytesToBig(I.subarray(0, 32));
  assert4.ok(k > 0n && k < CURVE_N, "Invalid master key (probability ~2^-127)");
  return { k, c: I.subarray(32) };
}
function refCkdPriv(node, index) {
  const data = Buffer.alloc(37);
  if (index >= 2147483648) {
    bigToBytes32(node.k).copy(data, 1);
  } else {
    Buffer.from(secp256k1.getPublicKey(bigToBytes32(node.k), true)).copy(data, 0);
  }
  data.writeUInt32BE(index >>> 0, 33);
  const I = createHmac2("sha512", node.c).update(data).digest();
  const IL = bytesToBig(I.subarray(0, 32));
  assert4.ok(IL < CURVE_N, "CKDpriv: IL >= n (probability ~2^-127)");
  const k = (IL + node.k) % CURVE_N;
  assert4.ok(k > 0n, "CKDpriv: resulting key is zero (probability ~2^-256)");
  data.fill(0);
  return { k, c: I.subarray(32) };
}
function refDerive(seed, path2) {
  let node = refMaster(seed);
  for (const index of parsePath(path2)) node = refCkdPriv(node, index);
  return bigToBytes32(node.k);
}
function refFingerprint(seed) {
  const master = refMaster(seed);
  const pub = Buffer.from(secp256k1.getPublicKey(bigToBytes32(master.k), true));
  const hash1602 = createHash2("ripemd160").update(sha2562(pub)).digest();
  return `0x${hash1602.subarray(0, 4).toString("hex")}`;
}
function crossCheck({ entropy, phrase, passphrase, seed, accounts, fingerprint }) {
  if (entropy) {
    assert4.equal(
      refEntropyToMnemonic(entropy, wordlist),
      phrase,
      "CROSS-CHECK FAILED: independent BIP-39 encoder disagrees on the mnemonic"
    );
  }
  const refSeed = refMnemonicToSeed(phrase, passphrase);
  assert4.ok(
    equalBytes(refSeed, seed),
    "CROSS-CHECK FAILED: independent PBKDF2 disagrees on the BIP-39 seed"
  );
  assert4.equal(
    refFingerprint(refSeed),
    fingerprint,
    "CROSS-CHECK FAILED: independent BIP-32 disagrees on the master fingerprint"
  );
  for (const account of accounts) {
    const refKey = refDerive(refSeed, account.path);
    assert4.ok(
      equalBytes(refKey, account.privateKey),
      `CROSS-CHECK FAILED: private key mismatch at ${account.path}`
    );
    assert4.equal(
      addressFromPrivateKey(refKey).address,
      account.address,
      `CROSS-CHECK FAILED: address mismatch at ${account.path}`
    );
    refKey.fill(0);
  }
  refSeed.fill(0);
}
function readUrandom(length) {
  const fd = fs.openSync("/dev/urandom", "r");
  try {
    const buf = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const n = fs.readSync(fd, buf, read, length - read, null);
      assert4.ok(n > 0, "/dev/urandom returned no data");
      read += n;
    }
    return buf;
  } finally {
    fs.closeSync(fd);
  }
}
function healthTest(name, sample) {
  const fail = (test) => assert4.fail(`ENTROPY HEALTH TEST FAILED - source "${name}" failed ${test}`);
  let run = 1;
  for (let i = 1; i < sample.length; i += 1) {
    run = sample[i] === sample[i - 1] ? run + 1 : 1;
    if (run >= 5) fail("the repetition count test (5 identical bytes in a row)");
  }
  for (let off = 0; off + 512 <= sample.length; off += 512) {
    const freq = new Uint16Array(256);
    let max = 0;
    for (let i = off; i < off + 512; i += 1) max = Math.max(max, ++freq[sample[i]]);
    if (max >= 13) fail(`the adaptive proportion test (one value ${max} times in 512)`);
  }
  let ones = 0;
  for (const byte of sample) ones += POPCOUNT[byte];
  const expected = sample.length * 4;
  const sigma = Math.sqrt(sample.length * 8 * 0.25);
  if (Math.abs(ones - expected) > 5 * sigma) {
    fail(`the monobit test (${ones} one-bits, expected about ${expected})`);
  }
}
function diceEntropy(rolls) {
  assert4.ok(
    rolls.length >= DICE_MIN_ROLLS,
    `Need at least ${DICE_MIN_ROLLS} d6 rolls (= ${(DICE_MIN_ROLLS * Math.log2(6)).toFixed(1)} bits); got ${rolls.length}`
  );
  const freq = new Array(6).fill(0);
  for (const r of rolls) freq[r - 1] += 1;
  const expected = rolls.length / 6;
  const chi = freq.reduce((a, f) => a + (f - expected) ** 2 / expected, 0);
  return {
    bytes: sha2562(
      Buffer.from(`${TOOL_ID}/source/dice`),
      Buffer.from([0]),
      Buffer.from(rolls.join(""), "utf8")
    ),
    bits: rolls.length * Math.log2(6),
    chi,
    // df = 5, p < 0.001 at 20.5. A warning, not a rejection: an honest die
    // occasionally rolls oddly, and because dice are XOR-mixed a biased die
    // cannot make the result weaker than the OS sources alone.
    biased: chi > 20.5,
    // The opposite tail. Real dice scatter; a distribution far FLATTER than
    // chance is the signature of digits typed from imagination rather than
    // rolled, or of someone cycling 1-2-3-4-5-6. P(chi2 < 0.55) is about
    // 0.1% for df = 5, so this almost never fires on genuine rolls.
    tooFlat: chi < 0.55
  };
}
function collectEntropy({ dice }) {
  const PROBE = 4096;
  const providers = [
    { name: "openssl-drbg", get: (n) => randomBytes4(n) },
    { name: "kernel-urandom", get: readUrandom }
  ];
  const report = [];
  const material = [];
  const probes = [];
  for (const provider of providers) {
    let probe;
    try {
      probe = provider.get(PROBE);
    } catch (error) {
      report.push({
        name: provider.name,
        status: `UNAVAILABLE (${error.code ?? error.message})`
      });
      continue;
    }
    healthTest(provider.name, probe);
    probes.push({ name: provider.name, probe });
    material.push({ name: provider.name, draw: provider.get(ENTROPY_BYTES) });
    report.push({ name: provider.name, status: "OK" });
  }
  assert4.equal(
    material.length,
    providers.length,
    `Only ${material.length}/${providers.length} required OS entropy paths available; refusing to generate`
  );
  for (let i = 0; i < probes.length; i += 1) {
    for (let j = i + 1; j < probes.length; j += 1) {
      assert4.ok(
        !probes[i].probe.equals(probes[j].probe),
        `Sources "${probes[i].name}" and "${probes[j].name}" returned identical bytes - this indicates a catastrophic duplicate/stubbed output`
      );
    }
  }
  for (const p of probes) p.probe.fill(0);
  const entropy = Buffer.alloc(ENTROPY_BYTES);
  for (const { name, draw } of material) {
    xorInto(
      entropy,
      sha2562(Buffer.from(`${TOOL_ID}/source/${name}`), Buffer.from([0]), draw)
    );
    draw.fill(0);
  }
  if (dice) {
    xorInto(entropy, dice.bytes);
    report.push({
      name: "dice-d6",
      status: `OK (${dice.rolls} rolls = ${dice.bits.toFixed(1)} bits${dice.biased ? ", CHI-SQUARE SUGGESTS A BIASED DIE" : ""})`
    });
  }
  assert4.ok(
    !entropy.equals(Buffer.alloc(ENTROPY_BYTES)),
    "Combined entropy is all zeros"
  );
  return { entropy, report };
}
function makeShamirRng() {
  const { entropy } = collectEntropy({ dice: null });
  let counter = 0;
  const rng = (length) => {
    const out = Buffer.alloc(length);
    for (let off = 0; off < length; off += 32) {
      const ctr = Buffer.alloc(4);
      ctr.writeUInt32BE(counter, 0);
      counter += 1;
      sha2562(Buffer.from(`${TOOL_ID}/shamir`), Buffer.from([0]), entropy, ctr).copy(out, off);
    }
    return out;
  };
  rng.dispose = () => entropy.fill(0);
  return rng;
}
async function readPassphraseTwice({ newWallet = false } = {}) {
  process3.stdout.write(
    `
BIP-39 passphrase (the "25th word").

  It is NOT a wordlist word - any text at all, case and spaces included.
  It goes into the PBKDF2 salt, so every different string yields a
  different, perfectly valid wallet. There is no such thing as a wrong
  passphrase: a typo silently gives you somebody else's empty wallet.

  WHAT IT BUYS: it is the only thing protecting you if someone finds the
  paper. Without it, the paper alone is the wallet.

  WHAT IT DOES NOT BUY: entropy. The seed already has 256 bits. And
  BIP-39 stretches with only 2048 PBKDF2 iterations, so an attacker
  holding your 24 words tests passphrase guesses cheaply - a weak one is
  worth almost nothing. Use 4+ Diceware words or 12+ random characters.

  IT IS NOT RECOVERABLE. Forget it and the funds are gone, permanently.
  It is stored nowhere, and SLIP-39 shares do not carry it either.

  COMPATIBILITY: MetaMask does NOT support BIP-39 passphrases. If you
  set one, importing these 24 words into MetaMask opens the EMPTY
  no-passphrase wallet, not yours - which looks exactly like theft.
  Ledger, Trezor and Rabby do support it.

  Empty = standard wallet, opens in every wallet's default import.
  Input is hidden. Press Enter on an empty line for no passphrase.

`
  );
  for (let failures = 0; ; ) {
    const outcome = await readPassphraseOnce({ newWallet });
    if (outcome.ok) return outcome.passphrase;
    if (!outcome.voluntary) {
      failures += 1;
      if (failures >= PASSPHRASE_ATTEMPTS) {
        throw new Error(
          `passphrase not confirmed after ${PASSPHRASE_ATTEMPTS} attempts - nothing was generated`
        );
      }
    }
    process3.stdout.write(
      `
  ! ${outcome.reason}
  ! Enter the passphrase again (Ctrl+U clears the line). Nothing
  ! collected so far is lost.

`
    );
  }
}
async function readPassphraseOnce({ newWallet }) {
  const firstRaw = await readInput("passphrase: ");
  if (newWallet) {
    try {
      validateNewWalletPassphrase(firstRaw);
    } catch (error) {
      return { ok: false, reason: error.message };
    }
  } else if (/[^\x20-\x7e]/.test(firstRaw)) {
    process3.stdout.write(
      "\n  ! Unicode recovery mode: the text will be normalized with NFKD.\n  ! Confirm the resulting wallet fingerprint against your record.\n"
    );
  }
  const first = normalizePassphrase(firstRaw);
  if (first === "") {
    process3.stdout.write("Using an EMPTY passphrase (standard wallet).\n");
    return { ok: true, passphrase: "" };
  }
  const secondRaw = await readInput("repeat:     ");
  if (normalizePassphrase(secondRaw) !== first) {
    return { ok: false, reason: "Passphrases do not match." };
  }
  process3.stdout.write("\nPassphrase accepted and confirmed.\n");
  const cautions = passphraseCautions(first);
  if (cautions.length > 0) {
    process3.stdout.write("\n");
    for (const caution of cautions) process3.stdout.write(`  ! ${caution}
`);
    if (newWallet) {
      const answer = await readInput(
        '\n  Type "keep" to use it anyway, or press Enter to choose another: ',
        { echo: true }
      );
      if (answer.trim().toLowerCase() !== "keep") {
        return { ok: false, voluntary: true, reason: "Choose a different passphrase." };
      }
    }
  }
  return { ok: true, passphrase: first };
}
async function readDice() {
  const bits = (n) => (n * Math.log2(6)).toFixed(1);
  process3.stdout.write(
    `
Dice entropy. You need at least ${DICE_MIN_ROLLS} d6 rolls (= ${bits(DICE_MIN_ROLLS)} bits).

  YOU DO NOT HAVE TO ROLL ONE DIE AT A TIME. Throw five or six dice as a
  handful and read them left to right: ` + DICE_MIN_ROLLS + " rolls is about " + Math.ceil(DICE_MIN_ROLLS / 6) + " throws\n  with six dice, or " + Math.ceil(DICE_MIN_ROLLS / 5) + " with five. Five to seven minutes.\n\n  Type the results as digits 1-6. Spaces and commas are ignored. You can\n  enter them in BATCHES: press Enter after each handful and keep going -\n  nothing is lost between batches. Input is hidden; only the running\n  count is echoed so you can confirm it.\n\n  More than the minimum is accepted, but adds nothing: the result is\n  hashed to 256 bits either way, and " + DICE_MIN_ROLLS + " fair rolls already exceed that.\n\n  DIGITS 1-6 ONLY, and they must come from a real die. Typing digits\n  out of your head is not randomness - people avoid repeats, favour\n  some digits and produce distributions FLATTER than chance. The\n  chi-square below is checked in both directions and will say so.\n\n  Type `cancel` on an empty prompt to continue without dice instead.\n\nThis is the ONLY entropy source independent of this machine. It is XORed\nwith the OS sources, so it can only help: a bad die cannot weaken the\nresult, and a backdoored OS RNG cannot compromise it.\n\n"
  );
  const rolls = [];
  while (rolls.length < DICE_MIN_ROLLS) {
    const raw = await readInput(`rolls (${rolls.length}/${DICE_MIN_ROLLS}): `);
    if (raw.trim().toLowerCase() === "cancel") {
      process3.stdout.write("  Cancelled - continuing without dice.\n");
      return null;
    }
    const chars = [...raw];
    const batch = chars.filter((c) => c >= "1" && c <= "6").map(Number);
    const wrongDigits = chars.filter((c) => /[0789]/.test(c)).length;
    const other = chars.filter((c) => !/[0-9\s,.-]/.test(c)).length;
    if (wrongDigits > 0) {
      process3.stdout.write(
        `  ! ${wrongDigits} digit(s) outside 1-6 (0, 7, 8 or 9) were ignored - a d6 cannot roll them. Check the line for a typo before continuing.
`
      );
    }
    if (other > 0) {
      process3.stdout.write(`  ! ${other} non-digit character(s) were ignored.
`);
    }
    if (batch.length === 0) {
      process3.stdout.write("  ! Nothing usable in that line. Digits 1-6 only.\n");
      continue;
    }
    rolls.push(...batch);
    const left = DICE_MIN_ROLLS - rolls.length;
    process3.stdout.write(
      left > 0 ? `  +${batch.length}, total ${rolls.length}/${DICE_MIN_ROLLS} - ${left} to go
` : `  +${batch.length}, total ${rolls.length} - enough
`
    );
  }
  const dice = diceEntropy(rolls);
  process3.stdout.write(
    `  accepted ${rolls.length} rolls = ${dice.bits.toFixed(1)} bits (chi-square ${dice.chi.toFixed(1)}, df=5)
`
  );
  if (dice.biased) {
    process3.stdout.write(
      "  ! Chi-square is high (p < 0.001). The die may be biased or the input\n  ! mistyped. Harmless here because of the XOR, but worth a second look.\n"
    );
  }
  if (dice.tooFlat) {
    process3.stdout.write(
      "  ! Chi-square is suspiciously LOW: this distribution is flatter than\n  ! chance produces. That is what typed-from-imagination digits look\n  ! like. If you did not physically roll these, roll them.\n"
    );
  }
  return { ...dice, rolls: rolls.length };
}
function printPhrase(phrase) {
  const words = phrase.split(" ");
  const rows = Math.ceil(words.length / 3);
  process3.stdout.write(
    "\n================================================================\n  WRITE THIS ON PAPER. DO NOT PHOTOGRAPH, COPY OR TYPE IT ELSEWHERE.\n================================================================\n\n"
  );
  for (let r = 0; r < rows; r += 1) {
    const cells = [];
    for (let c = 0; c < 3; c += 1) {
      const i = r + c * rows;
      if (i < words.length) {
        cells.push(`${String(i + 1).padStart(2)}. ${words[i].padEnd(9)}`);
      }
    }
    process3.stdout.write(`    ${cells.join("   ")}
`);
  }
  process3.stdout.write(`
  read-back: ${phrase}
`);
}
function printAccounts(accounts, { showPrivate, showPublic }) {
  for (const account of accounts) {
    process3.stdout.write(`index:       ${account.index}
`);
    process3.stdout.write(`path:        ${account.path}
`);
    process3.stdout.write(`address:     ${account.address}
`);
    if (showPublic) {
      process3.stdout.write(`public key:  0x${bytesToHex(account.publicKey)}
`);
    }
    if (showPrivate) {
      process3.stdout.write(`private key: 0x${account.privateKey.toString("hex")}
`);
    }
    process3.stdout.write("\n");
  }
}
function printAddressQRs(accounts) {
  const symbols = encodeAddressQRs(accounts.map((a) => a.address));
  process3.stdout.write(
    `
ADDRESS QR (${symbols.length} symbol${symbols.length > 1 ? "s" : ""})
  Scanning these gives you the address list on a phone so you can compare
  it against what your wallet shows after import. It carries addresses
  only - never the phrase, keys, shares or an extended public key.
  This is a transcription aid, not independent verification.
`
  );
  for (const { label, symbol } of symbols) {
    process3.stdout.write(`
  ${label}  (v${symbol.version}, ${symbol.size}x${symbol.size})

`);
    process3.stdout.write(`${renderQR(symbol, { quiet: 4 })}
`);
  }
}
async function offerScreenWipe() {
  process3.stdout.write(
    '\nScreen wipe. Type the word "wipe" and press Enter to clear the screen and\nthe terminal scrollback. Press Enter alone to leave the output on screen.\nDo this only AFTER writing the phrase down and verifying it with\n`npm run verify`. Cleared output cannot be recovered.\n\n'
  );
  const answer = await readInput("> ", { echo: true });
  if (answer.trim().toLowerCase() === "wipe") {
    process3.stdout.write(`${ESC}[3J${ESC}[2J${ESC}[H`);
    process3.stdout.write(
      "Screen and scrollback cleared. This affects THIS terminal only - it does\nnot touch tmux buffers, iTerm2 Instant Replay recordings, or any session\nlog your terminal keeps on disk.\n"
    );
  }
}
function parseGroupSpec(spec) {
  return spec.split(",").map((part) => {
    const m = /^([0-9]+)of([0-9]+)$/i.exec(part.trim());
    assert4.ok(m, `Bad share specification "${part}". Use e.g. 2of3.`);
    const threshold = Number.parseInt(m[1], 10);
    const count = Number.parseInt(m[2], 10);
    assert4.ok(
      threshold >= 1 && threshold <= count && count <= 16,
      `Bad share specification "${part}": need 1 <= threshold <= count <= 16.`
    );
    assert4.ok(
      !(threshold === 1 && count > 1),
      `"${part}" would make every share a full copy of the secret. Use 1of1, or raise the threshold.`
    );
    return { threshold, count };
  });
}
function printShares(groupsOfShares, groups, groupThreshold) {
  process3.stdout.write(
    "\n================================================================\n  SLIP-39 BACKUP SHARES - WRITE ON PAPER, STORE SEPARATELY\n================================================================\n\n  These shares restore the BIP-39 ENTROPY of this wallet.\n  They are NOT a BIP-32 seed. A Trezor recovering them would show\n  DIFFERENT addresses. Recover with:  npm run combine\n\n  They do NOT contain your BIP-39 passphrase. If you set one, it must\n  be stored separately or the shares alone restore nothing.\n\n"
  );
  const need = groupThreshold === 1 ? `any ${groups[0].threshold} of the ${groups[0].count} shares below` : `any ${groupThreshold} of the ${groups.length} groups, at their thresholds`;
  process3.stdout.write(`  To restore you need: ${need}.
`);
  process3.stdout.write(
    "  Fewer than that cannot restore the wallet. SLIP-39's four-byte digest\n  leaks up to about 32 bits, so for this 256-bit secret roughly 224 bits\n  remain unknown: infeasible, but not a literal zero-information claim.\n"
  );
  groupsOfShares.forEach((shares, gi) => {
    process3.stdout.write(
      `
  ---- GROUP ${gi + 1} of ${groupsOfShares.length} (need ${groups[gi].threshold} of these ${groups[gi].count}) ----
`
    );
    shares.forEach((share, si) => {
      const words = share.split(" ");
      process3.stdout.write(`
  Group ${gi + 1}, share ${si + 1}  (${words.length} words)
`);
      const rows = Math.ceil(words.length / 4);
      for (let r = 0; r < rows; r += 1) {
        const cells = [];
        for (let c = 0; c < 4; c += 1) {
          const i = r + c * rows;
          if (i < words.length) {
            cells.push(`${String(i + 1).padStart(2)}. ${words[i].padEnd(8)}`);
          }
        }
        process3.stdout.write(`    ${cells.join("  ")}
`);
      }
    });
  });
  process3.stdout.write(
    "\n  Store each share in a DIFFERENT physical place. Two shares in one\n  drawer is one share with extra steps.\n"
  );
}
function describeLayout(groups, groupThreshold) {
  return groupThreshold === 1 && groups.length === 1 ? `any ${groups[0].threshold} of ${groups[0].count} shares` : `any ${groupThreshold} of ${groups.length} groups, each at its own threshold`;
}
var EXHAUSTIVE_LIMIT = 5e3;
var SAMPLE_SIZE = 500;
function verifyShareLayout({ groupThreshold, groups, shares, entropy, rng }) {
  const check = (subset) => assert4.ok(
    equalBytes(combineShares(subset, ""), entropy),
    "ROUND-TRIP FAILED: a valid subset of shares does not restore the entropy"
  );
  const total = countAdmissibleSubsetsExact(groupThreshold, groups);
  if (total <= BigInt(EXHAUSTIVE_LIMIT)) {
    for (const subset of admissibleSubsets(groupThreshold, groups, shares)) check(subset);
    process3.stdout.write(
      `
  ok  all ${total} admissible share combinations verified to restore this exact wallet
`
    );
    return;
  }
  check(
    groups.slice(0, groupThreshold).flatMap((g, gi) => shares[gi].slice(0, g.threshold))
  );
  const sampledRanks = /* @__PURE__ */ new Set(["0"]);
  while (sampledRanks.size <= SAMPLE_SIZE) {
    const rank = randomAdmissibleRank(total, rng);
    const key = rank.toString();
    if (sampledRanks.has(key)) continue;
    sampledRanks.add(key);
    check(admissibleSubsetAtRank(groupThreshold, groups, shares, rank));
  }
  process3.stdout.write(
    `
  ok  ${SAMPLE_SIZE + 1} of ${total.toLocaleString("en-US")} admissible combinations verified (1 canonical + ` + SAMPLE_SIZE + " unique random ranks).\n  !   Exhaustive checking was SKIPPED: this layout has too many\n  !   combinations to enumerate. Every subset tested passed, but not\n  !   every subset was tested. A simpler layout such as 2of3 or 3of5\n  !   is verified exhaustively.\n"
  );
}
async function readShares() {
  process3.stdout.write(
    "\nType your SLIP-39 shares, one per line, from your PAPER backups.\nInput is hidden. Press Enter on an empty line when you are done.\n\n"
  );
  const shares = [];
  for (let i = 1; ; i += 1) {
    const line = await readInput(`share ${i} (empty line to finish): `);
    if (line.trim() === "") break;
    shares.push(line.trim());
    process3.stdout.write(`  accepted ${line.trim().split(/\s+/).length} words
`);
  }
  assert4.ok(shares.length > 0, "No shares entered");
  return shares;
}
function levenshtein(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const cur = [i];
    for (let j = 1; j <= b.length; j += 1) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
    prev = cur;
  }
  return prev[b.length];
}
function repairWords(input) {
  const typed = input.normalize("NFKD").toLowerCase().trim().split(/\s+/).filter(Boolean);
  const known = new Set(wordlist);
  const words = [];
  const notes = [];
  const problems = [];
  for (const [i, word] of typed.entries()) {
    if (known.has(word)) {
      words.push(word);
      continue;
    }
    const prefixed = wordlist.filter((w) => w.startsWith(word));
    if (word.length >= 3 && prefixed.length === 1) {
      words.push(prefixed[0]);
      notes.push(`  word ${i + 1}: "${word}" expanded to "${prefixed[0]}"`);
      continue;
    }
    const near = wordlist.map((w) => [levenshtein(word, w), w]).sort((x, y) => x[0] - y[0]).slice(0, 3).map(([d, w]) => `${w} (distance ${d})`);
    problems.push(
      `  word ${i + 1}: "${word}" is not a BIP-39 word. Closest: ${near.join(", ")}`
    );
    words.push(word);
  }
  return { words, notes, problems };
}
function selfTest({ quiet = false } = {}) {
  const log = (m) => {
    if (!quiet) process3.stdout.write(`  ok  ${m}
`);
  };
  if (!quiet) process3.stdout.write("\nSELF-TEST\n");
  assertWordlistIntegrity();
  log("BIP-39 English wordlist matches the published SHA-256");
  for (const vector of [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
  ]) {
    assert4.equal(toChecksumAddress(vector.slice(2).toLowerCase()), vector);
  }
  log("EIP-55 checksum matches all four official vectors");
  const zeroEntropy = new Uint8Array(32);
  const expectedPhrase = `${"abandon ".repeat(23)}art`;
  const expectedSeed = Buffer.from(
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    "hex"
  );
  const phrase = entropyToMnemonic(zeroEntropy, wordlist);
  assert4.equal(phrase, expectedPhrase);
  assert4.equal(validateMnemonic(phrase, wordlist), true);
  assert4.equal(bytesToHex(mnemonicToEntropy(phrase, wordlist)), "00".repeat(32));
  assert4.ok(equalBytes(mnemonicToSeedSync(phrase, "TREZOR"), expectedSeed));
  log("BIP-39 256-bit vector: mnemonic, checksum, PBKDF2 seed");
  assert4.equal(refEntropyToMnemonic(zeroEntropy, wordlist), expectedPhrase);
  assert4.ok(equalBytes(refMnemonicToSeed(phrase, "TREZOR"), expectedSeed));
  log("reference BIP-39 implementation reproduces the same vector");
  const devPhrase = "test test test test test test test test test test test junk";
  assert4.equal(validateMnemonic(devPhrase, wordlist), true);
  const devSeed = mnemonicToSeedSync(devPhrase);
  const devKey = HDKey.fromMasterSeed(devSeed).derive("m/44'/60'/0'/0/0");
  assert4.equal(
    `0x${bytesToHex(devKey.privateKey)}`,
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
  );
  assert4.equal(
    addressFromPrivateKey(devKey.privateKey).address,
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
  );
  log("BIP-32 + EVM address vector: Hardhat account 0, mixed-case checksum");
  assert4.ok(equalBytes(refDerive(devSeed, "m/44'/60'/0'/0/0"), devKey.privateKey));
  assert4.equal(
    refFingerprint(devSeed),
    `0x${(HDKey.fromMasterSeed(devSeed).fingerprint >>> 0).toString(16).padStart(8, "0")}`
  );
  log("reference BIP-32 CKDpriv and master fingerprint agree");
  const rehearsalSeed = mnemonicToSeedSync(expectedPhrase, "");
  const rehearsal = primaryAccounts(rehearsalSeed, SAFE_OWNER_SCHEME, 1);
  assert4.equal(rehearsal.fingerprint, "0x5436d724");
  assert4.equal(
    rehearsal.accounts[0].address,
    "0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb"
  );
  assert4.equal(rehearsal.accounts[0].path, "m/44'/60'/0'/0/0");
  rehearsal.dispose();
  rehearsal.accounts[0].privateKey.fill(0);
  rehearsalSeed.fill(0);
  log("Safe owner public rehearsal vector: fingerprint, path and address");
  for (const scheme of Object.keys(PATH_SCHEMES)) {
    const { accounts, fingerprint, dispose } = primaryAccounts(devSeed, scheme, 5);
    crossCheck({
      phrase: devPhrase,
      passphrase: "",
      seed: devSeed,
      accounts,
      fingerprint
    });
    assert4.equal(new Set(accounts.map((a) => a.address)).size, accounts.length);
    for (const a of accounts) assert4.match(a.address, /^0x[0-9A-Fa-f]{40}$/);
    dispose();
    log(`scheme "${scheme}" (${templateFor(scheme)}) cross-checks clean`);
  }
  const withPass = HDKey.fromMasterSeed(mnemonicToSeedSync(devPhrase, "x")).derive(
    "m/44'/60'/0'/0/0"
  );
  assert4.ok(!equalBytes(withPass.privateKey, devKey.privateKey));
  log("BIP-39 passphrase produces a different wallet");
  assert4.throws(
    () => healthTest("stuck", Buffer.alloc(4096)),
    /repetition count/,
    "health test failed to reject an all-zero source"
  );
  const skewed = Buffer.alloc(4096);
  for (let i = 0; i < skewed.length; i += 1) skewed[i] = i % 2 ? 255 : 254;
  assert4.throws(
    () => healthTest("skewed", skewed),
    /adaptive proportion|monobit/,
    "health test failed to reject a skewed source"
  );
  assert4.throws(() => diceEntropy([1, 2, 3]), /at least/, "dice minimum not enforced");
  assert4.throws(
    () => crossCheck({
      phrase: devPhrase,
      passphrase: "",
      seed: devSeed,
      fingerprint: refFingerprint(devSeed),
      accounts: [
        {
          path: "m/44'/60'/0'/0/0",
          privateKey: Buffer.alloc(32, 1),
          address: "0x0000000000000000000000000000000000000000"
        }
      ]
    }),
    /CROSS-CHECK FAILED/,
    "cross-check failed to reject a tampered key"
  );
  assert4.throws(() => parsePath("x/1"), /must start with/, "path parser too permissive");
  assert4.notEqual(refEntropyToMnemonic(Buffer.alloc(32, 1), wordlist), expectedPhrase);
  log("negative tests: health, dice, cross-check and path guards all fire");
  slip39SelfTest({ vectors: slip39_vectors_default, fixtures: slip39_fixtures_default, log });
  qrSelfTest({ log });
  const repaired = repairWords("aban ABANDON  abandonx");
  assert4.equal(repaired.words[0], "abandon");
  assert4.equal(repaired.words[1], "abandon");
  assert4.equal(repaired.problems.length, 1);
  log("mnemonic repair: prefix expansion and typo detection");
  if (!quiet) {
    process3.stdout.write("\nSelf-test OK - all vectors and negative tests passed.\n");
  }
}
function isPermissionDenial(error) {
  for (let cause = error; cause; cause = cause.cause) {
    if (cause?.code === "ERR_ACCESS_DENIED") return true;
  }
  return false;
}
function describeFailure(error) {
  for (let cause = error; cause; cause = cause.cause) {
    if (cause?.code) return cause.code;
  }
  return error?.message ?? String(error);
}
async function proveSandbox() {
  const rows = [];
  const probe = async (name, fn) => {
    try {
      await fn();
      rows.push({ ok: false, name, detail: "ALLOWED" });
    } catch (error) {
      if (isPermissionDenial(error)) {
        rows.push({ ok: true, name, detail: "ERR_ACCESS_DENIED" });
      } else {
        rows.push({
          ok: false,
          name,
          detail: `NOT ENFORCED - failed with ${describeFailure(error)}, not a permission denial`
        });
      }
    }
  };
  process3.stdout.write("\nTRUSTED-CODE CAPABILITY GUARD\n");
  if (!process3.permission) {
    process3.stdout.write(
      "  x   Permission model is OFF - nothing below is enforced.\n      Run this through `npm run prove-guard`, which passes --permission.\n"
    );
  } else if (!supportsNetworkPermission()) {
    process3.stdout.write(
      `  x   This Node (${process3.version}) has no network permission scope. The
      two network probes below cannot be denied by it; --allow-net arrived
      in Node 25. Use Node 26 LTS.
`
    );
  }
  await probe("network: fetch()", () => fetch("http://127.0.0.1:65530"));
  await probe("network: dns lookup", async () => {
    const dns = await import("node:dns/promises");
    await dns.lookup("example.com");
  });
  await probe("subprocess: execSync", async () => {
    const cp = await import("node:child_process");
    cp.execSync("id");
  });
  await probe("worker thread", async () => {
    const wt = await import("node:worker_threads");
    new wt.Worker("", { eval: true });
  });
  await probe("file write", () => {
    const directory = fs.mkdtempSync(
      path.join(os2.tmpdir(), "heatdeath-capability-probe-")
    );
    fs.rmdirSync(directory);
  });
  await probe("read outside the package", () => fs.readFileSync(`${os2.homedir()}/.ssh/id_rsa`));
  for (const row of rows) {
    process3.stdout.write(
      `  ${row.ok ? "ok  " : "FAIL"}  ${row.name.padEnd(26)} ${row.detail}
`
    );
  }
  const sample = readUrandom(32);
  process3.stdout.write(
    `
  ok    /dev/urandom readable (${sample.length} bytes) - required for entropy
`
  );
  sample.fill(0);
  const denied = rows.filter((r) => r.ok).length;
  process3.stdout.write(
    `
${denied}/${rows.length} capability probes denied by the runtime.
`
  );
  process3.stdout.write(
    "\nSCOPE: this is not a malicious-code sandbox. Permission checks are a\nseatbelt for code whose provenance you already trust. A signed but\nmalicious program can attack its own process and secret memory.\n\nNOTE: inside a prebuilt binary this output proves nothing. The binary\ncontains this source as plain text and can be patched, and a patched\nbuild will happily print the same line. Self-attestation from an\nartifact an attacker controls is circular. Trust this result only when\nyou ran it from source you read, or from a build you reproduced\nyourself - see docs/en/VERIFY.md.\n"
  );
  if (denied !== rows.length) {
    throw new Error("the capability guard is NOT fully enforced - see FAIL rows above");
  }
}
async function generate({ showPrivate, showPublic, scheme, count, useDice, wipe, qr }) {
  assertRuntime();
  selfTest({ quiet: true });
  process3.stdout.write("\nSelf-test OK (run `npm run self-test` to see every vector).\n");
  const dice = useDice ? await readDice() : null;
  const { entropy, report } = collectEntropy({ dice });
  process3.stdout.write("\nENTROPY SOURCES\n");
  for (const r of report) process3.stdout.write(`  - ${r.name.padEnd(16)} ${r.status}
`);
  process3.stdout.write(
    `  = ${ENTROPY_BYTES * 8} bits, combined by XOR of domain-separated SHA-256
`
  );
  if (!useDice) {
    process3.stdout.write(
      "  ! No dice used. Every source above lives on this machine. Consider\n  ! `npm run generate:dice` for a source independent of it.\n"
    );
  }
  let seed = null;
  let bundle = null;
  try {
    const phrase = entropyToMnemonic(entropy, wordlist);
    assert4.equal(phrase.split(" ").length, 24);
    assert4.equal(validateMnemonic(phrase, wordlist), true);
    assert4.ok(
      equalBytes(mnemonicToEntropy(phrase, wordlist), entropy),
      "ROUND-TRIP FAILED: the mnemonic does not reconstruct the generated entropy"
    );
    const passphrase = await readPassphraseTwice({ newWallet: true });
    seed = mnemonicToSeedSync(phrase, passphrase);
    bundle = primaryAccounts(seed, scheme, count);
    const { accounts, fingerprint } = bundle;
    crossCheck({ entropy, phrase, passphrase, seed, accounts, fingerprint });
    assert4.equal(
      new Set(accounts.map((a) => a.address)).size,
      accounts.length,
      "Duplicate addresses in derivation output"
    );
    process3.stdout.write("\nVERIFICATION\n");
    process3.stdout.write("  ok  round-trip: the mnemonic reconstructs the exact entropy\n");
    process3.stdout.write(
      "  ok  cross-check: independent BIP-39/BIP-32 implementation agrees\n"
    );
    process3.stdout.write(`  ok  ${accounts.length} distinct addresses derived
`);
    printPhrase(phrase);
    process3.stdout.write(
      `
  BIP-39 passphrase:  ${passphrase ? "SET (not shown)" : "empty"}
`
    );
    process3.stdout.write(
      `  derivation scheme:  ${scheme} - ${templateFor(scheme)}
`
    );
    process3.stdout.write(
      `  master fingerprint: ${fingerprint}  (not secret; use it to confirm a restore)

`
    );
    if (PATH_SCHEMES[scheme].linkable) {
      process3.stdout.write(
        "  ! Privacy: every address below shares one extended public key. Anyone\n  ! holding it can link them all to a single wallet. Use --scheme=account\n  ! for addresses that are not linkable this way.\n\n"
      );
    }
    printAccounts(accounts, { showPrivate, showPublic });
    if (qr) printAddressQRs(accounts);
    if (!showPublic) {
      process3.stdout.write(
        "Public keys were not printed. Publishing the public key of an address that\nhas never sent a transaction removes its 160-bit hash barrier against a\nfuture quantum attack. Use --show-public only if you truly need them.\n"
      );
    }
    if (!showPrivate) {
      process3.stdout.write(
        "Private keys were not printed. The mnemonic already controls every derived\naccount, so exporting individual keys usually only adds risk.\n"
      );
    }
    const verifyCmd = scheme === DEFAULT_SCHEME ? "npm run verify" : `npm run verify:${scheme}`;
    process3.stdout.write(
      `
NEXT STEP - verify what you wrote, before funding anything:
    ${verifyCmd}
Use the SAME derivation scheme (${scheme}). Type the phrase from your
PAPER, not from this screen.

    master fingerprint   ${fingerprint}
`
    );
    if (accounts.length >= 2) {
      process3.stdout.write(
        `    index 1 address      ${accounts[1].address}

Confirm BOTH. The fingerprint and the index 0 address are identical
under both schemes, so only index 1 and above prove you verified with
the scheme you actually generated with.
`
      );
    } else {
      process3.stdout.write(
        `
Only one account was derived, and index 0 is the same path under both
schemes - so this run cannot prove which scheme you used. Verify with
    ${verifyCmd} -- --accounts=2
`
      );
    }
  } finally {
    if (bundle) {
      bundle.dispose();
      for (const a of bundle.accounts) a.privateKey.fill(0);
    }
    if (seed) seed.fill(0);
    entropy.fill(0);
    if (dice) dice.bytes.fill(0);
  }
  if (wipe) await offerScreenWipe();
}
async function verify({ scheme, count, showPrivate, showPublic, qr }) {
  assertRuntime();
  selfTest({ quiet: true });
  process3.stdout.write("\nSelf-test OK.\n");
  process3.stdout.write(
    "\nType the recovery phrase FROM YOUR PAPER BACKUP. Input is hidden.\nUnambiguous abbreviations of 3+ letters are expanded automatically, and\nunknown words are reported with their nearest wordlist candidates.\n\n"
  );
  const raw = await readInput("phrase: ");
  const { words, notes, problems } = repairWords(raw);
  if (notes.length > 0) {
    process3.stdout.write("\nEXPANSIONS\n");
    for (const n of notes) process3.stdout.write(`${n}
`);
  }
  if (problems.length > 0) {
    process3.stdout.write("\nPROBLEMS\n");
    for (const p of problems) process3.stdout.write(`${p}
`);
    throw new Error(`${problems.length} word(s) are not valid BIP-39 words`);
  }
  assert4.ok(
    [12, 15, 18, 21, 24].includes(words.length),
    `A BIP-39 phrase has 12/15/18/21/24 words; you entered ${words.length}`
  );
  const phrase = words.join(" ");
  assert4.equal(
    validateMnemonic(phrase, wordlist),
    true,
    "CHECKSUM FAILED. Every word is a valid BIP-39 word, but the phrase as a whole is not - a word is in the wrong position, or one word is wrong. Re-read the paper carefully; the order matters."
  );
  process3.stdout.write(`
  ok  ${words.length} valid words, BIP-39 checksum correct
`);
  const passphrase = await readPassphraseTwice();
  const seed = mnemonicToSeedSync(phrase, passphrase);
  const { accounts, fingerprint, dispose } = primaryAccounts(seed, scheme, count);
  crossCheck({ entropy: null, phrase, passphrase, seed, accounts, fingerprint });
  process3.stdout.write("  ok  cross-check: independent implementation agrees\n");
  process3.stdout.write(
    `
  BIP-39 passphrase:  ${passphrase ? "SET (not shown)" : "empty"}
`
  );
  process3.stdout.write(
    `  derivation scheme:  ${scheme} - ${templateFor(scheme)}
`
  );
  process3.stdout.write(`  master fingerprint: ${fingerprint}
`);
  process3.stdout.write(
    "  note: the fingerprint and the index 0 address are identical under both\n        schemes. Only index 1 and above tell them apart.\n\n"
  );
  printAccounts(accounts, { showPrivate, showPublic });
  if (qr) printAddressQRs(accounts);
  process3.stdout.write(
    "If the fingerprint and the addresses match what you recorded, the paper\nbackup is correct. If they do not, the phrase you typed is NOT the one you\ngenerated - do not fund it.\n"
  );
  dispose();
  for (const a of accounts) a.privateKey.fill(0);
  seed.fill(0);
}
var useColour = () => Boolean(process3.stdout.isTTY) && !process3.env.NO_COLOR;
var paint = (code, text) => useColour() ? `${ESC}[${code}m${text}${ESC}[0m` : text;
var bold = (t) => paint("1", t);
var dim = (t) => paint("2", t);
var red = (t) => paint("31", t);
var green = (t) => paint("32", t);
var yellow = (t) => paint("33", t);
function step(number, total, title) {
  process3.stdout.write(
    `
${bold(`${ESC}[7m STEP ${number}/${total} ${ESC}[0m`)} ${bold(title)}
${dim("-".repeat(64))}
`
  );
}
async function confirm(prompt, word) {
  const answer = await readInput(`${prompt} [${word}] `, { echo: true });
  return answer.trim().toLowerCase() === word.toLowerCase();
}
async function blindReadBack(phrase, { banner = "" } = {}) {
  const words = phrase.split(" ");
  const hidePhrase = () => {
    process3.stdout.write(`${ESC}[3J${ESC}[2J${ESC}[H`);
    process3.stdout.write(
      (banner ? `${red(banner)}

` : "") + `${bold("READ-BACK CHECK")}
The phrase is off the screen. Type it from your PAPER - not from memory,
and not by scrolling back. Input is hidden.
` + dim("(type `show` to display the phrase again)\n")
    );
  };
  while (!await confirm(`
${yellow("Written it down on paper?")} Type`, "written")) {
    process3.stdout.write(dim("  Take your time. The phrase is still on screen above.\n"));
  }
  hidePhrase();
  for (; ; ) {
    const typed = await readInput("\nphrase: ");
    if (typed.trim().toLowerCase() === "show") {
      printPhrase(phrase);
      while (!await confirm(`
${yellow("Phrase copied to paper?")} Type`, "written")) {
        process3.stdout.write(dim("  The phrase remains on screen until you confirm.\n"));
      }
      hidePhrase();
      continue;
    }
    const { words: fixed, notes, problems } = repairWords(typed);
    for (const note of notes) process3.stdout.write(dim(`${note}
`));
    for (const problem of problems) process3.stdout.write(red(`${problem}
`));
    const mismatches = [];
    for (let i = 0; i < Math.max(words.length, fixed.length); i += 1) {
      if (fixed[i] !== words[i]) mismatches.push(i + 1);
    }
    if (mismatches.length === 0) {
      process3.stdout.write(green("\n  MATCH. Your paper reproduces the phrase exactly.\n"));
      return;
    }
    process3.stdout.write(
      red(`
  MISMATCH at word ${mismatches.join(", ")}.
`) + "  Your paper is wrong; the generated phrase is correct. Fix the paper:\n"
    );
    for (const position of mismatches.slice(0, 24)) {
      const expected = words[position - 1] ?? "(missing)";
      const got = fixed[position - 1] ?? "(missing)";
      process3.stdout.write(
        `    ${String(position).padStart(2)}. correct: ${bold(expected)}   you typed: ${red(got)}
`
      );
    }
    process3.stdout.write(dim("\n  Correct the paper before continuing.\n"));
    while (!await confirm("Paper corrected? Type", "corrected")) {
      process3.stdout.write(dim("  The corrections remain on screen until you confirm.\n"));
    }
    hidePhrase();
  }
}
function deterministicRehearsalRng() {
  let counter = 0;
  const rng = (length) => {
    const out = Buffer.alloc(length);
    for (let offset = 0; offset < length; offset += 32) {
      const ctr = Buffer.alloc(4);
      ctr.writeUInt32BE(counter, 0);
      counter += 1;
      sha2562(Buffer.from(`${TOOL_ID}/public-rehearsal`), ctr).copy(out, offset);
    }
    return out;
  };
  rng.dispose = () => {
  };
  return rng;
}
function safeOwnerStep(number, title, rehearsal) {
  step(number, 6, title);
  if (rehearsal) process3.stdout.write(`${red(REHEARSAL_BANNER)}
`);
}
async function safeOwnerCeremony({ rehearsal }) {
  safeOwnerStep(1, "Environment, role and integrity", rehearsal);
  if (rehearsal) {
    if (!process3.stdin.isTTY || !process3.stdout.isTTY) {
      throw new Error("the interactive rehearsal requires a terminal");
    }
    process3.stdout.write(
      yellow("  This rehearsal uses a public deterministic phrase. It is safe to run\n") + "  while online, but every displayed word, share and address is public.\n"
    );
  } else {
    assertRuntime({ requirePermission: true });
  }
  selfTest({ quiet: true });
  process3.stdout.write(green("  ok  ") + "known-answer vectors passed before the ceremony\n\n");
  process3.stdout.write(
    bold("This profile creates ONE cold/recovery owner for a Safe.\n") + "It is not a daily signer, does not deploy or inspect a Safe, and does not\nsign transactions. Importing its phrase into an online wallet ends its\ncold status. Every Safe owner should have an independently generated seed.\n"
  );
  if (!await confirm("\nUse only as a cold/recovery owner? Type", "cold")) {
    throw new Error("stopped at your request - this profile is not for a daily signer");
  }
  if (!rehearsal) {
    process3.stdout.write(
      "\nConfirm Wi-Fi, Ethernet and Bluetooth are off; session logging and\nclipboard managers are disabled; paper and pen are ready.\n"
    );
    if (!await confirm("Environment ready? Type", "ready")) {
      throw new Error("stopped at your request - nothing was generated");
    }
  }
  safeOwnerStep(2, "Entropy", rehearsal);
  let dice = null;
  let entropy = null;
  let seed = null;
  let bundle = null;
  let failure = null;
  try {
    if (rehearsal) {
      entropy = Buffer.from(REHEARSAL_ENTROPY);
      process3.stdout.write("  Public fixture: 32 zero bytes from the official BIP-39 vector.\n");
    } else {
      process3.stdout.write(
        "The OS sources are sufficient. Physical dice add the only entropy source\nindependent of this computer (128 rolls minimum).\n\n"
      );
      if (await confirm("Mix in physical dice? Type", "yes")) dice = await readDice();
      const collected = collectEntropy({ dice });
      entropy = collected.entropy;
      for (const row of collected.report) {
        process3.stdout.write(`  ${green("ok")}  ${row.name.padEnd(16)} ${row.status}
`);
      }
    }
    safeOwnerStep(3, "BIP-39 passphrase", rehearsal);
    let passphrase = "";
    if (rehearsal) {
      process3.stdout.write(
        "  Rehearsal passphrase is fixed to empty. Never type a real passphrase\n  into a rehearsal. In a real ceremony an empty passphrase is the\n  operationally simpler default for a team recovery key.\n"
      );
    } else {
      process3.stdout.write(
        yellow("For an organisational recovery key, empty is the recommended default.\n") + "A set passphrase must be backed up separately, is absent from SLIP-39\nshares, and permanently destroys access if forgotten.\n"
      );
      passphrase = await readPassphraseTwice({ newWallet: true });
    }
    safeOwnerStep(4, "Generate one owner", rehearsal);
    const phrase = entropyToMnemonic(entropy, wordlist);
    assert4.ok(equalBytes(mnemonicToEntropy(phrase, wordlist), entropy));
    seed = mnemonicToSeedSync(phrase, passphrase);
    bundle = primaryAccounts(seed, SAFE_OWNER_SCHEME, 1);
    crossCheck({
      entropy,
      phrase,
      passphrase,
      seed,
      accounts: bundle.accounts,
      fingerprint: bundle.fingerprint
    });
    process3.stdout.write(green("  ok  ") + "round-trip and independent cross-check agree\n");
    if (rehearsal) process3.stdout.write(`${red(REHEARSAL_BANNER)}
`);
    printPhrase(phrase);
    safeOwnerStep(5, "Mandatory paper read-back", rehearsal);
    await blindReadBack(phrase, { banner: rehearsal ? REHEARSAL_BANNER : "" });
    process3.stdout.write(
      `
  role:               ${bold("Safe cold/recovery owner")}
  derivation path:    ${bold(pathFor(SAFE_OWNER_SCHEME, 0))}
  master fingerprint: ${bold(bundle.fingerprint)}
  OWNER ADDRESS:       ${bold(bundle.accounts[0].address)}
`
    );
    printAddressQRs(bundle.accounts);
    safeOwnerStep(6, "Threshold backup and independent verification", rehearsal);
    process3.stdout.write(
      "A single paper is a single point of failure. A 2-of-3 SLIP-39 backup\nsurvives one lost location. Shares contain the BIP-39 entropy, never\nthe optional passphrase.\n\n"
    );
    if (await confirm("Create 2-of-3 shares? Type", "yes")) {
      const rng = rehearsal ? deterministicRehearsalRng() : makeShamirRng();
      try {
        const groups = parseGroupSpec("2of3");
        const shares = splitSecretIntoShares({
          secret: entropy,
          passphrase: "",
          groupThreshold: 1,
          groups,
          extendable: true,
          iterationExponent: 0,
          rng
        });
        for (const subset of admissibleSubsets(1, groups, shares)) {
          assert4.ok(equalBytes(combineShares(subset, ""), entropy));
        }
        process3.stdout.write(green("\n  ok  ") + "all admissible share subsets recovered the entropy\n");
        if (rehearsal) process3.stdout.write(`${red(REHEARSAL_BANNER)}
`);
        printShares(shares, groups, 1);
      } finally {
        rng.dispose();
      }
    } else if (!await confirm("Accept the single-backup risk? Type", "single")) {
      throw new Error("backup choice not confirmed; the phrase remains on your paper");
    }
    process3.stdout.write(
      `
${bold("CEREMONY COMPLETE.")} Before adding this owner to a Safe:
  1. Shut down this session and verify from the paper in a fresh one.
  2. Have a second person compare the full checksummed owner address.
  3. Test the recovery procedure before the Safe holds meaningful funds.
  4. Never derive another Safe owner from this same phrase.
`
    );
    if (rehearsal) {
      process3.stdout.write(
        `
${red(REHEARSAL_BANNER)}
Feedback (never include seeds, private keys, balances or confidential data):
https://github.com/ilyamk/heatdeath/discussions
`
      );
    }
  } catch (error) {
    failure = error;
  } finally {
    bundle?.dispose();
    for (const account of bundle?.accounts ?? []) account.privateKey.fill(0);
    seed?.fill(0);
    entropy?.fill(0);
    if (dice) dice.bytes.fill(0);
  }
  if (!rehearsal) {
    try {
      await offerScreenWipe();
    } catch (wipeError) {
      if (!failure) throw wipeError;
    }
  }
  if (failure) throw failure;
}
function doctor() {
  const { blockers, warnings } = inspectRuntime({
    requireTty: true,
    requirePermission: true
  });
  process3.stdout.write("\nSAFE OWNER ENVIRONMENT DOCTOR\n\n");
  if (blockers.length === 0) process3.stdout.write("  ok  no blocking conditions detected\n");
  for (const row of blockers) process3.stdout.write(`  BLOCK  ${row.id}: ${row.message}
`);
  for (const row of warnings) process3.stdout.write(`  WARN   ${row.id}: ${row.message}
`);
  process3.stdout.write(
    "\nDoctor creates no secret. Its checks cannot detect terminal recording, host\nmalware, cameras or a compromised operating system.\n"
  );
  if (blockers.length > 0) process3.exitCode = 2;
}
async function wizard(cli) {
  const TOTAL = 6;
  const groups = parseGroupSpec(cli.shareSpec);
  assert4.ok(
    cli.groupThreshold >= 1 && cli.groupThreshold <= groups.length,
    `--group-threshold must be between 1 and ${groups.length}`
  );
  const layout = describeLayout(groups, cli.groupThreshold);
  step(1, TOTAL, "Environment and integrity");
  assertRuntime();
  selfTest({ quiet: true });
  process3.stdout.write(
    green("  ok  ") + "known-answer vectors passed before any secret exists\n" + (process3.permission ? green("  ok  ") + "capability guard active (`npm run prove-guard` to inspect it)\n" : yellow("  !   ") + "capability guard OFF - prefer signed npm commands\n")
  );
  process3.stdout.write(
    "\n" + bold("Before continuing, confirm you have:") + "\n  * turned off Wi-Fi, Ethernet and Bluetooth\n  * disabled iTerm2 Instant Replay and unlimited scrollback\n  * quit clipboard managers (Raycast, Paste, Alfred)\n  * paper and pen in front of you\n" + dim("  Details: QUICKSTART.md\n")
  );
  if (!await confirm("\nAll of the above done? Type", "ready")) {
    throw new Error("stopped at your request - nothing was generated");
  }
  step(2, TOTAL, "Entropy");
  let dice = null;
  process3.stdout.write(
    bold("Both answers give you a secure wallet. The difference is what you\nare trusting.\n\n") + `  ${bold("no")}  - 256 bits from two required OS paths with health checks.
        Fully automatic, takes seconds. This is what most people do.

  ${bold("yes")} - the same, PLUS numbers from a real die you roll yourself,
        mixed in by XOR. This is a PHYSICAL die: about ${Math.ceil(DICE_MIN_ROLLS / 6)} throws of a
        handful of dice, five to seven minutes of your time.

Dice are the only entropy source independent of this machine, so they
cover one specific scenario: the OS random generator itself being broken
or backdoored. They are XORed in, never substituted, so they cannot make
the result worse.
` + dim("  Not hypothetical: a firmware bug shipped by a hardware-wallet vendor\n  in 2026 cut real entropy to ~40 bits. Only users who had rolled\n  dice were unaffected.\n\n")
  );
  if (cli.useDice) {
    process3.stdout.write(dim("  --dice was given, so the dice step starts without asking.\n"));
    dice = await readDice();
  } else if (await confirm("Roll dice yourself? Type", "yes")) {
    dice = await readDice();
  } else {
    process3.stdout.write(
      yellow("  !   ") + "Continuing without dice. Every remaining source lives on\n      this machine, so you are trusting it completely.\n"
    );
  }
  const { entropy, report } = collectEntropy({ dice });
  for (const r of report) process3.stdout.write(`  ${green("ok")}  ${r.name.padEnd(16)} ${r.status}
`);
  step(3, TOTAL, "Passphrase - the optional 25th word");
  process3.stdout.write(
    bold("Both answers give you a secure wallet. The difference is what happens\nif someone finds your paper.\n\n") + `  ${bold("empty")} - the paper IS the wallet. Whoever reads those 24 words takes
          the funds. Opens in every wallet, MetaMask included.

  ${bold("set")}   - the 24 words alone become worthless: they open a different,
          empty wallet. But MetaMask cannot open yours at all, and
          forgetting the passphrase loses the funds permanently.

` + bold("If you set one, type 4 or more random words") + `, like
      ${dim("harbor tulip cactus velvet")}
  Not a password you use anywhere else. Not a phrase you expect to
  reconstruct from memory - write it down and store it in a DIFFERENT
  place from the 24 words, or it protects nothing.

` + yellow("  A short passphrase is the worst option of the three: too weak to\n  protect the paper, still strong enough to lose the funds if you\n  forget it.\n")
  );
  const passphrase = await readPassphraseTwice({ newWallet: true });
  step(4, TOTAL, "Generation");
  let seed = null;
  let bundle = null;
  try {
    const phrase = entropyToMnemonic(entropy, wordlist);
    assert4.equal(validateMnemonic(phrase, wordlist), true);
    assert4.ok(
      equalBytes(mnemonicToEntropy(phrase, wordlist), entropy),
      "ROUND-TRIP FAILED: the mnemonic does not reconstruct the generated entropy"
    );
    seed = mnemonicToSeedSync(phrase, passphrase);
    bundle = primaryAccounts(seed, cli.scheme, Math.max(cli.count, 2));
    crossCheck({
      entropy,
      phrase,
      passphrase,
      seed,
      accounts: bundle.accounts,
      fingerprint: bundle.fingerprint
    });
    process3.stdout.write(
      green("  ok  ") + "round-trip and independent cross-check both agree\n"
    );
    printPhrase(phrase);
    step(5, TOTAL, "Read-back - this is the step people skip");
    await blindReadBack(phrase);
    process3.stdout.write(
      `
  master fingerprint: ${bold(bundle.fingerprint)}
  scheme:             ${cli.scheme} - ${templateFor(cli.scheme)}
  index 1 address:    ${bold(bundle.accounts[1].address)}
` + dim("  Write these two down as well. They identify this wallet later.\n")
    );
    printAccounts(bundle.accounts.slice(0, cli.count), {
      showPrivate: cli.showPrivate,
      showPublic: cli.showPublic
    });
    if (cli.qr) printAddressQRs(bundle.accounts.slice(0, cli.count));
    step(6, TOTAL, "Backup against loss");
    process3.stdout.write(
      `One piece of paper is a single point of failure, and losing it is more
likely than any attack. SLIP-39 splits the wallet into shares: ${layout}
restore it. Fewer leave about 224 bits unknown; the SLIP-39 digest
prevents a literal zero-information claim.

` + dim("  Shares carry the entropy, NOT your passphrase. Store them apart.\n") + dim(`  Layout: --shares=${cli.shareSpec} --group-threshold=${cli.groupThreshold}

`)
    );
    if (await confirm(`Create SLIP-39 shares (${layout}) now? Type`, "yes")) {
      const rng = makeShamirRng();
      try {
        const shares = splitSecretIntoShares({
          secret: entropy,
          passphrase: "",
          groupThreshold: cli.groupThreshold,
          groups,
          extendable: true,
          iterationExponent: 0,
          rng
        });
        verifyShareLayout({
          groupThreshold: cli.groupThreshold,
          groups,
          shares,
          entropy,
          rng
        });
        printShares(shares, groups, cli.groupThreshold);
      } finally {
        rng.dispose();
      }
    }
    process3.stdout.write(
      `
${bold("DONE.")} Before you move meaningful funds:
  1. Import the phrase into your wallet. The addresses must match.
  2. Send a small amount. Confirm you can send it back.
  3. Re-check the backup any time with ${bold("npm run verify")}.
`
    );
  } finally {
    bundle?.dispose();
    for (const a of bundle?.accounts ?? []) a.privateKey.fill(0);
    entropy.fill(0);
    seed?.fill(0);
    if (dice) dice.bytes.fill(0);
  }
  await offerScreenWipe();
}
async function exportToOnePassword({ scheme, count, dryRun }) {
  assertRuntime();
  selfTest({ quiet: true });
  process3.stdout.write("\nSelf-test OK.\n");
  let spawn;
  try {
    ({ spawn } = await import("node:child_process"));
  } catch (error) {
    throw new Error(
      `cannot start a subprocess - run this through \`npm run op-export\`, which grants --allow-child-process (${error.code ?? error.message})`
    );
  }
  const collect = (child) => new Promise((resolve) => {
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => {
      out += d;
    });
    child.stderr.on("data", (d) => {
      err += d;
    });
    child.on("error", (e) => resolve({ code: -1, out: "", err: e.message }));
    child.on("close", (code) => resolve({ code, out, err }));
  });
  const SH = "/bin/sh";
  const CAT = "/bin/cat";
  const run = (bin, args) => {
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    return collect(child);
  };
  const resolved = await run(SH, ["-c", "command -v op"]);
  const opPath = resolved.out.trim();
  if (resolved.code !== 0 || !opPath.startsWith("/")) {
    throw new Error(
      "the 1Password CLI (op) was not found on PATH. Install it and enable its desktop-app integration, then try again."
    );
  }
  process3.stdout.write("\nChecking the 1Password CLI...\n");
  const version = await run(opPath, ["--version"]);
  if (version.code !== 0) {
    throw new Error(
      "`op` is not available. Install the 1Password CLI and enable its desktop-app integration, then try again."
    );
  }
  process3.stdout.write(`  ok  op ${version.out.trim()} at ${opPath}
`);
  const vaults = await run(opPath, ["vault", "list", "--format=json"]);
  if (vaults.code !== 0) {
    throw new Error(
      `\`op\` cannot reach your vaults: ${vaults.err.trim().slice(0, 200)}`
    );
  }
  const vaultList = JSON.parse(vaults.out).map((v) => v.name);
  process3.stdout.write(`  ok  ${vaultList.length} vault(s): ${vaultList.join(", ")}
`);
  process3.stdout.write(
    "\n" + bold("READ THIS BEFORE CONTINUING") + "\nThis writes the COMPLETE wallet into 1Password: the 24 words, the\nprivate keys, and all three SLIP-39 shares together in one item.\n\n" + yellow("  Three shares in one vault are not a threshold backup. They are the\n  secret in one place. Anyone who opens this item owns the wallet.\n\n") + "  That is acceptable for a short-lived staging buffer - the thing you\n  are doing right now - and it is not acceptable as storage. Move the\n  contents where they belong and DELETE THE ITEM. The command to delete\n  it is printed at the end.\n\n  Also: the seed leaves this machine. 1Password syncs it, encrypted, to\n  its servers, and decrypts it on every device where you unlock the\n  vault.\n"
  );
  if (dryRun) {
    process3.stdout.write(
      green("\n  DRY RUN") + " - op will preview the item and write nothing.\n  The prompts below are identical to the real run on purpose: a\n  rehearsal that skips steps rehearses the wrong thing.\n"
    );
  }
  if (!await confirm("\nUnderstood, continue? Type", "yes")) {
    throw new Error("cancelled - nothing was written");
  }
  process3.stdout.write(
    "\n" + bold("What do you want to stage?") + `

  ${bold("new")}      - generate a fresh wallet right now and stage it.
             Nothing needs to exist yet.

  ${bold("existing")} - stage a wallet you already have, by typing its
             24 words from paper.

`
  );
  let fresh = null;
  while (fresh === null) {
    const answer = (await readInput("new or existing? ", { echo: true })).trim().toLowerCase();
    if (answer === "new") fresh = true;
    else if (answer === "existing") fresh = false;
    else process3.stdout.write(dim("  Type exactly `new` or `existing`.\n"));
  }
  let phrase;
  let entropy;
  let passphrase;
  if (fresh) {
    process3.stdout.write(
      yellow("\n  Note: generating here means the seed is born in this process,\n  which runs at 5/6 because it may spawn `op`. Generating with\n  `npm run wizard` instead keeps the full 6/6 guard - but then\n  the phrase has to be typed back in here, which is its own\n  exposure. Neither is free; pick the one you prefer.\n")
    );
    const dice = await confirm("\nRoll dice for extra entropy? Type", "yes") ? await readDice() : null;
    const collected = collectEntropy({ dice });
    for (const r of collected.report) {
      process3.stdout.write(`  ${green("ok")}  ${r.name.padEnd(16)} ${r.status}
`);
    }
    entropy = collected.entropy;
    if (dice) dice.bytes.fill(0);
    phrase = entropyToMnemonic(entropy, wordlist);
    assert4.equal(phrase.split(" ").length, 24);
    assert4.equal(validateMnemonic(phrase, wordlist), true);
    assert4.ok(
      equalBytes(mnemonicToEntropy(phrase, wordlist), entropy),
      "ROUND-TRIP FAILED: the mnemonic does not reconstruct the generated entropy"
    );
    passphrase = await readPassphraseTwice({ newWallet: true });
    printPhrase(phrase);
    process3.stdout.write(
      yellow("\n  Write this on paper NOW, before it goes into 1Password.\n") + "  The 1Password item is a staging buffer you are going to delete;\n  the paper is what survives.\n"
    );
    while (!await confirm("\nWritten it down? Type", "written")) {
      process3.stdout.write(dim("  The phrase is still on screen above.\n"));
    }
  } else {
    process3.stdout.write(
      "\nType the recovery phrase to stage, FROM YOUR PAPER. Input is hidden.\n\n"
    );
    const raw = await readInput("phrase: ");
    const { words, notes, problems } = repairWords(raw);
    for (const note of notes) process3.stdout.write(dim(`${note}
`));
    if (problems.length > 0) {
      for (const problem of problems) process3.stdout.write(red(`${problem}
`));
      throw new Error(`${problems.length} word(s) are not valid BIP-39 words`);
    }
    phrase = words.join(" ");
    assert4.equal(
      validateMnemonic(phrase, wordlist),
      true,
      "CHECKSUM FAILED - a word is wrong or out of order. Nothing was written."
    );
    entropy = Buffer.from(mnemonicToEntropy(phrase, wordlist));
    passphrase = await readPassphraseTwice();
  }
  const seed = mnemonicToSeedSync(phrase, passphrase);
  const { accounts, fingerprint, dispose } = primaryAccounts(seed, scheme, count);
  const rng = makeShamirRng();
  try {
    crossCheck({ entropy, phrase, passphrase, seed, accounts, fingerprint });
    process3.stdout.write("\n  ok  cross-check: independent implementation agrees\n");
    const groups = parseGroupSpec("2of3");
    const shares = splitSecretIntoShares({
      secret: entropy,
      passphrase: "",
      groupThreshold: 1,
      groups,
      extendable: true,
      iterationExponent: 0,
      rng
    });
    for (const subset of admissibleSubsets(1, groups, shares)) {
      assert4.ok(
        equalBytes(combineShares(subset, ""), entropy),
        "ROUND-TRIP FAILED: a valid subset of shares does not restore the entropy"
      );
    }
    process3.stdout.write("  ok  all 3 SLIP-39 share combinations verified\n");
    const anchor = accounts[1] ?? accounts[0];
    process3.stdout.write(
      `
  master fingerprint: ${bold(fingerprint)}
  index ${anchor.index} address:    ${bold(anchor.address)}
` + dim("  Confirm these match what you recorded before writing anything.\n")
    );
    const stamp = (/* @__PURE__ */ new Date()).toISOString().replace(/\.\d+Z$/, "Z");
    const title = `HEATDEATH STAGING ${fingerprint} ${stamp}`;
    const fields = [
      {
        id: "notesPlain",
        type: "STRING",
        purpose: "NOTES",
        label: "notesPlain",
        value: `TEMPORARY STAGING ITEM - DELETE AFTER TRANSFER.

This item contains a complete wallet: the recovery phrase, derived private keys, and ALL THREE SLIP-39 shares. Three shares in one place are not a threshold backup - whoever opens this item owns the wallet.

Move each part where it belongs (shares to three SEPARATE physical locations, phrase to paper) and then delete this item.

Created by HEATDEATH, derivation ${templateFor(scheme)}, ${stamp}.`
      },
      { id: "mnemonic", type: "CONCEALED", label: "BIP-39 mnemonic (24 words)", value: phrase },
      {
        id: "bip39_passphrase",
        type: "STRING",
        label: "BIP-39 passphrase",
        value: passphrase ? "SET - stored separately on purpose, NOT in this item" : "empty (standard wallet)"
      },
      { id: "fingerprint", type: "STRING", label: "master fingerprint", value: fingerprint },
      { id: "derivation", type: "STRING", label: "derivation path", value: templateFor(scheme) }
    ];
    accounts.forEach((a) => {
      fields.push({ id: `addr_${a.index}`, type: "STRING", label: `address ${a.index} (${a.path})`, value: a.address });
      fields.push({ id: `pub_${a.index}`, type: "CONCEALED", label: `public key ${a.index}`, value: `0x${bytesToHex(a.publicKey)}` });
      fields.push({ id: `priv_${a.index}`, type: "CONCEALED", label: `private key ${a.index}`, value: `0x${a.privateKey.toString("hex")}` });
    });
    shares[0].forEach((share, i) => {
      fields.push({
        id: `slip39_${i + 1}`,
        type: "CONCEALED",
        label: `SLIP-39 share ${i + 1} of 3 (any 2 restore)`,
        value: share
      });
    });
    const vault = vaultList.includes("Private") ? "Private" : vaultList[0];
    process3.stdout.write(
      `
Writing ${fields.length} fields to vault ${bold(vault)}.
Route: this process -> cat -> op, all on stdin. Never an argument,
never an environment variable, never a file on disk.
` + dim("(cat is there because op refuses the socket Node hands a child;\n the shell pipe between them is a real one. See the source.)\n1Password may ask you to authorise this.\n")
    );
    const payload = Buffer.from(
      JSON.stringify({ title, category: "SECURE_NOTE", fields }),
      "utf8"
    );
    let created;
    try {
      created = await sendSecretPayload({
        spawn,
        shell: SH,
        cat: CAT,
        opPath,
        vault,
        payload,
        preview: dryRun
      });
    } finally {
      payload.fill(0);
    }
    if (created.code !== 0) {
      throw new Error(
        `op item create failed (exit ${created.code}); its stderr is withheld because it handled secret input.

  Check: 1Password unlocked, and Settings > Developer >
  "Integrate with 1Password CLI" enabled. Try \`op vault list\`
  in a terminal first - it will prompt for authorisation.`
      );
    }
    if (dryRun) {
      process3.stdout.write(
        green("\n  ok  ") + "DRY RUN succeeded - op accepted the item and wrote NOTHING.\n      Re-run without --dry-run to create it for real.\n"
      );
      return;
    }
    process3.stdout.write(
      green("\n  ok  ") + `item created in vault ${vault}
      title: ${title}
`
    );
    process3.stdout.write(
      "\n" + bold("NOW FINISH THE JOB:") + `
  1. Move the three SLIP-39 shares to three SEPARATE physical places.
  2. Write the 24 words on paper and verify with \`npm run verify\`.
  3. Delete this item - it is a staging buffer, not storage:

       op item delete "${title}" --vault ${vault}

` + dim("  Until you do, your entire wallet sits in one 1Password item and\n  is synced to their servers.\n")
    );
  } finally {
    rng.dispose();
    dispose();
    for (const a of accounts) a.privateKey.fill(0);
    entropy.fill(0);
    seed.fill(0);
  }
}
async function split2({ shareSpec, groupThreshold, scheme, count }) {
  assertRuntime();
  selfTest({ quiet: true });
  process3.stdout.write("\nSelf-test OK.\n");
  const groups = parseGroupSpec(shareSpec);
  assert4.ok(
    groupThreshold >= 1 && groupThreshold <= groups.length,
    `--group-threshold must be between 1 and ${groups.length}`
  );
  process3.stdout.write(
    "\nType the recovery phrase you want to back up, FROM YOUR PAPER.\nInput is hidden. Abbreviations of 3+ letters are expanded.\n\n"
  );
  const raw = await readInput("phrase: ");
  const { words, notes, problems } = repairWords(raw);
  for (const note of notes) process3.stdout.write(`${note}
`);
  if (problems.length > 0) {
    for (const p of problems) process3.stdout.write(`${p}
`);
    throw new Error(`${problems.length} word(s) are not valid BIP-39 words`);
  }
  const phrase = words.join(" ");
  assert4.equal(
    validateMnemonic(phrase, wordlist),
    true,
    "CHECKSUM FAILED - a word is wrong or out of order. Nothing was split."
  );
  const entropy = Buffer.from(mnemonicToEntropy(phrase, wordlist));
  process3.stdout.write(
    `  ok  ${words.length} words, checksum correct, ${entropy.length * 8}-bit entropy
`
  );
  process3.stdout.write(
    "\nWhich wallet is this? Enter the BIP-39 passphrase you use with this\nphrase, so the fingerprint below matches what `npm run verify` showed.\nIt is NOT stored in the shares.\n"
  );
  const idPassphrase = await readPassphraseTwice();
  const idSeed = mnemonicToSeedSync(phrase, idPassphrase);
  const idBundle = primaryAccounts(idSeed, scheme, Math.max(count, 2));
  crossCheck({
    entropy,
    phrase,
    passphrase: idPassphrase,
    seed: idSeed,
    accounts: idBundle.accounts,
    fingerprint: idBundle.fingerprint
  });
  process3.stdout.write(
    `
YOU ARE ABOUT TO SPLIT THIS WALLET
  master fingerprint: ${idBundle.fingerprint}
  scheme:             ${scheme} - ${templateFor(scheme)}
  index 1 address:    ${idBundle.accounts[1].address}

  If these do not match what you recorded when you generated this
  wallet, STOP. You mistyped a word in a way the checksum accepted,
  and you are about to back up someone else's wallet.
`
  );
  idBundle.dispose();
  for (const a of idBundle.accounts) a.privateKey.fill(0);
  idSeed.fill(0);
  process3.stdout.write(
    "\nNOTE ON PASSPHRASES\n  SLIP-39 shares carry the ENTROPY only. A BIP-39 passphrase (the 25th\n  word) is NOT included and cannot be recovered from them. If this\n  wallet uses one, these shares alone restore nothing - store the\n  passphrase separately, and remember that losing it loses the funds.\n  This tool deliberately does not offer SLIP-39's own passphrase: two\n  different passphrase concepts in one backup is a way to lose money.\n"
  );
  const rng = makeShamirRng();
  let shares;
  try {
    shares = splitSecretIntoShares({
      secret: entropy,
      passphrase: "",
      groupThreshold,
      groups,
      extendable: true,
      iterationExponent: 0,
      rng
    });
    verifyShareLayout({ groupThreshold, groups, shares, entropy, rng });
    printShares(shares, groups, groupThreshold);
    process3.stdout.write(
      `
NEXT STEP - before you rely on these, test recovery:
    npm run combine
Type a threshold subset and confirm it prints the same phrase and the
same index 1 address as \`npm run verify\`.
`
    );
  } finally {
    rng.dispose();
    entropy.fill(0);
  }
}
async function combine({ scheme, count, showPrivate, showPublic, qr }) {
  assertRuntime();
  selfTest({ quiet: true });
  process3.stdout.write("\nSelf-test OK.\n");
  const mnemonics = await readShares();
  const entropy = combineShares(mnemonics, "");
  process3.stdout.write(
    `
  ok  ${mnemonics.length} shares combined into ${entropy.length * 8} bits
`
  );
  const phrase = entropyToMnemonic(entropy, wordlist);
  assert4.equal(validateMnemonic(phrase, wordlist), true);
  assert4.ok(
    equalBytes(mnemonicToEntropy(phrase, wordlist), entropy),
    "ROUND-TRIP FAILED: recovered entropy does not survive BIP-39 encoding"
  );
  const passphrase = await readPassphraseTwice();
  const seed = mnemonicToSeedSync(phrase, passphrase);
  const { accounts, fingerprint, dispose } = primaryAccounts(seed, scheme, count);
  crossCheck({ entropy, phrase, passphrase, seed, accounts, fingerprint });
  process3.stdout.write("  ok  cross-check: independent implementation agrees\n");
  printPhrase(phrase);
  process3.stdout.write(
    `
  BIP-39 passphrase:  ${passphrase ? "SET (not shown)" : "empty"}
`
  );
  process3.stdout.write(`  derivation scheme:  ${scheme} - ${templateFor(scheme)}
`);
  process3.stdout.write(`  master fingerprint: ${fingerprint}
`);
  process3.stdout.write(
    `  note: the fingerprint and the index 0 address are identical under both
        schemes. Only index 1 and above tell them apart, so if you split
        an --scheme=account wallet, recombine with that same scheme.

`
  );
  printAccounts(accounts, { showPrivate, showPublic });
  if (qr) printAddressQRs(accounts);
  process3.stdout.write(
    "These shares were assumed to come from `npm run split`, which uses no\nSLIP-39 passphrase. A share set produced elsewhere WITH one decrypts to\ndifferent bytes and still yields a valid-looking phrase for a wallet that\nis not yours - the SLIP-39 digest cannot detect it. Your safety net is\nthe fingerprint above: if it does not match what you recorded, stop.\n"
  );
  dispose();
  for (const a of accounts) a.privateKey.fill(0);
  entropy.fill(0);
  seed.fill(0);
}
var LICENCE_NOTICE = `
HEATDEATH - offline BIP-39 / EVM seed generator
Copyright (C) 2026 ILIA MAKSIMENKA

This program is free software under the GNU Affero General Public License,
version 3 or later. You may use, study, modify and redistribute it, but a
redistributed or network-deployed derivative must be released under the same
licence, with its source. See LICENSE for the full terms.

This program comes with ABSOLUTELY NO WARRANTY. It generates keys that control
money; you carry that risk yourself, and no third party has audited this tool.

Embedded third-party material is under its own terms - MIT and three-clause
BSD, both GPL-compatible. See NOTICE.md for the full list and their notices.

A separate commercial licence is available if AGPL-3.0 does not suit you.
`;
var USAGE = `
HEATDEATH - offline BIP-39 / EVM seed generator. Hardened build.

  node generate.mjs --wizard   [options]   guided end-to-end setup (start here)
  node generate.mjs --doctor               inspect readiness without a secret
  node generate.mjs --rehearse-safe-owner  public Safe cold-owner rehearsal
  node generate.mjs --safe-owner            create one Safe cold/recovery owner
  node generate.mjs --self-test            run every known-answer and negative test
  node generate.mjs --generate [options]   create a new 24-word wallet
  node generate.mjs --verify   [options]   re-derive from a phrase you type
  node generate.mjs --split    [options]   split a phrase into SLIP-39 shares
  node generate.mjs --combine  [options]   restore a phrase from SLIP-39 shares
  node generate.mjs --op-export            generate or stage a wallet into 1Password
  node generate.mjs --prove-guard          show the trusted-code capability guard
  node generate.mjs --license              licence and third-party notices

Options
  --dice                 mix in d6 rolls typed by hand (the only entropy
                         source independent of this machine)
  --scheme=metamask      m/44'/60'/0'/0/i  (default; MetaMask, Rabby, Trust)
  --scheme=account       m/44'/60'/i'/0/0  (Ledger Live; not xpub-linkable)
  --accounts=N           how many addresses to derive (default ${DEFAULT_ACCOUNTS}, max ${MAX_ACCOUNTS})
  --show-public          also print public keys (see the warning it prints)
  --show-private         also print private keys (rarely needed)
  --wipe-screen          offer to clear screen and scrollback when finished
  --dry-run              with --op-export: let op preview the item and write
                         nothing. Rehearse the flow before committing to it.
  --qr                   also print the ADDRESS LIST as scannable QR codes,
                         so a second device can be compared without retyping.
                         Addresses only - never the phrase, keys or shares.
  --shares=2of3          SLIP-39 layout for --split. Comma-separate for
                         multiple groups, e.g. --shares=2of3,3of5
  --group-threshold=N    how many groups are needed (default 1)

--op-export writes the COMPLETE wallet - phrase, private keys and all three
SLIP-39 shares - into ONE 1Password item, as a staging buffer for the moment
of creation. Three shares in one vault are not a threshold backup; delete the
item once the contents are where they belong. It needs --allow-child-process
to run the op CLI, so its capability scope is 5/6 instead of 6/6, which is why it is a
separate command. The secret reaches op only through the child's stdin -
never argv, never an environment variable, never a file.

SLIP-39 shares here carry the BIP-39 ENTROPY, not a BIP-32 seed. Restore them
with --combine. A Trezor reads a SLIP-39 secret as a seed directly and would
show different addresses. Shares never carry your BIP-39 passphrase.

Node 26 LTS is required. The capability guard's network scope (--allow-net)
exists only from Node 25; on an older runtime --prove-guard reports the network
probes as NOT ENFORCED and the launchers refuse secret-capable commands.

On macOS a downloaded binary is quarantined and Gatekeeper kills it silently
(exit 137, no output). Clear it with:  xattr -d com.apple.quarantine ./FILE

Secrets are read interactively with echo disabled and are never accepted as
command-line arguments: argv is visible to every process via \`ps\` and is
recorded in shell history.
`;
var parseArgs = (argv) => parseCli(argv, {
  defaultScheme: DEFAULT_SCHEME,
  schemes: Object.keys(PATH_SCHEMES),
  defaultAccounts: DEFAULT_ACCOUNTS,
  maxAccounts: MAX_ACCOUNTS
});
try {
  const cli = parseArgs(process3.argv.slice(2));
  if (cli.command === "self-test") {
    assertRuntime({ requireTty: false });
    selfTest();
  } else if (cli.command === "doctor") {
    doctor();
  } else if (cli.command === "rehearse-safe-owner") {
    await safeOwnerCeremony({ rehearsal: true });
  } else if (cli.command === "safe-owner") {
    await safeOwnerCeremony({ rehearsal: false });
  } else if (cli.command === "wizard") {
    await wizard(cli);
  } else if (cli.command === "generate") {
    await generate(cli);
  } else if (cli.command === "verify") {
    await verify(cli);
  } else if (cli.command === "split") {
    await split2(cli);
  } else if (cli.command === "combine") {
    await combine(cli);
  } else if (cli.command === "op-export") {
    await exportToOnePassword(cli);
  } else if (cli.command === "license") {
    process3.stdout.write(LICENCE_NOTICE);
  } else if (cli.command === "prove-guard") {
    await proveSandbox();
  } else {
    process3.stdout.write(USAGE);
    process3.exitCode = 0;
  }
} catch (error) {
  process3.stderr.write(`
ERROR: ${error.message}
`);
  process3.exitCode = 1;
}
/*! Bundled license information:

@noble/curves/utils.js:
@noble/curves/abstract/modular.js:
@noble/curves/abstract/curve.js:
@noble/curves/abstract/der.js:
@noble/curves/abstract/weierstrass.js:
@noble/curves/secp256k1.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@scure/base/index.js:
  (*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@scure/bip32/index.js:
  (*! scure-bip32 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) *)

@scure/bip39/index.js:
  (*! scure-bip39 - MIT License (c) 2022 Patricio Palladino, Paul Miller (paulmillr.com) *)
*/
