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
// SLIP-39: Shamir's Secret Sharing for mnemonic codes.
// https://github.com/satoshilabs/slips/blob/master/slip-0039.md
//
// WHY THIS MODULE EXISTS
// ----------------------
// A single 24-word phrase on a single piece of paper is a single point of
// failure. Fire, water, theft and simple misplacement destroy it, and those
// are more probable than any attack in this project's threat model. SLIP-39
// splits a secret into shares such that any `threshold` of them reconstruct
// it and any fewer reveal NOTHING (information-theoretically, not merely
// computationally).
//
// HOW IT IS WIRED, AND WHY IT KEEPS MetaMask COMPATIBILITY
// --------------------------------------------------------
// Shamir is applied to the SAME 32 bytes of entropy from which the BIP-39
// mnemonic is built. The wallet stays an ordinary BIP-39 wallet; SLIP-39 is
// only a backup FORMAT. Recombining a threshold of shares yields exactly
// those 32 bytes, hence the same phrase and the same addresses. Nothing here
// changes what a wallet imports.
//
// DELIBERATE DEVIATION FROM THIS PROJECT'S "TWO IMPLEMENTATIONS" RULE
// -------------------------------------------------------------------
// generate.mjs derives every key twice, in two independent implementations,
// and refuses to print unless they agree. That rule is NOT applied here, and
// the reason is deliberate rather than lazy:
//
//   * There is no audited SLIP-39 package in the @noble/@scure ecosystem
//     (@scure/slip39 does not exist). Adding an unaudited third-party
//     dependency to the one tool whose entire posture is "four pinned,
//     audited packages" would cost more security than it buys.
//   * A second in-process implementation by the same author would share any
//     misreading of the specification, which is the dominant risk when
//     implementing a standard from scratch.
//
// What is used instead is STRONGER for this specific operation:
//
//   1. All 45 official test vectors from trezor/python-shamir-mnemonic —
//      15 that must decode to a known secret and 30 that must be REJECTED.
//      These were produced by the reference implementation, so they are a
//      genuine external check, not a self-consistency check.
//   2. Verification of the wordlist against its published SHA-256.
//   3. EXHAUSTIVE round-trip: after splitting, the secret is recovered from
//      EVERY admissible subset of shares and compared against the original.
//      This tests the property that actually matters — "any threshold of
//      these papers restores my wallet" — directly rather than by proxy.
//
// See README.md, section "SLIP-39".
//

import assert from "node:assert/strict";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";

// ---------------------------------------------------------------------------
// SPECIFICATION CONSTANTS
// ---------------------------------------------------------------------------

const RADIX_BITS = 10; // one wordlist index per 10 bits
const ID_LENGTH_BITS = 15;
const EXTENDABLE_FLAG_LENGTH_BITS = 1;
const ITERATION_EXP_LENGTH_BITS = 4;
const ID_EXP_LENGTH_WORDS = 2; // (15 + 1 + 4) / 10
const CHECKSUM_LENGTH_WORDS = 3;
const DIGEST_LENGTH_BYTES = 4;
const METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS; // 7
const MIN_STRENGTH_BITS = 128;
const MAX_SHARE_COUNT = 16;
const SECRET_INDEX = 255;
const DIGEST_INDEX = 254;
const BASE_ITERATION_COUNT = 10000;
const ROUND_COUNT = 4;

const CUSTOMIZATION_STRING_ORIG = Buffer.from("shamir", "utf8");
const CUSTOMIZATION_STRING_EXTENDABLE = Buffer.from("shamir_extendable", "utf8");

// SHA-256 of the canonical SLIP-39 wordlist (wordlist.txt from
// trezor/python-shamir-mnemonic, newline separated with a trailing newline).
// A mismatch means shares produced here would be unreadable by every other
// SLIP-39 implementation.
export const SLIP39_WORDLIST_SHA256 =
  "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3";

export const SLIP39_WORDLIST = (
  "academic acid acne acquire acrobat activity actress adapt adequate adjust " +
  "admit adorn adult advance advocate afraid again agency agree aide aircraft " +
  "airline airport ajar alarm album alcohol alien alive alpha already alto " +
  "aluminum always amazing ambition amount amuse analysis anatomy ancestor " +
  "ancient angel angry animal answer antenna anxiety apart aquatic arcade " +
  "arena argue armed artist artwork aspect auction august aunt average " +
  "aviation avoid award away axis axle beam beard beaver become bedroom " +
  "behavior being believe belong benefit best beyond bike biology birthday " +
  "bishop black blanket blessing blimp blind blue body bolt boring born both " +
  "boundary bracelet branch brave breathe briefing broken brother browser " +
  "bucket budget building bulb bulge bumpy bundle burden burning busy buyer " +
  "cage calcium camera campus canyon capacity capital capture carbon cards " +
  "careful cargo carpet carve category cause ceiling center ceramic champion " +
  "change charity check chemical chest chew chubby cinema civil class clay " +
  "cleanup client climate clinic clock clogs closet clothes club cluster coal " +
  "coastal coding column company corner costume counter course cover cowboy " +
  "cradle craft crazy credit cricket criminal crisis critical crowd crucial " +
  "crunch crush crystal cubic cultural curious curly custody cylinder daisy " +
  "damage dance darkness database daughter deadline deal debris debut decent " +
  "decision declare decorate decrease deliver demand density deny depart " +
  "depend depict deploy describe desert desire desktop destroy detailed " +
  "detect device devote diagnose dictate diet dilemma diminish dining diploma " +
  "disaster discuss disease dish dismiss display distance dive divorce " +
  "document domain domestic dominant dough downtown dragon dramatic dream " +
  "dress drift drink drove drug dryer duckling duke duration dwarf dynamic " +
  "early earth easel easy echo eclipse ecology edge editor educate either " +
  "elbow elder election elegant element elephant elevator elite else email " +
  "emerald emission emperor emphasis employer empty ending endless endorse " +
  "enemy energy enforce engage enjoy enlarge entrance envelope envy epidemic " +
  "episode equation equip eraser erode escape estate estimate evaluate " +
  "evening evidence evil evoke exact example exceed exchange exclude excuse " +
  "execute exercise exhaust exotic expand expect explain express extend extra " +
  "eyebrow facility fact failure faint fake false family famous fancy fangs " +
  "fantasy fatal fatigue favorite fawn fiber fiction filter finance findings " +
  "finger firefly firm fiscal fishing fitness flame flash flavor flea " +
  "flexible flip float floral fluff focus forbid force forecast forget formal " +
  "fortune forward founder fraction fragment frequent freshman friar fridge " +
  "friendly frost froth frozen fumes funding furl fused galaxy game garbage " +
  "garden garlic gasoline gather general genius genre genuine geology gesture " +
  "glad glance glasses glen glimpse goat golden graduate grant grasp gravity " +
  "gray greatest grief grill grin grocery gross group grownup grumpy guard " +
  "guest guilt guitar gums hairy hamster hand hanger harvest have havoc hawk " +
  "hazard headset health hearing heat helpful herald herd hesitate hobo " +
  "holiday holy home hormone hospital hour huge human humidity hunting " +
  "husband hush husky hybrid idea identify idle image impact imply improve " +
  "impulse include income increase index indicate industry infant inform " +
  "inherit injury inmate insect inside install intend intimate invasion " +
  "involve iris island isolate item ivory jacket jerky jewelry join judicial " +
  "juice jump junction junior junk jury justice kernel keyboard kidney kind " +
  "kitchen knife knit laden ladle ladybug lair lamp language large laser " +
  "laundry lawsuit leader leaf learn leaves lecture legal legend legs lend " +
  "length level liberty library license lift likely lilac lily lips liquid " +
  "listen literary living lizard loan lobe location losing loud loyalty luck " +
  "lunar lunch lungs luxury lying lyrics machine magazine maiden mailman main " +
  "makeup making mama manager mandate mansion manual marathon march market " +
  "marvel mason material math maximum mayor meaning medal medical member " +
  "memory mental merchant merit method metric midst mild military mineral " +
  "minister miracle mixed mixture mobile modern modify moisture moment " +
  "morning mortgage mother mountain mouse move much mule multiple muscle " +
  "museum music mustang nail national necklace negative nervous network news " +
  "nuclear numb numerous nylon oasis obesity object observe obtain ocean " +
  "often olympic omit oral orange orbit order ordinary organize ounce oven " +
  "overall owner paces pacific package paid painting pajamas pancake pants " +
  "papa paper parcel parking party patent patrol payment payroll peaceful " +
  "peanut peasant pecan penalty pencil percent perfect permit petition " +
  "phantom pharmacy photo phrase physics pickup picture piece pile pink " +
  "pipeline pistol pitch plains plan plastic platform playoff pleasure plot " +
  "plunge practice prayer preach predator pregnant premium prepare presence " +
  "prevent priest primary priority prisoner privacy prize problem process " +
  "profile program promise prospect provide prune public pulse pumps punish " +
  "puny pupal purchase purple python quantity quarter quick quiet race racism " +
  "radar railroad rainbow raisin random ranked rapids raspy reaction realize " +
  "rebound rebuild recall receiver recover regret regular reject relate " +
  "remember remind remove render repair repeat replace require rescue " +
  "research resident response result retailer retreat reunion revenue review " +
  "reward rhyme rhythm rich rival river robin rocky romantic romp roster " +
  "round royal ruin ruler rumor sack safari salary salon salt satisfy satoshi " +
  "saver says scandal scared scatter scene scholar science scout scramble " +
  "screw script scroll seafood season secret security segment senior shadow " +
  "shaft shame shaped sharp shelter sheriff short should shrimp sidewalk " +
  "silent silver similar simple single sister skin skunk slap slavery sled " +
  "slice slim slow slush smart smear smell smirk smith smoking smug snake " +
  "snapshot sniff society software soldier solution soul source space spark " +
  "speak species spelling spend spew spider spill spine spirit spit spray " +
  "sprinkle square squeeze stadium staff standard starting station stay " +
  "steady step stick stilt story strategy strike style subject submit sugar " +
  "suitable sunlight superior surface surprise survive sweater swimming swing " +
  "switch symbolic sympathy syndrome system tackle tactics tadpole talent " +
  "task taste taught taxi teacher teammate teaspoon temple tenant tendency " +
  "tension terminal testify texture thank that theater theory therapy thorn " +
  "threaten thumb thunder ticket tidy timber timely ting tofu together " +
  "tolerate total toxic tracks traffic training transfer trash traveler treat " +
  "trend trial tricycle trip triumph trouble true trust twice twin type " +
  "typical ugly ultimate umbrella uncover undergo unfair unfold unhappy union " +
  "universe unkind unknown unusual unwrap upgrade upstairs username usher " +
  "usual valid valuable vampire vanish various vegan velvet venture verdict " +
  "verify very veteran vexed victim video view vintage violence viral visitor " +
  "visual vitamins vocal voice volume voter voting walnut warmth warn watch " +
  "wavy wealthy weapon webcam welcome welfare western width wildlife window " +
  "wine wireless wisdom withdraw wits wolf woman work worthy wrap wrist " +
  "writing wrote year yelp yield yoga zero"
).split(" ");

const WORD_INDEX = new Map(SLIP39_WORDLIST.map((w, i) => [w, i]));

export function assertSlip39WordlistIntegrity() {
  assert.equal(SLIP39_WORDLIST.length, 1024, "SLIP-39 wordlist must have 1024 words");
  const digest = createHash("sha256")
    .update(`${SLIP39_WORDLIST.join("\n")}\n`)
    .digest("hex");
  assert.equal(
    digest,
    SLIP39_WORDLIST_SHA256,
    "SLIP-39 wordlist does not match the published SHA-256; shares produced " +
      "with it would not be readable by other implementations",
  );
}

// ---------------------------------------------------------------------------
// GF(256) ARITHMETIC
// ---------------------------------------------------------------------------

const EXP = new Uint8Array(255);
const LOG = new Uint8Array(256);
{
  let poly = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = poly;
    LOG[poly] = i;
    // Multiply by the polynomial (x + 1), i.e. by 3 - NOT by 2. For the AES
    // reduction polynomial the element 2 is not primitive, so a doubling
    // generator produces a table that is silently wrong for most products.
    poly = (poly << 1) ^ poly;
    if (poly & 0x100) poly ^= 0x11b; // reduce by x^8 + x^4 + x^3 + x + 1
  }
}

/**
 * Lagrange interpolation of the shares at abscissa `x`, over GF(256),
 * performed independently on each byte position.
 */
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
    for (const xj of xs) sum += LOG[xi ^ xj]; // xj === xi contributes LOG[0] = 0
    // JS % keeps the sign of the dividend, so normalise into [0, 255).
    const basis = (((logProd - LOG[xi ^ x] - sum) % 255) + 255) % 255;
    for (let k = 0; k < result.length; k += 1) {
      const v = yi[k];
      result[k] ^= v === 0 ? 0 : EXP[(LOG[v] + basis) % 255];
    }
  }
  return result;
}

function createDigest(randomData, sharedSecret) {
  return createHmac("sha256", randomData)
    .update(sharedSecret)
    .digest()
    .subarray(0, DIGEST_LENGTH_BYTES);
}

function splitSecret(threshold, shareCount, sharedSecret, rng) {
  assert.ok(threshold >= 1, "Threshold must be a positive integer");
  assert.ok(threshold <= shareCount, "Threshold exceeds the number of shares");
  assert.ok(shareCount <= MAX_SHARE_COUNT, `At most ${MAX_SHARE_COUNT} shares`);

  // Threshold 1 means every share IS the secret, so this returns identical
  // copies. That is correct and useful at the GROUP level - group threshold 1
  // over several groups is the "either location recovers on its own" topology,
  // and no individual share is a bare copy because each group is itself split.
  // It is NOT acceptable at the MEMBER level, where it would hand out bare
  // copies of the group secret; splitSecretIntoShares rejects that case per
  // group, exactly as the reference implementation does.
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
    [SECRET_INDEX, Buffer.from(sharedSecret)],
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
    "Invalid digest of the shared secret: the shares do not belong together, " +
      "or one of them was transcribed incorrectly",
  );
  return sharedSecret;
}

// ---------------------------------------------------------------------------
// PASSPHRASE ENCRYPTION (4-round Feistel network over PBKDF2-HMAC-SHA256)
// ---------------------------------------------------------------------------

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
    "sha256",
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

const encryptSecret = (s, p, e, id, ext) => feistel(s, p, e, id, ext, false);
const decryptSecret = (s, p, e, id, ext) => feistel(s, p, e, id, ext, true);

/**
 * The specification restricts passphrases to printable ASCII so that a share
 * recovered on a different device, keyboard layout or locale decrypts to the
 * same secret. Accepting anything else would silently create wallets that
 * cannot be restored elsewhere.
 */
function encodePassphrase(passphrase) {
  const s = passphrase ?? "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    assert.ok(
      c >= 32 && c <= 126,
      "SLIP-39 passphrases must be printable ASCII (code points 32-126)",
    );
  }
  return Buffer.from(s, "utf8");
}

// ---------------------------------------------------------------------------
// RS1024 CHECKSUM
// ---------------------------------------------------------------------------

const RS1024_GEN = [
  0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
  0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120,
];

function rs1024Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 20;
    chk = (((chk & 0xfffff) << 10) ^ v) >>> 0;
    for (let i = 0; i < 10; i += 1) {
      if ((b >>> i) & 1) chk = (chk ^ RS1024_GEN[i]) >>> 0;
    }
  }
  return chk >>> 0;
}

const customization = (extendable) =>
  Array.from(extendable ? CUSTOMIZATION_STRING_EXTENDABLE : CUSTOMIZATION_STRING_ORIG);

function rs1024CreateChecksum(data, extendable) {
  const values = [...customization(extendable), ...data, 0, 0, 0];
  const polymod = rs1024Polymod(values) ^ 1;
  const out = [];
  for (let i = CHECKSUM_LENGTH_WORDS - 1; i >= 0; i -= 1) {
    out.push((polymod >>> (10 * i)) & 1023);
  }
  return out;
}

const rs1024Verify = (data, extendable) =>
  rs1024Polymod([...customization(extendable), ...data]) === 1;

// ---------------------------------------------------------------------------
// SHARE ENCODING / DECODING
// ---------------------------------------------------------------------------

const bitsToWords = (bits) => Math.ceil(bits / RADIX_BITS);

export function encodeShare(share) {
  assert.ok(Number.isInteger(share.identifier) && share.identifier >= 0 &&
    share.identifier < 2 ** ID_LENGTH_BITS, "identifier out of range");
  assert.ok(Number.isInteger(share.iterationExponent) && share.iterationExponent >= 0 &&
    share.iterationExponent < 2 ** ITERATION_EXP_LENGTH_BITS,
  "iteration exponent out of range");
  assert.ok(Number.isInteger(share.groupCount) && share.groupCount >= 1 &&
    share.groupCount <= MAX_SHARE_COUNT, "group count out of range");
  assert.ok(Number.isInteger(share.groupIndex) && share.groupIndex >= 0 &&
    share.groupIndex < share.groupCount, "group index must be below group count");
  assert.ok(Number.isInteger(share.groupThreshold) && share.groupThreshold >= 1 &&
    share.groupThreshold <= share.groupCount, "group threshold out of range");
  assert.ok(Number.isInteger(share.memberIndex) && share.memberIndex >= 0 &&
    share.memberIndex < MAX_SHARE_COUNT, "member index out of range");
  assert.ok(Number.isInteger(share.memberThreshold) && share.memberThreshold >= 1 &&
    share.memberThreshold <= MAX_SHARE_COUNT, "member threshold out of range");
  assert.ok(Buffer.isBuffer(share.value) || share.value instanceof Uint8Array,
    "share value must be bytes");
  assert.ok(share.value.length >= MIN_STRENGTH_BITS / 8 && share.value.length % 2 === 0,
    "share value must have a valid even byte length");
  const valueWordCount = bitsToWords(share.value.length * 8);
  let acc = 0n;
  const push = (v, bits) => {
    acc = (acc << BigInt(bits)) | BigInt(v);
  };
  push(share.identifier, ID_LENGTH_BITS);
  push(share.extendable ? 1 : 0, EXTENDABLE_FLAG_LENGTH_BITS);
  push(share.iterationExponent, ITERATION_EXP_LENGTH_BITS);
  push(share.groupIndex, 4);
  push(share.groupThreshold - 1, 4);
  push(share.groupCount - 1, 4);
  push(share.memberIndex, 4);
  push(share.memberThreshold - 1, 4);
  acc = (acc << BigInt(valueWordCount * RADIX_BITS)) |
    BigInt(`0x${Buffer.from(share.value).toString("hex")}`);

  const total = ID_EXP_LENGTH_WORDS + 2 + valueWordCount;
  const data = [];
  for (let i = total - 1; i >= 0; i -= 1) {
    data.push(Number((acc >> BigInt(10 * i)) & 1023n));
  }
  return [...data, ...rs1024CreateChecksum(data, share.extendable)]
    .map((i) => SLIP39_WORDLIST[i])
    .join(" ");
}

export function decodeShare(mnemonic) {
  assert.equal(typeof mnemonic, "string", "SLIP-39 mnemonic must be a primitive string");
  const words = mnemonic.toLowerCase().trim().split(/\s+/).filter(Boolean);
  assert.ok(
    words.length >= METADATA_LENGTH_WORDS + bitsToWords(MIN_STRENGTH_BITS),
    `A SLIP-39 share has at least ${
      METADATA_LENGTH_WORDS + bitsToWords(MIN_STRENGTH_BITS)
    } words; got ${words.length}`,
  );
  const indexes = words.map((w) => {
    const i = WORD_INDEX.get(w);
    assert.ok(i !== undefined, `"${w}" is not a SLIP-39 word`);
    return i;
  });

  // The first two words carry id(15) | ext(1) | e(4). The extendable flag
  // selects the checksum's customization string, so it must be read before
  // the checksum can be verified - hence this manual unpack of just those bits.
  const extendable = Boolean((((indexes[0] << 10) | indexes[1]) >>> 4) & 1);
  assert.ok(
    rs1024Verify(indexes, extendable),
    "Invalid SLIP-39 checksum: a word is wrong or out of order",
  );

  const data = indexes.slice(0, indexes.length - CHECKSUM_LENGTH_WORDS);
  const valueWordCount = data.length - ID_EXP_LENGTH_WORDS - 2;
  const paddingBits = (RADIX_BITS * valueWordCount) % 16;
  assert.ok(paddingBits <= 8, "Invalid SLIP-39 share length");

  let acc = 0n;
  for (const w of data) acc = (acc << 10n) | BigInt(w);
  const valueBits = BigInt(valueWordCount * RADIX_BITS);
  const valueInt = acc & ((1n << valueBits) - 1n);
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
    valueInt >> (valueBits - BigInt(paddingBits)) === 0n || paddingBits === 0,
    "Invalid SLIP-39 padding",
  );
  const valueBytes = Number(valueBits - BigInt(paddingBits)) / 8;
  const value = Buffer.from(
    valueInt.toString(16).padStart(valueBytes * 2, "0").slice(-valueBytes * 2),
    "hex",
  );
  assert.ok(
    groupCount >= groupThreshold,
    "Invalid SLIP-39 share: group threshold exceeds group count",
  );
  assert.ok(
    groupIndex < groupCount,
    "Invalid SLIP-39 share: group index is outside the declared group count",
  );

  return {
    identifier, extendable, iterationExponent, groupIndex, groupThreshold,
    groupCount, memberIndex, memberThreshold, value,
  };
}

// ---------------------------------------------------------------------------
// PUBLIC API
// ---------------------------------------------------------------------------

/**
 * Split `secret` into groups of shares.
 *
 * @param groups array of { threshold, count } — one entry per group
 * @returns array of groups, each an array of mnemonic strings
 */
export function splitSecretIntoShares({
  secret,
  passphrase = "",
  groupThreshold = 1,
  groups,
  extendable = true,
  iterationExponent = 1,
  identifier,
  rng = randomBytes,
}) {
  assert.ok(
    secret.length >= MIN_STRENGTH_BITS / 8 && secret.length % 2 === 0,
    `The secret must be at least ${MIN_STRENGTH_BITS / 8} bytes and even in length`,
  );
  assert.ok(Array.isArray(groups) && groups.length >= 1, "At least one group required");
  assert.ok(groups.length <= MAX_SHARE_COUNT, `At most ${MAX_SHARE_COUNT} groups`);
  assert.ok(
    Number.isInteger(groupThreshold) && groupThreshold >= 1 && groupThreshold <= groups.length,
    "Group threshold must be between 1 and the number of groups",
  );
  for (const g of groups) {
    assert.ok(
      Number.isInteger(g.threshold) && Number.isInteger(g.count) &&
        g.threshold >= 1 && g.threshold <= g.count && g.count <= MAX_SHARE_COUNT,
      `Invalid group ${JSON.stringify(g)}`,
    );
    assert.ok(
      !(g.threshold === 1 && g.count > 1),
      "A group with threshold 1 must contain exactly one share: every share " +
        "would otherwise be a full copy of the group secret",
    );
  }

  const id = identifier ?? (rng(2).readUInt16BE(0) & ((1 << ID_LENGTH_BITS) - 1));
  const pass = encodePassphrase(passphrase);
  const encrypted = encryptSecret(secret, pass, iterationExponent, id, extendable);
  const groupShares = splitSecret(groupThreshold, groups.length, encrypted, rng);

  return groupShares.map(([groupIndex, groupSecret], gi) => {
    const { threshold, count } = groups[gi];
    return splitSecret(threshold, count, groupSecret, rng).map(([memberIndex, value]) =>
      encodeShare({
        identifier: id,
        extendable,
        iterationExponent,
        groupIndex,
        groupThreshold,
        groupCount: groups.length,
        memberIndex,
        memberThreshold: threshold,
        value,
      }),
    );
  });
}

/** Recover the original secret from a sufficient set of share mnemonics. */
export function combineShares(mnemonics, passphrase = "") {
  assert.ok(
    Array.isArray(mnemonics) && mnemonics.length > 0,
    "At least one SLIP-39 share is required",
  );
  const shares = mnemonics.map(decodeShare);

  const first = shares[0];
  for (const s of shares) {
    assert.ok(
      s.identifier === first.identifier &&
        s.extendable === first.extendable &&
        s.iterationExponent === first.iterationExponent &&
        s.groupThreshold === first.groupThreshold &&
        s.groupCount === first.groupCount,
      "These shares belong to different SLIP-39 backups",
    );
  }

  const byGroup = new Map();
  for (const s of shares) {
    if (!byGroup.has(s.groupIndex)) byGroup.set(s.groupIndex, []);
    byGroup.get(s.groupIndex).push(s);
  }
  assert.equal(
    byGroup.size,
    first.groupThreshold,
    `Wrong number of groups: expected exactly ${first.groupThreshold}, got ${byGroup.size}`,
  );

  const groupSecrets = [];
  for (const [groupIndex, members] of byGroup) {
    const t = members[0].memberThreshold;
    for (const m of members) {
      assert.equal(
        m.memberThreshold, t,
        "Shares in one group disagree about the member threshold",
      );
    }
    assert.equal(
      new Set(members.map((m) => m.memberIndex)).size,
      members.length,
      "Duplicate share within a group",
    );
    assert.equal(
      members.length, t,
      `Wrong number of shares in group ${groupIndex}: expected exactly ${t}, ` +
        `got ${members.length}`,
    );
    assert.equal(
      new Set(members.map((m) => m.value.length)).size, 1,
      "Shares in one group have inconsistent lengths",
    );
    groupSecrets.push([
      groupIndex,
      recoverSecret(t, members.map((m) => [m.memberIndex, m.value])),
    ]);
  }

  const encrypted = recoverSecret(first.groupThreshold, groupSecrets);
  assert.ok(
    encrypted.length >= MIN_STRENGTH_BITS / 8 && encrypted.length % 2 === 0,
    "Recovered secret has an invalid length",
  );
  return decryptSecret(
    encrypted,
    encodePassphrase(passphrase),
    first.iterationExponent,
    first.identifier,
    first.extendable,
  );
}

/** Exact binomial coefficient. */
function chooseBig(n, k) {
  if (k < 0 || k > n) return 0n;
  k = Math.min(k, n - k);
  let r = 1n;
  for (let i = 1; i <= k; i += 1) {
    r = (r * BigInt(n - k + i)) / BigInt(i);
  }
  return r;
}

function combinationsOfIndexes(n, k) {
  const out = [];
  const visit = (start, chosen) => {
    if (chosen.length === k) { out.push(chosen); return; }
    for (let i = start; i <= n - (k - chosen.length); i += 1) {
      visit(i + 1, [...chosen, i]);
    }
  };
  visit(0, []);
  return out;
}

/**
 * How many admissible share subsets exist, WITHOUT materialising them.
 *
 * The count is a product across groups and explodes: 8-of-16 in two groups
 * with a group threshold of 2 is C(16,8)^2, about 165 million. Callers must
 * consult this before asking for the full list.
 */
export function countAdmissibleSubsetsExact(groupThreshold, groups) {
  assert.ok(Array.isArray(groups) && groups.length >= 1 && groups.length <= MAX_SHARE_COUNT,
    "invalid group list");
  assert.ok(Number.isInteger(groupThreshold) && groupThreshold >= 1 &&
    groupThreshold <= groups.length, "invalid group threshold");
  for (const group of groups) {
    assert.ok(Number.isInteger(group.count) && Number.isInteger(group.threshold) &&
      group.threshold >= 1 && group.threshold <= group.count &&
      group.count <= MAX_SHARE_COUNT, "invalid group layout");
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

export function countAdmissibleSubsets(groupThreshold, groups) {
  const exact = countAdmissibleSubsetsExact(groupThreshold, groups);
  assert.ok(exact <= BigInt(Number.MAX_SAFE_INTEGER),
    "admissible subset count exceeds Number.MAX_SAFE_INTEGER; use the exact API");
  return Number(exact);
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

export function admissibleSubsetAtRank(groupThreshold, groups, mnemonics, rank) {
  const total = countAdmissibleSubsetsExact(groupThreshold, groups);
  assert.ok(typeof rank === "bigint" && rank >= 0n && rank < total,
    "admissible subset rank out of range");
  const groupSets = combinationsOfIndexes(groups.length, groupThreshold);
  let chosenGroups;
  for (const candidate of groupSets) {
    const weight = candidate.reduce((product, gi) =>
      product * chooseBig(groups[gi].count, groups[gi].threshold), 1n);
    if (rank < weight) { chosenGroups = candidate; break; }
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
  for (;;) {
    const candidate = BigInt(`0x${Buffer.from(rng(bytes)).toString("hex") || "0"}`) & mask;
    if (candidate < limit) return candidate;
  }
}

export function randomAdmissibleRank(total, rng) {
  assert.ok(typeof total === "bigint" && total > 0n, "total must be a positive bigint");
  return randomBigIntBelow(total, rng);
}

/** One uniformly chosen admissible subset, sampled by exact global rank. */
export function randomAdmissibleSubset(groupThreshold, groups, mnemonics, rng) {
  const total = countAdmissibleSubsetsExact(groupThreshold, groups);
  return admissibleSubsetAtRank(
    groupThreshold, groups, mnemonics, randomAdmissibleRank(total, rng),
  );
}

/** Every admissible combination of shares, for the exhaustive round-trip test. */
export function admissibleSubsets(groupThreshold, groups, mnemonics) {
  const chooseK = (arr, k) => {
    if (k === 0) return [[]];
    if (arr.length < k) return [];
    const [head, ...rest] = arr;
    return [
      ...chooseK(rest, k - 1).map((c) => [head, ...c]),
      ...chooseK(rest, k),
    ];
  };
  const groupChoices = chooseK(
    groups.map((_, i) => i),
    groupThreshold,
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

export const SLIP39_LIMITS = { MAX_SHARE_COUNT, MIN_STRENGTH_BITS };

// ---------------------------------------------------------------------------
// SELF-TEST
//
// Replaces the dual-implementation rule for this module. See the header.
// ---------------------------------------------------------------------------

// Fixed scenarios for the exhaustive round-trip. Deliberately hard-coded: the
// number of admissible subsets is a product across groups and explodes near
// MAX_SHARE_COUNT, so this must never run over a user-supplied configuration.
const ROUND_TRIP_SCENARIOS = [
  { name: "1-of-1", groupThreshold: 1, groups: [{ threshold: 1, count: 1 }] },
  { name: "2-of-3", groupThreshold: 1, groups: [{ threshold: 2, count: 3 }] },
  { name: "3-of-5", groupThreshold: 1, groups: [{ threshold: 3, count: 5 }] },
  {
    name: "2 of 3 groups, 2-of-3 each",
    groupThreshold: 2,
    groups: [
      { threshold: 2, count: 3 },
      { threshold: 2, count: 3 },
      { threshold: 2, count: 3 },
    ],
  },
  {
    name: "mixed thresholds",
    groupThreshold: 2,
    groups: [
      { threshold: 1, count: 1 },
      { threshold: 3, count: 4 },
      { threshold: 2, count: 2 },
    ],
  },
];

const equalBytesLocal = (a, b) => Buffer.from(a).equals(Buffer.from(b));

export function slip39SelfTest({ vectors, fixtures, log = () => {}, rng = randomBytes }) {
  assertSlip39WordlistIntegrity();
  log("SLIP-39 wordlist matches the published SHA-256");

  // Arithmetic spot-check. The GF(256) tables must be generated by multiplying
  // by (x + 1); a doubling generator produces a table that is wrong for most
  // products and still passes a naive round-trip, because encode and decode
  // would share the error. Two published AES values pin it.
  const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[(LOG[a] + LOG[b]) % 255]);
  assert.equal(gfMul(3, 7), 9, "GF(256) multiplication is wrong");
  assert.equal(gfMul(0x57, 0x83), 0xc1, "GF(256) multiplication is wrong");
  assert.equal(new Set(EXP).size, 255, "GF(256) generator is not primitive");
  log("GF(256) arithmetic matches published values");

  // Official vectors: 15 must decode to a known secret, 30 must be REJECTED.
  // These come from the reference implementation, so they are a genuine
  // external check rather than a self-consistency check.
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

  // ENCODE pinned against reference-produced output.
  //
  // The 45 vectors above only ever feed decodeShare. encodeShare - the half
  // that produces the words a user writes down - is exercised by nothing
  // external, and the round-trip test only proves encode and decode are
  // mutually inverse, which they would still be if both were wrong in the
  // same way. Re-encoding every share string from the vector file and
  // demanding byte identity fixes that: those strings were produced by the
  // reference implementation, so this is external truth, not self-agreement.
  let reencoded = 0;
  let extendableSeen = 0;
  for (const [, mnemonics] of vectors) {
    for (const mnemonic of mnemonics) {
      let share;
      try {
        share = decodeShare(mnemonic);
      } catch {
        continue; // deliberately malformed vector; decode rejection is the point
      }
      assert.equal(
        encodeShare(share), mnemonic.toLowerCase().trim().split(/\s+/).join(" "),
        "encodeShare does not reproduce a reference share byte for byte",
      );
      if (share.extendable) extendableSeen += 1;
      reencoded += 1;
    }
  }
  assert.ok(reencoded > 0, "no shares were re-encoded");
  // The extendable path uses a different customization string and an empty
  // salt; without at least one such share it would go unpinned.
  assert.ok(extendableSeen > 0, "no extendable share exercised the encode path");
  log(
    `${reencoded} reference shares re-encoded byte-identically ` +
      `(${extendableSeen} extendable)`,
  );

  // Deterministic fixtures for the field ranges the official vectors never
  // reach: groupIndex 4-15, memberIndex 10-15, groupCount 5-16, group
  // threshold 3-16, iteration exponent 15. Every one of those lives in the
  // high nibble of a packed field, which is exactly where an off-by-one in
  // the bit packing would hide.
  //
  // These are REGRESSION anchors, not external truth - they were produced by
  // this implementation (and validated against python-shamir-mnemonic when
  // created, see slip39-fixtures.json). The external encode check is the
  // re-encoding above.
  if (fixtures) {
    // Field pins: encodeShare called directly on synthetic records whose every
    // packed field sits at an extreme. No key derivation is involved, and that
    // is deliberate - pushing iterationExponent 15 through a real split costs
    // 327,680,000 PBKDF2 iterations and 26 seconds, on a self-test that gates
    // every single command. The KDF is not what these pins test; the bit
    // packing is.
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
        rng: makeRng(`evm-seed-tool/slip39-fixture/${f.name}`),
      }).flat();
      assert.equal(flat.length, f.shareCount, `fixture "${f.name}": share count changed`);
      assert.equal(flat[0], f.firstShare, `fixture "${f.name}": first share changed`);
      assert.equal(flat[flat.length - 1], f.lastShare, `fixture "${f.name}": last share changed`);
      assert.equal(
        createHash("sha256").update(flat.join("\n")).digest("hex"), f.sha256,
        `fixture "${f.name}": encoded shares changed`,
      );
    }
    const shares = fixtures.fixtures.reduce((a, f) => a + f.shareCount, 0);
    log(`${fixtures.fixtures.length} deterministic fixtures (${shares} shares) byte-identical`);
  }

  // Exhaustive round-trip: recover from EVERY admissible subset. This tests
  // the property the user actually depends on - "any threshold of these
  // papers restores my wallet" - rather than a proxy for it.
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
          rng,
        });
        for (const subset of admissibleSubsets(
          scenario.groupThreshold, scenario.groups, shares,
        )) {
          assert.ok(
            combineShares(subset, "").equals(secret),
            `SLIP-39 round-trip failed: ${scenario.name}, ${bytes} bytes`,
          );
          subsetCount += 1;
        }
      }
    }
  }
  log(`exhaustive round-trip: ${subsetCount} admissible share subsets all recovered`);

  // Negative tests: the guards must fire.
  assert.throws(
    () => splitSecretIntoShares({ secret: Buffer.alloc(8), groups: [{ threshold: 1, count: 1 }] }),
    /at least/, "accepted a secret below the minimum strength",
  );
  assert.throws(
    () => splitSecretIntoShares({ secret: Buffer.alloc(32), groups: [{ threshold: 1, count: 3 }] }),
    /threshold 1/, "allowed MEMBER threshold 1 with multiple shares",
  );
  // The mirror case that must be ALLOWED: group threshold 1 over several
  // groups, each independently recoverable. Regression guard - a guard meant
  // for the member level was previously rejecting this topology outright.
  {
    const secret = rng(32);
    const groups = [{ threshold: 2, count: 3 }, { threshold: 3, count: 5 }];
    const shares = splitSecretIntoShares({ secret, groupThreshold: 1, groups, rng });
    assert.ok(equalBytesLocal(combineShares(shares[0].slice(0, 2), ""), secret));
    assert.ok(equalBytesLocal(combineShares(shares[1].slice(0, 3), ""), secret));
  }
  assert.throws(() => combineShares(["not a share"]), /at least|not a SLIP-39 word/,
    "accepted a non-share");
  log("SLIP-39 negative tests: length, threshold-1 and garbage input all rejected");
}
