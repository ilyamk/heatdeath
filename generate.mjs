#!/usr/bin/env node
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
// Offline EVM seed generator - hardened build.
//
// Design rules this file follows, in priority order:
//
//   1. Fail closed. Every integrity check refuses to emit a secret rather
//      than emitting an unverified one. A tool that produces nothing is
//      recoverable; a tool that produces a wrong phrase is not.
//   2. Two independent implementations must agree before anything is shown.
//      The primary path uses @scure/bip39 + @scure/bip32. The reference path
//      re-implements BIP-39 mnemonic encoding, PBKDF2 seed derivation and
//      BIP-32 CKDpriv on node:crypto alone. See REFERENCE IMPLEMENTATION.
//   3. No network, no subprocesses, no file writes. Enforced by the Node
//      permission model when launched through the provided npm scripts. This
//      is least privilege for trusted code, not a malicious-code sandbox.
//   4. Secrets never touch argv (visible in `ps`), never touch a file, never
//      touch the clipboard. Interactive input is read with echo disabled.
//
// Everything this file CANNOT protect against is listed in README.md under
// "Zones that cannot be closed technically". Read that section.

import assert from "node:assert/strict";
import os from "node:os";
import fs from "node:fs";
import process from "node:process";
import {
  createHash,
  createHmac,
  pbkdf2Sync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { HDKey } from "@scure/bip32";
import {
  entropyToMnemonic,
  mnemonicToEntropy,
  mnemonicToSeedSync,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

import {
  admissibleSubsets,
  admissibleSubsetAtRank,
  combineShares,
  countAdmissibleSubsetsExact,
  randomAdmissibleRank,
  slip39SelfTest,
  splitSecretIntoShares,
} from "./slip39.mjs";
import SLIP39_VECTORS from "./slip39-vectors.json" with { type: "json" };
import SLIP39_FIXTURES from "./slip39-fixtures.json" with { type: "json" };
import { encodeAddressQRs, qrSelfTest, renderQR } from "./qr.mjs";
import { parseCli } from "./cli.mjs";
import {
  ESC,
  looksObviouslyWeakPassphrase,
  normalizePassphrase,
  readInput,
  validateNewWalletPassphrase,
} from "./terminal.mjs";
import { sendSecretPayload } from "./op-transport.mjs";

// ---------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------

const TOOL_ID = "heatdeath/v2";
const ENTROPY_BYTES = 32; // 256 bits - the BIP-39 maximum, yields 24 words.
const DEFAULT_ACCOUNTS = 11;
const MAX_ACCOUNTS = 100;
const DICE_MIN_ROLLS = 128; // 128 * log2(6) = 330.9 bits, margin over 256
                            // so that even a visibly imperfect die stays
                            // far above the 128-bit level that matters.

// secp256k1 group order. A BIP-32 child key must land in [1, n-1].
const CURVE_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// SHA-256 of the canonical BIP-39 English wordlist (english.txt, newline
// separated, trailing newline), published with the BIP-39 specification.
// A mismatch means the wordlist shipped in node_modules is not the standard
// one, which would silently produce a phrase no other wallet can read.
const WORDLIST_SHA256 =
  "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

// Derivation path templates. "%i" is replaced by the account index.
//
// Both templates are BIP-44 conformant; they differ in WHICH level varies.
// This has a direct privacy consequence, see README, section "Anonymity".
const PATH_SCHEMES = {
  // Varies the address index. All accounts share one extended public key,
  // so anyone holding that xpub can link every address to one wallet.
  // This is what MetaMask, Rabby, Trust and Ledger "Legacy" use.
  metamask: {
    template: "m/44'/60'/0'/0/%i",
    linkable: true,
    note: "MetaMask / Rabby / Trust / Ledger Legacy. Addresses share one xpub.",
  },
  // Varies the hardened account level. Each index sits behind its own
  // hardened boundary, so no single xpub links them, and a leaked child
  // key does not expose its siblings. This is what Ledger Live uses.
  // NOT validated against a published third-party vector - see README.
  account: {
    template: "m/44'/60'/%i'/0/0",
    linkable: false,
    note: "Ledger Live. Hardened per account - addresses are NOT xpub-linkable.",
  },
};
const DEFAULT_SCHEME = "metamask";

// ---------------------------------------------------------------------------
// SMALL UTILITIES
// ---------------------------------------------------------------------------

const sha256 = (...chunks) => {
  const h = createHash("sha256");
  for (const c of chunks) h.update(c);
  return h.digest();
};

const POPCOUNT = new Uint8Array(256);
for (let i = 0; i < 256; i += 1) POPCOUNT[i] = (i & 1) + POPCOUNT[i >> 1];

function bigToBytes32(value) {
  assert.ok(value > 0n && value < CURVE_N, "Scalar out of range");
  return Buffer.from(value.toString(16).padStart(64, "0"), "hex");
}

function bytesToBig(bytes) {
  return BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
}

function xorInto(target, source) {
  assert.equal(target.length, source.length);
  for (let i = 0; i < target.length; i += 1) target[i] ^= source[i];
  return target;
}

function equalBytes(a, b) {
  return a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Parse "m/44'/60'/0'/0/0" into an array of 32-bit child indexes. */
function parsePath(path) {
  const parts = path.split("/");
  assert.equal(parts[0], "m", `Path must start with "m": ${path}`);
  return parts.slice(1).map((part) => {
    const hardened = /['hH]$/.test(part);
    const raw = hardened ? part.slice(0, -1) : part;
    assert.match(raw, /^[0-9]+$/, `Bad path element: ${part}`);
    const n = Number.parseInt(raw, 10);
    assert.ok(n >= 0 && n < 0x80000000, `Path element out of range: ${part}`);
    return hardened ? n + 0x80000000 : n;
  });
}

const pathFor = (scheme, index) =>
  PATH_SCHEMES[scheme].template.replace("%i", String(index));

/** Human-readable form of a scheme template, e.g. "m/44'/60'/0'/0/i". */
const templateFor = (scheme) => PATH_SCHEMES[scheme].template.replace("%i", "i");

// ---------------------------------------------------------------------------
// RUNTIME GUARDS
//
// Refusals are reserved for conditions that make secrecy impossible by
// construction. Everything else is a warning: a refusal that users learn to
// bypass with a flag is worse than a warning they actually read.
// ---------------------------------------------------------------------------

/** Detect an inspector activated at runtime (for example via SIGUSR1). */
function inspectorUrl() {
  try {
    return process.getBuiltinModule?.("node:inspector")?.url?.();
  } catch {
    return undefined;
  }
}

function assertRuntime({ requireTty = true } = {}) {
  const fatal = [];
  const warn = [];

  // --- Fatal: the secret would provably leave this machine or this process.

  if (process.env.SSH_TTY || process.env.SSH_CONNECTION) {
    fatal.push(
      "This is an SSH session. Every character printed here crosses a network " +
        "and lands in a remote terminal's scrollback. Run on the physical machine.",
    );
  }

  const inspectFlags = [...process.execArgv, process.env.NODE_OPTIONS ?? ""]
    .join(" ")
    .match(/--inspect[\w-]*/g);
  if (inspectFlags) {
    fatal.push(
      `A debugger port is enabled (${inspectFlags.join(", ")}). Anything ` +
        "attached to it can read the seed straight out of process memory.",
    );
  }
  const inspector = inspectorUrl();
  if (inspector) fatal.push(`An inspector is already listening on ${inspector}.`);

  if (requireTty && !process.stdout.isTTY) {
    fatal.push(
      "stdout is not a terminal. NOTE: this check is a convenience guard, not " +
        "a security boundary - script(1), `tmux pipe-pane`, expect and terminal " +
        "session logging all defeat it trivially. You remain responsible for " +
        "ensuring nothing is recording this terminal.",
    );
  }

  // --- Warnings: real risk, but the user may have a legitimate reason.

  if (!process.permission) {
    warn.push(
      "Node's trusted-code capability guard is OFF. Network, subprocesses and file writes " +
        "are technically possible from this process. Prefer `npm run generate`, " +
        "which enables it.",
    );
  } else {
    for (const scope of ["net", "child", "worker", "fs.write", "addon"]) {
      if (process.permission.has(scope)) {
        warn.push(`Permission model is enabled but "${scope}" is ALLOWED.`);
      }
    }
    if (process.permission.has("fs.read", process.cwd())) {
      warn.push(
        "Repository-wide filesystem read is allowed. This is expected only in " +
          "source-checkout mode; signed bundle commands need /dev/urandom only.",
      );
    }
    if (!process.permission.has("fs.read", "/dev/urandom")) {
      fatal.push("The required /dev/urandom read capability is missing.");
    }
  }

  if (typeof process.getuid === "function" && process.getuid() === 0) {
    warn.push("Running as root. This tool needs no privileges whatsoever.");
  }

  if (process.env.TMUX || process.env.STY) {
    warn.push(
      "Running inside tmux/screen. These keep large scrollback buffers and can " +
        "be configured to log the session to disk.",
    );
  }

  // Only meaningful when the permission model is OFF. A single-executable
  // build made with execArgvExtension "none" cannot have flags injected
  // through the environment at all, so warning there would be misleading.
  if (process.env.NODE_OPTIONS && !process.permission) {
    warn.push(
      `NODE_OPTIONS is set ("${process.env.NODE_OPTIONS}"). It can inject code ` +
        "via --require / --import before this file runs.",
    );
  }

  const cwd = process.cwd();
  for (const dir of [
    "Library/Mobile Documents", "iCloud", "Dropbox", "Google Drive",
    "OneDrive", "Yandex.Disk", "pCloud", "MEGA",
  ]) {
    if (cwd.includes(dir)) {
      warn.push(`Working directory looks cloud-synchronised (matched "${dir}").`);
    }
  }

  try {
    const live = Object.entries(os.networkInterfaces())
      .filter(([, addrs]) => (addrs ?? []).some((a) => !a.internal))
      .map(([name]) => name);
    if (live.length > 0) {
      // Listed as a count plus a sample: a dozen utun* entries would push the
      // warnings that matter off the top of the block.
      const sample = live.slice(0, 3).join(", ");
      warn.push(
        `${live.length} network interface(s) are up (${sample}` +
          `${live.length > 3 ? ", ..." : ""}). Disable Wi-Fi, Ethernet and ` +
          "Bluetooth before generating.",
      );
    }
  } catch {
    /* os.networkInterfaces unavailable - skip. */
  }

  if (warn.length > 0) {
    process.stdout.write("\nWARNINGS\n");
    for (const w of warn) process.stdout.write(`  ! ${w}\n`);
  }
  if (fatal.length > 0) {
    throw new Error(
      `refusing to continue:\n${fatal.map((f) => `  x ${f}`).join("\n")}`,
    );
  }
  return { warnings: warn };
}

function assertWordlistIntegrity() {
  assert.equal(wordlist.length, 2048, "Wordlist must contain exactly 2048 words");
  assert.equal(
    sha256(`${wordlist.join("\n")}\n`).toString("hex"),
    WORDLIST_SHA256,
    "BIP-39 English wordlist does not match the published SHA-256. A phrase " +
      "produced with it would not be readable by other wallets.",
  );
}

// ---------------------------------------------------------------------------
// PRIMARY IMPLEMENTATION (@scure / @noble)
// ---------------------------------------------------------------------------

function toChecksumAddress(lowercaseHex) {
  assert.match(lowercaseHex, /^[0-9a-f]{40}$/);
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(lowercaseHex)));
  let result = "0x";
  for (let i = 0; i < lowercaseHex.length; i += 1) {
    const character = lowercaseHex[i];
    result += Number.parseInt(hash[i], 16) >= 8
      ? character.toUpperCase()
      : character;
  }
  return result;
}

/** Address from a raw 32-byte private key. Shared by both implementations. */
function addressFromPrivateKey(privateKey) {
  const publicKey = secp256k1.getPublicKey(privateKey, false);
  assert.equal(publicKey.length, 65);
  assert.equal(publicKey[0], 4);
  const digest = keccak_256(publicKey.slice(1));
  return {
    address: toChecksumAddress(bytesToHex(digest.slice(-20))),
    publicKey,
  };
}

function primaryAccounts(seed, scheme, count) {
  const master = HDKey.fromMasterSeed(seed);
  const fingerprint = `0x${(master.fingerprint >>> 0).toString(16).padStart(8, "0")}`;
  const nodes = [];
  const accounts = [];
  for (let index = 0; index < count; index += 1) {
    const path = pathFor(scheme, index);
    // Derive from the master for EVERY index. Caching an account-level node
    // and calling deriveChild() is only valid for the "metamask" template;
    // reusing that shortcut for "account" would silently emit wrong addresses.
    const node = master.derive(path);
    assert.ok(node.privateKey, `No private key at ${path}`);
    nodes.push(node);
    accounts.push({
      index,
      path,
      privateKey: Buffer.from(node.privateKey),
      ...addressFromPrivateKey(node.privateKey),
    });
  }
  return {
    accounts,
    fingerprint,
    dispose: () => {
      for (const n of nodes) n.wipePrivateData();
      master.wipePrivateData();
    },
  };
}

// ---------------------------------------------------------------------------
// REFERENCE IMPLEMENTATION
//
// Independent of @scure/bip39 and @scure/bip32. Uses only node:crypto for
// SHA-256, HMAC-SHA512, RIPEMD-160 and PBKDF2.
//
// HONEST SCOPE: keccak256 (@noble/hashes) and secp256k1 (@noble/curves) are
// SHARED between both paths - Node ships neither, and hand-rolling a sponge
// permutation plus curve arithmetic here would add hundreds of lines of the
// least auditable code in the project to defend against a threat that the
// lockfile integrity hashes and `npm audit signatures` already cover. What
// this reference path DOES independently verify: BIP-39 mnemonic encoding,
// the BIP-39 checksum, PBKDF2 seed stretching and all BIP-32 CKDpriv
// arithmetic including hardened derivation.
// ---------------------------------------------------------------------------

function refEntropyToMnemonic(entropy, words) {
  const csBits = (entropy.length * 8) / 32;
  assert.ok(Number.isInteger(csBits) && csBits >= 4 && csBits <= 8);
  let bits = "";
  for (const byte of entropy) bits += byte.toString(2).padStart(8, "0");
  bits += sha256(entropy)[0].toString(2).padStart(8, "0").slice(0, csBits);
  assert.equal(bits.length % 11, 0);
  const out = [];
  for (let i = 0; i < bits.length; i += 11) {
    out.push(words[Number.parseInt(bits.slice(i, i + 11), 2)]);
  }
  return out.join(" ");
}

function refMnemonicToSeed(mnemonic, passphrase = "") {
  return pbkdf2Sync(
    Buffer.from(mnemonic.normalize("NFKD"), "utf8"),
    Buffer.from(`mnemonic${passphrase.normalize("NFKD")}`, "utf8"),
    2048,
    64,
    "sha512",
  );
}

function refMaster(seed) {
  const I = createHmac("sha512", "Bitcoin seed").update(seed).digest();
  const k = bytesToBig(I.subarray(0, 32));
  assert.ok(k > 0n && k < CURVE_N, "Invalid master key (probability ~2^-127)");
  return { k, c: I.subarray(32) };
}

function refCkdPriv(node, index) {
  const data = Buffer.alloc(37);
  if (index >= 0x80000000) {
    bigToBytes32(node.k).copy(data, 1); // data[0] stays 0x00
  } else {
    Buffer.from(secp256k1.getPublicKey(bigToBytes32(node.k), true)).copy(data, 0);
  }
  data.writeUInt32BE(index >>> 0, 33);
  const I = createHmac("sha512", node.c).update(data).digest();
  const IL = bytesToBig(I.subarray(0, 32));
  assert.ok(IL < CURVE_N, "CKDpriv: IL >= n (probability ~2^-127)");
  const k = (IL + node.k) % CURVE_N;
  assert.ok(k > 0n, "CKDpriv: resulting key is zero (probability ~2^-256)");
  data.fill(0);
  return { k, c: I.subarray(32) };
}

function refDerive(seed, path) {
  let node = refMaster(seed);
  for (const index of parsePath(path)) node = refCkdPriv(node, index);
  return bigToBytes32(node.k);
}

function refFingerprint(seed) {
  const master = refMaster(seed);
  const pub = Buffer.from(secp256k1.getPublicKey(bigToBytes32(master.k), true));
  const hash160 = createHash("ripemd160").update(sha256(pub)).digest();
  return `0x${hash160.subarray(0, 4).toString("hex")}`;
}

/**
 * Re-derive everything the primary path produced and refuse on any mismatch.
 * This is the gate standing between a tampered dependency tree and a phrase
 * written on paper.
 */
function crossCheck({ entropy, phrase, passphrase, seed, accounts, fingerprint }) {
  if (entropy) {
    assert.equal(
      refEntropyToMnemonic(entropy, wordlist),
      phrase,
      "CROSS-CHECK FAILED: independent BIP-39 encoder disagrees on the mnemonic",
    );
  }
  const refSeed = refMnemonicToSeed(phrase, passphrase);
  assert.ok(
    equalBytes(refSeed, seed),
    "CROSS-CHECK FAILED: independent PBKDF2 disagrees on the BIP-39 seed",
  );
  assert.equal(
    refFingerprint(refSeed),
    fingerprint,
    "CROSS-CHECK FAILED: independent BIP-32 disagrees on the master fingerprint",
  );
  for (const account of accounts) {
    const refKey = refDerive(refSeed, account.path);
    assert.ok(
      equalBytes(refKey, account.privateKey),
      `CROSS-CHECK FAILED: private key mismatch at ${account.path}`,
    );
    assert.equal(
      addressFromPrivateKey(refKey).address,
      account.address,
      `CROSS-CHECK FAILED: address mismatch at ${account.path}`,
    );
    refKey.fill(0);
  }
  refSeed.fill(0);
}

// ---------------------------------------------------------------------------
// ENTROPY
// ---------------------------------------------------------------------------

function readUrandom(length) {
  const fd = fs.openSync("/dev/urandom", "r");
  try {
    const buf = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const n = fs.readSync(fd, buf, read, length - read, null);
      assert.ok(n > 0, "/dev/urandom returned no data");
      read += n;
    }
    return buf;
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * NIST SP 800-90B style start-up health tests, byte-oriented, assuming a full
 * 8 bits of entropy per byte.
 *
 * HONEST SCOPE: these detect CATASTROPHIC failure only - stuck bits, a zeroed
 * buffer, a device returning constants. They cannot distinguish a good CSPRNG
 * from AES-CTR under a key the attacker knows. Passing them is not evidence of
 * cryptographic quality; failing them is proof of a broken source.
 */
function healthTest(name, sample) {
  const fail = (test) =>
    assert.fail(`ENTROPY HEALTH TEST FAILED - source "${name}" failed ${test}`);

  // Repetition Count Test. Cutoff 5 gives a false-positive rate around 1e-6
  // over a 4 KiB sample.
  let run = 1;
  for (let i = 1; i < sample.length; i += 1) {
    run = sample[i] === sample[i - 1] ? run + 1 : 1;
    if (run >= 5) fail("the repetition count test (5 identical bytes in a row)");
  }

  // Proportion test over a 512-byte window. NIST's Adaptive Proportion Test
  // counts repetitions of the FIRST sample in each window; this counts the
  // most frequent value instead, which is a strictly stronger check and a
  // different one - so the cutoff is NOT NIST's table value and this is not
  // a claim of SP 800-90B conformance. Cutoff 13 over the most-frequent
  // value gives a false-positive rate on the order of 1e-3 per run, which is
  // acceptable only because failing is fail-closed and re-running is free.
  for (let off = 0; off + 512 <= sample.length; off += 512) {
    const freq = new Uint16Array(256);
    let max = 0;
    for (let i = off; i < off + 512; i += 1) max = Math.max(max, ++freq[sample[i]]);
    if (max >= 13) fail(`the adaptive proportion test (one value ${max} times in 512)`);
  }

  // Monobit, 5 sigma.
  let ones = 0;
  for (const byte of sample) ones += POPCOUNT[byte];
  const expected = sample.length * 4;
  const sigma = Math.sqrt(sample.length * 8 * 0.25);
  if (Math.abs(ones - expected) > 5 * sigma) {
    fail(`the monobit test (${ones} one-bits, expected about ${expected})`);
  }
}

function diceEntropy(rolls) {
  assert.ok(
    rolls.length >= DICE_MIN_ROLLS,
    `Need at least ${DICE_MIN_ROLLS} d6 rolls (= ${
      (DICE_MIN_ROLLS * Math.log2(6)).toFixed(1)
    } bits); got ${rolls.length}`,
  );
  const freq = new Array(6).fill(0);
  for (const r of rolls) freq[r - 1] += 1;
  const expected = rolls.length / 6;
  const chi = freq.reduce((a, f) => a + (f - expected) ** 2 / expected, 0);
  return {
    bytes: sha256(
      Buffer.from(`${TOOL_ID}/source/dice`),
      Buffer.from([0]),
      Buffer.from(rolls.join(""), "utf8"),
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
    tooFlat: chi < 0.55,
  };
}

/**
 * Collect 256 bits of entropy.
 *
 * Each source is normalised to 32 bytes through a domain-separated SHA-256 and
 * the results are XORed. Under XOR the output is unpredictable if ANY single
 * input is unpredictable, so adding a source can never make the result weaker
 * than the best source alone.
 *
 * HONEST SCOPE ON INDEPENDENCE: crypto.randomBytes is backed by OpenSSL while
 * /dev/urandom is read directly through the kernel interface. They are two
 * code paths, not proof of two independent physical entropy sources. Dice are
 * the only source independent of this machine.
 */
function collectEntropy({ dice }) {
  const PROBE = 4096;
  const providers = [
    { name: "openssl-drbg", get: (n) => randomBytes(n) },
    { name: "kernel-urandom", get: readUrandom },
  ];

  const report = [];
  const material = [];
  const probes = [];

  for (const provider of providers) {
    let probe;
    try {
      probe = provider.get(PROBE);
    } catch (error) {
      // /dev/urandom can be unreachable under a stricter permission set.
      report.push({
        name: provider.name,
        status: `UNAVAILABLE (${error.code ?? error.message})`,
      });
      continue;
    }
    // NOTE ON SCOPE: the health tests run on this 4 KiB PROBE, not on the
    // 32-byte draw taken below that actually becomes entropy. A 32-byte
    // sample is far too small for any of these tests to mean anything. So
    // this vets the SOURCE's current behaviour, not the specific bytes you
    // will use - the all-zero guard and the XOR construction cover those.
    healthTest(provider.name, probe);
    probes.push({ name: provider.name, probe });
    material.push({ name: provider.name, draw: provider.get(ENTROPY_BYTES) });
    report.push({ name: provider.name, status: "OK" });
  }

  assert.equal(
    material.length, providers.length,
    `Only ${material.length}/${providers.length} required OS entropy paths ` +
      "available; refusing to generate",
  );

  // Identical probes prove catastrophic wiring/stubbing. Unequal probes do
  // not prove independence and make no claim about VM snapshots or clones.
  for (let i = 0; i < probes.length; i += 1) {
    for (let j = i + 1; j < probes.length; j += 1) {
      assert.ok(
        !probes[i].probe.equals(probes[j].probe),
        `Sources "${probes[i].name}" and "${probes[j].name}" returned identical ` +
          "bytes - this indicates a catastrophic duplicate/stubbed output",
      );
    }
  }
  for (const p of probes) p.probe.fill(0);

  const entropy = Buffer.alloc(ENTROPY_BYTES);
  for (const { name, draw } of material) {
    xorInto(
      entropy,
      sha256(Buffer.from(`${TOOL_ID}/source/${name}`), Buffer.from([0]), draw),
    );
    draw.fill(0);
  }
  if (dice) {
    xorInto(entropy, dice.bytes);
    report.push({
      name: "dice-d6",
      status: `OK (${dice.rolls} rolls = ${dice.bits.toFixed(1)} bits` +
        `${dice.biased ? ", CHI-SQUARE SUGGESTS A BIASED DIE" : ""})`,
    });
  }

  assert.ok(
    !entropy.equals(Buffer.alloc(ENTROPY_BYTES)),
    "Combined entropy is all zeros",
  );
  return { entropy, report };
}

/**
 * Byte source for Shamir share masking, drawn from the SAME multi-source pool
 * as the seed entropy rather than from a single call to randomBytes.
 *
 * This is not decoration. At threshold 2 the split has no random base shares:
 * it interpolates from the digest share and the secret. An attacker holding
 * ONE share who can predict the digest share's random part is left with only
 * the 4 unknown digest bytes - and every guess is checkable against the
 * digest, so that is a 2^32 search that recovers the secret outright. Masking
 * bytes therefore need the same standard as the seed itself.
 *
 * A fresh pool is collected rather than reusing the seed's, so the two never
 * share material even in principle.
 */
function makeShamirRng() {
  const { entropy } = collectEntropy({ dice: null });
  let counter = 0;
  const rng = (length) => {
    const out = Buffer.alloc(length);
    for (let off = 0; off < length; off += 32) {
      const ctr = Buffer.alloc(4);
      ctr.writeUInt32BE(counter, 0);
      counter += 1;
      sha256(Buffer.from(`${TOOL_ID}/shamir`), Buffer.from([0]), entropy, ctr)
        .copy(out, off);
    }
    return out;
  };
  rng.dispose = () => entropy.fill(0);
  return rng;
}

// ---------------------------------------------------------------------------
// TERMINAL INPUT
//
// Secrets are read here and never from argv: process arguments are visible to
// every process on the machine via `ps` and are recorded in shell history.
// ---------------------------------------------------------------------------

async function readPassphraseTwice({ newWallet = false } = {}) {
  process.stdout.write(
    "\nBIP-39 passphrase (the \"25th word\").\n\n" +
      "  It is NOT a wordlist word - any text at all, case and spaces included.\n" +
      "  It goes into the PBKDF2 salt, so every different string yields a\n" +
      "  different, perfectly valid wallet. There is no such thing as a wrong\n" +
      "  passphrase: a typo silently gives you somebody else's empty wallet.\n\n" +
      "  WHAT IT BUYS: it is the only thing protecting you if someone finds the\n" +
      "  paper. Without it, the paper alone is the wallet.\n\n" +
      "  WHAT IT DOES NOT BUY: entropy. The seed already has 256 bits. And\n" +
      "  BIP-39 stretches with only 2048 PBKDF2 iterations, so an attacker\n" +
      "  holding your 24 words tests passphrase guesses cheaply - a weak one is\n" +
      "  worth almost nothing. Use 4+ Diceware words or 12+ random characters.\n\n" +
      "  IT IS NOT RECOVERABLE. Forget it and the funds are gone, permanently.\n" +
      "  It is stored nowhere, and SLIP-39 shares do not carry it either.\n\n" +
      "  COMPATIBILITY: MetaMask does NOT support BIP-39 passphrases. If you\n" +
      "  set one, importing these 24 words into MetaMask opens the EMPTY\n" +
      "  no-passphrase wallet, not yours - which looks exactly like theft.\n" +
      "  Ledger, Trezor and Rabby do support it.\n\n" +
      "  Empty = standard wallet, opens in every wallet's default import.\n" +
      "  Input is hidden. Press Enter on an empty line for no passphrase.\n\n",
  );
  const firstRaw = await readInput("passphrase: ");
  if (newWallet) validateNewWalletPassphrase(firstRaw);
  else if (/[^\x20-\x7e]/.test(firstRaw)) {
    process.stdout.write(
      "\n  ! Unicode recovery mode: the text will be normalized with NFKD.\n" +
        "  ! Confirm the resulting wallet fingerprint against your record.\n",
    );
  }
  const first = normalizePassphrase(firstRaw);
  if (first === "") {
    process.stdout.write("Using an EMPTY passphrase (standard wallet).\n");
    return "";
  }
  const secondRaw = await readInput("repeat:     ");
  if (newWallet) validateNewWalletPassphrase(secondRaw);
  const second = normalizePassphrase(secondRaw);
  // A silent typo here produces a permanently different, unrecoverable wallet.
  assert.equal(first, second, "Passphrases do not match - nothing was generated");

  process.stdout.write("\nPassphrase accepted and confirmed.\n");
  if (looksObviouslyWeakPassphrase(first)) {
    process.stdout.write(
      "\n  ! This passphrase has an obvious weak structure or is short.\n" +
        "  ! Software cannot infer how randomly a passphrase was selected and\n" +
        "  ! therefore cannot assign it honest entropy or cracking-time numbers.\n" +
        "  ! Use independently sampled Diceware words/random characters, or use\n" +
        "  ! no passphrase. Ctrl+C now to reconsider.\n",
    );
  }
  return first;
}

async function readDice() {
  const bits = (n) => (n * Math.log2(6)).toFixed(1);
  process.stdout.write(
    `\nDice entropy. You need at least ${DICE_MIN_ROLLS} d6 rolls ` +
      `(= ${bits(DICE_MIN_ROLLS)} bits).\n\n` +
      "  YOU DO NOT HAVE TO ROLL ONE DIE AT A TIME. Throw five or six dice as a\n" +
      "  handful and read them left to right: " + DICE_MIN_ROLLS +
      " rolls is about " + Math.ceil(DICE_MIN_ROLLS / 6) +
      " throws\n  with six dice, or " + Math.ceil(DICE_MIN_ROLLS / 5) +
      " with five. Five to seven minutes.\n\n" +
      "  Type the results as digits 1-6. Spaces and commas are ignored. You can\n" +
      "  enter them in BATCHES: press Enter after each handful and keep going -\n" +
      "  nothing is lost between batches. Input is hidden; only the running\n" +
      "  count is echoed so you can confirm it.\n\n" +
      "  More than the minimum is accepted, but adds nothing: the result is\n" +
      "  hashed to 256 bits either way, and " + DICE_MIN_ROLLS +
      " fair rolls already exceed that.\n\n" +
      "  DIGITS 1-6 ONLY, and they must come from a real die. Typing digits\n" +
      "  out of your head is not randomness - people avoid repeats, favour\n" +
      "  some digits and produce distributions FLATTER than chance. The\n" +
      "  chi-square below is checked in both directions and will say so.\n\n" +
      "  Type `cancel` on an empty prompt to continue without dice instead.\n\n" +
      "This is the ONLY entropy source independent of this machine. It is XORed\n" +
      "with the OS sources, so it can only help: a bad die cannot weaken the\n" +
      "result, and a backdoored OS RNG cannot compromise it.\n\n",
  );

  // Accumulate across as many batches as it takes. Aborting the whole run
  // because a batch fell short would throw away everything already typed -
  // which, at roll 120 of 128, is the kind of thing that makes people give up
  // on dice altogether and take the weaker path.
  const rolls = [];
  while (rolls.length < DICE_MIN_ROLLS) {
    const raw = await readInput(`rolls (${rolls.length}/${DICE_MIN_ROLLS}): `);
    if (raw.trim().toLowerCase() === "cancel") {
      process.stdout.write("  Cancelled - continuing without dice.\n");
      return null;
    }
    const batch = [...raw].filter((c) => c >= "1" && c <= "6").map(Number);
    const ignored = [...raw].filter((c) => !/[1-6\s,.-]/.test(c)).length;
    if (ignored > 0) {
      process.stdout.write(`  ! ${ignored} character(s) outside 1-6 were ignored.\n`);
    }
    if (batch.length === 0) {
      process.stdout.write("  ! Nothing usable in that line. Digits 1-6 only.\n");
      continue;
    }
    rolls.push(...batch);
    const left = DICE_MIN_ROLLS - rolls.length;
    process.stdout.write(
      left > 0
        ? `  +${batch.length}, total ${rolls.length}/${DICE_MIN_ROLLS} - ${left} to go\n`
        : `  +${batch.length}, total ${rolls.length} - enough\n`,
    );
  }

  const dice = diceEntropy(rolls);
  process.stdout.write(
    `  accepted ${rolls.length} rolls = ${dice.bits.toFixed(1)} bits ` +
      `(chi-square ${dice.chi.toFixed(1)}, df=5)\n`,
  );
  if (dice.biased) {
    process.stdout.write(
      "  ! Chi-square is high (p < 0.001). The die may be biased or the input\n" +
        "  ! mistyped. Harmless here because of the XOR, but worth a second look.\n",
    );
  }
  if (dice.tooFlat) {
    process.stdout.write(
      "  ! Chi-square is suspiciously LOW: this distribution is flatter than\n" +
        "  ! chance produces. That is what typed-from-imagination digits look\n" +
        "  ! like. If you did not physically roll these, roll them.\n",
    );
  }
  return { ...dice, rolls: rolls.length };
}

// ---------------------------------------------------------------------------
// OUTPUT
// ---------------------------------------------------------------------------

function printPhrase(phrase) {
  const words = phrase.split(" ");
  const rows = Math.ceil(words.length / 3);
  process.stdout.write(
    "\n================================================================\n" +
      "  WRITE THIS ON PAPER. DO NOT PHOTOGRAPH, COPY OR TYPE IT ELSEWHERE.\n" +
      "================================================================\n\n",
  );
  for (let r = 0; r < rows; r += 1) {
    const cells = [];
    for (let c = 0; c < 3; c += 1) {
      const i = r + c * rows;
      if (i < words.length) {
        cells.push(`${String(i + 1).padStart(2)}. ${words[i].padEnd(9)}`);
      }
    }
    process.stdout.write(`    ${cells.join("   ")}\n`);
  }
  // Printed twice on purpose: the numbered grid is what you write from, the
  // flat line is an independent read-back that catches a transcription slip.
  process.stdout.write(`\n  read-back: ${phrase}\n`);
}

function printAccounts(accounts, { showPrivate, showPublic }) {
  for (const account of accounts) {
    process.stdout.write(`index:       ${account.index}\n`);
    process.stdout.write(`path:        ${account.path}\n`);
    process.stdout.write(`address:     ${account.address}\n`);
    if (showPublic) {
      process.stdout.write(`public key:  0x${bytesToHex(account.publicKey)}\n`);
    }
    if (showPrivate) {
      process.stdout.write(`private key: 0x${account.privateKey.toString("hex")}\n`);
    }
    process.stdout.write("\n");
  }
}

/**
 * Print the address list as scannable QR symbols.
 *
 * Takes ADDRESSES ONLY, and encodeAddressQRs re-validates every entry against
 * the EVM address shape before encoding. Nothing else in this file may be
 * routed here: a mnemonic, a private key, a SLIP-39 share or an extended
 * public key would all be rejected, and that rejection is the point.
 *
 * This is a convenience for comparing an address list against a second device
 * without retyping 42 hex characters. It is NOT independent verification -
 * checking a derivation independently needs the second device to DERIVE the
 * addresses, which needs the seed there. See docs/en/COMPARISON.md.
 */
function printAddressQRs(accounts) {
  const symbols = encodeAddressQRs(accounts.map((a) => a.address));
  process.stdout.write(
    `\nADDRESS QR (${symbols.length} symbol${symbols.length > 1 ? "s" : ""})\n` +
      "  Scanning these gives you the address list on a phone so you can compare\n" +
      "  it against what your wallet shows after import. It carries addresses\n" +
      "  only - never the phrase, keys, shares or an extended public key.\n" +
      "  This is a transcription aid, not independent verification.\n",
  );
  for (const { label, symbol } of symbols) {
    process.stdout.write(`\n  ${label}  (v${symbol.version}, ${symbol.size}x${symbol.size})\n\n`);
    process.stdout.write(`${renderQR(symbol, { quiet: 4 })}\n`);
  }
}

async function offerScreenWipe() {
  process.stdout.write(
    "\nScreen wipe. Type the word \"wipe\" and press Enter to clear the screen and\n" +
      "the terminal scrollback. Press Enter alone to leave the output on screen.\n" +
      "Do this only AFTER writing the phrase down and verifying it with\n" +
      "`npm run verify`. Cleared output cannot be recovered.\n\n",
  );
  const answer = await readInput("> ", { echo: true });
  if (answer.trim().toLowerCase() === "wipe") {
    // ED 3 clears scrollback, ED 2 clears the screen, H homes the cursor.
    process.stdout.write(`${ESC}[3J${ESC}[2J${ESC}[H`);
    process.stdout.write(
      "Screen and scrollback cleared. This affects THIS terminal only - it does\n" +
        "not touch tmux buffers, iTerm2 Instant Replay recordings, or any session\n" +
        "log your terminal keeps on disk.\n",
    );
  }
}

// ---------------------------------------------------------------------------
// SLIP-39 BACKUP SPLITTING
//
// CRITICAL SEMANTIC NOTE, and the reason every banner below shouts it:
// this tool splits the BIP-39 ENTROPY. Trezor and the reference
// shamir-mnemonic tool treat a recovered SLIP-39 master secret as a BIP-32
// SEED DIRECTLY. Measured against the official vectors, those two readings
// produce completely different wallets from identical shares. Recovering
// these shares on a Trezor therefore yields UNFAMILIAR ADDRESSES. Recover
// them with `--combine` here, or with any tool that then runs the recovered
// bytes through BIP-39.
// ---------------------------------------------------------------------------

/** Parse "2of3" or "2of3,3of5" into [{threshold, count}, ...]. */
function parseGroupSpec(spec) {
  return spec.split(",").map((part) => {
    const m = /^([0-9]+)of([0-9]+)$/i.exec(part.trim());
    assert.ok(m, `Bad share specification "${part}". Use e.g. 2of3.`);
    const threshold = Number.parseInt(m[1], 10);
    const count = Number.parseInt(m[2], 10);
    assert.ok(
      threshold >= 1 && threshold <= count && count <= 16,
      `Bad share specification "${part}": need 1 <= threshold <= count <= 16.`,
    );
    assert.ok(
      !(threshold === 1 && count > 1),
      `"${part}" would make every share a full copy of the secret. ` +
        "Use 1of1, or raise the threshold.",
    );
    return { threshold, count };
  });
}

function printShares(groupsOfShares, groups, groupThreshold) {
  process.stdout.write(
    "\n================================================================\n" +
      "  SLIP-39 BACKUP SHARES - WRITE ON PAPER, STORE SEPARATELY\n" +
      "================================================================\n\n" +
      "  These shares restore the BIP-39 ENTROPY of this wallet.\n" +
      "  They are NOT a BIP-32 seed. A Trezor recovering them would show\n" +
      "  DIFFERENT addresses. Recover with:  npm run combine\n\n" +
      "  They do NOT contain your BIP-39 passphrase. If you set one, it must\n" +
      "  be stored separately or the shares alone restore nothing.\n\n",
  );
  const need = groupThreshold === 1
    ? `any ${groups[0].threshold} of the ${groups[0].count} shares below`
    : `any ${groupThreshold} of the ${groups.length} groups, at their thresholds`;
  process.stdout.write(`  To restore you need: ${need}.\n`);
  process.stdout.write(
    "  Fewer than that cannot restore the wallet. SLIP-39's four-byte digest\n" +
      "  leaks up to about 32 bits, so for this 256-bit secret roughly 224 bits\n" +
      "  remain unknown: infeasible, but not a literal zero-information claim.\n",
  );

  groupsOfShares.forEach((shares, gi) => {
    process.stdout.write(
      `\n  ---- GROUP ${gi + 1} of ${groupsOfShares.length} ` +
        `(need ${groups[gi].threshold} of these ${groups[gi].count}) ----\n`,
    );
    shares.forEach((share, si) => {
      const words = share.split(" ");
      process.stdout.write(`\n  Group ${gi + 1}, share ${si + 1}  (${words.length} words)\n`);
      const rows = Math.ceil(words.length / 4);
      for (let r = 0; r < rows; r += 1) {
        const cells = [];
        for (let c = 0; c < 4; c += 1) {
          const i = r + c * rows;
          if (i < words.length) {
            cells.push(`${String(i + 1).padStart(2)}. ${words[i].padEnd(8)}`);
          }
        }
        process.stdout.write(`    ${cells.join("  ")}\n`);
      }
    });
  });
  process.stdout.write(
    "\n  Store each share in a DIFFERENT physical place. Two shares in one\n" +
      "  drawer is one share with extra steps.\n",
  );
}

async function readShares() {
  process.stdout.write(
    "\nType your SLIP-39 shares, one per line, from your PAPER backups.\n" +
      "Input is hidden. Press Enter on an empty line when you are done.\n\n",
  );
  const shares = [];
  for (let i = 1; ; i += 1) {
    const line = await readInput(`share ${i} (empty line to finish): `);
    if (line.trim() === "") break;
    shares.push(line.trim());
    process.stdout.write(`  accepted ${line.trim().split(/\s+/).length} words\n`);
  }
  assert.ok(shares.length > 0, "No shares entered");
  return shares;
}

// ---------------------------------------------------------------------------
// MNEMONIC REPAIR (for --verify)
// ---------------------------------------------------------------------------

function levenshtein(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i += 1) {
    const cur = [i];
    for (let j = 1; j <= b.length; j += 1) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
    prev = cur;
  }
  return prev[b.length];
}

/**
 * Normalise typed words. BIP-39 guarantees the first four letters of every
 * English word are unique, so an unambiguous prefix is expanded rather than
 * rejected. Unknown words are reported with their nearest candidates: the
 * dominant real-world failure of a paper backup is a misread letter, not a
 * broken CSPRNG.
 */
function repairWords(input) {
  const typed = input
    .normalize("NFKD")
    .toLowerCase()
    .trim()
    .split(/\s+/)
    .filter(Boolean);
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
    const near = wordlist
      .map((w) => [levenshtein(word, w), w])
      .sort((x, y) => x[0] - y[0])
      .slice(0, 3)
      .map(([d, w]) => `${w} (distance ${d})`);
    problems.push(
      `  word ${i + 1}: "${word}" is not a BIP-39 word. Closest: ${near.join(", ")}`,
    );
    words.push(word);
  }
  return { words, notes, problems };
}

// ---------------------------------------------------------------------------
// SELF-TEST
//
// Known-answer vectors for every component, PLUS negative tests that prove the
// refusal paths actually fire. A hardening pass whose guards were never
// observed firing has not been tested.
// ---------------------------------------------------------------------------

function selfTest({ quiet = false } = {}) {
  const log = (m) => {
    if (!quiet) process.stdout.write(`  ok  ${m}\n`);
  };
  if (!quiet) process.stdout.write("\nSELF-TEST\n");

  assertWordlistIntegrity();
  log("BIP-39 English wordlist matches the published SHA-256");

  // --- EIP-55 official test vectors, from the EIP-55 specification.
  for (const vector of [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
  ]) {
    assert.equal(toChecksumAddress(vector.slice(2).toLowerCase()), vector);
  }
  log("EIP-55 checksum matches all four official vectors");

  // --- BIP-39 official 256-bit vector. The passphrase is "TREZOR" only
  // because that is how the published BIP-39 vectors are defined.
  const zeroEntropy = new Uint8Array(32);
  const expectedPhrase = `${"abandon ".repeat(23)}art`;
  const expectedSeed = Buffer.from(
    "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd309717" +
      "0af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    "hex",
  );
  const phrase = entropyToMnemonic(zeroEntropy, wordlist);
  assert.equal(phrase, expectedPhrase);
  assert.equal(validateMnemonic(phrase, wordlist), true);
  assert.equal(bytesToHex(mnemonicToEntropy(phrase, wordlist)), "00".repeat(32));
  assert.ok(equalBytes(mnemonicToSeedSync(phrase, "TREZOR"), expectedSeed));
  log("BIP-39 256-bit vector: mnemonic, checksum, PBKDF2 seed");

  // --- The reference implementation must reproduce the same vector.
  assert.equal(refEntropyToMnemonic(zeroEntropy, wordlist), expectedPhrase);
  assert.ok(equalBytes(refMnemonicToSeed(phrase, "TREZOR"), expectedSeed));
  log("reference BIP-39 implementation reproduces the same vector");

  // --- Well-known public Hardhat development vector. NEVER use this phrase.
  const devPhrase = "test test test test test test test test test test test junk";
  assert.equal(validateMnemonic(devPhrase, wordlist), true);
  const devSeed = mnemonicToSeedSync(devPhrase);
  const devKey = HDKey.fromMasterSeed(devSeed).derive("m/44'/60'/0'/0/0");
  assert.equal(
    `0x${bytesToHex(devKey.privateKey)}`,
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  );
  assert.equal(
    addressFromPrivateKey(devKey.privateKey).address,
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  );
  log("BIP-32 + EVM address vector: Hardhat account 0, mixed-case checksum");

  // --- Reference BIP-32 must agree, hardened levels included.
  assert.ok(equalBytes(refDerive(devSeed, "m/44'/60'/0'/0/0"), devKey.privateKey));
  assert.equal(
    refFingerprint(devSeed),
    `0x${(HDKey.fromMasterSeed(devSeed).fingerprint >>> 0)
      .toString(16)
      .padStart(8, "0")}`,
  );
  log("reference BIP-32 CKDpriv and master fingerprint agree");

  // --- Both path schemes, full cross-check, no duplicate addresses.
  for (const scheme of Object.keys(PATH_SCHEMES)) {
    const { accounts, fingerprint, dispose } = primaryAccounts(devSeed, scheme, 5);
    crossCheck({
      phrase: devPhrase,
      passphrase: "",
      seed: devSeed,
      accounts,
      fingerprint,
    });
    assert.equal(new Set(accounts.map((a) => a.address)).size, accounts.length);
    for (const a of accounts) assert.match(a.address, /^0x[0-9A-Fa-f]{40}$/);
    dispose();
    log(`scheme "${scheme}" (${templateFor(scheme)}) cross-checks clean`);
  }

  // --- A passphrase must change the wallet completely.
  const withPass = HDKey.fromMasterSeed(mnemonicToSeedSync(devPhrase, "x")).derive(
    "m/44'/60'/0'/0/0",
  );
  assert.ok(!equalBytes(withPass.privateKey, devKey.privateKey));
  log("BIP-39 passphrase produces a different wallet");

  // --- NEGATIVE TESTS: every guard must actually fire.
  assert.throws(
    () => healthTest("stuck", Buffer.alloc(4096)),
    /repetition count/,
    "health test failed to reject an all-zero source",
  );
  const skewed = Buffer.alloc(4096);
  for (let i = 0; i < skewed.length; i += 1) skewed[i] = i % 2 ? 0xff : 0xfe;
  assert.throws(
    () => healthTest("skewed", skewed),
    /adaptive proportion|monobit/,
    "health test failed to reject a skewed source",
  );
  assert.throws(() => diceEntropy([1, 2, 3]), /at least/, "dice minimum not enforced");
  assert.throws(
    () =>
      crossCheck({
        phrase: devPhrase,
        passphrase: "",
        seed: devSeed,
        fingerprint: refFingerprint(devSeed),
        accounts: [
          {
            path: "m/44'/60'/0'/0/0",
            privateKey: Buffer.alloc(32, 1),
            address: "0x0000000000000000000000000000000000000000",
          },
        ],
      }),
    /CROSS-CHECK FAILED/,
    "cross-check failed to reject a tampered key",
  );
  assert.throws(() => parsePath("x/1"), /must start with/, "path parser too permissive");
  assert.notEqual(refEntropyToMnemonic(Buffer.alloc(32, 1), wordlist), expectedPhrase);
  log("negative tests: health, dice, cross-check and path guards all fire");

  // --- SLIP-39: official vectors, GF(256) arithmetic, exhaustive round-trip.
  // This module has no second implementation (see slip39.mjs header); these
  // external vectors and the round-trip stand in for one.
  slip39SelfTest({ vectors: SLIP39_VECTORS, fixtures: SLIP39_FIXTURES, log });

  // QR encoder: GF(256)/0x11D pinning and the address-only input guard.
  qrSelfTest({ log });

  // --- Mnemonic repair helper.
  const repaired = repairWords("aban ABANDON  abandonx");
  assert.equal(repaired.words[0], "abandon");
  assert.equal(repaired.words[1], "abandon");
  assert.equal(repaired.problems.length, 1);
  log("mnemonic repair: prefix expansion and typo detection");

  if (!quiet) {
    process.stdout.write("\nSelf-test OK - all vectors and negative tests passed.\n");
  }
}

// ---------------------------------------------------------------------------
// COMMANDS
// ---------------------------------------------------------------------------

/**
 * Demonstrate the Node trusted-code capability guard. This is a useful
 * least-privilege guard against accidental access by reviewed code; Node's
 * documentation explicitly does not define it as a malicious-code sandbox.
 *
 * This exists because "the tool is offline" is otherwise an assertion the user
 * has to take on trust. Here it is an observation they can reproduce.
 */
async function proveSandbox() {
  const rows = [];
  const probe = async (name, fn) => {
    try {
      await fn();
      rows.push({ ok: false, name, detail: "ALLOWED" });
    } catch (error) {
      rows.push({
        ok: true,
        name,
        detail: error.code ?? error.cause?.code ?? "blocked",
      });
    }
  };

  process.stdout.write("\nTRUSTED-CODE CAPABILITY GUARD\n");
  if (!process.permission) {
    process.stdout.write(
      "  x   Permission model is OFF - nothing below is enforced.\n" +
        "      Run this through `npm run prove-guard`, which passes --permission.\n",
    );
  }

  await probe("network: fetch()", () => fetch("http://127.0.0.1:1"));
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
  await probe("file write", () =>
    fs.writeFileSync("/tmp/heatdeath-sandbox-probe", "x"));
  await probe("read outside the package", () =>
    fs.readFileSync(`${os.homedir()}/.ssh/id_rsa`));

  for (const row of rows) {
    process.stdout.write(
      `  ${row.ok ? "ok " : "FAIL"}  ${row.name.padEnd(26)} ${row.detail}\n`,
    );
  }

  // Allowed on purpose, and read with a bounded length: /dev/urandom is an
  // endless stream, so a plain readFileSync on it never returns.
  const sample = readUrandom(32);
  process.stdout.write(
    `\n  ok    /dev/urandom readable (${sample.length} bytes) - required for entropy\n`,
  );
  sample.fill(0);

  const denied = rows.filter((r) => r.ok).length;
  process.stdout.write(
    `\n${denied}/${rows.length} capability probes denied by the runtime.\n`,
  );
  process.stdout.write(
    "\nSCOPE: this is not a malicious-code sandbox. Permission checks are a\n" +
      "seatbelt for code whose provenance you already trust. A signed but\n" +
      "malicious program can attack its own process and secret memory.\n\n" +
      "NOTE: inside a prebuilt binary this output proves nothing. The binary\n" +
      "contains this source as plain text and can be patched, and a patched\n" +
      "build will happily print the same line. Self-attestation from an\n" +
      "artifact an attacker controls is circular. Trust this result only when\n" +
      "you ran it from source you read, or from a build you reproduced\n" +
      "yourself - see docs/en/VERIFY.md.\n",
  );
  if (denied !== rows.length) {
    throw new Error("the capability guard is NOT fully enforced - see FAIL rows above");
  }
}

async function generate({ showPrivate, showPublic, scheme, count, useDice, wipe, qr }) {
  assertRuntime();
  // Known-answer vectors run BEFORE any secret exists. A tampered or
  // mismatched dependency tree is caught here, not after the phrase is on
  // paper. It costs milliseconds.
  selfTest({ quiet: true });
  process.stdout.write("\nSelf-test OK (run `npm run self-test` to see every vector).\n");

  const dice = useDice ? await readDice() : null;
  const { entropy, report } = collectEntropy({ dice });

  process.stdout.write("\nENTROPY SOURCES\n");
  for (const r of report) process.stdout.write(`  - ${r.name.padEnd(16)} ${r.status}\n`);
  process.stdout.write(
    `  = ${ENTROPY_BYTES * 8} bits, combined by XOR of domain-separated SHA-256\n`,
  );
  if (!useDice) {
    process.stdout.write(
      "  ! No dice used. Every source above lives on this machine. Consider\n" +
        "  ! `npm run generate:dice` for a source independent of it.\n",
    );
  }

  // Secret material exists from here on. The finally block zeroises it even
  // when a check throws part-way through.
  let seed = null;
  let bundle = null;
  try {
    const phrase = entropyToMnemonic(entropy, wordlist);
    assert.equal(phrase.split(" ").length, 24);
    assert.equal(validateMnemonic(phrase, wordlist), true);

    // Round trip: the words about to be written on paper must reconstruct
    // exactly the bytes that were generated.
    assert.ok(
      equalBytes(mnemonicToEntropy(phrase, wordlist), entropy),
      "ROUND-TRIP FAILED: the mnemonic does not reconstruct the generated entropy",
    );

    const passphrase = await readPassphraseTwice({ newWallet: true });
    seed = mnemonicToSeedSync(phrase, passphrase);
    bundle = primaryAccounts(seed, scheme, count);
    const { accounts, fingerprint } = bundle;

    // Everything above must succeed before a single secret is shown.
    crossCheck({ entropy, phrase, passphrase, seed, accounts, fingerprint });
    assert.equal(
      new Set(accounts.map((a) => a.address)).size,
      accounts.length,
      "Duplicate addresses in derivation output",
    );

    process.stdout.write("\nVERIFICATION\n");
    process.stdout.write("  ok  round-trip: the mnemonic reconstructs the exact entropy\n");
    process.stdout.write(
      "  ok  cross-check: independent BIP-39/BIP-32 implementation agrees\n",
    );
    process.stdout.write(`  ok  ${accounts.length} distinct addresses derived\n`);

    printPhrase(phrase);

    process.stdout.write(
      `\n  BIP-39 passphrase:  ${passphrase ? "SET (not shown)" : "empty"}\n`,
    );
    process.stdout.write(
      `  derivation scheme:  ${scheme} - ${templateFor(scheme)}\n`,
    );
    process.stdout.write(
      `  master fingerprint: ${fingerprint}  (not secret; use it to confirm a restore)\n\n`,
    );
    if (PATH_SCHEMES[scheme].linkable) {
      process.stdout.write(
        "  ! Privacy: every address below shares one extended public key. Anyone\n" +
          "  ! holding it can link them all to a single wallet. Use --scheme=account\n" +
          "  ! for addresses that are not linkable this way.\n\n",
      );
    }

    printAccounts(accounts, { showPrivate, showPublic });
    if (qr) printAddressQRs(accounts);

    if (!showPublic) {
      process.stdout.write(
        "Public keys were not printed. Publishing the public key of an address that\n" +
          "has never sent a transaction removes its 160-bit hash barrier against a\n" +
          "future quantum attack. Use --show-public only if you truly need them.\n",
      );
    }
    if (!showPrivate) {
      process.stdout.write(
        "Private keys were not printed. The mnemonic already controls every derived\n" +
          "account, so exporting individual keys usually only adds risk.\n",
      );
    }

    // The master fingerprint is computed at the master level and index 0 resolves
    // to the same path under both templates, so NEITHER distinguishes the scheme.
    // Verifying with the wrong scheme would match on both and still leave every
    // index >= 1 wrong. The anchor below is index 1 for exactly that reason.
    const verifyCmd =
      scheme === DEFAULT_SCHEME ? "npm run verify" : `npm run verify:${scheme}`;
    process.stdout.write(
      "\nNEXT STEP - verify what you wrote, before funding anything:\n" +
        `    ${verifyCmd}\n` +
        `Use the SAME derivation scheme (${scheme}). Type the phrase from your\n` +
        "PAPER, not from this screen.\n\n" +
        `    master fingerprint   ${fingerprint}\n`,
    );
    if (accounts.length >= 2) {
      process.stdout.write(
        `    index 1 address      ${accounts[1].address}\n\n` +
          "Confirm BOTH. The fingerprint and the index 0 address are identical\n" +
          "under both schemes, so only index 1 and above prove you verified with\n" +
          "the scheme you actually generated with.\n",
      );
    } else {
      process.stdout.write(
        "\nOnly one account was derived, and index 0 is the same path under both\n" +
          "schemes - so this run cannot prove which scheme you used. Verify with\n" +
          `    ${verifyCmd} -- --accounts=2\n`,
      );
    }

  } finally {
    // Best effort only. JavaScript strings are immutable, so `phrase` itself
    // cannot be erased and lives in the heap until garbage collection.
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
  process.stdout.write("\nSelf-test OK.\n");

  process.stdout.write(
    "\nType the recovery phrase FROM YOUR PAPER BACKUP. Input is hidden.\n" +
      "Unambiguous abbreviations of 3+ letters are expanded automatically, and\n" +
      "unknown words are reported with their nearest wordlist candidates.\n\n",
  );
  const raw = await readInput("phrase: ");
  const { words, notes, problems } = repairWords(raw);

  if (notes.length > 0) {
    process.stdout.write("\nEXPANSIONS\n");
    for (const n of notes) process.stdout.write(`${n}\n`);
  }
  if (problems.length > 0) {
    process.stdout.write("\nPROBLEMS\n");
    for (const p of problems) process.stdout.write(`${p}\n`);
    throw new Error(`${problems.length} word(s) are not valid BIP-39 words`);
  }
  assert.ok(
    [12, 15, 18, 21, 24].includes(words.length),
    `A BIP-39 phrase has 12/15/18/21/24 words; you entered ${words.length}`,
  );

  const phrase = words.join(" ");
  assert.equal(
    validateMnemonic(phrase, wordlist),
    true,
    "CHECKSUM FAILED. Every word is a valid BIP-39 word, but the phrase as a " +
      "whole is not - a word is in the wrong position, or one word is wrong. " +
      "Re-read the paper carefully; the order matters.",
  );
  process.stdout.write(`\n  ok  ${words.length} valid words, BIP-39 checksum correct\n`);

  const passphrase = await readPassphraseTwice();
  const seed = mnemonicToSeedSync(phrase, passphrase);
  const { accounts, fingerprint, dispose } = primaryAccounts(seed, scheme, count);
  crossCheck({ entropy: null, phrase, passphrase, seed, accounts, fingerprint });
  process.stdout.write("  ok  cross-check: independent implementation agrees\n");

  process.stdout.write(
    `\n  BIP-39 passphrase:  ${passphrase ? "SET (not shown)" : "empty"}\n`,
  );
  process.stdout.write(
    `  derivation scheme:  ${scheme} - ${templateFor(scheme)}\n`,
  );
  process.stdout.write(`  master fingerprint: ${fingerprint}\n`);
  process.stdout.write(
    "  note: the fingerprint and the index 0 address are identical under both\n" +
      "        schemes. Only index 1 and above tell them apart.\n\n",
  );
  printAccounts(accounts, { showPrivate, showPublic });
  if (qr) printAddressQRs(accounts);
  process.stdout.write(
    "If the fingerprint and the addresses match what you recorded, the paper\n" +
      "backup is correct. If they do not, the phrase you typed is NOT the one you\n" +
      "generated - do not fund it.\n",
  );

  dispose();
  for (const a of accounts) a.privateKey.fill(0);
  seed.fill(0);
}

// ---------------------------------------------------------------------------
// GUIDED MODE
//
// WHY THIS EXISTS, AND WHY IT CANNOT WEAKEN ANYTHING
// -------------------------------------------------
// The dangerous step in this workflow is not cryptographic. It is a human one:
// people generate a phrase, glance at it, write it down, and never run the
// verification. A wrong letter that still satisfies the BIP-39 checksum
// happens about once in 256 and is discovered years later, when it is a total
// loss.
//
// This mode contains NO cryptography of its own. Every operation below is a
// call into a function that already exists and is already covered by the
// self-test: assertRuntime, selfTest, collectEntropy, crossCheck,
// primaryAccounts, splitSecretIntoShares. It is orchestration. It cannot make
// the guarantees weaker because it does not implement any of them - it only
// removes the option of skipping a step.
//
// It is also strictly STRONGER than the manual path on the one axis that
// matters most: the read-back below clears the screen first and then compares
// what you type against the generated phrase word by word, in memory. The
// manual path asks you to compare addresses by eye, which is exactly the check
// a tired person performs badly.
// ---------------------------------------------------------------------------

const useColour = () => Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const paint = (code, text) => (useColour() ? `${ESC}[${code}m${text}${ESC}[0m` : text);
const bold = (t) => paint("1", t);
const dim = (t) => paint("2", t);
const red = (t) => paint("31", t);
const green = (t) => paint("32", t);
const yellow = (t) => paint("33", t);

function step(number, total, title) {
  process.stdout.write(
    `\n${bold(`${ESC}[7m STEP ${number}/${total} ${ESC}[0m`)} ${bold(title)}\n` +
      `${dim("-".repeat(64))}\n`,
  );
}

async function confirm(prompt, word) {
  const answer = await readInput(`${prompt} [${word}] `, { echo: true });
  return answer.trim().toLowerCase() === word.toLowerCase();
}

/**
 * Blind read-back: the phrase leaves the screen, then you type it from paper
 * and it is compared word by word against what was generated.
 *
 * The screen is cleared only AFTER you confirm the phrase is written down, and
 * the phrase can always be shown again on request. Nothing is destroyed while
 * a mismatch is outstanding - a wizard that lost someone's seed to a cleared
 * screen would be worse than no wizard.
 */
async function blindReadBack(phrase) {
  const words = phrase.split(" ");

  // The "written it down?" gate is asked ONCE, before the screen is cleared.
  // After a mismatch we return straight to the typing prompt: the paper has
  // just been corrected, and asking again whether it is written down would be
  // both confusing and a dead end.
  while (!(await confirm(`\n${yellow("Written it down on paper?")} Type`, "written"))) {
    process.stdout.write(dim("  Take your time. The phrase is still on screen above.\n"));
  }
  process.stdout.write(`${ESC}[3J${ESC}[2J${ESC}[H`);
  process.stdout.write(
    `${bold("READ-BACK CHECK")}\n` +
      "The phrase is off the screen. Type it from your PAPER - not from memory,\n" +
      "and not by scrolling back. Input is hidden.\n" +
      dim("(type `show` to display the phrase again)\n"),
  );

  for (;;) {
    const typed = await readInput("\nphrase: ");
    if (typed.trim().toLowerCase() === "show") {
      printPhrase(phrase);
      continue;
    }

    const { words: fixed, notes, problems } = repairWords(typed);
    for (const note of notes) process.stdout.write(dim(`${note}\n`));
    for (const problem of problems) process.stdout.write(red(`${problem}\n`));

    const mismatches = [];
    for (let i = 0; i < Math.max(words.length, fixed.length); i += 1) {
      if (fixed[i] !== words[i]) mismatches.push(i + 1);
    }
    if (mismatches.length === 0) {
      process.stdout.write(green("\n  MATCH. Your paper reproduces the phrase exactly.\n"));
      return;
    }

    process.stdout.write(
      red(`\n  MISMATCH at word ${mismatches.join(", ")}.\n`) +
        "  Your paper is wrong; the generated phrase is correct. Fix the paper:\n",
    );
    for (const position of mismatches.slice(0, 24)) {
      const expected = words[position - 1] ?? "(missing)";
      const got = fixed[position - 1] ?? "(missing)";
      process.stdout.write(
        `    ${String(position).padStart(2)}. correct: ${bold(expected)}` +
          `   you typed: ${red(got)}\n`,
      );
    }
    process.stdout.write(dim("\n  Correct the paper, then type it again.\n"));
  }
}

async function wizard(cli) {
  const TOTAL = 6;

  step(1, TOTAL, "Environment and integrity");
  assertRuntime();
  selfTest({ quiet: true });
  process.stdout.write(
    green("  ok  ") + "known-answer vectors passed before any secret exists\n" +
      (process.permission
        ? green("  ok  ") + "capability guard active (`npm run prove-guard` to inspect it)\n"
        : yellow("  !   ") + "capability guard OFF - prefer signed npm commands\n"),
  );
  process.stdout.write(
    "\n" + bold("Before continuing, confirm you have:") + "\n" +
      "  * turned off Wi-Fi, Ethernet and Bluetooth\n" +
      "  * disabled iTerm2 Instant Replay and unlimited scrollback\n" +
      "  * quit clipboard managers (Raycast, Paste, Alfred)\n" +
      "  * paper and pen in front of you\n" +
      dim("  Details: QUICKSTART.md\n"),
  );
  if (!(await confirm("\nAll of the above done? Type", "ready"))) {
    throw new Error("stopped at your request - nothing was generated");
  }

  step(2, TOTAL, "Entropy");
  let dice = null;
  process.stdout.write(
    bold("Both answers give you a secure wallet. The difference is what you\n" +
         "are trusting.\n\n") +
      `  ${bold("no")}  - 256 bits from two required OS paths with health checks.\n` +
      "        Fully automatic, takes seconds. This is what most people do.\n\n" +
      `  ${bold("yes")} - the same, PLUS numbers from a real die you roll yourself,\n` +
      "        mixed in by XOR. This is a PHYSICAL die: about " +
      `${Math.ceil(DICE_MIN_ROLLS / 6)} throws of a\n` +
      "        handful of dice, five to seven minutes of your time.\n\n" +
      "Dice are the only entropy source independent of this machine, so they\n" +
      "cover one specific scenario: the OS random generator itself being broken\n" +
      "or backdoored. They are XORed in, never substituted, so they cannot make\n" +
      "the result worse.\n" +
      dim("  Not hypothetical: a firmware bug shipped by a hardware-wallet vendor\n" +
          "  in 2026 cut real entropy to ~40 bits. Only users who had rolled\n" +
          "  dice were unaffected.\n\n"),
  );
  if (await confirm("Roll dice yourself? Type", "yes")) {
    dice = await readDice();
  } else {
    process.stdout.write(
      yellow("  !   ") + "Continuing without dice. Every remaining source lives on\n" +
      "      this machine, so you are trusting it completely.\n",
    );
  }
  const { entropy, report } = collectEntropy({ dice });
  for (const r of report) process.stdout.write(`  ${green("ok")}  ${r.name.padEnd(16)} ${r.status}\n`);

  step(3, TOTAL, "Passphrase - the optional 25th word");
  process.stdout.write(
    bold("Both answers give you a secure wallet. The difference is what happens\n" +
         "if someone finds your paper.\n\n") +
      `  ${bold("empty")} - the paper IS the wallet. Whoever reads those 24 words takes\n` +
      "          the funds. Opens in every wallet, MetaMask included.\n\n" +
      `  ${bold("set")}   - the 24 words alone become worthless: they open a different,\n` +
      "          empty wallet. But MetaMask cannot open yours at all, and\n" +
      "          forgetting the passphrase loses the funds permanently.\n\n" +
      bold("If you set one, type 4 or more random words") + ", like\n" +
      `      ${dim("harbor tulip cactus velvet")}\n` +
      "  Not a password you use anywhere else. Not a phrase you expect to\n" +
      "  reconstruct from memory - write it down and store it in a DIFFERENT\n" +
      "  place from the 24 words, or it protects nothing.\n\n" +
      yellow("  A short passphrase is the worst option of the three: too weak to\n" +
             "  protect the paper, still strong enough to lose the funds if you\n" +
             "  forget it.\n"),
  );
  const passphrase = await readPassphraseTwice({ newWallet: true });

  step(4, TOTAL, "Generation");
  const phrase = entropyToMnemonic(entropy, wordlist);
  assert.equal(validateMnemonic(phrase, wordlist), true);
  assert.ok(
    equalBytes(mnemonicToEntropy(phrase, wordlist), entropy),
    "ROUND-TRIP FAILED: the mnemonic does not reconstruct the generated entropy",
  );
  const seed = mnemonicToSeedSync(phrase, passphrase);
  const bundle = primaryAccounts(seed, cli.scheme, Math.max(cli.count, 2));
  try {
    crossCheck({
      entropy, phrase, passphrase, seed,
      accounts: bundle.accounts, fingerprint: bundle.fingerprint,
    });
    process.stdout.write(
      green("  ok  ") + "round-trip and independent cross-check both agree\n",
    );
    printPhrase(phrase);

    step(5, TOTAL, "Read-back - this is the step people skip");
    await blindReadBack(phrase);

    process.stdout.write(
      `\n  master fingerprint: ${bold(bundle.fingerprint)}\n` +
        `  scheme:             ${cli.scheme} - ${templateFor(cli.scheme)}\n` +
        `  index 1 address:    ${bold(bundle.accounts[1].address)}\n` +
        dim("  Write these two down as well. They identify this wallet later.\n"),
    );
    printAccounts(bundle.accounts.slice(0, cli.count), {
      showPrivate: false, showPublic: false,
    });
    if (cli.qr) printAddressQRs(bundle.accounts.slice(0, cli.count));

    step(6, TOTAL, "Backup against loss");
    process.stdout.write(
      "One piece of paper is a single point of failure, and losing it is more\n" +
        "likely than any attack. SLIP-39 splits the wallet into shares: any two\n" +
        "of three restore it. One alone leaves about 224 bits unknown; the\n" +
        "SLIP-39 digest prevents a literal zero-information claim.\n\n" +
        dim("  Shares carry the entropy, NOT your passphrase. Store them apart.\n\n"),
    );
    if (await confirm("Create 2-of-3 shares now? Type", "yes")) {
      const rng = makeShamirRng();
      try {
        const groups = parseGroupSpec("2of3");
        const shares = splitSecretIntoShares({
          secret: entropy, passphrase: "", groupThreshold: 1, groups,
          extendable: true, iterationExponent: 0, rng,
        });
        for (const subset of admissibleSubsets(1, groups, shares)) {
          assert.ok(
            equalBytes(combineShares(subset, ""), entropy),
            "ROUND-TRIP FAILED: a valid subset of shares does not restore the entropy",
          );
        }
        process.stdout.write(green("\n  ok  ") + "all 3 share combinations verified\n");
        printShares(shares, groups, 1);
      } finally {
        rng.dispose();
      }
    }

    process.stdout.write(
      `\n${bold("DONE.")} Before you move meaningful funds:\n` +
        "  1. Import the phrase into your wallet. The addresses must match.\n" +
        "  2. Send a small amount. Confirm you can send it back.\n" +
        `  3. Re-check the backup any time with ${bold("npm run verify")}.\n`,
    );
  } finally {
    bundle.dispose();
    for (const a of bundle.accounts) a.privateKey.fill(0);
    entropy.fill(0);
    seed.fill(0);
    if (dice) dice.bytes.fill(0);
  }

  await offerScreenWipe();
}

// ---------------------------------------------------------------------------
// 1PASSWORD EXPORT
//
// WHAT THIS IS FOR, AND WHAT IT COSTS
// -----------------------------------
// A staging buffer for the moment of creation: everything derived in one
// place so it can be moved onward by hand once, instead of a dozen separate
// transcriptions. It is NOT a storage design. The item it writes is meant to
// be deleted as soon as the contents have been placed where they belong, and
// the item says so in its own notes.
//
// THIS RELAXES THE CAPABILITY GUARD, DELIBERATELY AND VISIBLY
// -------------------------------------------------
// Running `op` needs --allow-child-process, so this command runs at 5/6
// instead of 6/6 and the child is not constrained by our permission model at
// all - it is another program with its own rights and its own network. That
// is why this is a SEPARATE command: generation and the wizard keep the full
// stricter guard, and the boundary stays where a reader can see it.
//
// HOW THE SECRET REACHES `op`
// ---------------------------
// Through the child's STDIN, and only through it. Measured on macOS:
//
//   argv                  VISIBLE to any process via `ps`
//   environment variable  visible via `ps -E` under the same uid
//   temp file             on disk, survives until deleted
//   stdin pipe            NOT visible - it lives in kernel memory
//
// So no value below is ever an argument, an environment variable, or a file.
// The only flags passed on the command line are the vault name and --format.
// ---------------------------------------------------------------------------

async function exportToOnePassword({ scheme, count, dryRun }) {
  assertRuntime();
  selfTest({ quiet: true });
  process.stdout.write("\nSelf-test OK.\n");

  // child_process is imported lazily: under the normal 6/6 guard the module
  // is unreachable, and this file must still load there.
  let spawn;
  try {
    ({ spawn } = await import("node:child_process"));
  } catch (error) {
    throw new Error(
      "cannot start a subprocess - run this through `npm run op-export`, " +
        `which grants --allow-child-process (${error.code ?? error.message})`,
    );
  }

  const collect = (child) =>
    new Promise((resolve) => {
      let out = "";
      let err = "";
      child.stdout.on("data", (d) => { out += d; });
      child.stderr.on("data", (d) => { err += d; });
      child.on("error", (e) => resolve({ code: -1, out: "", err: e.message }));
      child.on("close", (code) => resolve({ code, out, err }));
    });

  // /bin/sh and /bin/cat by absolute path, never through PATH.
  //
  // PATH on this kind of machine begins with user-writable directories, so a
  // bare "sh" or "cat" is whatever an attacker with ordinary user access put
  // there first. These two are SIP-restricted on macOS and cannot be replaced
  // even by root, which makes them the one part of this chain that is not a
  // trust decision.
  const SH = "/bin/sh";
  const CAT = "/bin/cat";

  /** Read-only op calls that carry no secret. */
  const run = (bin, args) => {
    const child = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
    return collect(child);
  };

  // Resolve op once, through SIP-protected sh, and show the user what will
  // actually run. op lives in a user-writable directory here, so its identity
  // is a trust decision the user should get to see rather than one made
  // silently on their behalf.
  const resolved = await run(SH, ["-c", "command -v op"]);
  const opPath = resolved.out.trim();
  if (resolved.code !== 0 || !opPath.startsWith("/")) {
    throw new Error(
      "the 1Password CLI (op) was not found on PATH. Install it and enable " +
        "its desktop-app integration, then try again.",
    );
  }

  /**
   * Send the payload to `op` on stdin, through `cat`.
   *
   * The interposed `cat` is not decoration. Node's spawn gives a child a
   * SOCKET for stdio: "pipe", and `op` refuses to read piped input that is not
   * a real pipe - it reports "provide the item category with --category",
   * which looks like a JSON problem and is not one. Measured on this machine:
   *
   *   echo ... | op          stdin is a FIFO    -> works
   *   op ... < file          stdin is a file    -> refused
   *   node spawn "pipe"      stdin is a SOCKET  -> refused
   *   node spawn + mkfifo    stdin is a FIFO    -> works
   *
   * A FIFO would work but needs --allow-fs-write and leaves a path other
   * processes could open. Letting the shell build the pipe instead costs
   * nothing: our socket feeds `cat`, and `cat` feeds `op` down a genuine
   * pipe. The vault name travels as a positional argument so it cannot be
   * interpolated into the command string; the payload never appears in any
   * argv at all - verified, zero occurrences under `ps`.
   */
  process.stdout.write("\nChecking the 1Password CLI...\n");
  const version = await run(opPath, ["--version"]);
  if (version.code !== 0) {
    throw new Error(
      "`op` is not available. Install the 1Password CLI and enable its " +
        "desktop-app integration, then try again.",
    );
  }
  process.stdout.write(`  ok  op ${version.out.trim()} at ${opPath}\n`);
  const vaults = await run(opPath, ["vault", "list", "--format=json"]);
  if (vaults.code !== 0) {
    throw new Error(
      `\`op\` cannot reach your vaults: ${vaults.err.trim().slice(0, 200)}`,
    );
  }
  const vaultList = JSON.parse(vaults.out).map((v) => v.name);
  process.stdout.write(`  ok  ${vaultList.length} vault(s): ${vaultList.join(", ")}\n`);

  process.stdout.write(
    "\n" + bold("READ THIS BEFORE CONTINUING") + "\n" +
      "This writes the COMPLETE wallet into 1Password: the 24 words, the\n" +
      "private keys, and all three SLIP-39 shares together in one item.\n\n" +
      yellow("  Three shares in one vault are not a threshold backup. They are the\n" +
             "  secret in one place. Anyone who opens this item owns the wallet.\n\n") +
      "  That is acceptable for a short-lived staging buffer - the thing you\n" +
      "  are doing right now - and it is not acceptable as storage. Move the\n" +
      "  contents where they belong and DELETE THE ITEM. The command to delete\n" +
      "  it is printed at the end.\n\n" +
      "  Also: the seed leaves this machine. 1Password syncs it, encrypted, to\n" +
      "  its servers, and decrypts it on every device where you unlock the\n" +
      "  vault.\n",
  );
  if (dryRun) {
    process.stdout.write(
      green("\n  DRY RUN") + " - op will preview the item and write nothing.\n" +
        "  The prompts below are identical to the real run on purpose: a\n" +
        "  rehearsal that skips steps rehearses the wrong thing.\n",
    );
  }
  if (!(await confirm("\nUnderstood, continue? Type", "yes"))) {
    throw new Error("cancelled - nothing was written");
  }

  // Two ways in, because the point of this command is the moment of creation.
  // Requiring an existing phrase would mean generating it, writing it down,
  // and then typing it back - which is exactly the hand-copying this exists to
  // avoid, and it exposes the phrase to one more keyboard round trip.
  process.stdout.write(
    "\n" + bold("What do you want to stage?") + "\n\n" +
      `  ${bold("new")}      - generate a fresh wallet right now and stage it.\n` +
      "             Nothing needs to exist yet.\n\n" +
      `  ${bold("existing")} - stage a wallet you already have, by typing its\n` +
      "             24 words from paper.\n\n",
  );
  let fresh = null;
  while (fresh === null) {
    const answer = (await readInput("new or existing? ", { echo: true }))
      .trim().toLowerCase();
    if (answer === "new") fresh = true;
    else if (answer === "existing") fresh = false;
    else process.stdout.write(dim("  Type exactly `new` or `existing`.\n"));
  }

  let phrase;
  let entropy;
  let passphrase;

  if (fresh) {
    process.stdout.write(
      yellow("\n  Note: generating here means the seed is born in this process,\n" +
             "  which runs at 5/6 because it may spawn `op`. Generating with\n" +
             "  `npm run wizard` instead keeps the full 6/6 guard - but then\n" +
             "  the phrase has to be typed back in here, which is its own\n" +
             "  exposure. Neither is free; pick the one you prefer.\n"),
    );
    const dice = (await confirm("\nRoll dice for extra entropy? Type", "yes"))
      ? await readDice()
      : null;
    const collected = collectEntropy({ dice });
    for (const r of collected.report) {
      process.stdout.write(`  ${green("ok")}  ${r.name.padEnd(16)} ${r.status}\n`);
    }
    entropy = collected.entropy;
    if (dice) dice.bytes.fill(0);

    phrase = entropyToMnemonic(entropy, wordlist);
    assert.equal(phrase.split(" ").length, 24);
    assert.equal(validateMnemonic(phrase, wordlist), true);
    assert.ok(
      equalBytes(mnemonicToEntropy(phrase, wordlist), entropy),
      "ROUND-TRIP FAILED: the mnemonic does not reconstruct the generated entropy",
    );
    passphrase = await readPassphraseTwice({ newWallet: true });
    printPhrase(phrase);
    process.stdout.write(
      yellow("\n  Write this on paper NOW, before it goes into 1Password.\n") +
        "  The 1Password item is a staging buffer you are going to delete;\n" +
        "  the paper is what survives.\n",
    );
    while (!(await confirm("\nWritten it down? Type", "written"))) {
      process.stdout.write(dim("  The phrase is still on screen above.\n"));
    }
  } else {
    process.stdout.write(
      "\nType the recovery phrase to stage, FROM YOUR PAPER. Input is hidden.\n\n",
    );
    const raw = await readInput("phrase: ");
    const { words, notes, problems } = repairWords(raw);
    for (const note of notes) process.stdout.write(dim(`${note}\n`));
    if (problems.length > 0) {
      for (const problem of problems) process.stdout.write(red(`${problem}\n`));
      throw new Error(`${problems.length} word(s) are not valid BIP-39 words`);
    }
    phrase = words.join(" ");
    assert.equal(
      validateMnemonic(phrase, wordlist), true,
      "CHECKSUM FAILED - a word is wrong or out of order. Nothing was written.",
    );
    entropy = Buffer.from(mnemonicToEntropy(phrase, wordlist));
    passphrase = await readPassphraseTwice();
  }
  const seed = mnemonicToSeedSync(phrase, passphrase);
  const { accounts, fingerprint, dispose } = primaryAccounts(seed, scheme, count);

  const rng = makeShamirRng();
  try {
    crossCheck({ entropy, phrase, passphrase, seed, accounts, fingerprint });
    process.stdout.write("\n  ok  cross-check: independent implementation agrees\n");

    const groups = parseGroupSpec("2of3");
    const shares = splitSecretIntoShares({
      secret: entropy, passphrase: "", groupThreshold: 1, groups,
      extendable: true, iterationExponent: 0, rng,
    });
    for (const subset of admissibleSubsets(1, groups, shares)) {
      assert.ok(
        equalBytes(combineShares(subset, ""), entropy),
        "ROUND-TRIP FAILED: a valid subset of shares does not restore the entropy",
      );
    }
    process.stdout.write("  ok  all 3 SLIP-39 share combinations verified\n");

    process.stdout.write(
      `\n  master fingerprint: ${bold(fingerprint)}\n` +
        `  index 1 address:    ${bold(accounts[1]?.address ?? accounts[0].address)}\n` +
        dim("  Confirm these match what you recorded before writing anything.\n"),
    );

    const stamp = new Date().toISOString().replace(/\.\d+Z$/, "Z");
    const title = `HEATDEATH STAGING ${fingerprint} ${stamp}`;
    const fields = [
      {
        id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain",
        value:
          "TEMPORARY STAGING ITEM - DELETE AFTER TRANSFER.\n\n" +
          "This item contains a complete wallet: the recovery phrase, derived " +
          "private keys, and ALL THREE SLIP-39 shares. Three shares in one " +
          "place are not a threshold backup - whoever opens this item owns " +
          "the wallet.\n\n" +
          "Move each part where it belongs (shares to three SEPARATE physical " +
          "locations, phrase to paper) and then delete this item.\n\n" +
          `Created by HEATDEATH, derivation ${templateFor(scheme)}, ` +
          `${stamp}.`,
      },
      { id: "mnemonic", type: "CONCEALED", label: "BIP-39 mnemonic (24 words)", value: phrase },
      {
        id: "bip39_passphrase", type: "STRING", label: "BIP-39 passphrase",
        value: passphrase
          ? "SET - stored separately on purpose, NOT in this item"
          : "empty (standard wallet)",
      },
      { id: "fingerprint", type: "STRING", label: "master fingerprint", value: fingerprint },
      { id: "derivation", type: "STRING", label: "derivation path", value: templateFor(scheme) },
    ];
    accounts.forEach((a) => {
      fields.push({ id: `addr_${a.index}`, type: "STRING", label: `address ${a.index} (${a.path})`, value: a.address });
      fields.push({ id: `pub_${a.index}`, type: "CONCEALED", label: `public key ${a.index}`, value: `0x${bytesToHex(a.publicKey)}` });
      fields.push({ id: `priv_${a.index}`, type: "CONCEALED", label: `private key ${a.index}`, value: `0x${a.privateKey.toString("hex")}` });
    });
    shares[0].forEach((share, i) => {
      fields.push({
        id: `slip39_${i + 1}`, type: "CONCEALED",
        label: `SLIP-39 share ${i + 1} of 3 (any 2 restore)`, value: share,
      });
    });

    const vault = vaultList.includes("Private") ? "Private" : vaultList[0];
    process.stdout.write(
      `\nWriting ${fields.length} fields to vault ${bold(vault)}.\n` +
        "Route: this process -> cat -> op, all on stdin. Never an argument,\n" +
        "never an environment variable, never a file on disk.\n" +
        dim("(cat is there because op refuses the socket Node hands a child;\n" +
            " the shell pipe between them is a real one. See the source.)\n" +
            "1Password may ask you to authorise this.\n"),
    );

    // The ONLY channel the secret travels on. Args carry the vault name and
    // output format, nothing else.
    // JSON.stringify necessarily creates one immutable JS string. Convert it
    // immediately to a mutable buffer and erase that buffer on every path.
    const payload = Buffer.from(
      JSON.stringify({ title, category: "SECURE_NOTE", fields }), "utf8",
    );
    let created;
    try {
      created = await sendSecretPayload({
        spawn, shell: SH, cat: CAT, opPath, vault, payload, preview: dryRun,
      });
    } finally {
      payload.fill(0);
    }
    if (created.code !== 0) {
      throw new Error(
        `op item create failed (exit ${created.code}); its stderr is withheld ` +
          "because it handled secret input.\n" +
          "\n  Check: 1Password unlocked, and Settings > Developer >\n" +
          "  \"Integrate with 1Password CLI\" enabled. Try `op vault list`\n" +
          "  in a terminal first - it will prompt for authorisation.",
      );
    }

    if (dryRun) {
      process.stdout.write(
        green("\n  ok  ") + "DRY RUN succeeded - op accepted the item and wrote " +
          "NOTHING.\n      Re-run without --dry-run to create it for real.\n",
      );
      return;
    }
    process.stdout.write(
        green("\n  ok  ") + `item created in vault ${vault}\n` +
        `      title: ${title}\n`,
    );
    process.stdout.write(
      "\n" + bold("NOW FINISH THE JOB:") + "\n" +
        "  1. Move the three SLIP-39 shares to three SEPARATE physical places.\n" +
        "  2. Write the 24 words on paper and verify with `npm run verify`.\n" +
        "  3. Delete this item - it is a staging buffer, not storage:\n\n" +
        `       op item delete "${title}" --vault ${vault}\n\n` +
        dim("  Until you do, your entire wallet sits in one 1Password item and\n" +
            "  is synced to their servers.\n"),
    );
  } finally {
    rng.dispose();
    dispose();
    for (const a of accounts) a.privateKey.fill(0);
    entropy.fill(0);
    seed.fill(0);
  }
}

async function split({ shareSpec, groupThreshold, scheme, count }) {
  assertRuntime();
  selfTest({ quiet: true });
  process.stdout.write("\nSelf-test OK.\n");

  const groups = parseGroupSpec(shareSpec);
  assert.ok(
    groupThreshold >= 1 && groupThreshold <= groups.length,
    `--group-threshold must be between 1 and ${groups.length}`,
  );

  process.stdout.write(
    "\nType the recovery phrase you want to back up, FROM YOUR PAPER.\n" +
      "Input is hidden. Abbreviations of 3+ letters are expanded.\n\n",
  );
  const raw = await readInput("phrase: ");
  const { words, notes, problems } = repairWords(raw);
  for (const note of notes) process.stdout.write(`${note}\n`);
  if (problems.length > 0) {
    for (const p of problems) process.stdout.write(`${p}\n`);
    throw new Error(`${problems.length} word(s) are not valid BIP-39 words`);
  }
  const phrase = words.join(" ");
  assert.equal(
    validateMnemonic(phrase, wordlist), true,
    "CHECKSUM FAILED - a word is wrong or out of order. Nothing was split.",
  );
  const entropy = Buffer.from(mnemonicToEntropy(phrase, wordlist));
  process.stdout.write(
    `  ok  ${words.length} words, checksum correct, ${entropy.length * 8}-bit entropy\n`,
  );

  // Identify the wallet being split, BEFORE any share is produced.
  //
  // A single misread word that still satisfies the BIP-39 checksum (about one
  // in 256) yields a different, perfectly valid wallet. The internal
  // round-trip below would pass - it round-trips whatever entropy it was
  // given - and the user would walk away with a mathematically flawless
  // backup of a wallet they do not own. Printing the fingerprint and the
  // index 1 address is the only thing that catches that here, rather than
  // deferring it to a `combine` run they may never perform.
  //
  // The passphrase is used ONLY to compute these identifiers so they can be
  // compared against what `verify` showed. It is NOT part of the shares.
  process.stdout.write(
    "\nWhich wallet is this? Enter the BIP-39 passphrase you use with this\n" +
      "phrase, so the fingerprint below matches what `npm run verify` showed.\n" +
      "It is NOT stored in the shares.\n",
  );
  const idPassphrase = await readPassphraseTwice();
  const idSeed = mnemonicToSeedSync(phrase, idPassphrase);
  const idBundle = primaryAccounts(idSeed, scheme, Math.max(count, 2));
  crossCheck({
    entropy, phrase, passphrase: idPassphrase, seed: idSeed,
    accounts: idBundle.accounts, fingerprint: idBundle.fingerprint,
  });
  process.stdout.write(
    "\nYOU ARE ABOUT TO SPLIT THIS WALLET\n" +
      `  master fingerprint: ${idBundle.fingerprint}\n` +
      `  scheme:             ${scheme} - ${templateFor(scheme)}\n` +
      `  index 1 address:    ${idBundle.accounts[1].address}\n\n` +
      "  If these do not match what you recorded when you generated this\n" +
      "  wallet, STOP. You mistyped a word in a way the checksum accepted,\n" +
      "  and you are about to back up someone else's wallet.\n",
  );
  idBundle.dispose();
  for (const a of idBundle.accounts) a.privateKey.fill(0);
  idSeed.fill(0);

  process.stdout.write(
    "\nNOTE ON PASSPHRASES\n" +
      "  SLIP-39 shares carry the ENTROPY only. A BIP-39 passphrase (the 25th\n" +
      "  word) is NOT included and cannot be recovered from them. If this\n" +
      "  wallet uses one, these shares alone restore nothing - store the\n" +
      "  passphrase separately, and remember that losing it loses the funds.\n" +
      "  This tool deliberately does not offer SLIP-39's own passphrase: two\n" +
      "  different passphrase concepts in one backup is a way to lose money.\n",
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
      rng,
    });

    // Fail closed: prove the shares actually recombine BEFORE showing them.
    // Printing shares that cannot restore the wallet would be the worst
    // possible outcome of this command.
    //
    // The number of admissible subsets is a PRODUCT across groups and
    // explodes - 8of16 in two groups at group threshold 2 is C(16,8)^2, about
    // 165 million - so it is counted first and only enumerated when small.
    // Above the bound a random sample is used, and the counts are printed:
    // silently checking 500 of 165 million while reporting "verified" would
    // be a lie of exactly the kind this tool exists to avoid.
    const EXHAUSTIVE_LIMIT = 5000;
    const SAMPLE_SIZE = 500;
    const total = countAdmissibleSubsetsExact(groupThreshold, groups);
    const check = (subset) => assert.ok(
      equalBytes(combineShares(subset, ""), entropy),
      "ROUND-TRIP FAILED: a valid subset of shares does not restore the entropy",
    );

    if (total <= BigInt(EXHAUSTIVE_LIMIT)) {
      for (const subset of admissibleSubsets(groupThreshold, groups, shares)) {
        check(subset);
      }
      process.stdout.write(
        `\n  ok  all ${total} admissible share combinations verified to ` +
          "restore this exact wallet\n",
      );
    } else {
      // Always include the canonical subset - the first threshold members of
      // the first threshold groups - so the most likely recovery path is
      // never left to chance.
      check(
        groups.slice(0, groupThreshold).flatMap((g, gi) => shares[gi].slice(0, g.threshold)),
      );
      const sampledRanks = new Set(["0"]); // canonical subset already checked
      while (sampledRanks.size <= SAMPLE_SIZE) {
        const rank = randomAdmissibleRank(total, rng);
        const key = rank.toString();
        if (sampledRanks.has(key)) continue;
        sampledRanks.add(key);
        check(admissibleSubsetAtRank(groupThreshold, groups, shares, rank));
      }
      process.stdout.write(
        `\n  ok  ${SAMPLE_SIZE + 1} of ${total.toLocaleString("en-US")} admissible ` +
          "combinations verified (1 canonical + " + SAMPLE_SIZE + " unique random ranks).\n" +
          "  !   Exhaustive checking was SKIPPED: this layout has too many\n" +
          "  !   combinations to enumerate. Every subset tested passed, but not\n" +
          "  !   every subset was tested. A simpler layout such as 2of3 or 3of5\n" +
          "  !   is verified exhaustively.\n",
      );
    }

    printShares(shares, groups, groupThreshold);
    process.stdout.write(
      "\nNEXT STEP - before you rely on these, test recovery:\n" +
        "    npm run combine\n" +
        `Type a threshold subset and confirm it prints the same phrase and the\n` +
        `same index 1 address as \`npm run verify\`.\n`,
    );
  } finally {
    rng.dispose();
    entropy.fill(0);
  }
}

async function combine({ scheme, count, showPrivate, showPublic, qr }) {
  assertRuntime();
  selfTest({ quiet: true });
  process.stdout.write("\nSelf-test OK.\n");

  const mnemonics = await readShares();
  const entropy = combineShares(mnemonics, "");
  process.stdout.write(
    `\n  ok  ${mnemonics.length} shares combined into ${entropy.length * 8} bits\n`,
  );

  const phrase = entropyToMnemonic(entropy, wordlist);
  assert.equal(validateMnemonic(phrase, wordlist), true);
  assert.ok(
    equalBytes(mnemonicToEntropy(phrase, wordlist), entropy),
    "ROUND-TRIP FAILED: recovered entropy does not survive BIP-39 encoding",
  );

  const passphrase = await readPassphraseTwice();
  const seed = mnemonicToSeedSync(phrase, passphrase);
  const { accounts, fingerprint, dispose } = primaryAccounts(seed, scheme, count);
  crossCheck({ entropy, phrase, passphrase, seed, accounts, fingerprint });
  process.stdout.write("  ok  cross-check: independent implementation agrees\n");

  printPhrase(phrase);
  process.stdout.write(
    `\n  BIP-39 passphrase:  ${passphrase ? "SET (not shown)" : "empty"}\n`,
  );
  process.stdout.write(`  derivation scheme:  ${scheme} - ${templateFor(scheme)}\n`);
  process.stdout.write(`  master fingerprint: ${fingerprint}\n`);
  process.stdout.write(
    "  note: the fingerprint and the index 0 address are identical under both\n" +
      "        schemes. Only index 1 and above tell them apart, so if you split\n" +
      `        an --scheme=account wallet, recombine with that same scheme.\n\n`,
  );
  printAccounts(accounts, { showPrivate, showPublic });
  if (qr) printAddressQRs(accounts);
  process.stdout.write(
    "These shares were assumed to come from `npm run split`, which uses no\n" +
      "SLIP-39 passphrase. A share set produced elsewhere WITH one decrypts to\n" +
      "different bytes and still yields a valid-looking phrase for a wallet that\n" +
      "is not yours - the SLIP-39 digest cannot detect it. Your safety net is\n" +
      "the fingerprint above: if it does not match what you recorded, stop.\n",
  );

  dispose();
  for (const a of accounts) a.privateKey.fill(0);
  entropy.fill(0);
  seed.fill(0);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const LICENCE_NOTICE = `
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

const USAGE = `
HEATDEATH - offline BIP-39 / EVM seed generator. Hardened build.

  node generate.mjs --wizard   [options]   guided end-to-end setup (start here)
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

On macOS a downloaded binary is quarantined and Gatekeeper kills it silently
(exit 137, no output). Clear it with:  xattr -d com.apple.quarantine ./FILE

Secrets are read interactively with echo disabled and are never accepted as
command-line arguments: argv is visible to every process via \`ps\` and is
recorded in shell history.
`;

const parseArgs = (argv) => parseCli(argv, {
  defaultScheme: DEFAULT_SCHEME,
  schemes: Object.keys(PATH_SCHEMES),
  defaultAccounts: DEFAULT_ACCOUNTS,
  maxAccounts: MAX_ACCOUNTS,
});

try {
  const cli = parseArgs(process.argv.slice(2));
  if (cli.command === "self-test") {
    // The self-test prints no secrets, so it may run with redirected stdout.
    // That is what makes it usable in CI and in a `shasum` audit trail.
    assertRuntime({ requireTty: false });
    selfTest();
  } else if (cli.command === "wizard") {
    await wizard(cli);
  } else if (cli.command === "generate") {
    await generate(cli);
  } else if (cli.command === "verify") {
    await verify(cli);
  } else if (cli.command === "split") {
    await split(cli);
  } else if (cli.command === "combine") {
    await combine(cli);
  } else if (cli.command === "op-export") {
    await exportToOnePassword(cli);
  } else if (cli.command === "license") {
    process.stdout.write(LICENCE_NOTICE);
  } else if (cli.command === "prove-guard") {
    // Prints no secrets, so redirected stdout is fine here.
    await proveSandbox();
  } else {
    process.stdout.write(USAGE);
    process.exitCode = 0;
  }
} catch (error) {
  // Error messages carry control-flow facts, not key material: no entropy,
  // seed, private key or valid mnemonic is ever interpolated.
  //
  // One deliberate exception: word-level diagnostics echo the token you typed
  // and, for a mistyped word, the nearest wordlist candidates. That is the
  // whole point of those messages - it is how a transcription error gets
  // fixed - and by construction the echoed token is NOT a valid wordlist
  // word. It does still reach stderr and terminal scrollback, so treat a
  // failed --verify / --combine session as sensitive output like any other.
  process.stderr.write(`\nERROR: ${error.message}\n`);
  process.exitCode = 1;
}
