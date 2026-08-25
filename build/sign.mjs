#!/usr/bin/env node
//
// Sign the release manifest with three independent signature schemes.
//
// WHY THREE
// ---------
// A signature has to outlive the artifact it protects, and a seed generator
// published today may still be downloaded in ten years. The three schemes rest
// on three different hardness assumptions, so no single cryptanalytic advance
// invalidates the release:
//
//   ed25519            elliptic curves - fast, universally verifiable today,
//                      and broken outright by a large quantum computer.
//   ML-DSA-87          FIPS 204, module lattices. The NIST primary choice.
//   SLH-DSA-SHA2-128s  FIPS 205, hash-based. The most conservative assumption
//                      available: it needs nothing beyond a secure hash. Slow
//                      and its signatures are large, which does not matter for
//                      signing one small manifest.
//
// WHAT THIS DOES AND DOES NOT BUY
// -------------------------------
// It proves an artifact came from whoever holds these keys and has not been
// altered since. It does NOT tell you who that is, and it cannot: the keys are
// deliberately pseudonymous. Anyone can generate keys and sign anything, so a
// signature only means something once you have pinned THESE public keys from a
// source you trust. That pinning is the user's job, and no amount of signing
// does it for them.
//
// The private keys live in keys/, which is gitignored. If they leak, an
// attacker can sign a backdoored build that verifies perfectly.
//
import { generateKeyPairSync, sign } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const ROOT = path.resolve(import.meta.dirname, "..");
const KEYS = path.join(ROOT, "keys");
const DIST = path.join(ROOT, "dist");

const SCHEMES = [
  { id: "ed25519", alg: "ed25519" },
  { id: "ml-dsa-87", alg: "ml-dsa-87" },
  { id: "slh-dsa-sha2-128s", alg: "slh-dsa-sha2-128s" },
];

const manifestPath = path.join(DIST, "SHA256SUMS");
if (!fs.existsSync(manifestPath)) {
  process.stderr.write("dist/SHA256SUMS not found - run ./build/build.sh first\n");
  process.exit(1);
}
const manifest = fs.readFileSync(manifestPath);

fs.mkdirSync(KEYS, { recursive: true });
process.stdout.write("==> signing dist/SHA256SUMS\n");

for (const { id, alg } of SCHEMES) {
  const privPath = path.join(KEYS, `${id}.priv.pem`);
  const pubPath = path.join(DIST, `${id}.pub.pem`);

  if (!fs.existsSync(privPath)) {
    const { publicKey, privateKey } = generateKeyPairSync(alg);
    // 0600: the whole scheme collapses if these are readable by other users.
    fs.writeFileSync(
      privPath,
      privateKey.export({ type: "pkcs8", format: "pem" }),
      { mode: 0o600 },
    );
    fs.writeFileSync(pubPath, publicKey.export({ type: "spki", format: "pem" }));
    process.stdout.write(`    ${id.padEnd(20)} NEW KEYPAIR generated\n`);
  } else if (!fs.existsSync(pubPath)) {
    process.stderr.write(`    ${id}: private key present but public key missing\n`);
    process.exit(1);
  }

  const privateKey = fs.readFileSync(privPath, "utf8");
  const signature = sign(null, manifest, privateKey);
  fs.writeFileSync(path.join(DIST, `SHA256SUMS.${id}.sig`), signature);
  process.stdout.write(
    `    ${id.padEnd(20)} signed (${signature.length} byte signature)\n`,
  );
}

process.stdout.write(
  "\nPublic keys written to dist/*.pub.pem. Publish them somewhere a reader\n" +
    "can pin them from - a release page, a pinned post, a well-known URL - and\n" +
    "keep keys/ off every machine that is not doing a release.\n" +
    "\nVerify with:  npm run verify-release\n",
);
