#!/usr/bin/env node
//
// Verify a downloaded release: file hashes against the manifest, and the
// manifest against three independent signatures.
//
// READ THIS BEFORE TRUSTING THE OUTPUT
// ------------------------------------
// A green result here means "these files match this manifest, and this
// manifest was signed by whoever holds the keys in dist/*.pub.pem". If the
// public keys arrived in the same download as the artifact, that is circular:
// an attacker who replaced the binary would simply have signed it with their
// own keys and shipped those too.
//
// The signature is only worth something once you have pinned the public key
// fingerprints from a DIFFERENT source than the download. This script prints
// those fingerprints so you can compare them; comparing them is your job and
// nothing here can do it for you.
//
import { createHash, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const ROOT = path.resolve(import.meta.dirname, "..");
const DIST = path.join(ROOT, "dist");
const SCHEMES = ["ed25519", "ml-dsa-87", "slh-dsa-sha2-128s"];

const read = (p) => fs.readFileSync(path.join(DIST, p));
let failures = 0;
let verified = 0;
let absent = 0;
const fail = (m) => { failures += 1; process.stdout.write(`  FAIL  ${m}\n`); };
const ok = (m) => process.stdout.write(`  ok    ${m}\n`);
const skip = (m) => { absent += 1; process.stdout.write(`  --    ${m}\n`); };

process.stdout.write("\n==> file hashes against dist/SHA256SUMS\n");
const manifest = read("SHA256SUMS");
for (const line of manifest.toString("utf8").split("\n").filter(Boolean)) {
  const [expected, name] = line.trim().split(/\s+/);
  const file = path.join(DIST, name);
  // An ABSENT artifact and a MISMATCHED one are different events and must not
  // be reported the same way. The single executable is deliberately not
  // committed - it is attached to the release - so a git clone legitimately
  // has only the bundle. Calling that a FAILURE told honest users to distrust
  // a correct checkout, which is how people learn to ignore this output.
  // A mismatch stays fatal: that is the case where bytes changed under you.
  if (!fs.existsSync(file)) {
    skip(`${name} not present - not checked`);
    continue;
  }
  const actual = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  if (actual === expected) { verified += 1; ok(`${name}`); }
  else fail(`${name} - expected ${expected}, got ${actual}`);
}

process.stdout.write("\n==> manifest signatures\n");
for (const id of SCHEMES) {
  try {
    const publicKey = read(`${id}.pub.pem`);
    const signature = read(`SHA256SUMS.${id}.sig`);
    if (verify(null, manifest, publicKey, signature)) ok(`${id}`);
    else fail(`${id} - SIGNATURE DOES NOT VERIFY`);
  } catch (error) {
    fail(`${id} - ${error.code ?? error.message}`);
  }
}

process.stdout.write("\n==> public key fingerprints (SHA-256 of the DER SPKI)\n");
process.stdout.write("    Compare these against a source OTHER than this download.\n");
for (const id of SCHEMES) {
  try {
    const pem = read(`${id}.pub.pem`).toString("utf8");
    const der = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ""), "base64");
    const fp = createHash("sha256").update(der).digest("hex");
    process.stdout.write(`    ${id.padEnd(20)} ${fp}\n`);
  } catch {
    process.stdout.write(`    ${id.padEnd(20)} (public key not present)\n`);
  }
}

const trailer =
  "Remember: this proves integrity against THESE keys, not that the keys\n" +
  "are the ones you meant to trust.\n";

if (failures > 0) {
  process.stdout.write(
    `\n${failures} check(s) FAILED. Do not run these artifacts. Build from\n` +
      "source instead - see dist/BUILD-RECIPE.txt.\n",
  );
  process.exitCode = 1;
} else if (verified === 0) {
  // Absence is tolerated one artifact at a time, never all of them: a run that
  // checked nothing must not be able to report success.
  process.stdout.write(
    "\nNOTHING WAS VERIFIED. No artifact named in the manifest is present, so\n" +
      "the signatures above attest to a manifest describing files you do not\n" +
      "have. Build from source - see dist/BUILD-RECIPE.txt.\n",
  );
  process.exitCode = 1;
} else if (absent > 0) {
  process.stdout.write(
    `\n${verified} artifact(s) verified, ${absent} not present.\n\n` +
      "That is expected in a git clone: the single executable is ~144 MB and is\n" +
      "attached to the release rather than committed. Everything that IS here\n" +
      "matches the manifest, and the manifest carries valid signatures. To check\n" +
      "the executable too, download it into dist/ and run this again.\n\n" +
      trailer,
  );
} else {
  process.stdout.write(`\nAll checks passed. ${trailer}`);
}
