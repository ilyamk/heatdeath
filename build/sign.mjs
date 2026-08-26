#!/usr/bin/env node
// Explicit, one-key-at-a-time release signing. Signing never creates or
// rotates an identity as a side effect.

import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { PINNED_RELEASE_FINGERPRINTS } from "./release-lib.mjs";

process.on("uncaughtException", (error) => {
  process.stderr.write(`signing refused: ${error.message}\n`);
  process.exitCode = 1;
});

const ROOT = path.resolve(import.meta.dirname, "..");
const ROOT_REAL = fs.realpathSync(ROOT);
const DIST = path.join(ROOT, "dist");
const SCHEMES = new Map([
  ["ed25519", "ed25519"],
  ["ml-dsa-87", "ml-dsa-87"],
  ["slh-dsa-sha2-128s", "slh-dsa-sha2-128s"],
]);

const args = new Map();
for (const arg of process.argv.slice(3)) {
  const at = arg.indexOf("=");
  if (at < 1) throw new Error(`expected --name=value, got ${arg}`);
  const key = arg.slice(0, at);
  if (args.has(key)) throw new Error(`duplicate option ${key}`);
  args.set(key, arg.slice(at + 1));
}
const action = process.argv[2];
const allowedArgs = action === "init-signing-key"
  ? new Set(["--scheme", "--out"])
  : action === "sign-release"
    ? new Set(["--scheme", "--key"])
    : new Set();
for (const key of args.keys()) {
  if (!allowedArgs.has(key)) throw new Error(`unknown option ${key}`);
}
const scheme = args.get("--scheme");
const algorithm = SCHEMES.get(scheme);
if (!algorithm) throw new Error(`--scheme must be one of ${[...SCHEMES.keys()].join(", ")}`);

function absoluteExternalPath(value, option) {
  if (!value || !path.isAbsolute(value)) throw new Error(`${option} must be an absolute path`);
  const resolved = path.resolve(value);
  if (resolved === ROOT || resolved.startsWith(`${ROOT}${path.sep}`)) {
    throw new Error(`${option} must be outside the repository`);
  }
  return resolved;
}

function canonicalExternalTarget(value, option) {
  const lexical = absoluteExternalPath(value, option);
  const canonicalParent = fs.realpathSync(path.dirname(lexical));
  if (
    canonicalParent === ROOT_REAL ||
    canonicalParent.startsWith(`${ROOT_REAL}${path.sep}`)
  ) {
    throw new Error(`${option} must resolve outside the repository`);
  }
  return path.join(canonicalParent, path.basename(lexical));
}

function existingExternalFile(value, option) {
  const canonical = canonicalExternalTarget(value, option);
  let descriptor;
  try {
    descriptor = fs.openSync(
      canonical, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new Error("private key must be a real file");
    return { descriptor, stat };
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    throw error;
  }
}

function fingerprint(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

if (action === "init-signing-key") {
  const output = canonicalExternalTarget(args.get("--out"), "--out");
  const { publicKey, privateKey } = generateKeyPairSync(algorithm);
  try {
    fs.writeFileSync(output, privateKey.export({ type: "pkcs8", format: "pem" }), {
      mode: 0o600,
      flag: "wx",
    });
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`refusing to overwrite ${output}`);
    throw error;
  }
  process.stdout.write(`${scheme} key created at ${output}\npublic fingerprint ${fingerprint(publicKey)}\n`);
} else if (action === "sign-release") {
  const externalKey = existingExternalFile(args.get("--key"), "--key");
  const stat = externalKey.stat;
  let privateKey;
  try {
    if ((stat.mode & 0o077) !== 0) {
      throw new Error("private key permissions must be 0600 or stricter");
    }
    privateKey = fs.readFileSync(externalKey.descriptor);
    const derived = createPublicKey(privateKey);
    const tracked = createPublicKey(fs.readFileSync(path.join(DIST, `${scheme}.pub.pem`)));
    if (fingerprint(tracked) !== PINNED_RELEASE_FINGERPRINTS.get(scheme)) {
      throw new Error(`tracked ${scheme} public key is not the pinned release identity`);
    }
    if (fingerprint(derived) !== fingerprint(tracked)) {
      throw new Error(`private key does not match tracked ${scheme} release identity`);
    }
    const manifest = fs.readFileSync(path.join(DIST, "SHA256SUMS"));
    const signature = sign(null, manifest, privateKey);
    fs.writeFileSync(path.join(DIST, `SHA256SUMS.${scheme}.sig`), signature);
    process.stdout.write(`${scheme} signed SHA256SUMS (${signature.length} bytes)\n`);
  } finally {
    privateKey?.fill(0);
    fs.closeSync(externalKey.descriptor);
  }
} else {
  throw new Error(
    "usage: sign.mjs init-signing-key --scheme=ID --out=/external/key.pem\n" +
      "   or: sign.mjs sign-release --scheme=ID --key=/external/key.pem",
  );
}
