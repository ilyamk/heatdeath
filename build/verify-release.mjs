#!/usr/bin/env node
// Verify release signatures, a strictly parsed manifest, required artifacts,
// and the source-provenance record. Public keys should be supplied separately.

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  parseReleaseManifest,
  PINNED_RELEASE_FINGERPRINTS,
  requireRealFile,
  validateSpdxSbom,
  verifyArtifactHashes,
  verifyManifestSignatures,
} from "./release-lib.mjs";
import { readReleaseConfig } from "./release-config.mjs";

process.on("uncaughtException", (error) => {
  process.stderr.write(`release verification refused: ${error.message}\n`);
  process.exitCode = 1;
});

const ROOT = path.resolve(import.meta.dirname, "..");
const config = readReleaseConfig(ROOT);
const SCHEMES = ["ed25519", "ml-dsa-87", "slh-dsa-sha2-128s"];
const argv = process.argv.slice(2);
const requireAll = argv.includes("--require-all");
const trustedArg = argv.find((arg) => arg.startsWith("--trusted-keys="));
const distArg = argv.find((arg) => arg.startsWith("--dist="));
for (const arg of argv) {
  if (arg !== "--require-all" && !arg.startsWith("--trusted-keys=") &&
      !arg.startsWith("--dist=")) {
    throw new Error(`unknown option ${arg}`);
  }
}
let DIST = path.join(ROOT, "dist");
if (distArg) {
  DIST = distArg.slice("--dist=".length);
  if (!path.isAbsolute(DIST)) throw new Error("--dist must be absolute");
  const stat = fs.lstatSync(DIST);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("artifact directory must be a real directory");
  }
}
let keyDir = DIST;
if (trustedArg) {
  keyDir = trustedArg.slice("--trusted-keys=".length);
  if (!path.isAbsolute(keyDir)) throw new Error("--trusted-keys must be absolute");
  const stat = fs.lstatSync(keyDir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("trusted key directory must be a real directory");
  }
} else {
  process.stdout.write(
    "NOTICE: public-key files come from the artifact directory; their fingerprints\n" +
      "must match identities pinned in this verifier. For an independent trust\n" +
      "channel, prefer --trusted-keys=/absolute/external/directory.\n\n",
  );
}

requireRealFile(path.join(DIST, "SHA256SUMS"), "manifest");
const manifest = fs.readFileSync(path.join(DIST, "SHA256SUMS"));
const entries = parseReleaseManifest(manifest.toString("utf8"), {
  allowed: config.allowedArtifacts, required: config.requiredArtifacts, requireAll,
});

let failures = 0;
const fail = (message) => { failures += 1; process.stdout.write(`  FAIL  ${message}\n`); };
const ok = (message) => process.stdout.write(`  ok    ${message}\n`);

process.stdout.write("==> signatures\n");
for (const result of verifyManifestSignatures({
  manifest, schemes: SCHEMES, keyDirectory: keyDir,
  signatureDirectory: DIST, fingerprints: PINNED_RELEASE_FINGERPRINTS,
})) {
  if (result.ok) ok(`${result.scheme} ${result.fingerprint}`);
  else fail(`${result.scheme}: ${result.error}`);
}

process.stdout.write("\n==> artifact hashes\n");
const optional = requireAll ? new Set() : new Set(["heatdeath"]);
for (const result of verifyArtifactHashes({ directory: DIST, entries, optional })) {
  if (result.absent) process.stdout.write("  --    heatdeath SEA absent (optional)\n");
  else if (result.ok) ok(result.name);
  else fail(`${result.name}: ${result.error}`);
}

try {
  const sbom = JSON.parse(fs.readFileSync(path.join(DIST, config.sbom), "utf8"));
  const packageJson = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const packageLock = JSON.parse(fs.readFileSync(path.join(ROOT, "package-lock.json"), "utf8"));
  validateSpdxSbom(sbom, { packageJson, packageLock });
  if (sbom.documentNamespace !==
      `https://github.com/ilyamk/heatdeath/releases/tag/${config.tag}#spdx-${
        JSON.parse(fs.readFileSync(path.join(DIST, "SOURCE-PROVENANCE.json"), "utf8")).commit
      }` || sbom.creationInfo?.creators?.length !== 1 ||
      sbom.creationInfo.creators[0] !== `Tool: npm/cli-${config.npmVersion}`) {
    throw new Error("SBOM canonical provenance fields are inconsistent");
  }
  ok(`${config.sbom} SPDX semantics`);
} catch (error) { fail(`SBOM: ${error.message}`); }

try {
  const provenance = JSON.parse(fs.readFileSync(
    path.join(DIST, "SOURCE-PROVENANCE.json"), "utf8",
  ));
  if (provenance.schemaVersion !== 1 ||
      provenance.version !== config.version || provenance.tag !== config.tag ||
      !/^[0-9a-f]{40}$/.test(provenance.commit) ||
      provenance.sourceArchive?.name !== config.sourceArchive ||
      provenance.sourceArchive?.sha256 !== entries.get(config.sourceArchive) ||
      provenance.sbom?.name !== config.sbom ||
      provenance.sbom?.sha256 !== entries.get(config.sbom) ||
      !/^[0-9a-f]{64}$/.test(provenance.packageLockSha256) ||
      provenance.node?.version !== config.nodeVersion ||
      !/^[0-9a-f]{64}$/.test(provenance.node?.binarySha256) ||
      provenance.npm !== config.npmVersion || provenance.esbuild !== config.esbuild ||
      provenance.platform !== "darwin" ||
      provenance.arch !== "arm64") {
    throw new Error("release metadata is incomplete or inconsistent");
  }
  ok("SOURCE-PROVENANCE.json semantics");
} catch (error) { fail(`provenance: ${error.message}`); }

if (failures) {
  process.stderr.write(`\n${failures} release verification check(s) failed. DO NOT RUN.\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("\nAll required artifacts and signatures verified.\n");
}
