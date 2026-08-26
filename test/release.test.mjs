import assert from "node:assert/strict";
import {
  createHash, createPublicKey, generateKeyPairSync, sign,
} from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  parseReleaseManifest,
  PINNED_RELEASE_FINGERPRINTS,
  publicKeyFingerprint,
  verifyArtifactHashes,
  verifyManifestSignatures,
  validateSpdxSbom,
} from "../build/release-lib.mjs";
import { readReleaseConfig } from "../build/release-config.mjs";

const hash = "a".repeat(64);
const config = readReleaseConfig();
const allowed = config.allowedArtifacts;
const required = config.requiredArtifacts;
const valid = required.map((name) => `${hash}  ${name}`).join("\n") + "\n";
const parse = (value, requireAll = false) => parseReleaseManifest(value, {
  allowed, required, requireAll,
});

test("release manifest accepts required artifacts and optional SEA", () => {
  assert.equal(parse(valid).size, required.length);
  assert.throws(() => parse(valid, true), /SEA entry/);
});

test("release manifest rejects traversal, absolute, duplicates and malformed lines", () => {
  for (const badName of ["../key", "/etc/passwd", "nested/file", "heatdeath mjs"]) {
    assert.throws(() => parse(`${valid}${hash}  ${badName}\n`));
  }
  assert.throws(() => parse(`${valid}${hash}  heatdeath.mjs\n`), /duplicate/);
  assert.throws(() => parse(valid.replace(/^a/, "A")), /malformed/);
  assert.throws(() => parse(valid.trimEnd()), /ending in one newline/);
});

test("tracked public keys retain every pinned release identity", () => {
  for (const [scheme, expected] of PINNED_RELEASE_FINGERPRINTS) {
    const pem = fs.readFileSync(path.resolve("dist", `${scheme}.pub.pem`));
    const der = createPublicKey(pem).export({ type: "spki", format: "der" });
    assert.equal(createHash("sha256").update(der).digest("hex"), expected);
  }
});

test("all release signature schemes verify end-to-end and reject tampering", (t) => {
  const directory = fs.mkdtempSync(path.join(t.mock.timers ? "/tmp/" : "/tmp/", "heatdeath-release-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const algorithms = new Map([
    ["ed25519", "ed25519"],
    ["ml-dsa-87", "ml-dsa-87"],
    ["slh-dsa-sha2-128s", "slh-dsa-sha2-128s"],
  ]);
  const fingerprints = new Map();
  const manifest = Buffer.from(valid);
  for (const [scheme, algorithm] of algorithms) {
    const { publicKey, privateKey } = generateKeyPairSync(algorithm);
    const pem = publicKey.export({ type: "spki", format: "pem" });
    fs.writeFileSync(path.join(directory, `${scheme}.pub.pem`), pem);
    fs.writeFileSync(
      path.join(directory, `SHA256SUMS.${scheme}.sig`),
      sign(null, manifest, privateKey),
    );
    fingerprints.set(scheme, publicKeyFingerprint(pem));
  }
  const verified = verifyManifestSignatures({
    manifest, schemes: [...algorithms.keys()], keyDirectory: directory,
    signatureDirectory: directory, fingerprints,
  });
  assert.ok(verified.every((result) => result.ok));

  const tampered = Buffer.from(`${valid} `);
  const rejected = verifyManifestSignatures({
    manifest: tampered, schemes: [...algorithms.keys()], keyDirectory: directory,
    signatureDirectory: directory, fingerprints,
  });
  assert.ok(rejected.every((result) => !result.ok));
});

test("release artifact hashing rejects byte changes and tolerates only optional SEA", (t) => {
  const directory = fs.mkdtempSync("/tmp/heatdeath-artifact-test-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "heatdeath.mjs"), "audited bytes");
  const expected = createHash("sha256").update("audited bytes").digest("hex");
  let results = verifyArtifactHashes({
    directory,
    entries: new Map([["heatdeath.mjs", expected], ["heatdeath", hash]]),
    optional: new Set(["heatdeath"]),
  });
  assert.ok(results.every((result) => result.ok));
  assert.equal(results[1].absent, true);
  fs.writeFileSync(path.join(directory, "heatdeath.mjs"), "tampered bytes");
  results = verifyArtifactHashes({
    directory, entries: new Map([["heatdeath.mjs", expected]]),
  });
  assert.equal(results[0].ok, false);
});

test("SPDX validation requires exact lockfile-backed dependency identities", () => {
  const packageJson = {
    name: "heatdeath", version: "2.1.0",
    dependencies: { "@noble/hashes": "2.3.0" },
    devDependencies: { esbuild: "0.28.2" },
  };
  const packageLock = { packages: {
    "": { name: "heatdeath", version: "2.1.0" },
    "node_modules/@noble/hashes": { version: "2.3.0" },
    "node_modules/esbuild": { version: "0.28.2" },
  } };
  const pkg = (name, version, id) => ({
    name, versionInfo: version, SPDXID: id,
    externalRefs: [{ referenceType: "purl",
      referenceLocator: `pkg:npm/${encodeURIComponent(name).replaceAll("%2F", "/")}@${version}` }],
  });
  const sbom = {
    spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT", name: "heatdeath@2.1.0",
    packages: [
      pkg("heatdeath", "2.1.0", "SPDXRef-Package-root"),
      pkg("@noble/hashes", "2.3.0", "SPDXRef-Package-hashes"),
      pkg("esbuild", "0.28.2", "SPDXRef-Package-esbuild"),
    ],
    relationships: [{ spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES", relatedSpdxElement: "SPDXRef-Package-root" }],
  };
  assert.equal(validateSpdxSbom(sbom, { packageJson, packageLock }), true);
  const omitted = structuredClone(sbom);
  omitted.packages.pop();
  assert.throws(() => validateSpdxSbom(omitted, { packageJson, packageLock }), /omits/);
  const injected = structuredClone(sbom);
  injected.packages.push(pkg("wallet-stealer", "1.0.0", "SPDXRef-Package-bad"));
  assert.throws(() => validateSpdxSbom(injected, { packageJson, packageLock }), /lockfile-backed/);
});
