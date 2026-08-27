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
  validateReleaseProvenance,
  verifyArtifactHashes,
  verifyManifestSignatures,
  validateSpdxSbom,
} from "../build/release-lib.mjs";
import { readReleaseConfig } from "../build/release-config.mjs";
import { finalizeRelease } from "../build/finalize-release.mjs";
import { canonicalizeSbom } from "../scripts/ci/canonicalize-sbom.mjs";

const hash = "a".repeat(64);
const config = readReleaseConfig();
const allowed = config.allowedArtifacts;
const required = config.requiredArtifacts;
const valid = required.map((name) => `${hash}  ${name}`).join("\n") + "\n";
const parse = (value, requireAll = false) => parseReleaseManifest(value, {
  allowed, required, requireAll,
});

test("release manifest requires both native artifacts and both provenance records", () => {
  assert.equal(parse(valid).size, required.length);
  assert.equal(parse(valid, true).size, allowed.size);
  const withoutLinux = valid.split("\n")
    .filter((line) => !line.endsWith("  heatdeath-linux-x64"))
    .join("\n");
  assert.throws(() => parse(withoutLinux), /required manifest entry/);
});

test("release manifest rejects traversal, absolute, duplicates and malformed lines", () => {
  for (const badName of ["../key", "/etc/passwd", "nested/file", "heatdeath mjs"]) {
    assert.throws(() => parse(`${valid}${hash}  ${badName}\n`));
  }
  assert.throws(() => parse(`${valid}${hash}  heatdeath.mjs\n`), /duplicate/);
  assert.throws(() => parse(valid.replace(/^a/, "A")), /malformed/);
  assert.throws(() => parse(valid.trimEnd()), /ending in one newline/);
});

test("release finalization hashes every required cross-platform artifact once", (t) => {
  const directory = fs.mkdtempSync("/tmp/heatdeath-finalize-test-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  for (const name of required) fs.writeFileSync(path.join(directory, name), `bytes:${name}`);
  assert.equal(finalizeRelease(directory), required.length);
  const manifest = fs.readFileSync(path.join(directory, "SHA256SUMS"), "utf8");
  assert.equal(parse(manifest, true).size, required.length);
  assert.throws(() => finalizeRelease(directory), /EEXIST/);
});

test("provenance pins native bytes, the shared commit and the exact lockfile", () => {
  const native = config.nativeArtifacts[0];
  const entries = new Map(required.map((name) => [name, hash]));
  const lockHash = "b".repeat(64);
  const provenance = {
    schemaVersion: 1,
    version: config.version,
    tag: config.tag,
    commit: "c".repeat(40),
    sourceArchive: { name: config.sourceArchive, sha256: hash },
    sbom: { name: config.sbom, sha256: hash },
    packageLockSha256: lockHash,
    node: { version: config.nodeVersion, binarySha256: hash },
    nativeArtifact: { name: native.name, sha256: hash },
    npm: config.npmVersion,
    esbuild: config.esbuild,
    platform: native.platform,
    arch: native.arch,
  };
  assert.equal(validateReleaseProvenance(provenance, {
    config, native, entries, packageLockSha256: lockHash,
  }), provenance.commit);
  assert.throws(() => validateReleaseProvenance(provenance, {
    config, native, entries, packageLockSha256: "d".repeat(64),
  }), /incomplete or inconsistent/);
  assert.throws(() => validateReleaseProvenance(provenance, {
    config, native, entries, packageLockSha256: lockHash,
    commonCommit: "e".repeat(40),
  }), /incomplete or inconsistent/);
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

test("release artifact hashing rejects byte changes and missing native artifacts", (t) => {
  const directory = fs.mkdtempSync("/tmp/heatdeath-artifact-test-");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "heatdeath.mjs"), "audited bytes");
  const expected = createHash("sha256").update("audited bytes").digest("hex");
  let results = verifyArtifactHashes({
    directory,
    entries: new Map([["heatdeath.mjs", expected], ["heatdeath-linux-x64", hash]]),
  });
  assert.equal(results[0].ok, true);
  assert.equal(results[1].ok, false);
  fs.writeFileSync(path.join(directory, "heatdeath.mjs"), "tampered bytes");
  results = verifyArtifactHashes({
    directory, entries: new Map([["heatdeath.mjs", expected]]),
  });
  assert.equal(results[0].ok, false);
});

test("SPDX validation requires exact lockfile-backed dependency identities", () => {
  const packageJson = {
    name: "heatdeath", version: "2.2.0",
    dependencies: { "@noble/hashes": "2.3.0" },
    devDependencies: { esbuild: "0.28.2" },
  };
  const packageLock = { packages: {
    "": { name: "heatdeath", version: "2.2.0" },
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
    SPDXID: "SPDXRef-DOCUMENT", name: "heatdeath@2.2.0",
    packages: [
      pkg("heatdeath", "2.2.0", "SPDXRef-Package-root"),
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

test("SBOM canonicalization removes platform-selected optional helpers", () => {
  const packageJson = {
    name: "heatdeath", version: "2.2.0",
    dependencies: { "@noble/hashes": "2.3.0" },
    devDependencies: { esbuild: "0.28.2" },
  };
  const packageLock = { packages: {
    "": { name: "heatdeath", version: "2.2.0" },
    "node_modules/@noble/hashes": { version: "2.3.0" },
    "node_modules/esbuild": { version: "0.28.2" },
    "node_modules/@esbuild/darwin-arm64": {
      version: "0.28.2", optional: true, os: ["darwin"], cpu: ["arm64"],
    },
    "node_modules/@esbuild/linux-x64": {
      version: "0.28.2", optional: true, os: ["linux"], cpu: ["x64"],
    },
  } };
  const pkg = (name, version, id) => ({
    name, versionInfo: version, SPDXID: id,
    externalRefs: [{ referenceType: "purl",
      referenceLocator: `pkg:npm/${encodeURIComponent(name).replaceAll("%2F", "/")}@${version}` }],
  });
  const common = [
    pkg("heatdeath", "2.2.0", "SPDXRef-Package-root"),
    pkg("@noble/hashes", "2.3.0", "SPDXRef-Package-hashes"),
    pkg("esbuild", "0.28.2", "SPDXRef-Package-esbuild"),
  ];
  const makeSbom = (platformName, platformId) => ({
    spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT", name: "heatdeath@2.2.0",
    packages: [...common, pkg(platformName, "0.28.2", platformId)],
    relationships: [
      { spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES",
        relatedSpdxElement: "SPDXRef-Package-root" },
      { spdxElementId: "SPDXRef-Package-esbuild", relationshipType: "DEPENDS_ON",
        relatedSpdxElement: platformId },
    ],
  });
  const metadata = {
    packageJson, packageLock, config,
    commit: "c".repeat(40), epoch: "1700000000",
  };
  const darwin = canonicalizeSbom({
    ...metadata,
    sbom: makeSbom("@esbuild/darwin-arm64", "SPDXRef-Package-esbuild-darwin"),
  });
  const linux = canonicalizeSbom({
    ...metadata,
    sbom: makeSbom("@esbuild/linux-x64", "SPDXRef-Package-esbuild-linux"),
  });
  assert.deepEqual(darwin, linux);
  assert.equal(
    `${JSON.stringify(darwin, null, 2)}\n`,
    `${JSON.stringify(linux, null, 2)}\n`,
  );
  assert.equal(darwin.packages.some(({ name }) => name.startsWith("@esbuild/")), false);
  assert.equal(darwin.relationships.length, 1);
});
