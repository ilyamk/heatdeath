export const PINNED_RELEASE_FINGERPRINTS = new Map([
  ["ed25519", "463c3b401b66d9dd8faf17ec042c9f41ae939745cf081a9babed18aa21cee4aa"],
  ["ml-dsa-87", "4afa05402782d13b99b1a385f1f3bf4afa4da341224a693a27dc116015a16b99"],
  ["slh-dsa-sha2-128s", "73297ec0f483ebe8184783599a3d9627da7febca8645396ecc0e56a5efbf44af"],
]);

export function parseReleaseManifest(text, {
  allowed, required, requireAll = false,
} = {}) {
  if (typeof text !== "string" || !text.endsWith("\n")) {
    throw new Error("manifest must be UTF-8 text ending in one newline");
  }
  const entries = new Map();
  const lines = text.slice(0, -1).split("\n");
  if (lines.some((line) => line === "")) throw new Error("blank manifest line");
  for (const [index, line] of lines.entries()) {
    const match = /^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$/.exec(line);
    if (!match) throw new Error(`malformed manifest line ${index + 1}`);
    const [, hash, name] = match;
    if (!allowed.has(name)) throw new Error(`unexpected or unsafe manifest name ${name}`);
    if (entries.has(name)) throw new Error(`duplicate manifest entry ${name}`);
    entries.set(name, hash);
  }
  for (const name of required) {
    if (!entries.has(name)) throw new Error(`required manifest entry missing: ${name}`);
  }
  if (requireAll && entries.size !== allowed.size) {
    throw new Error("complete manifest must contain every allow-listed artifact");
  }
  return entries;
}

export function publicKeyFingerprint(publicKey) {
  const der = createPublicKey(publicKey).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex");
}

export function requireRealFile(file, label = path.basename(file)) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a real file`);
  }
}

export function verifyManifestSignatures({
  manifest, schemes, keyDirectory, signatureDirectory, fingerprints,
}) {
  return schemes.map((scheme) => {
    try {
      const publicPath = path.join(keyDirectory, `${scheme}.pub.pem`);
      const signaturePath = path.join(signatureDirectory, `SHA256SUMS.${scheme}.sig`);
      requireRealFile(publicPath, `${scheme} public key`);
      requireRealFile(signaturePath, `${scheme} signature`);
      const publicKey = fs.readFileSync(publicPath);
      const fingerprint = publicKeyFingerprint(publicKey);
      if (fingerprint !== fingerprints.get(scheme)) {
        throw new Error("public key fingerprint is not the pinned release identity");
      }
      if (!verify(null, manifest, publicKey, fs.readFileSync(signaturePath))) {
        throw new Error("signature mismatch");
      }
      return { scheme, fingerprint, ok: true };
    } catch (error) {
      return { scheme, ok: false, error: error.code ?? error.message };
    }
  });
}

export function verifyArtifactHashes({ directory, entries, optional = new Set() }) {
  const results = [];
  for (const [name, expected] of entries) {
    const file = path.join(directory, name);
    if (!fs.existsSync(file) && optional.has(name)) {
      results.push({ name, ok: true, absent: true });
      continue;
    }
    try {
      requireRealFile(file, name);
      const actual = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
      if (actual !== expected) throw new Error(`expected ${expected}, got ${actual}`);
      results.push({ name, ok: true });
    } catch (error) {
      results.push({ name, ok: false, error: error.code ?? error.message });
    }
  }
  return results;
}

export function validateSpdxSbom(sbom, { packageJson, packageLock }) {
  if (!sbom || sbom.spdxVersion !== "SPDX-2.3" || sbom.dataLicense !== "CC0-1.0" ||
      sbom.SPDXID !== "SPDXRef-DOCUMENT" ||
      sbom.name !== `${packageJson.name}@${packageJson.version}` ||
      !Array.isArray(sbom.packages) || !Array.isArray(sbom.relationships)) {
    throw new Error("SBOM is not the expected SPDX 2.3 document");
  }

  const locked = new Set();
  for (const [location, value] of Object.entries(packageLock.packages ?? {})) {
    if (!value?.version) continue;
    const name = location === "" ? packageJson.name :
      location.replace(/^.*node_modules\//, "");
    locked.add(`${name}@${value.version}`);
  }

  const seenPackages = new Set();
  const spdxIds = new Set(["SPDXRef-DOCUMENT"]);
  for (const pkg of sbom.packages) {
    if (typeof pkg?.name !== "string" || typeof pkg?.versionInfo !== "string" ||
        typeof pkg?.SPDXID !== "string") {
      throw new Error("SBOM contains an incomplete package record");
    }
    const identity = `${pkg.name}@${pkg.versionInfo}`;
    if (!locked.has(identity)) throw new Error(`SBOM package is not lockfile-backed: ${identity}`);
    if (seenPackages.has(identity) || spdxIds.has(pkg.SPDXID)) {
      throw new Error(`SBOM contains a duplicate package identity: ${identity}`);
    }
    const expectedPurl = `pkg:npm/${encodeURIComponent(pkg.name).replaceAll("%2F", "/")}@${pkg.versionInfo}`;
    const hasPurl = pkg.externalRefs?.some((reference) =>
      reference.referenceType === "purl" && reference.referenceLocator === expectedPurl);
    if (!hasPurl) throw new Error(`SBOM package has no exact npm purl: ${identity}`);
    seenPackages.add(identity);
    spdxIds.add(pkg.SPDXID);
  }

  const required = {
    [packageJson.name]: packageJson.version,
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };
  for (const [name, version] of Object.entries(required)) {
    if (!seenPackages.has(`${name}@${version}`)) {
      throw new Error(`SBOM omits required package: ${name}@${version}`);
    }
  }
  for (const relation of sbom.relationships) {
    if (!spdxIds.has(relation.spdxElementId) || !spdxIds.has(relation.relatedSpdxElement)) {
      throw new Error("SBOM relationship references an unknown SPDX identifier");
    }
  }
  return true;
}

export function validateReleaseProvenance(provenance, {
  config, native, entries, packageLockSha256, commonCommit = null,
}) {
  if (provenance?.schemaVersion !== 1 ||
      provenance.version !== config.version || provenance.tag !== config.tag ||
      !/^[0-9a-f]{40}$/.test(provenance.commit ?? "") ||
      (commonCommit !== null && provenance.commit !== commonCommit) ||
      provenance.sourceArchive?.name !== config.sourceArchive ||
      provenance.sourceArchive?.sha256 !== entries.get(config.sourceArchive) ||
      provenance.sbom?.name !== config.sbom ||
      provenance.sbom?.sha256 !== entries.get(config.sbom) ||
      provenance.packageLockSha256 !== packageLockSha256 ||
      provenance.node?.version !== config.nodeVersion ||
      !/^[0-9a-f]{64}$/.test(provenance.node?.binarySha256 ?? "") ||
      provenance.nativeArtifact?.name !== native.name ||
      provenance.nativeArtifact?.sha256 !== entries.get(native.name) ||
      provenance.npm !== config.npmVersion || provenance.esbuild !== config.esbuild ||
      provenance.platform !== native.platform || provenance.arch !== native.arch) {
    throw new Error("release metadata is incomplete or inconsistent");
  }
  return provenance.commit;
}
import { createHash, createPublicKey, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
