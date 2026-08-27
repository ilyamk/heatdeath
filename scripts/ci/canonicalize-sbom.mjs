#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { validateSpdxSbom } from "../../build/release-lib.mjs";
import { readReleaseConfig } from "../../build/release-config.mjs";

function lockPackageName(location) {
  return location.replace(/^.*node_modules\//, "");
}

function platformSpecificIdentities(packageLock) {
  const identities = new Set();
  for (const [location, record] of Object.entries(packageLock.packages ?? {})) {
    if (!location || !record?.version || record.optional !== true) continue;
    if (!Array.isArray(record.os) && !Array.isArray(record.cpu)) continue;
    identities.add(`${lockPackageName(location)}@${record.version}`);
  }
  return identities;
}

function sortRecordArrays(pkg) {
  for (const key of ["checksums", "externalRefs", "licenseInfoFromFiles"]) {
    if (Array.isArray(pkg[key])) {
      pkg[key].sort((left, right) =>
        JSON.stringify(left).localeCompare(JSON.stringify(right)));
    }
  }
}

function sortObjectKeys(value) {
  if (Array.isArray(value)) return value.map(sortObjectKeys);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, sortObjectKeys(item)]),
  );
}

export function canonicalizeSbom({
  sbom, packageJson, packageLock, config, commit, epoch,
}) {
  assert.match(commit ?? "", /^[0-9a-f]{40}$/, "commit must be a full Git object ID");
  assert.match(String(epoch ?? ""), /^\d+$/, "epoch must be seconds since Unix epoch");
  validateSpdxSbom(sbom, { packageJson, packageLock });

  const result = structuredClone(sbom);
  const platformIdentities = platformSpecificIdentities(packageLock);
  const removedIds = new Set(
    result.packages
      .filter((pkg) => platformIdentities.has(`${pkg.name}@${pkg.versionInfo}`))
      .map((pkg) => pkg.SPDXID),
  );
  result.packages = result.packages.filter((pkg) => !removedIds.has(pkg.SPDXID));
  result.relationships = result.relationships.filter((relationship) =>
    !removedIds.has(relationship.spdxElementId) &&
    !removedIds.has(relationship.relatedSpdxElement));

  for (const pkg of result.packages) sortRecordArrays(pkg);
  result.packages.sort((left, right) =>
    `${left.name}\0${left.versionInfo}\0${left.SPDXID}`.localeCompare(
      `${right.name}\0${right.versionInfo}\0${right.SPDXID}`,
    ));
  result.relationships.sort((left, right) =>
    `${left.spdxElementId}\0${left.relationshipType}\0${left.relatedSpdxElement}`.localeCompare(
      `${right.spdxElementId}\0${right.relationshipType}\0${right.relatedSpdxElement}`,
    ));

  result.documentNamespace =
    `https://github.com/ilyamk/heatdeath/releases/tag/${config.tag}#spdx-${commit}`;
  result.creationInfo = {
    created: new Date(Number(epoch) * 1000).toISOString(),
    creators: [`Tool: npm/cli-${config.npmVersion}`],
  };
  validateSpdxSbom(result, { packageJson, packageLock });
  return sortObjectKeys(result);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const [input, output, commit, epoch] = process.argv.slice(2);
  if (!input || !output) {
    throw new Error("usage: canonicalize-sbom INPUT OUTPUT COMMIT EPOCH");
  }
  const root = path.resolve(import.meta.dirname, "../..");
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const packageLock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
  const config = readReleaseConfig(root);
  const sbom = JSON.parse(fs.readFileSync(input, "utf8"));
  const canonical = canonicalizeSbom({
    sbom, packageJson, packageLock, config, commit, epoch,
  });
  fs.writeFileSync(output, `${JSON.stringify(canonical, null, 2)}\n`, { flag: "wx" });
}
