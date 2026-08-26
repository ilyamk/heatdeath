import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { readReleaseConfig } from "./release-config.mjs";

const [commit, nodeBinaryHash, sourceArchive, sourceHash, sbomName, sbomHash, npmVersion] =
  process.argv.slice(2);
const root = path.resolve(import.meta.dirname, "..");
const config = readReleaseConfig(root);
const lock = fs.readFileSync(path.join(root, "package-lock.json"));
const provenance = {
  schemaVersion: 1,
  version: config.version,
  tag: config.tag,
  commit,
  sourceArchive: { name: sourceArchive, sha256: sourceHash },
  sbom: { name: sbomName, sha256: sbomHash },
  packageLockSha256: createHash("sha256").update(lock).digest("hex"),
  node: { version: process.version, binarySha256: nodeBinaryHash },
  npm: npmVersion,
  esbuild: config.esbuild,
  platform: process.platform,
  arch: process.arch,
};
fs.writeFileSync(
  path.join(root, "dist", "SOURCE-PROVENANCE.json"),
  `${JSON.stringify(provenance, null, 2)}\n`,
);
