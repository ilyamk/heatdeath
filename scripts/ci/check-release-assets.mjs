#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { readReleaseConfig } from "../../build/release-config.mjs";

const directory = path.resolve(process.argv[2] ?? "");
const requireAll = process.argv.includes("--require-all");
assert.ok(path.isAbsolute(directory) && fs.statSync(directory).isDirectory(),
  "first argument must be an existing release asset directory");

const config = readReleaseConfig();
const expected = new Set([
  ...config.requiredArtifacts,
  "SHA256SUMS",
  ...["ed25519", "ml-dsa-87", "slh-dsa-sha2-128s"].flatMap((scheme) => [
    `${scheme}.pub.pem`, `SHA256SUMS.${scheme}.sig`,
  ]),
]);
if (!requireAll) {
  for (const name of [
    ...config.nativeArtifacts.map(({ name }) => name), ...config.provenanceArtifacts,
  ]) expected.delete(name);
}

const actual = new Set(fs.readdirSync(directory));
assert.deepEqual(
  [...actual].sort(), [...expected].sort(),
  "release must contain exactly the documented allow-listed assets",
);
for (const name of actual) {
  const stat = fs.lstatSync(path.join(directory, name));
  assert.ok(stat.isFile() && !stat.isSymbolicLink(), `${name} must be a real file`);
}
process.stdout.write(`release asset contract: ${actual.size} exact files verified\n`);
