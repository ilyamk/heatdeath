#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const metafile = process.argv[2];
assert.ok(metafile, "usage: node build/check-core-boundary.mjs <esbuild-metafile.json>");

const graph = JSON.parse(fs.readFileSync(metafile, "utf8"));
const forbiddenRoots = new Set(["enterprise", "hosted", "telemetry"]);
const forbidden = Object.keys(graph.inputs ?? {}).filter((input) => {
  const normalized = path.normalize(input).replaceAll("\\", "/");
  const parts = normalized.split("/").filter((part) => part !== "." && part !== "..");
  return parts.some((part) => forbiddenRoots.has(part));
});

assert.deepEqual(
  forbidden,
  [],
  "offline core bundle must not include hosted, telemetry, or enterprise code",
);
process.stdout.write(
  `offline core boundary: ${Object.keys(graph.inputs ?? {}).length} bundled inputs verified\n`,
);
