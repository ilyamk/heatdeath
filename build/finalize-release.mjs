#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import { readReleaseConfig } from "./release-config.mjs";

export function finalizeRelease(directory, {
  root = path.resolve(import.meta.dirname, ".."),
} = {}) {
  const resolved = path.resolve(directory);
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error("release candidate must be a real directory");
  }
  const config = readReleaseConfig(root);
  const lines = [];
  for (const name of config.requiredArtifacts) {
    const file = path.join(resolved, name);
    const artifact = fs.lstatSync(file);
    if (!artifact.isFile() || artifact.isSymbolicLink()) {
      throw new Error(`${name} must be a real file`);
    }
    const digest = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    lines.push(`${digest}  ${name}`);
  }
  fs.writeFileSync(path.join(resolved, "SHA256SUMS"), `${lines.join("\n")}\n`, { flag: "wx" });
  return lines.length;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const root = path.resolve(import.meta.dirname, "..");
  const directory = path.resolve(process.argv[2] ?? path.join(root, "dist"));
  const count = finalizeRelease(directory, { root });
  process.stdout.write(`finalized ${count} release artifacts\n`);
}
