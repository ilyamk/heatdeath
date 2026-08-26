#!/usr/bin/env node
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { gzipSync } from "node:zlib";
import { readReleaseConfig } from "../../build/release-config.mjs";

export function createSourceArchive({ output, ref = "HEAD", root = path.resolve(import.meta.dirname, "../..") }) {
  if (!output) throw new Error("output path is required");
  const config = readReleaseConfig(root);
  const tar = execFileSync("git", [
    "archive", "--format=tar", `--prefix=heatdeath-${config.version}/`, ref,
  ], { cwd: root, maxBuffer: 64 * 1024 * 1024 });
  const archive = gzipSync(tar, { level: 9 });
  // RFC 1952 byte 9 identifies the compressor OS. zlib derives it from the
  // build platform even when mtime/name are absent, so normalize it to UNKNOWN.
  archive[9] = 255;
  fs.writeFileSync(output, archive, { flag: "wx" });
  return {
    tarSha256: createHash("sha256").update(tar).digest("hex"),
    archiveSha256: createHash("sha256").update(archive).digest("hex"),
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  const [output, ref = "HEAD"] = process.argv.slice(2);
  const hashes = createSourceArchive({ output, ref });
  process.stdout.write(`${JSON.stringify(hashes)}\n`);
}
