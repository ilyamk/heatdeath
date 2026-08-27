#!/usr/bin/env node
// Public npm entrypoint: verify the signed release payload before creating the
// process that may ever see a secret. This parent process handles no secrets.

import { spawnSync } from "node:child_process";
import process from "node:process";
import path from "node:path";

process.on("uncaughtException", (error) => {
  process.stderr.write(`verified runner refused: ${error.message}\n`);
  process.exitCode = 1;
});

const ROOT = path.resolve(import.meta.dirname, "..");
if (process.env.NODE_OPTIONS?.trim()) {
  throw new Error("unset NODE_OPTIONS before starting a verified secret-capable command");
}
const separator = process.argv.indexOf("--");
if (separator === -1 || separator === process.argv.length - 1) {
  throw new Error("run-verified requires arguments after --");
}
const args = process.argv.slice(separator + 1);
const opExport = args.includes("--op-export");

const verified = spawnSync(process.execPath, ["build/verify-release.mjs"], {
  cwd: ROOT,
  stdio: "inherit",
});
if (verified.status !== 0) {
  process.stderr.write("Release preflight failed; the secret process was not started.\n");
  process.exit(1);
}

const nodeArgs = ["--permission", "--allow-fs-read=/dev/urandom"];
if (opExport) nodeArgs.push("--allow-child-process");
nodeArgs.push("dist/heatdeath.mjs", ...args);
const child = spawnSync(process.execPath, nodeArgs, { cwd: ROOT, stdio: "inherit" });
if (child.error) throw child.error;
process.exit(child.status ?? 1);
