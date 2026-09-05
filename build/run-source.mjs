#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const ROOT = path.resolve(import.meta.dirname, "..");
if (process.env.NODE_OPTIONS?.trim()) {
  process.stderr.write(
    "source runner refused: unset NODE_OPTIONS before starting a secret-capable command\n",
  );
  process.exit(1);
}
const separator = process.argv.indexOf("--");
if (separator < 0) throw new Error("run-source requires arguments after --");
const args = process.argv.slice(separator + 1);
// Imported only after the NODE_OPTIONS refusal above: an inherited
// --permission would otherwise deny reading this very module first.
const { launcherRefusal } = await import("./launcher-guard.mjs");
const refusal = launcherRefusal(args, process);
if (refusal) {
  process.stderr.write(`source runner refused: ${refusal}\n`);
  process.exit(1);
}
process.stderr.write(
  "WARNING: source-checkout mode is not release-signature verified and grants\n" +
    "read access to the repository for ESM dependencies. Audit this tree first.\n",
);
const nodeArgs = ["--permission", "--allow-fs-read=.", "--allow-fs-read=/dev/urandom"];
if (args.includes("--op-export")) nodeArgs.push("--allow-child-process");
const child = spawnSync(process.execPath, [...nodeArgs, "generate.mjs", ...args], {
  cwd: ROOT,
  stdio: "inherit",
});
if (child.error) throw child.error;
process.exit(child.status ?? 1);
