import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const checker = path.resolve(import.meta.dirname, "../build/check-core-boundary.mjs");

function writeGraph(t, inputs) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "heatdeath-boundary-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, "metafile.json");
  fs.writeFileSync(file, JSON.stringify({ inputs }));
  return file;
}

test("offline core boundary accepts cryptographic and terminal inputs", (t) => {
  const graph = writeGraph(t, {
    "generate.mjs": {},
    "terminal.mjs": {},
    "node_modules/@scure/bip39/index.js": {},
  });
  const output = execFileSync(process.execPath, [checker, graph], { encoding: "utf8" });
  assert.match(output, /3 bundled inputs verified/);
});

test("offline core boundary rejects hosted, telemetry and enterprise inputs", (t) => {
  for (const forbidden of [
    "enterprise/coordinator.mjs",
    "src/hosted/licence.mjs",
    "packages/telemetry/index.mjs",
  ]) {
    const graph = writeGraph(t, { "generate.mjs": {}, [forbidden]: {} });
    const result = spawnSync(process.execPath, [checker, graph], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /offline core bundle must not include/);
  }
});
