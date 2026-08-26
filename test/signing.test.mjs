import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");

test("signing rejects an external lexical path that resolves into the repository", (t) => {
  const repositoryKeyDirectory = fs.mkdtempSync(path.join(ROOT, ".signing-path-test-"));
  const externalDirectory = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "heatdeath-signing-path-test-"),
  );
  t.after(() => {
    fs.rmSync(externalDirectory, { recursive: true, force: true });
    fs.rmSync(repositoryKeyDirectory, { recursive: true, force: true });
  });
  const key = path.join(repositoryKeyDirectory, "key.pem");
  fs.writeFileSync(key, "not a private key", { mode: 0o600 });
  fs.symlinkSync(repositoryKeyDirectory, path.join(externalDirectory, "repository-link"));

  const result = spawnSync(process.execPath, [
    "build/sign.mjs", "sign-release", "--scheme=ed25519",
    `--key=${path.join(externalDirectory, "repository-link", "key.pem")}`,
  ], { cwd: ROOT, encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /must resolve outside the repository/);
  assert.doesNotMatch(result.stderr, /DECODER|unsupported/i);
});
