import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";

import { isSecretCapable, launcherRefusal } from "../build/launcher-guard.mjs";

const oldNode = { version: "v24.14.0", allowedNodeEnvironmentFlags: new Set(["--allow-addons"]) };
const newNode = { version: "v26.8.1", allowedNodeEnvironmentFlags: new Set(["--allow-net"]) };

test("secret-capable commands are refused on a Node without a network scope", () => {
  for (const args of [["--wizard", "--qr"], ["--generate"], ["--verify"], ["--safe-owner"],
    ["--split"], ["--combine"], ["--op-export", "--accounts=3"]]) {
    assert.equal(isSecretCapable(args), true);
    const refusal = launcherRefusal(args, oldNode);
    assert.match(refusal, /v24\.14\.0/);
    assert.match(refusal, /--allow-net/);
    assert.equal(launcherRefusal(args, newNode), null);
  }
});

test("diagnostics that create no secret still run so the refusal can be inspected", () => {
  for (const args of [["--self-test"], ["--prove-guard"], ["--prove-sandbox"],
    ["--doctor"], ["--license"], ["--help"]]) {
    assert.equal(isSecretCapable(args), false);
    assert.equal(launcherRefusal(args, oldNode), null);
  }
});

test("the real launchers apply the guard before spawning anything", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const supported = process.allowedNodeEnvironmentFlags.has("--allow-net");
  for (const launcher of ["build/run-source.mjs", "build/run-verified.mjs"]) {
    // --verify would block on terminal input if it ever started; with stdin
    // closed it must either be refused by the guard or refused by the runtime
    // TTY check, and on an old Node the guard must win.
    const result = spawnSync(process.execPath, [launcher, "--", "--verify"], {
      cwd: root, encoding: "utf8", input: "",
    });
    assert.notEqual(result.status, 0);
    if (!supported) {
      assert.match(result.stderr, /runner refused: Node v\d+.*--allow-net/s);
      assert.doesNotMatch(result.stderr, /Self-test|refusing to continue/);
    }
  }
});
