import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const ROOT = path.resolve(import.meta.dirname, "..");

test("repository contract rejects stale lockfile root metadata", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "heatdeath-contract-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const script = "scripts/ci/check-repository.mjs";
  fs.mkdirSync(path.join(temporary, "scripts/ci"), { recursive: true });
  for (const name of ["package.json", script]) {
    fs.copyFileSync(path.join(ROOT, name), path.join(temporary, name));
  }
  const original = fs.readFileSync(path.join(ROOT, "package-lock.json"), "utf8");
  for (const field of ["version", "engines", "dependencies", "devDependencies"]) {
    const lock = JSON.parse(original);
    delete lock.packages[""][field];
    fs.writeFileSync(path.join(temporary, "package-lock.json"), JSON.stringify(lock));
    const result = spawnSync(process.execPath, [path.join(temporary, script)], {
      encoding: "utf8",
    });
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.ok(result.stderr.includes(`package-lock.json root ${field} must match package.json`),
      result.stderr);
  }
});

test("release verification installs the checked-out tag's npm, including historical pins", (t) => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "heatdeath-release-npm-"));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  fs.mkdirSync(path.join(temporary, "source"));
  fs.mkdirSync(path.join(temporary, "bin"));
  fs.writeFileSync(path.join(temporary, "bin/npm"), `#!/bin/sh
set -eu
case "$1" in
  install)
    test "$2" = --global
    test "$3" = --ignore-scripts
    printf '%s' "\${4#npm@}" > "$NPM_STATE"
    ;;
  --version) cat "$NPM_STATE" ;;
  *) exit 1 ;;
esac
`, { mode: 0o755 });
  const workflow = fs.readFileSync(path.join(ROOT, ".github/workflows/release-verify.yml"), "utf8");
  const step = /      - name: Install and verify the tag's pinned npm\n([\s\S]*?)(?=      - name:)/.exec(workflow);
  assert.ok(step, "release npm setup step must exist");
  const run = /        run: \|[^\n]*\n([\s\S]*)/.exec(step[1]);
  assert.ok(run, "release npm setup must have a shell script");
  const script = run[1].replace(/^          /gm, "");
  const current = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).packageManager;
  for (const packageManager of ["npm@11.19.0", current, "npm@invalid"]) {
    const state = path.join(temporary, "npm-version");
    fs.rmSync(state, { force: true });
    fs.writeFileSync(path.join(temporary, "source/package.json"), JSON.stringify({ packageManager }));
    const result = spawnSync("bash", ["-c", script], {
      cwd: temporary,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: [path.join(temporary, "bin"), path.dirname(process.execPath), process.env.PATH].join(path.delimiter),
        NPM_STATE: state,
      },
    });
    if (packageManager === "npm@invalid") {
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.equal(fs.existsSync(state), false);
    } else {
      assert.equal(result.status, 0, result.stdout + result.stderr);
      assert.equal(fs.readFileSync(state, "utf8"), packageManager.slice(4));
    }
  }
});
