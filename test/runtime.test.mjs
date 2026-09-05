import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";

import { inspectRuntime } from "../runtime.mjs";

function fakeRuntime(overrides = {}) {
  const allowed = overrides.allowed ?? new Set(["fs.read:/dev/urandom"]);
  return {
    env: {},
    execArgv: [],
    version: "v26.8.1",
    allowedNodeEnvironmentFlags: new Set(["--allow-net"]),
    stdin: { isTTY: true },
    stdout: { isTTY: true },
    cwd: () => "/offline/heatdeath",
    getuid: () => 501,
    permission: {
      has(scope, reference) {
        return allowed.has(reference ? `${scope}:${reference}` : scope);
      },
    },
    ...overrides,
  };
}

test("runtime inspection reports a ready least-privilege environment", () => {
  const result = inspectRuntime({
    requirePermission: true,
    runtime: fakeRuntime(),
    networkInterfaces: () => ({}),
  });
  assert.deepEqual(result.blockers, []);
  assert.deepEqual(result.warnings, []);
  assert.equal(Object.isFrozen(result), true);
});

test("runtime inspection aggregates independent blockers and warnings", () => {
  const runtime = fakeRuntime({
    env: { SSH_TTY: "/dev/pts/1", TMUX: "1" },
    execArgv: ["--inspect"],
    stdin: { isTTY: false },
    stdout: { isTTY: false },
    permission: undefined,
    getuid: () => 0,
  });
  const result = inspectRuntime({
    requirePermission: true,
    runtime,
    networkInterfaces: () => ({ en0: [{ internal: false }] }),
  });
  const blockerIds = result.blockers.map(({ id }) => id);
  assert.ok(blockerIds.includes("ssh"));
  assert.ok(blockerIds.includes("debugger"));
  assert.ok(blockerIds.includes("stdout-tty"));
  assert.ok(blockerIds.includes("stdin-tty"));
  assert.ok(blockerIds.includes("permission-model"));
  const warningIds = result.warnings.map(({ id }) => id);
  assert.ok(warningIds.includes("root"));
  assert.ok(warningIds.includes("terminal-multiplexer"));
  assert.ok(warningIds.includes("network-interfaces"));
});

test("an over-broad permission is a blocker only for strict ceremonies", () => {
  const runtime = fakeRuntime({ allowed: new Set(["fs.read:/dev/urandom", "net"]) });
  assert.equal(inspectRuntime({
    runtime, requirePermission: false, networkInterfaces: () => ({}),
  }).warnings.some(({ id }) => id === "permission-net"), true);
  assert.equal(inspectRuntime({
    runtime, requirePermission: true, networkInterfaces: () => ({}),
  }).blockers.some(({ id }) => id === "permission-net"), true);
});

test("strict inspection rejects resource-scoped grants and ambient NODE_OPTIONS", () => {
  const runtime = fakeRuntime({
    env: { NODE_OPTIONS: "--allow-fs-write=/tmp/inherited" },
    execArgv: [
      "--permission",
      "--allow-fs-read=.",
      "--allow-fs-read=/dev/urandom",
      "--allow-fs-write=/tmp/scoped",
    ],
  });
  const result = inspectRuntime({
    runtime, requirePermission: true, networkInterfaces: () => ({}),
  });
  const blockerIds = result.blockers.map(({ id }) => id);
  assert.ok(blockerIds.includes("permission-fs.write-resource"));
  assert.ok(blockerIds.includes("node-options"));
});

test("strict inspection covers Node 26 native escape capabilities", () => {
  for (const scope of ["addon", "ffi", "inspector", "wasi"]) {
    const runtime = fakeRuntime({
      allowed: new Set(["fs.read:/dev/urandom", scope]),
    });
    assert.ok(inspectRuntime({
      runtime, requirePermission: true, networkInterfaces: () => ({}),
    }).blockers.some(({ id }) => id === `permission-${scope}`));
  }
});

test("a Node without a network permission scope cannot pass as a full guard", () => {
  const runtime = fakeRuntime({
    version: "v24.14.0",
    allowedNodeEnvironmentFlags: new Set(["--allow-addons"]),
  });
  const relaxed = inspectRuntime({
    runtime, requirePermission: false, networkInterfaces: () => ({}),
  });
  assert.ok(relaxed.warnings.some(({ id }) => id === "permission-net-unsupported"));
  const strict = inspectRuntime({
    runtime, requirePermission: true, networkInterfaces: () => ({}),
  });
  const blocker = strict.blockers.find(({ id }) => id === "permission-net-unsupported");
  assert.ok(blocker);
  assert.match(blocker.message, /v24\.14\.0/);
  assert.match(blocker.message, /--allow-net/);
});

test("memory-dumping and code-preloading flags block regardless of strictness", () => {
  for (const flag of [
    "--heapsnapshot-signal=SIGUSR2", "--heap-prof", "--cpu-prof",
    "--report-on-signal", "--import=./hook.mjs", "-r", "--env-file=.env",
  ]) {
    const result = inspectRuntime({
      runtime: fakeRuntime({ execArgv: ["--permission", flag] }),
      requirePermission: false,
      networkInterfaces: () => ({}),
    });
    const blocker = result.blockers.find(({ id }) => id === "diagnostic-flags");
    assert.ok(blocker, `${flag} must be a blocker`);
    assert.ok(blocker.message.includes(flag));
  }
  const clean = inspectRuntime({
    runtime: fakeRuntime({ execArgv: ["--permission", "--allow-fs-read=/dev/urandom"] }),
    networkInterfaces: () => ({}),
  });
  assert.equal(clean.blockers.some(({ id }) => id === "diagnostic-flags"), false);
});

test("prove-guard counts only ERR_ACCESS_DENIED as a denial", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const result = spawnSync(
    process.execPath,
    ["--permission", "--allow-fs-read=.", "--allow-fs-read=/dev/urandom",
      "generate.mjs", "--prove-guard"],
    { cwd: root, encoding: "utf8" },
  );
  assert.doesNotMatch(result.stdout, /\bblocked\b/);
  if (process.allowedNodeEnvironmentFlags.has("--allow-net")) {
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /6\/6 capability probes denied/);
    assert.doesNotMatch(result.stdout, /NOT ENFORCED/);
  } else {
    assert.equal(result.status, 1);
    assert.match(result.stdout, /no network permission scope/);
    assert.match(result.stdout, /NOT ENFORCED|ALLOWED/);
    assert.doesNotMatch(result.stdout, /6\/6 capability probes denied/);
  }
});

test("doctor rejects a real resource-scoped write grant", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const result = spawnSync(
    process.execPath,
    [
      "--permission",
      "--allow-fs-read=.",
      "--allow-fs-read=/dev/urandom",
      "--allow-fs-write=/tmp/heatdeath-scoped-review-test",
      "generate.mjs",
      "--doctor",
    ],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(result.status, 2);
  assert.match(result.stdout, /BLOCK  permission-fs\.write-resource/);
  assert.match(result.stdout, /--allow-fs-write=\/tmp\/heatdeath-scoped-review-test/);
});

test("source launcher refuses inherited NODE_OPTIONS before spawning the secret process", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const result = spawnSync(
    process.execPath,
    ["build/run-source.mjs", "--", "--self-test"],
    {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        NODE_OPTIONS: "--permission --allow-fs-write=/tmp/inherited",
      },
    },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /source runner refused: unset NODE_OPTIONS/);
  assert.doesNotMatch(result.stdout, /SELF-TEST/);
});

test("verified launcher refuses inherited NODE_OPTIONS before release preflight", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const result = spawnSync(
    process.execPath,
    ["build/run-verified.mjs", "--", "--self-test"],
    {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        NODE_OPTIONS: "--permission --allow-fs-write=/tmp/inherited",
      },
    },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /verified runner refused: unset NODE_OPTIONS/);
  assert.doesNotMatch(result.stderr, /Release preflight failed/);
});

test("doctor creates no secret and exits 2 when terminal input is redirected", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const result = spawnSync(
    process.execPath,
    ["build/run-source.mjs", "--", "--doctor"],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(result.status, 2);
  assert.match(result.stdout, /SAFE OWNER ENVIRONMENT DOCTOR/);
  assert.match(result.stdout, /BLOCK  stdin-tty/);
  assert.match(result.stdout, /Doctor creates no secret/);
});
