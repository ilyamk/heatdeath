#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";

const ROOT = path.resolve(import.meta.dirname, "../..");
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
assert.match(pkg.packageManager ?? "", /^npm@\d+\.\d+\.\d+$/,
  "packageManager must pin an exact npm release");

for (const section of ["dependencies", "devDependencies"]) {
  for (const [name, version] of Object.entries(pkg[section] ?? {})) {
    assert.match(
      version,
      /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/,
      `${section}.${name} must be pinned to one exact version`,
    );
  }
}

const checkoutCommands = [
  "self-test", "wizard", "generate", "generate:dice", "generate:account",
  "generate:private", "verify", "verify:account", "split", "combine",
  "op-export", "op-export:dry", "prove-guard",
];
for (const command of checkoutCommands) {
  assert.match(pkg.scripts?.[command] ?? "", /build\/run-source\.mjs/,
    `${command} must remain usable from an unsigned source checkout`);
  assert.match(pkg.scripts?.[`${command}:verified`] ?? "", /build\/run-verified\.mjs/,
    `${command}:verified must enforce signed release preflight`);
}

const files = execFileSync(
  "git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { cwd: ROOT },
).toString("utf8").split("\0").filter(Boolean);

const privateMaterial = [];
for (const relative of files) {
  const absolute = path.join(ROOT, relative);
  let descriptor;
  try {
    descriptor = fs.openSync(
      absolute, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
  } catch (error) {
    if (error.code === "ELOOP") continue;
    throw error;
  }
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.size > 4 * 1024 * 1024) continue;
    const bytes = fs.readFileSync(descriptor);
    if (/-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/.test(bytes.toString("utf8"))) {
      privateMaterial.push(relative);
    }
  } finally {
    fs.closeSync(descriptor);
  }
}
assert.deepEqual(privateMaterial, [], "private signing material must never be tracked");

const workflowDirectory = path.join(ROOT, ".github/workflows");
const workflows = fs.readdirSync(workflowDirectory)
  .filter((name) => /\.ya?ml$/.test(name));
const unsafeUses = [];
const unsafeEvents = [];
for (const name of workflows) {
  const relative = `.github/workflows/${name}`;
  const text = fs.readFileSync(path.join(workflowDirectory, name), "utf8");
  if (/\bpull_request_target\s*:|\bworkflow_run\s*:/.test(text)) unsafeEvents.push(relative);
  for (const match of text.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gm)) {
    const ref = match[1].replace(/^['"]|['"]$/g, "");
    if (ref.startsWith("./")) continue;
    const at = ref.lastIndexOf("@");
    if (at < 1 || !/^[0-9a-f]{40}$/.test(ref.slice(at + 1))) {
      unsafeUses.push(`${relative}: ${ref}`);
    }
  }
}
assert.deepEqual(unsafeEvents, [], "privileged PR promotion events are prohibited");
assert.deepEqual(unsafeUses, [], "every external action must use a full commit SHA");

const releaseNpm = pkg.packageManager.slice("npm@".length);
for (const workflow of ["release-candidate.yml", "release-verify.yml"]) {
  const text = fs.readFileSync(path.join(workflowDirectory, workflow), "utf8");
  assert.ok(text.includes(`test "$(npm --version)" = "${releaseNpm}"`),
    `${workflow} must enforce package.json's exact release npm`);
}
const reproducibleWorkflow = fs.readFileSync(
  path.join(workflowDirectory, "reproducible-build.yml"), "utf8");
assert.doesNotMatch(reproducibleWorkflow, /^\s+paths:/m,
  "a required reproducibility check must run for every pull request");

const releaseVerifyWorkflow = fs.readFileSync(
  path.join(workflowDirectory, "release-verify.yml"), "utf8");
assert.doesNotMatch(releaseVerifyWorkflow, /\bgh release download\b/,
  "draft assets cannot be resolved through the public release-by-tag endpoint");
assert.match(
  releaseVerifyWorkflow,
  /releases\/assets\/\$\{asset_id\}/,
  "draft assets must be downloaded through their authenticated asset IDs",
);

const trackedKeys = files.filter((name) =>
  /(?:^|\/)(?:keys?|secrets?)(?:\/|$)/i.test(name) && !/\.pub\.pem$/.test(name));
assert.deepEqual(trackedKeys, [], "key directories may contain tracked public .pub.pem files only");

process.stdout.write(
  `repository contract: ${files.length} files, ${workflows.length} workflows, ` +
    "exact dependencies, pinned actions and no private keys verified\n",
);
