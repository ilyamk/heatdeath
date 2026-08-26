#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const ROOT = path.resolve(import.meta.dirname, "../..");
const markdown = [];

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if ([".git", "node_modules"].includes(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(absolute);
    else if (entry.name.endsWith(".md")) markdown.push(absolute);
  }
}

function names(directory) {
  return fs.readdirSync(directory)
    .filter((name) => name.endsWith(".md"))
    .sort();
}

function commandLines(text) {
  const commands = new Set();
  let fenced = false;
  for (const raw of text.split("\n")) {
    if (/^```/.test(raw)) {
      fenced = !fenced;
      continue;
    }
    if (!fenced) continue;
    let line = raw.trim()
      .replace(/\s+#.*$/, "")
      .replace(/\s{2,}[^-].*$/, "");
    const npmRun = /^(npm run \S+)(.*)$/.exec(line);
    if (npmRun && !npmRun[2].trimStart().startsWith("--")) line = npmRun[1];
    if (/^(npm|node|git|gh|shasum|sha256sum|xattr|codesign|\.\/dist\/|python3?)\b/.test(line)) {
      commands.add(line);
    }
  }
  return commands;
}

function assertCommandParity(english, russian) {
  const en = commandLines(fs.readFileSync(english, "utf8"));
  const ru = commandLines(fs.readFileSync(russian, "utf8"));
  const onlyEn = [...en].filter((command) => !ru.has(command));
  const onlyRu = [...ru].filter((command) => !en.has(command));
  assert.deepEqual(
    { onlyEn, onlyRu },
    { onlyEn: [], onlyRu: [] },
    `executable documentation drift between ${path.relative(ROOT, english)} and ` +
      `${path.relative(ROOT, russian)}`,
  );
}

walk(ROOT);
assert.deepEqual(
  names(path.join(ROOT, "docs/en")),
  names(path.join(ROOT, "docs/ru")),
  "docs/en and docs/ru must contain the same document names",
);

for (const name of names(path.join(ROOT, "docs/en"))) {
  assertCommandParity(
    path.join(ROOT, "docs/en", name),
    path.join(ROOT, "docs/ru", name),
  );
}
assertCommandParity(path.join(ROOT, "README.en.md"), path.join(ROOT, "README.ru.md"));
assertCommandParity(path.join(ROOT, "QUICKSTART.en.md"), path.join(ROOT, "QUICKSTART.md"));

const broken = [];
for (const file of markdown) {
  const text = fs.readFileSync(file, "utf8");
  for (const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    let target = match[1].trim();
    if (target.startsWith("<") && target.endsWith(">")) target = target.slice(1, -1);
    target = target.split(/\s+["']/u, 1)[0];
    if (/^(?:https?:|mailto:|#)/i.test(target)) continue;
    target = target.split("#", 1)[0];
    if (!target) continue;
    let decoded;
    try { decoded = decodeURIComponent(target); } catch { decoded = target; }
    const resolved = path.resolve(path.dirname(file), decoded);
    if (!resolved.startsWith(`${ROOT}${path.sep}`) || !fs.existsSync(resolved)) {
      broken.push(`${path.relative(ROOT, file)} -> ${target}`);
    }
  }
}
assert.deepEqual(broken, [], "broken or escaping local Markdown links");

const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
const releaseName = `heatdeath-v${pkg.version}-source.tar.gz`;
for (const relative of [
  "docs/en/BUILD.md", "docs/ru/BUILD.md",
  "docs/en/VERIFY.md", "docs/ru/VERIFY.md",
]) {
  const text = fs.readFileSync(path.join(ROOT, relative), "utf8");
  assert.ok(text.includes(pkg.version), `${relative} must name release ${pkg.version}`);
  assert.ok(text.includes(releaseName), `${relative} must name ${releaseName}`);
}

process.stdout.write(
  `documentation contract: ${markdown.length} Markdown files, bilingual commands and links verified\n`,
);
