import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { gunzipSync } from "node:zlib";
import { createSourceArchive } from "../scripts/ci/create-source-archive.mjs";

test("source archives repeat byte-identically with a platform-neutral gzip header", (t) => {
  const directory = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "heatdeath-archive-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const first = path.join(directory, "first.tar.gz");
  const second = path.join(directory, "second.tar.gz");
  const firstHashes = createSourceArchive({ output: first });
  const secondHashes = createSourceArchive({ output: second });
  const bytes = fs.readFileSync(first);
  assert.deepEqual(bytes, fs.readFileSync(second));
  assert.deepEqual(firstHashes, secondHashes);
  assert.equal(bytes[9], 255);
  assert.ok(gunzipSync(bytes).length > 1024);
});
