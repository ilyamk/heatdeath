import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import test from "node:test";

import { sendSecretPayload } from "../op-transport.mjs";

function fakeSpawn({ code = 1, epipe = false } = {}) {
  return () => {
    const child = new EventEmitter();
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    queueMicrotask(() => {
      child.stderr.write("partial-secret-fragment");
      if (epipe) child.stdin.emit("error", Object.assign(new Error("broken pipe"), { code: "EPIPE" }));
      child.stdout.end('{"id":"safe-id"}');
      child.stderr.end();
      child.emit("close", code);
    });
    return child;
  };
}

test("secret transport never returns stderr, including partial echoes", async () => {
  const result = await sendSecretPayload({
    spawn: fakeSpawn(), shell: "/bin/sh", cat: "/bin/cat",
    opPath: "/fake/op", vault: "Private", payload: Buffer.from("whole-secret"),
  });
  assert.deepEqual(Object.keys(result).sort(), ["code", "transportFailed"]);
  assert.equal(JSON.stringify(result).includes("partial-secret"), false);
});

test("EPIPE is a generic transport failure even if child reports success", async () => {
  const result = await sendSecretPayload({
    spawn: fakeSpawn({ code: 0, epipe: true }), shell: "/bin/sh", cat: "/bin/cat",
    opPath: "/fake/op", vault: "Private", payload: Buffer.from("secret"),
  });
  assert.equal(result.code, -1);
  assert.equal(result.transportFailed, true);
});
