import assert from "node:assert/strict";
import test from "node:test";

import fc from "fast-check";

import { parseCli } from "../cli.mjs";
import { decodeShare, encodeShare } from "../slip39.mjs";
import { TerminalInputDecoder } from "../terminal.mjs";

const CLI_DEFAULTS = {
  defaultScheme: "metamask",
  schemes: ["metamask", "account"],
  defaultAccounts: 11,
  maxAccounts: 100,
};
const COMMANDS = new Set([
  "help", "generate", "verify", "combine", "split", "op-export",
  "wizard", "self-test", "prove-guard", "license",
  "doctor", "safe-owner", "rehearse-safe-owner",
]);

test("fast-check fuzzes CLI and terminal parsers without escaping their invariants", () => {
  fc.assert(fc.property(
    fc.array(fc.string({ maxLength: 80 }), { maxLength: 20 }),
    (argv) => {
      try {
        const parsed = parseCli(argv, CLI_DEFAULTS);
        assert.ok(COMMANDS.has(parsed.command));
        assert.ok(parsed.flags instanceof Set);
        if (parsed.command !== "help") {
          assert.ok(CLI_DEFAULTS.schemes.includes(parsed.scheme));
          assert.ok(Number.isSafeInteger(parsed.count));
          assert.ok(parsed.count >= 1 && parsed.count <= CLI_DEFAULTS.maxAccounts);
        }
      } catch (error) {
        assert.ok(error instanceof assert.AssertionError);
      }
    },
  ), { numRuns: 1_000 });

  fc.assert(fc.property(
    fc.array(fc.string({ maxLength: 64 }), { maxLength: 32 }),
    (chunks) => {
      const decoder = new TerminalInputDecoder();
      for (const chunk of chunks) {
        const event = decoder.push(chunk);
        assert.equal(typeof event.completed, "boolean");
        assert.equal(typeof event.aborted, "boolean");
        assert.ok(Number.isSafeInteger(event.erased) && event.erased >= 0);
        assert.equal(typeof event.echo, "string");
      }
      assert.ok(decoder.value.length <= chunks.join("").length);
    },
  ), { numRuns: 500 });
});

const shareArbitrary = fc.integer({ min: 1, max: 16 }).chain((groupCount) =>
  fc.record({
    identifier: fc.integer({ min: 0, max: 32_767 }),
    extendable: fc.boolean(),
    iterationExponent: fc.integer({ min: 0, max: 15 }),
    groupIndex: fc.integer({ min: 0, max: groupCount - 1 }),
    groupThreshold: fc.integer({ min: 1, max: groupCount }),
    groupCount: fc.constant(groupCount),
    memberIndex: fc.integer({ min: 0, max: 15 }),
    memberThreshold: fc.integer({ min: 1, max: 16 }),
    value: fc.uint8Array({ minLength: 16, maxLength: 64 })
      .filter((value) => value.length % 2 === 0),
  }));

test("fast-check fuzzes the complete valid SLIP-39 share metadata space", () => {
  fc.assert(fc.property(shareArbitrary, (share) => {
    const expected = { ...share, value: Buffer.from(share.value) };
    const mnemonic = encodeShare(expected);
    const decoded = decodeShare(mnemonic);
    assert.deepEqual(decoded, expected);
    assert.equal(encodeShare(decoded), mnemonic);
  }), { numRuns: 500 });
});
