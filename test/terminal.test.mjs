import assert from "node:assert/strict";
import test from "node:test";

import {
  TerminalInputDecoder,
  normalizePassphrase,
  validateNewWalletPassphrase,
} from "../terminal.mjs";

test("backspace removes one complete grapheme", () => {
  const input = new TerminalInputDecoder();
  input.push("a😀");
  input.push("\u007f");
  assert.equal(input.value, "a");

  input.push("e\u0301");
  input.push("\u0008");
  assert.equal(input.value, "a");
  assert.equal(input.value.isWellFormed(), true);
});

test("CSI, SS3 and bracketed-paste wrappers never enter input", () => {
  const input = new TerminalInputDecoder();
  input.push("ab\u001b[D\u001bOA");
  input.push("\u001b[200~pasted text\u001b[201~\r");
  assert.equal(input.value, "abpasted text");
});

test("an incomplete escape sequence cannot swallow Enter or Ctrl+C", () => {
  const enter = new TerminalInputDecoder();
  enter.push("value\u001b[");
  assert.equal(enter.push("\r").completed, true);
  assert.equal(enter.value, "value");

  const abort = new TerminalInputDecoder();
  abort.push("value\u001b");
  assert.equal(abort.push("\u0003").aborted, true);
});

test("new-wallet passphrases are portable ASCII; recovery remains Unicode", () => {
  validateNewWalletPassphrase("");
  validateNewWalletPassphrase("four words ~ 123");
  assert.throws(() => validateNewWalletPassphrase("café"), /printable ASCII/);
  assert.equal(normalizePassphrase("é"), "e\u0301");
});
