import assert from "node:assert/strict";
import test from "node:test";

import { encodeAddressQRs } from "../qr.mjs";

test("address QR input must be a primitive immutable string", () => {
  const stateful = { toString: () => "0x" + "ab".repeat(20) };
  assert.throws(() => encodeAddressQRs([stateful]), /primitive string/);
  assert.doesNotThrow(() => encodeAddressQRs(["0x" + "ab".repeat(20)]));
});
