import assert from "node:assert/strict";
import test from "node:test";

import { parseCli } from "../cli.mjs";

const config = {
  defaultScheme: "metamask",
  schemes: ["metamask", "account"],
  defaultAccounts: 11,
  maxAccounts: 100,
};
const parse = (args) => parseCli(args, config);

test("CLI accepts exactly one scoped command", () => {
  assert.equal(parse(["--generate", "--accounts=2", "--qr"]).count, 2);
  assert.throws(() => parse(["--generate", "--verify"]), /exactly one command/);
  assert.throws(() => parse(["--verify", "--dice"]), /not valid/);
  assert.throws(() => parse(["--generate", "--dry-run"]), /not valid/);
  assert.equal(parse(["--doctor"]).command, "doctor");
  assert.equal(parse(["--rehearse-safe-owner"]).command, "rehearse-safe-owner");
  assert.equal(parse(["--safe-owner"]).command, "safe-owner");
  assert.throws(() => parse(["--safe-owner", "--accounts=2"]), /not valid/);
  assert.throws(() => parse(["--safe-owner", "--show-private"]), /not valid/);
});

test("CLI rejects partial, duplicate and unsafe integers", () => {
  for (const bad of ["1junk", "1.5", "+1", "01", "9007199254740992"]) {
    assert.throws(() => parse(["--generate", `--accounts=${bad}`]));
  }
  assert.throws(() => parse(["--generate", "--accounts=1", "--accounts=2"]),
    /Duplicate/);
  assert.throws(() => parse(["--generate", "--qr", "--qr"]), /Duplicate/);
});

test("--help always returns help without touching other arguments", () => {
  assert.equal(parse(["--garbage", "--help", "--generate"]).command, "help");
});
