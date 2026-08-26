import assert from "node:assert/strict";
import test from "node:test";

import {
  admissibleSubsetAtRank,
  countAdmissibleSubsets,
  countAdmissibleSubsetsExact,
  encodeShare,
} from "../slip39.mjs";

test("admissible subset counts remain exact beyond Number", () => {
  const groups = Array.from({ length: 16 }, () => ({ threshold: 8, count: 16 }));
  const exact = countAdmissibleSubsetsExact(16, groups);
  assert.equal(exact, 12870n ** 16n);
  assert.throws(() => countAdmissibleSubsets(16, groups), /MAX_SAFE_INTEGER/);
});

test("global rank enumerates each weighted admissible subset once", () => {
  const groups = [{ threshold: 1, count: 1 }, { threshold: 2, count: 3 }];
  const shares = [["a"], ["b", "c", "d"]];
  const total = countAdmissibleSubsetsExact(1, groups);
  const ranked = Array.from({ length: Number(total) }, (_, i) =>
    admissibleSubsetAtRank(1, groups, shares, BigInt(i)).join(""));
  assert.equal(total, 4n);
  assert.equal(new Set(ranked).size, 4);
  assert.deepEqual(new Set(ranked), new Set(["a", "bc", "bd", "cd"]));
});

test("encoder rejects impossible metadata before packing", () => {
  assert.throws(() => encodeShare({
    identifier: 1, extendable: true, iterationExponent: 0,
    groupIndex: 15, groupThreshold: 1, groupCount: 1,
    memberIndex: 0, memberThreshold: 1, value: Buffer.alloc(16),
  }), /group index/);
});
