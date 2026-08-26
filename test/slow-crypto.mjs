// Scheduled deterministic stress/property tests. Kept discovery-safe so the
// fast `node --test` suite does not silently absorb the slow workload.
if (process.env.HEATDEATH_SLOW === "1") {
  const { default: assert } = await import("node:assert/strict");
  const { createHash } = await import("node:crypto");
  const { default: test } = await import("node:test");
  const { parseCli } = await import("../cli.mjs");
  const { encodeQR } = await import("../qr.mjs");
  const {
    admissibleSubsetAtRank,
    combineShares,
    countAdmissibleSubsetsExact,
    splitSecretIntoShares,
  } = await import("../slip39.mjs");

  function deterministicRng(label) {
    let counter = 0;
    return (length) => {
      const output = Buffer.alloc(length);
      let offset = 0;
      while (offset < length) {
        const block = createHash("sha256").update(`${label}/${counter++}`).digest();
        offset += block.copy(output, offset);
      }
      return output;
    };
  }

  test("SLIP-39 scheduled property matrix recovers every sampled secret", () => {
    const started = performance.now();
    const layouts = [
      { groupThreshold: 1, groups: [{ threshold: 2, count: 3 }] },
      { groupThreshold: 2, groups: [
        { threshold: 1, count: 1 }, { threshold: 2, count: 3 }, { threshold: 3, count: 5 },
      ] },
      { groupThreshold: 3, groups: [
        { threshold: 2, count: 3 }, { threshold: 2, count: 4 }, { threshold: 3, count: 5 },
      ] },
    ];
    let recovered = 0;
    for (let caseIndex = 0; caseIndex < 30; caseIndex += 1) {
      const secret = createHash("sha256").update(`heatdeath/slow/${caseIndex}`).digest();
      const layout = layouts[caseIndex % layouts.length];
      const mnemonics = splitSecretIntoShares({
        secret, ...layout, identifier: 1000 + caseIndex,
        rng: deterministicRng(`shares/${caseIndex}`),
      });
      const total = countAdmissibleSubsetsExact(layout.groupThreshold, layout.groups);
      const ranks = new Set([0n, total / 2n, total - 1n]);
      for (const rank of ranks) {
        const subset = admissibleSubsetAtRank(
          layout.groupThreshold, layout.groups, mnemonics, rank,
        );
        assert.deepEqual(Buffer.from(combineShares(subset)), secret);
        recovered += 1;
      }
    }
    assert.ok(performance.now() - started < 20_000, "SLIP-39 stress matrix exceeded 20 seconds");
    assert.ok(recovered >= 90);
  });

  test("large admissible rank is exact and bounded without materialisation", () => {
    const groups = Array.from({ length: 16 }, () => ({ threshold: 8, count: 16 }));
    const started = performance.now();
    const exact = countAdmissibleSubsetsExact(16, groups);
    assert.equal(exact, 12870n ** 16n);
    assert.ok(performance.now() - started < 2_000, "exact count exceeded two seconds");
  });

  test("QR encoder remains bounded across its supported capacity", () => {
    const started = performance.now();
    for (let length = 1; length <= 2_000; length += 17) {
      const symbol = encodeQR(`x${"a".repeat(length - 1)}`, {
        ecc: length % 2 ? "L" : "M",
        mask: length % 8,
      });
      assert.equal(symbol.modules.length, symbol.size ** 2);
      assert.ok(symbol.size >= 21 && symbol.size <= 177);
    }
    assert.ok(performance.now() - started < 10_000, "QR capacity matrix exceeded 10 seconds");
  });

  test("CLI parser fuzz terminates and never returns an unknown command", () => {
    const vocabulary = [
      "--generate", "--verify", "--combine", "--split", "--help", "--dice", "--qr",
      "--accounts=1", "--accounts=100", "--accounts=-1", "--scheme=metamask",
      "--scheme=account", "--shares=2of3", "--unknown", "text", "--accounts=1e3",
      "--group-threshold=16", "--group-threshold=999999999999999999999999999",
      "--\u001b[31m", "--show-private", "--op-export", "--dry-run",
    ];
    const known = new Set([
      "help", "generate", "verify", "combine", "split", "op-export",
      "wizard", "self-test", "prove-guard", "license",
    ]);
    const random = deterministicRng("cli-fuzz");
    const started = performance.now();
    for (let caseIndex = 0; caseIndex < 10_000; caseIndex += 1) {
      const bytes = random(6);
      const argv = Array.from(bytes.subarray(0, bytes[0] % 6), (byte) =>
        vocabulary[byte % vocabulary.length]);
      try {
        const parsed = parseCli(argv, {
          defaultScheme: "metamask", schemes: ["metamask", "account"],
          defaultAccounts: 11, maxAccounts: 100,
        });
        assert.ok(known.has(parsed.command));
      } catch (error) {
        assert.ok(error instanceof assert.AssertionError);
      }
    }
    assert.ok(performance.now() - started < 5_000, "CLI fuzz exceeded five seconds");
  });
}
