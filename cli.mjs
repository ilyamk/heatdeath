import assert from "node:assert/strict";

const COMMANDS = new Map([
  ["--self-test", "self-test"],
  ["--wizard", "wizard"],
  ["--generate", "generate"],
  ["--verify", "verify"],
  ["--split", "split"],
  ["--combine", "combine"],
  ["--op-export", "op-export"],
  ["--prove-guard", "prove-guard"],
  ["--prove-sandbox", "prove-guard"],
  ["--license", "license"],
]);

const BOOLEAN_SCOPES = new Map([
  ["--dice", new Set(["wizard", "generate"])],
  ["--show-public", new Set(["wizard", "generate", "verify", "combine"])],
  ["--show-private", new Set(["wizard", "generate", "verify", "combine"])],
  ["--wipe-screen", new Set(["wizard", "generate"])],
  ["--dry-run", new Set(["op-export"])],
  ["--qr", new Set(["wizard", "generate", "verify", "combine"])],
]);

const OPTION_SCOPES = new Map([
  ["--scheme", new Set(["wizard", "generate", "verify", "split", "combine", "op-export"])],
  ["--accounts", new Set(["wizard", "generate", "verify", "split", "combine", "op-export"])],
  ["--shares", new Set(["wizard", "split"])],
  ["--group-threshold", new Set(["wizard", "split"])],
]);

function exactInteger(value, name, min, max = Number.MAX_SAFE_INTEGER) {
  assert.match(value, /^(0|[1-9][0-9]*)$/, `${name} must be a base-10 integer`);
  const number = Number(value);
  assert.ok(Number.isSafeInteger(number) && number >= min && number <= max,
    `${name} must be an integer between ${min} and ${max}`);
  return number;
}

export function parseCli(argv, {
  defaultScheme, schemes, defaultAccounts, maxAccounts,
} = {}) {
  if (argv.includes("--help")) {
    return { command: "help", flags: new Set(["--help"]) };
  }

  const flags = new Set();
  const opts = new Map();
  for (const arg of argv) {
    assert.ok(arg.startsWith("--"), `Unexpected positional argument "${arg}"`);
    const eq = arg.indexOf("=");
    if (eq === -1) {
      assert.ok(!flags.has(arg), `Duplicate flag "${arg}"`);
      flags.add(arg);
    } else {
      const key = arg.slice(0, eq);
      assert.ok(!opts.has(key), `Duplicate option "${key}"`);
      assert.ok(arg.slice(eq + 1).length > 0, `${key} requires a value`);
      opts.set(key, arg.slice(eq + 1));
    }
  }

  for (const flag of flags) {
    assert.ok(COMMANDS.has(flag) || BOOLEAN_SCOPES.has(flag), `Unknown flag "${flag}"`);
  }
  for (const key of opts.keys()) {
    assert.ok(OPTION_SCOPES.has(key), `Unknown option "${key}"`);
  }

  const selected = [...flags].filter((flag) => COMMANDS.has(flag));
  assert.equal(selected.length, 1, "select exactly one command (use --help for usage)");
  const command = COMMANDS.get(selected[0]);
  assert.equal(
    selected.filter((flag) => COMMANDS.get(flag) === command).length, 1,
    "command aliases cannot be used together",
  );

  for (const flag of flags) {
    if (BOOLEAN_SCOPES.has(flag)) {
      assert.ok(BOOLEAN_SCOPES.get(flag).has(command), `${flag} is not valid with --${command}`);
    }
  }
  for (const key of opts.keys()) {
    assert.ok(OPTION_SCOPES.get(key).has(command), `${key} is not valid with --${command}`);
  }

  const scheme = opts.get("--scheme") ?? defaultScheme;
  assert.ok(schemes.includes(scheme),
    `Unknown --scheme "${scheme}". Available: ${schemes.join(", ")}`);
  const count = exactInteger(
    opts.get("--accounts") ?? String(defaultAccounts), "--accounts", 1, maxAccounts,
  );
  const groupThreshold = exactInteger(
    opts.get("--group-threshold") ?? "1", "--group-threshold", 1, 16,
  );

  return {
    command, flags, scheme, count,
    shareSpec: opts.get("--shares") ?? "2of3",
    groupThreshold,
    showPrivate: flags.has("--show-private"),
    showPublic: flags.has("--show-public"),
    useDice: flags.has("--dice"),
    wipe: flags.has("--wipe-screen"),
    dryRun: flags.has("--dry-run"),
    qr: flags.has("--qr"),
  };
}
