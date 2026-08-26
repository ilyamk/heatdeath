// The only transport that handles a complete wallet payload. It deliberately
// discards all child stderr bytes: after secret input, diagnostics are tainted
// even if they contain only a fragment that cannot be substring-matched.

export async function sendSecretPayload({
  spawn, shell, cat, opPath, vault, payload, preview = false,
}) {
  const script =
    `exec ${cat} | "$1" item create --vault "$2" --format=json ` +
    `${preview ? "--dry-run " : ""}-`;
  const child = spawn(shell, ["-c", script, "sh", opPath, vault], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  let transportFailed = false;
  // `op --format=json` may echo concealed fields in its result. Success is
  // determined solely by the exit status, so stdout is discarded as tainted
  // just like stderr; retaining it merely to extract an item id is not worth
  // duplicating the complete wallet in another immutable JS string.
  child.stdout.on("data", () => {});
  child.stderr.on("data", () => {}); // discard, never retain secret-path stderr
  child.stdin.on("error", () => { transportFailed = true; });

  const result = await new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (!settled) { settled = true; resolve(value); }
    };
    child.on("error", () => finish({ code: -1, transportFailed: true }));
    child.on("close", (code) => finish({ code, transportFailed }));
    child.stdin.end(payload);
  });
  if (result.transportFailed && result.code === 0) result.code = -1;
  return result;
}
