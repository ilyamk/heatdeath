// Shared preflight for the source and verified launchers. Both spawn the
// secret-capable process under Node's Permission Model; this module decides
// whether that model can actually enforce what the documentation promises.
//
// The network scope (`--allow-net`) exists only from Node 25.0.0. On an older
// Node the guard still denies subprocesses, workers and writes, but network
// and DNS stay wide open while `process.permission` reports nothing amiss.
// Refusing to start a secret-capable command there is the honest outcome:
// a guard that cannot deny the network must not be presented as one.

/** Commands that create or read no secret and may run to show a diagnosis. */
export const SECRET_FREE_COMMANDS = Object.freeze(new Set([
  "--self-test", "--prove-guard", "--prove-sandbox", "--doctor", "--license", "--help",
]));

export function isSecretCapable(args) {
  return !args.some((argument) => SECRET_FREE_COMMANDS.has(argument));
}

/**
 * Returns a refusal message, or null when the launch may proceed.
 * `runtime` is process-shaped so the decision is testable on any Node.
 */
export function launcherRefusal(args, runtime) {
  if (!isSecretCapable(args)) return null;
  if (runtime.allowedNodeEnvironmentFlags?.has("--allow-net")) return null;
  return (
    `Node ${runtime.version} has no network permission scope (--allow-net, Node >= 25), ` +
    "so the capability guard cannot deny network or DNS access. Secret-capable commands " +
    "will not start on this runtime. Use Node 26 LTS (see .node-version). Diagnostics " +
    "still run: --self-test, --prove-guard, --doctor."
  );
}
