import os from "node:os";
import process from "node:process";

/** Detect an inspector activated at runtime (for example via SIGUSR1). */
function inspectorUrl(runtime) {
  try {
    return runtime.getBuiltinModule?.("node:inspector")?.url?.();
  } catch {
    return undefined;
  }
}

const FORBIDDEN_PERMISSION_SCOPES = Object.freeze([
  "net", "child", "worker", "fs.write", "addon", "ffi", "inspector", "wasi",
]);

// Flags that copy process memory to disk or run code before this file does.
// A heap snapshot or heap profile contains every live string, the mnemonic
// included; a preloaded module observes everything this process does. The
// launchers never pass these, so their presence means a hand-built command.
const FORBIDDEN_EXEC_ARGV = Object.freeze([
  "--heapsnapshot-signal", "--heapsnapshot-near-heap-limit", "--heap-prof",
  "--cpu-prof", "--prof", "--diagnostic-dir",
  "--report-on-signal", "--report-on-fatalerror", "--report-uncaught-exception",
  "--require", "-r", "--import", "--loader", "--experimental-loader",
  "--env-file", "--env-file-if-exists",
]);

function forbiddenExecArgv(execArgv) {
  return execArgv.filter((argument) =>
    FORBIDDEN_EXEC_ARGV.some((flag) => argument === flag || argument.startsWith(`${flag}=`)));
}

/**
 * Whether this Node build has a network permission scope at all. The
 * Permission Model gained `--allow-net` in Node 25.0.0; before that, network
 * and DNS access cannot be denied by it, and `process.permission.has("net")`
 * merely returns false for a scope the runtime does not know. Feature-detect
 * rather than compare versions so a backport is recognised for what it does.
 */
export function supportsNetworkPermission(runtime = process) {
  return Boolean(runtime.allowedNodeEnvironmentFlags?.has("--allow-net"));
}

function permissionFlagConcerns(runtime) {
  const concerns = [];
  const allowedReads = new Set([".", runtime.cwd(), "/dev/urandom"]);
  for (const argument of runtime.execArgv ?? []) {
    if (argument === "--allow-fs-write" || argument.startsWith("--allow-fs-write=")) {
      concerns.push({
        id: "permission-fs.write-resource",
        message: `Filesystem write grant is present in execArgv (${argument}).`,
      });
    }
    if (argument.startsWith("--allow-fs-read=")) {
      const resource = argument.slice("--allow-fs-read=".length);
      if (!allowedReads.has(resource)) {
        concerns.push({
          id: "permission-fs.read-resource",
          message: `Unexpected filesystem read grant is present in execArgv (${argument}).`,
        });
      }
    }
  }
  return concerns;
}

/**
 * Collect every observable runtime concern without printing or throwing.
 * Tests can inject a process-shaped object and a network enumerator; production
 * callers use the real process and os.networkInterfaces.
 */
export function inspectRuntime({
  requireTty = true,
  requirePermission = false,
  runtime = process,
  networkInterfaces = () => os.networkInterfaces(),
} = {}) {
  const blockers = [];
  const warnings = [];

  if (runtime.env.SSH_TTY || runtime.env.SSH_CONNECTION) {
    blockers.push({
      id: "ssh",
      message: "This is an SSH session. Every character printed here crosses a network " +
        "and lands in a remote terminal's scrollback. Run on the physical machine.",
    });
  }

  const inspectFlags = [...runtime.execArgv, runtime.env.NODE_OPTIONS ?? ""]
    .join(" ")
    .match(/--inspect[\w-]*/g);
  if (inspectFlags) {
    blockers.push({
      id: "debugger",
      message: `A debugger port is enabled (${inspectFlags.join(", ")}). Anything ` +
        "attached to it can read the seed straight out of process memory.",
    });
  }
  const inspector = inspectorUrl(runtime);
  if (inspector) {
    blockers.push({ id: "inspector", message: `An inspector is already listening on ${inspector}.` });
  }
  const dumpFlags = forbiddenExecArgv(runtime.execArgv ?? []);
  if (dumpFlags.length > 0) {
    blockers.push({
      id: "diagnostic-flags",
      message: `Node was started with ${dumpFlags.join(", ")}. Such flags write process ` +
        "memory to disk or run code before this file - a heap snapshot contains the seed. " +
        "Start through the provided launchers, which pass none of them.",
    });
  }

  if (requireTty && !runtime.stdout.isTTY) {
    blockers.push({
      id: "stdout-tty",
      message: "stdout is not a terminal. NOTE: this check is a convenience guard, not " +
        "a security boundary - script(1), `tmux pipe-pane`, expect and terminal session " +
        "logging all defeat it trivially. You remain responsible for ensuring nothing " +
        "is recording this terminal.",
    });
  }
  if (requireTty && !runtime.stdin?.isTTY) {
    blockers.push({
      id: "stdin-tty",
      message: "stdin is not a terminal. Secret input must come directly from the " +
        "interactive terminal, never a pipe, redirected file, or automation harness.",
    });
  }

  if (!runtime.permission) {
    const row = {
      id: "permission-model",
      message: "Node's trusted-code capability guard is OFF. Network, subprocesses and " +
        "file writes are technically possible from this process. Use a provided source " +
        "or verified launcher, which enables it.",
    };
    (requirePermission ? blockers : warnings).push(row);
  } else {
    if (!supportsNetworkPermission(runtime)) {
      const row = {
        id: "permission-net-unsupported",
        message: `This Node (${runtime.version ?? "unknown version"}) has no network ` +
          "permission scope, so the capability guard cannot deny network or DNS access " +
          "from this process. Node 25 introduced --allow-net; use Node 26 LTS.",
      };
      (requirePermission ? blockers : warnings).push(row);
    }
    for (const scope of FORBIDDEN_PERMISSION_SCOPES) {
      if (runtime.permission.has(scope)) {
        const row = { id: `permission-${scope}`, message: `Permission "${scope}" is ALLOWED.` };
        (requirePermission ? blockers : warnings).push(row);
      }
    }
    for (const row of permissionFlagConcerns(runtime)) {
      (requirePermission ? blockers : warnings).push(row);
    }
    if (runtime.permission.has("fs.read", runtime.cwd())) {
      warnings.push({
        id: "repository-read",
        message: "Repository-wide filesystem read is allowed. This is expected only in " +
          "source-checkout mode; signed bundle commands need /dev/urandom only.",
      });
    }
    if (!runtime.permission.has("fs.read", "/dev/urandom")) {
      blockers.push({
        id: "urandom-read",
        message: "The required /dev/urandom read capability is missing.",
      });
    }
  }

  if (typeof runtime.getuid === "function" && runtime.getuid() === 0) {
    warnings.push({ id: "root", message: "Running as root. This tool needs no privileges whatsoever." });
  }
  if (runtime.env.TMUX || runtime.env.STY) {
    warnings.push({
      id: "terminal-multiplexer",
      message: "Running inside tmux/screen. These keep large scrollback buffers and can " +
        "be configured to log the session to disk.",
    });
  }
  if (runtime.env.NODE_OPTIONS?.trim()) {
    const row = {
      id: "node-options",
      message: `NODE_OPTIONS is set ("${runtime.env.NODE_OPTIONS}"). It can inject code ` +
        "or broaden resource-scoped permissions before this file runs.",
    };
    (requirePermission ? blockers : warnings).push(row);
  }

  const cwd = runtime.cwd();
  for (const dir of [
    "Library/Mobile Documents", "iCloud", "Dropbox", "Google Drive",
    "OneDrive", "Yandex.Disk", "pCloud", "MEGA",
  ]) {
    if (cwd.includes(dir)) {
      warnings.push({
        id: "cloud-directory",
        message: `Working directory looks cloud-synchronised (matched "${dir}").`,
      });
      break;
    }
  }

  try {
    const live = Object.entries(networkInterfaces())
      .filter(([, addrs]) => (addrs ?? []).some((address) => !address.internal))
      .map(([name]) => name);
    if (live.length > 0) {
      const sample = live.slice(0, 3).join(", ");
      warnings.push({
        id: "network-interfaces",
        message: `${live.length} network interface(s) are up (${sample}` +
          `${live.length > 3 ? ", ..." : ""}). Disable Wi-Fi, Ethernet and ` +
          "Bluetooth before generating.",
      });
    }
  } catch {
    warnings.push({ id: "network-unknown", message: "Network interfaces could not be inspected." });
  }

  return Object.freeze({
    blockers: Object.freeze(blockers),
    warnings: Object.freeze(warnings),
  });
}
