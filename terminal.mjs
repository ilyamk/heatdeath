// Terminal input primitives are kept separate so escape handling and Unicode
// deletion can be tested without ever feeding a real secret to a test runner.

import process from "node:process";

const ETX = "\u0003";
const EOT = "\u0004";
export const ESC = "\u001b";
const BS = "\u0008";
const DEL = "\u007f";
const NAK = "\u0015"; // Ctrl+U: discard the whole line, as in every shell
const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });

function dropLastGrapheme(value) {
  const segments = [...segmenter.segment(value)];
  return segments.length === 0 ? value : value.slice(0, segments.at(-1).index);
}

const graphemeCount = (value) => [...segmenter.segment(value)].length;

export class TerminalInputDecoder {
  #value = "";
  #escape = "";
  #paste = false;

  get value() { return this.#value; }

  push(chunk) {
    let completed = false;
    let aborted = false;
    let erased = 0;
    let echo = "";

    for (const ch of chunk) {
      if (this.#escape) {
        if (ch === ETX || ch === EOT) {
          this.#escape = "";
          aborted = true;
          break;
        }
        if ((ch === "\r" || ch === "\n") && !this.#paste) {
          this.#escape = "";
          completed = true;
          break;
        }
        this.#escape += ch;
        if (this.#escape === `${ESC}[200~`) {
          this.#paste = true;
          this.#escape = "";
        } else if (this.#escape === `${ESC}[201~`) {
          this.#paste = false;
          this.#escape = "";
        } else if (
          (this.#escape.startsWith(`${ESC}[`) && this.#escape.length >= 3 &&
            /[@-~]$/.test(ch)) ||
          (this.#escape.startsWith(`${ESC}O`) && this.#escape.length >= 3) ||
          (!this.#escape.startsWith(`${ESC}[`) &&
            !this.#escape.startsWith(`${ESC}O`) && this.#escape.length >= 2)
        ) {
          this.#escape = "";
        } else if (this.#escape.length > 64) {
          this.#escape = "";
        }
        continue;
      }

      if (ch === ESC) {
        this.#escape = ESC;
        continue;
      }
      if (ch === "\r" || ch === "\n") {
        if (this.#paste) {
          this.#value += ch;
          echo += ch;
        } else {
          completed = true;
          break;
        }
        continue;
      }
      if (ch === ETX || ch === EOT) {
        aborted = true;
        break;
      }
      if (ch === BS || ch === DEL) {
        const next = dropLastGrapheme(this.#value);
        if (next !== this.#value) {
          this.#value = next;
          erased += 1;
        }
        continue;
      }
      // Hidden input gives no feedback, so a suspected typo deep in a
      // passphrase would otherwise mean backspacing blind, one character at
      // a time. Ctrl+U starts the line over, exactly as a shell would.
      if (ch === NAK && !this.#paste) {
        erased += graphemeCount(this.#value);
        this.#value = "";
        continue;
      }
      if (ch < " " && !this.#paste) continue;
      this.#value += ch;
      echo += ch;
    }
    return { completed, aborted, erased, echo };
  }
}

export async function readInput(prompt, { echo = false, stdin = process.stdin,
  stdout = process.stdout } = {}) {
  if (!stdin.isTTY || typeof stdin.setRawMode !== "function") {
    throw new Error("stdin is not a terminal; this command needs interactive input");
  }

  const wasRaw = Boolean(stdin.isRaw);
  const decoder = new TerminalInputDecoder();
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");
  stdout.write(prompt);

  try {
    await new Promise((resolve, reject) => {
      const cleanup = () => {
        stdin.off("data", onData);
        stdin.off("error", onError);
        stdin.off("end", onEnd);
      };
      const onError = (error) => { cleanup(); reject(error); };
      const onEnd = () => { cleanup(); reject(new Error("terminal input ended unexpectedly")); };
      const onData = (chunk) => {
        const event = decoder.push(chunk);
        if (echo && event.echo) stdout.write(event.echo);
        if (echo && event.erased) stdout.write("\b \b".repeat(event.erased));
        if (event.aborted) {
          cleanup();
          stdout.write("\n");
          reject(new Error("aborted by user"));
        } else if (event.completed) {
          cleanup();
          stdout.write("\n");
          resolve();
        }
      };
      stdin.on("data", onData);
      stdin.once("error", onError);
      stdin.once("end", onEnd);
    });
  } finally {
    stdin.setRawMode(wasRaw);
    stdin.pause();
  }

  const value = decoder.value;
  if (!value.isWellFormed()) {
    throw new Error("input contains malformed Unicode; nothing was accepted");
  }
  return value;
}

export function normalizePassphrase(value) {
  if (typeof value !== "string" || !value.isWellFormed()) {
    throw new TypeError("passphrase must be well-formed Unicode text");
  }
  return value.normalize("NFKD");
}

export function validateNewWalletPassphrase(value) {
  if (value === "") return;
  if (!/^[\x20-\x7e]+$/.test(value)) {
    throw new Error(
      "new-wallet passphrases must contain printable ASCII only (space through ~)",
    );
  }
  // Input is hidden, so a leading or trailing space is invisible to the
  // person typing it - and a wallet restored without it is a different,
  // empty wallet. Refuse rather than warn: nothing legitimate needs one.
  if (value !== value.trim()) {
    throw new Error(
      "new-wallet passphrases must not start or end with a space: hidden input " +
        "cannot show it, and restoring without it opens a different, empty wallet",
    );
  }
}

/**
 * Structural warnings about a passphrase that is valid but easy to get wrong
 * later. Runs of spaces are the hidden-input hazard: "a  b" and "a b" are
 * different wallets and look identical on paper.
 */
export function passphraseCautions(value) {
  const cautions = [];
  if (/ {2,}/.test(value)) {
    cautions.push(
      "It contains two or more consecutive spaces. They count, and they are " +
        "invisible on paper; a single space between words is far safer.",
    );
  }
  if (looksObviouslyWeakPassphrase(value)) {
    cautions.push(
      "It has an obvious weak structure or is short. Software cannot infer how " +
        "randomly a passphrase was chosen, so no honest entropy figure can be given; " +
        "use independently sampled Diceware words or random characters.",
    );
  }
  return cautions;
}

export function looksObviouslyWeakPassphrase(value) {
  if (value.length < 16) return true;
  if (/^(.)\1+$/u.test(value)) return true;
  if (/^(.{1,8})\1+$/u.test(value)) return true;
  if (/^(password|passphrase|letmein|qwerty|123456|correct horse battery staple)/iu
    .test(value.trim())) return true;
  return false;
}
