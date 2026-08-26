// Terminal input primitives are kept separate so escape handling and Unicode
// deletion can be tested without ever feeding a real secret to a test runner.

import process from "node:process";

const ETX = "\u0003";
const EOT = "\u0004";
export const ESC = "\u001b";
const BS = "\u0008";
const DEL = "\u007f";
const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });

function dropLastGrapheme(value) {
  const segments = [...segmenter.segment(value)];
  return segments.length === 0 ? value : value.slice(0, segments.at(-1).index);
}

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
}

export function looksObviouslyWeakPassphrase(value) {
  if (value.length < 16) return true;
  if (/^(.)\1+$/u.test(value)) return true;
  if (/^(.{1,8})\1+$/u.test(value)) return true;
  if (/^(password|passphrase|letmein|qwerty|123456|correct horse battery staple)/iu
    .test(value.trim())) return true;
  return false;
}
