# Building from source

> How to build HEATDEATH yourself, why the build is byte-for-byte reproducible,
> and which three keys in the SEA configuration must never be changed.

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/BUILD.md) · [📖 Glossary](GLOSSARY.md)

---

**Contents**

- [What `build.sh` does](#what-buildsh-does)
- [SEA configuration](#sea-configuration)
- [Determinism](#determinism)
- [Signing keys](#signing-keys)
- [Other runtimes](#other-runtimes)
- [Cross-platform support](#cross-platform-support)

---

```sh
rm -rf node_modules && npm ci --ignore-scripts
npm run build          # -> dist/
npm run sign           # -> signatures (requires keys in keys/)
npm run verify-release
```

## What `build.sh` does

Every step is a gate. The build fails rather than shipping a doubtful artifact.

1. Prints the Node and esbuild versions, warning if they diverge from the recipe.
2. **Self-test from source.** Never ship something untested.
3. Bundles with esbuild: from the repository root, relative entry path, ESM format.
4. **Verifies the bundle in isolation** — copies it to a temporary directory with
   no `node_modules` and runs `--self-test` there.
5. Builds the single executable with `node --build-sea`, then ad-hoc `codesign`.
6. **Verifies the binary's sandbox** — requires exactly `6/6 denied`, otherwise FATAL.
7. **Verifies that `NODE_OPTIONS` cannot loosen the sandbox** — attempts a write to
   `/tmp`; if the file appears, the build fails.
8. Writes the `SHA256SUMS` manifest and `BUILD-RECIPE.txt`.

## SEA configuration

`build/sea.json`:

```json
{
  "main": "../dist/heatdeath.mjs",
  "mainFormat": "module",
  "output": "../dist/heatdeath",
  "execArgv": ["--permission", "--allow-fs-read=/dev/urandom"],
  "execArgvExtension": "none"
}
```

Three keys, each mandatory, and each non-obvious.

**`mainFormat: "module"`.** Without it the entry point runs as CommonJS and dies with
`SyntaxError: Cannot use import statement outside a module`. This is precisely why
the belief that SEA cannot handle ESM is so widespread — it can, starting from this
key. The workaround of converting to CJS does not help: `esbuild --format=cjs`
refuses because of top-level `await`.

**`execArgv`.** Bakes the flags into the binary permanently. The result must be
checked through `process.permission` and **not** through `process.execArgv`: the
flags are applied before user code runs and are not reflected there, where the array
is empty. This is a common source of incorrect conclusions.

**`execArgvExtension: "none"` — a requirement, not an option.** The default is
`"env"`, and then `NODE_OPTIONS` **extends** the baked-in flags. The measured
difference between two otherwise identical binaries:

```
"none" + NODE_OPTIONS=--allow-fs-write=/tmp  ->  6/6 denied, no file written
"env"  + NODE_OPTIONS=--allow-fs-write=/tmp  ->  5/6, file write ALLOWED
```

In other words, with the default, anyone who controls the environment removes the
sandbox with an environment variable. Step 7 in `build.sh` exists for this reason.

The binary needs access to `/dev/urandom` **only**: everything else is inlined into
the bundle, and the package directory does not need to be readable.

## Determinism

| Artifact | Reproducible | Condition |
|---|---|---|
| `heatdeath.mjs` | yes | same esbuild version, run from the root with a relative path |
| `heatdeath` | yes | same Node build (v26.5.0, darwin/arm64), same output filename |
| Signatures | **no** | ML-DSA is randomised; the manifest itself stays identical |

An absolute path to the entry file leaks into the bundle as comments and makes the
hash machine-specific. The binary's output filename participates in the ad-hoc
signature as an identifier, so renaming it changes the bytes.

## Signing keys

On its first run, `npm run sign` generates three key pairs and writes the private
halves to `keys/` with mode `0600`. That directory is in `.gitignore`.

- **Leaking the keys** means an attacker signs a backdoored build and it verifies
  perfectly.
- **Losing the keys** means you can no longer sign under the same identity, and
  users have to pin new fingerprints from scratch.

Keep `keys/` off every machine that is not doing a release.

## Other runtimes

Both were evaluated and both were rejected.

**Deno** — the best sandbox of the three: escaping it failed both through
`--allow-all` at runtime and through environment variables; the flags are not stored
as plain text; 64 MB and cross-compilation to six platforms. The tool passes its
self-test under Deno, meaning the `node:crypto` compatibility layer covers
`pbkdf2Sync`, `createHmac` and `timingSafeEqual`, and both independent
implementations survive the port. **But `deno compile` is not reproducible** — two
runs diverge. Reproducibility outweighs sandbox quality, because a backdoor in the
RNG bypasses the sandbox entirely: it needs no permissions at all.

**Bun** — 61 MB, passes the self-test, but **has no permission model whatsoever**:
`--prove-sandbox` returns 2/6 and the tool refuses to certify itself.
Disqualified.

## Cross-platform support

Node SEA **cannot cross-compile**. The current release is darwin/arm64 only, built
and verified on the target platform. Other platforms would need CI runners; Linux
and Windows users are left with the `.mjs` bundle, which runs anywhere Node does.

This is a deliberate choice: an unverified binary for a platform nobody has ever run
it on is worse than no binary at all.

---

## References and further reading

- [Node.js — Single Executable Applications: `sea-config`, `mainFormat`, `execArgv`, `execArgvExtension`](https://nodejs.org/api/single-executable-applications.html)
- [Node.js — Permission Model: what `--permission` and the `--allow-*` flags actually deny](https://nodejs.org/api/permissions.html)
- [esbuild — the bundler that produces the `.mjs` artifact](https://esbuild.github.io/)
- [Reproducible Builds — definitions and practice](https://reproducible-builds.org/)
- [Reproducible Builds — the formal definition of the property](https://reproducible-builds.org/docs/definition/)
- [`deno compile` — evaluated and rejected alternative](https://docs.deno.com/runtime/reference/cli/compile/)
- [Bun — single-file executables, rejected for having no permission model](https://bun.sh/docs/bundler/executables)
- [Apple Code Signing Services — why the output filename ends up inside the signature](https://developer.apple.com/documentation/security/code-signing-services)

---

<sub>Part of **HEATDEATH** — an offline BIP-39 / EVM seed generator that proves its
properties instead of claiming them.<br>
Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE), the same terms as the code it documents.<br>
Russian version: [Русский](../ru/BUILD.md). Editing one language version obliges you
to update the other — see [CONTRIBUTING.md](../../CONTRIBUTING.md).</sub>
