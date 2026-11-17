# Build and release discipline

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/BUILD.md)

`npm run build` is a developer build. It runs tests and known-answer vectors,
bundles with the pinned esbuild, and self-tests `dist/heatdeath.mjs`. It does not
create native binaries, provenance or signatures.

Reproduce historical releases from their own tags and original toolchain pins.
Install the pinned npm explicitly: Node bundles a different npm version.

```sh
npm install --global --ignore-scripts npm@12.2.2
```

`npm run build:release` creates one native part of release `v2.4.0`. It requires:

- a clean worktree and annotated `v2.4.0` tag pointing at `HEAD`;
- Node v26.13.1, npm 12.2.2 and esbuild 0.28.2;
- either darwin/arm64 or linux/x64.

Each platform produces the same bundle, deterministic
`heatdeath-v2.4.0-source.tar.gz`, SPDX `heatdeath-v2.4.0.spdx.json` and recipe,
plus its own SEA and provenance:

- `heatdeath-darwin-arm64` and `SOURCE-PROVENANCE-darwin-arm64.json`;
- `heatdeath-linux-x64` and `SOURCE-PROVENANCE-linux-x64.json`.

CI compares the common bytes, combines both native parts, and creates the final
manifest:

```sh
node build/finalize-release.mjs candidate
```

The common SPDX document removes only optional native helper packages selected by
the host (for example `@esbuild/darwin-arm64` versus `@esbuild/linux-x64`) and
their relationships. The logical `esbuild` package remains. The complete lockfile
hash and each platform's provenance retain the builder evidence while keeping the
product SBOM byte-identical across platforms.

Only that complete manifest is signed offline. Each provenance record pins the
tag, commit, source and SBOM hashes, lockfile, Node binary, npm, esbuild, native
artifact hash, platform and architecture.

The SEA embeds the exact Node runtime, has `execArgvExtension: "none"`, and grants
only `/dev/urandom` read access. It remains a convenience artifact; the readable
cross-platform `.mjs` bundle is the primary audit target.

---

<sub>Part of **HEATDEATH**. Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE). Russian version: [Русский](../ru/BUILD.md).</sub>
