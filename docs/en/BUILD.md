# Build and release discipline

There are two deliberately different operations.

`npm run build` is a developer build. It runs `node:test`, all internal known-answer
vectors, invokes the lockfile-installed esbuild **0.28.2** directly, bundles from a
relative path, and self-tests the standalone bundle. It neither builds a SEA nor
changes release provenance or signatures.

`npm run build:release` is fail-closed. It requires:

- a clean worktree;
- the annotated tag `v2.1.0` pointing at `HEAD`;
- Node **v26.7.0** on **darwin/arm64**;
- package version 2.1.0 and local esbuild 0.28.2.

It creates the bundle, the darwin/arm64 SEA, the deterministic
`heatdeath-v2.1.0-source.tar.gz` source archive (Git archive compressed by the
pinned Node/zlib build with a normalized RFC 1952 OS byte),
`SOURCE-PROVENANCE.json`, and a manifest covering those files plus
the build recipe and `heatdeath-v2.1.0.spdx.json` SPDX SBOM. Provenance records
the tag, commit, lockfile, source archive and SBOM hashes, Node version and binary
hash, npm 11.19.0 (bundled with Node v26.7.0), esbuild version, platform, and architecture.

The release command does **not** sign. Each identity is used explicitly:

```sh
npm run sign-release -- --scheme=ed25519 --key=/absolute/external/ed25519.pem
npm run sign-release -- --scheme=ml-dsa-87 --key=/absolute/external/ml-dsa.pem
npm run sign-release -- --scheme=slh-dsa-sha2-128s --key=/absolute/external/slh-dsa.pem
```

The key must be outside the repository, must not be a symlink, and must have mode
0600 or stricter. Its derived public-key fingerprint must match the already tracked
release identity. A missing key is a hard failure; signing never generates or
rotates one. New identities are created only by the separately named
`init-signing-key` command and must be distributed through an independent channel.

The SEA has `execArgvExtension: "none"` and grants only `/dev/urandom` read access.
The six denial probes validate that trusted code is running with least privilege.
Node's Permission Model is explicitly a capability guard, not a sandbox against
malicious code. Code trust comes from review, reproducibility, provenance, and
independently pinned signatures.

Actual publication remains a human release step after independent review. Never
create a release tag from uncommitted code and never publish private keys.
The complete candidate, offline-signing, draft-verification and immutable-release
sequence is in [RELEASE.md](RELEASE.md).
