# Release ceremony

Releases deliberately separate an untrusted online builder from offline signing.
GitHub never receives any production signing key.

1. Merge only after all required CI, dependency, security and reproducibility
   checks pass.
2. Create a signed annotated tag matching `package.json`, for example `v2.1.0`.
3. The `Build release candidate` workflow builds the exact darwin/arm64 bundle,
   SEA, `heatdeath-v2.1.0-source.tar.gz`, `heatdeath-v2.1.0.spdx.json`, provenance,
   recipe and manifest. It creates GitHub attestations and uploads an **unsigned**
   seven-day candidate.
4. Download the candidate onto the controlled release machine and independently
   reproduce it with Node v26.7.0 and its bundled npm 11.19.0.
5. Sign `SHA256SUMS` once with each external key:

```sh
npm run sign-release -- --scheme=ed25519 --key=/absolute/external/ed25519.pem
npm run sign-release -- --scheme=ml-dsa-87 --key=/absolute/external/ml-dsa.pem
npm run sign-release -- --scheme=slh-dsa-sha2-128s --key=/absolute/external/slh-dsa.pem
```

6. Create a draft GitHub Release and attach exactly the allow-listed files. Do
   not publish it yet.
7. Run `Verify release assets` manually against the draft tag. It downloads the
   assets again, checks all signatures and hashes, rebuilds independently on a
   clean macOS arm64 runner, compares every byte, validates `codesign`, executes
   the self-test and proves the capability guard.
8. Publish only after that workflow is green. Immutable Releases must be enabled;
   publication then locks the tag and assets. The published event repeats the
   verification.

Never upload private keys, never sign in Actions, never publish first and verify
later, and never reuse a release tag.
