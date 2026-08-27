# Release ceremony

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/RELEASE.md)

Releases separate online native builders from offline signing. GitHub never
receives a production signing key.

1. Merge only after all required CI, security and reproducibility checks pass.
2. Create a signed annotated tag matching `package.json`, for example `v2.2.0`.
3. `Build release candidate` builds independent darwin/arm64 and linux/x64 parts.
4. The combine job requires identical bundle, source archive, SBOM and recipe,
   then creates one manifest covering both binaries and provenance records.
5. Download the seven-day unsigned candidate and reproduce each native part on
   its named platform with Node v26.7.0 and npm 11.19.0.
6. Sign `SHA256SUMS` with each offline identity:

```sh
npm run sign-release -- --scheme=ed25519 --key=/absolute/external/ed25519.pem
npm run sign-release -- --scheme=ml-dsa-87 --key=/absolute/external/ml-dsa.pem
npm run sign-release -- --scheme=slh-dsa-sha2-128s --key=/absolute/external/slh-dsa.pem
```

7. Create a draft GitHub Release with exactly the allow-listed assets.
8. While the release is still a draft, dispatch `Verify release assets` with its
   tag. Read-only jobs on both platforms check signatures, hashes, SBOM and
   provenance, rebuild their native part, compare bytes, execute self-test and
   capability probes, and validate the GitHub attestation.
9. Publish only after both jobs pass. Immutable Releases must already be enabled.

Never upload private keys, sign in Actions, publish before verification, or reuse
a release tag.

---

<sub>Part of **HEATDEATH**. Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE). Russian version: [Русский](../ru/RELEASE.md).</sub>
