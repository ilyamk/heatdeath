# Making sure you run what you think you run

> How to confirm the code in front of you is the code that executes — from release
> signatures to reproducing the build yourself.

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/VERIFY.md) · [📖 Glossary](GLOSSARY.md)

---

**Contents**

- [The order of trust](#the-order-of-trust)
- [Verifying a release](#verifying-a-release)
- [Reproducing the build](#reproducing-the-build)
- [Why `--prove-sandbox` proves nothing inside a binary](#why---prove-sandbox-proves-nothing-inside-a-binary)
- [Verifying the wallet itself](#verifying-the-wallet-itself)
- [Cross-checking with someone else's code](#cross-checking-with-someone-elses-code)
- [macOS: the binary dies silently](#macos-the-binary-dies-silently)
- [How the QR encoder was verified](#how-the-qr-encoder-was-verified)

---

## The order of trust

1. **Readable source** — `generate.mjs` and `slip39.mjs`. Maximum trust: you read
   what executes.
2. **The bundle** `dist/heatdeath.mjs` — 276 KB, no dependencies, human-readable,
   byte-for-byte reproducible.
3. **The binary** `dist/heatdeath` — 144 MB. Convenience only. Treat it as
   unverified until you have reproduced its SHA-256 yourself.

The further down this list you go, the more you are trusting somebody else.

---

## Verifying a release

```sh
( cd dist && shasum -a 256 -c SHA256SUMS --ignore-missing )
npm run verify-release
```

Expected **after downloading the complete release**:

```
==> file hashes against dist/SHA256SUMS
  ok    heatdeath.mjs
  ok    heatdeath

==> manifest signatures
  ok    ed25519
  ok    ml-dsa-87
  ok    slh-dsa-sha2-128s
```

Expected **in a fresh clone of the repository**, where the 144 MB binary is absent —
it is attached to the release rather than committed:

```
==> file hashes against dist/SHA256SUMS
  ok    heatdeath.mjs
  --    heatdeath not present - not checked

1 artifact(s) verified, 1 not present.
```

This is not a failure, and the exit code stays `0`. An **absent** artifact and one
whose hash **does not match** are fundamentally different events: the first is
expected, the second means the bytes changed under you. That is why they are
reported differently.

Two cases in which the check does fail, with exit code `1`:

| Situation | Output |
|---|---|
| Hash mismatch | `FAIL heatdeath.mjs - expected …, got …` |
| **No** artifact from the manifest is present | `NOTHING WAS VERIFIED` |

The second case exists so that a run which verified nothing cannot report success.
The `shasum --ignore-missing` flag has no such protection: on an empty `dist/` it
returns `0`. So read the `heatdeath.mjs: OK` line, not merely the exit code.

### What this proves and what it does not

A green result means: the files match the manifest, and the manifest was signed by
whoever holds the keys in `dist/*.pub.pem`.

**If the public keys arrived in the same download as the artifact, that is
circular.** An attacker who replaced the binary would simply have signed it with
their own keys and shipped those too.

A signature only starts to mean something once you have compared the **key
fingerprints against a source other than the download itself**. `npm run
verify-release` prints those fingerprints for exactly this purpose. Comparing them
is your job, and no script can do it for you.

---

## Reproducing the build

The strongest mechanism available: not "trust the signature" but "build it yourself
and compare".

```sh
rm -rf node_modules && npm ci --ignore-scripts
./build/build.sh
( cd dist && shasum -a 256 -c SHA256SUMS )
```

Exact versions and details are in `dist/BUILD-RECIPE.txt`.

- **The `.mjs` bundle reproduces on any machine** with the same esbuild version.
  It contains neither absolute paths nor timestamps.
- **The binary reproduces only against the same Node build** (v26.5.0,
  darwin/arm64), because it embeds the entire runtime.

Two subtleties, both established by measurement rather than assumption:

- esbuild must run **from the repository root with a relative path** to the entry
  file. An absolute path leaks into the bundle as comments and makes the hash
  machine-specific.
- The binary's output filename is fixed: ad-hoc `codesign` embeds the name as the
  signing identifier, so renaming changes the bytes.

If the hashes do not match, **do not run the artifact**. Read the source instead:
the bundle is designated the primary artifact precisely because auditing it requires
no build at all.

---

## Why `--prove-sandbox` proves nothing inside a binary

```sh
npm run prove-sandbox             # from source - this you can believe
./dist/heatdeath --prove-sandbox  # from the binary - not proof by itself
```

The binary contains the source **as plain text**: `strings` extracts it verbatim,
sandbox flags included. A patched build will print the same `6/6 denied` while doing
whatever it likes. Self-attestation by an artifact the attacker controls is
circular.

You may believe this output only if you ran it from source you have read, or from a
build you reproduced yourself.

---

## Verifying the wallet itself

Separate from file integrity: confirming that the phrase you wrote down restores
exactly the wallet you expect.

```sh
npm run verify
```

Type the phrase **from paper**, not from the screen. Compare the `master
fingerprint` and the address at **index 1**.

> Index 1, because at `i = 0` the paths of both derivation schemes coincide, and the
> fingerprint does not depend on the scheme at all. Neither distinguishes `metamask`
> from `account`, so verifying with the wrong scheme would "succeed" while leaving
> every address from the first one onward incorrect.

## Cross-checking with someone else's code

Our second implementation was written by the same author in the same language. It
catches a swapped dependency, but not a shared misreading of the specification. Only
foreign code gives a fully independent check — the procedure is in
[COMPARISON.md](COMPARISON.md#cross-checking-against-third-party-tools).

---

## macOS: the binary dies silently

A binary downloaded by a browser receives `com.apple.quarantine`, and Gatekeeper
kills it **without a single message** — exit 137, empty stdout and stderr. It looks
exactly like "nothing happens".

```sh
xattr -d com.apple.quarantine ./heatdeath
```

We do not notarise builds: that costs $99/year and binds the release to a legal
entity, which contradicts the pseudonymity of the signatures.

---

## How the QR encoder was verified

`qr.mjs` implements ISO/IEC 18004 (byte mode, ECC levels L and M, versions 1–40). It
is checked by two external oracles, neither of which is our own code:

1. **The OpenCV detector decodes our output** back to the original string. This is
   validity as a phone actually experiences it.
2. **The matrix matches the Python `qrcode` library bit for bit** with the mask
   pinned. Pinning is mandatory: the mask is chosen by penalty score, and two correct
   implementations may legitimately pick different ones, after which they agree on
   no module whatsoever.

---

## References and further reading

- [RFC 8032 — EdDSA, including Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- [FIPS 204 — ML-DSA (CRYSTALS-Dilithium), lattice-based signatures](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [FIPS 205 — SLH-DSA (SPHINCS+), signatures resting on hash functions only](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
- [FIPS 180-4 — the SHA-2 family, including the SHA-256 used in the manifest](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [Reproducible Builds — what "reproducible build" formally means](https://reproducible-builds.org/docs/definition/)
- [Node.js Permission Model — what `--prove-sandbox` demonstrates](https://nodejs.org/api/permissions.html)
- [Apple Gatekeeper — why an unsigned binary dies without a message](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web)
- [ISO/IEC 18004 — the QR code standard the built-in encoder was checked against](https://www.iso.org/standard/62021.html)
- [python-qrcode — the external oracle used to compare the QR matrix](https://github.com/lincolnloop/python-qrcode)
- [OpenCV — the second independent decoder that read our symbols](https://opencv.org/)

---

<sub>Part of **HEATDEATH** — an offline BIP-39 / EVM seed generator that proves its
properties instead of claiming them.<br>
Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE), the same terms as the code it documents.<br>
Russian version: [Русский](../ru/VERIFY.md). Editing one language version obliges you
to update the other — see [CONTRIBUTING.md](../../CONTRIBUTING.md).</sub>
