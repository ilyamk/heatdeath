# Security policy

## Supported releases

Only the newest immutable GitHub release is supported. Source on `main` may be
ahead of the last signed release and must be treated as developer code.

## Reporting a vulnerability

Do not open a public issue for a defect that could expose a mnemonic, derive a
wrong wallet, weaken entropy, bypass release verification, or compromise signing
material. Use GitHub's
[private vulnerability report](https://github.com/ilyamk/heatdeath/security/advisories/new)
form. If private vulnerability reporting is temporarily unavailable, open
an issue containing no technical details and ask the maintainer to establish a
private channel.

Include:

- the exact commit or release tag;
- the command and minimal non-secret input that reproduces the problem;
- expected and actual results;
- whether funds, signing keys, or release assets may be affected;
- any suggested embargo requirements.

Never send a real recovery phrase or private key. Use the public Hardhat test
mnemonic or deterministic synthetic fixtures.

## Release trust

Production Ed25519, ML-DSA-87, and SLH-DSA private keys are offline and are not
GitHub Actions secrets. A GitHub attestation is additional provenance; it does
not replace the three signatures, independently pinned public-key fingerprints,
or reproducible-build comparison.
