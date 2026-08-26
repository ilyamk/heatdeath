# Glossary

> Every specialist term used in the HEATDEATH documentation, with a pointer to the
> document where it is explained in depth.

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/GLOSSARY.md)

---

**Contents**

- [Standards and specifications](#standards-and-specifications)
- [Cryptographic primitives](#cryptographic-primitives)
- [Keys, seeds and addresses](#keys-seeds-and-addresses)
- [Randomness and how it is checked](#randomness-and-how-it-is-checked)
- [Attacks and limits](#attacks-and-limits)
- [SLIP-39 and threshold backup](#slip-39-and-threshold-backup)
- [Runtime and build](#runtime-and-build)
- [Isolation and the trusted path](#isolation-and-the-trusted-path)
- [Terms from the MetaMask analysis](#terms-from-the-metamask-analysis)

---

## Standards and specifications

| Term | Meaning | More detail |
|---|---|---|
| **BIP-32** | Hierarchical deterministic wallets: a tree of keys derived from one seed. [Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) | [ENTROPY.md](ENTROPY.md) |
| **BIP-39** | The mnemonic phrase standard: entropy → words → seed via PBKDF2. [Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) | [ENTROPY.md](ENTROPY.md) |
| **BIP-44** | The structure of derivation paths `m/44'/60'/0'/0/i`. [Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) | [ENTROPY.md](ENTROPY.md) |
| **BIP-38** | Password encryption of a private key. Not implemented here. [Specification](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki) | [COMPARISON.md](COMPARISON.md) |
| **SLIP-39** | Shamir secret sharing over mnemonic shares with a 1024-word list. [Specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **EIP-55** | The EVM address checksum encoded in letter case. [Specification](https://eips.ethereum.org/EIPS/eip-55) | [VERIFY.md](VERIFY.md) |
| **ERC-4337** | Account abstraction in Ethereum; the theoretical route to post-quantum transaction signatures. [Specification](https://eips.ethereum.org/EIPS/eip-4337) | [ENTROPY.md](ENTROPY.md) |
| **FIPS 204 / FIPS 205** | NIST standards for post-quantum signatures: ML-DSA and SLH-DSA respectively | [VERIFY.md](VERIFY.md) |
| **NIST SP 800-90B** | The methodology for assessing entropy sources and health tests | [ENTROPY.md](ENTROPY.md) |
| **ISO/IEC 18004** | The QR code standard the built-in encoder was checked against | [VERIFY.md](VERIFY.md) |
| **RFC 8018** | The definition of PBKDF2 (PKCS #5 v2.1) | [ENTROPY.md](ENTROPY.md) |
| **RFC 8032** | The definition of EdDSA, including Ed25519 | [VERIFY.md](VERIFY.md) |

## Cryptographic primitives

| Term | Meaning | More detail |
|---|---|---|
| **PBKDF2** | A key derivation function that stretches by iteration count. In BIP-39 it is 2048 iterations of HMAC-SHA512, which is **not** a defence | [ENTROPY.md](ENTROPY.md) |
| **HMAC** | A message authentication code built on a hash function | [ENTROPY.md](ENTROPY.md) |
| **SHA-256 / SHA-512** | Hash functions of the SHA-2 family (FIPS 180-4) | [VERIFY.md](VERIFY.md) |
| **AES-GCM** | A block cipher in an authenticated mode; used by the MetaMask vault | [METAMASK.md](METAMASK.md) |
| **secp256k1** | The elliptic curve of Bitcoin and Ethereum. Practical security level: 128 bits | [ENTROPY.md](ENTROPY.md) |
| **keccak256** | The hash function producing an EVM address (its last 20 bytes) | [VERIFY.md](VERIFY.md) |
| **Ed25519** | A classical signature on an Edwards curve. Broken by Shor's algorithm | [VERIFY.md](VERIFY.md) |
| **ML-DSA** | Post-quantum signature on module lattices (FIPS 204), formerly CRYSTALS-Dilithium | [ENTROPY.md](ENTROPY.md) |
| **SLH-DSA** | Post-quantum signature resting on hash functions only (FIPS 205), formerly SPHINCS+. The most conservative assumption | [ENTROPY.md](ENTROPY.md) |
| **GF(256)** | The finite field of 256 elements, the arithmetic of SLIP-39. The generator is multiplication by `x+1`, **not** doubling. Getting this wrong was a real bug here, caught by the vectors | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Feistel network** | A reversible encryption construction; in SLIP-39 it is 4 rounds over PBKDF2 | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **RS1024** | The checksum of a SLIP-39 mnemonic share | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Shamir's scheme** | Splitting a secret into `n` shares with threshold `k`: any `k` restore it, and `k−1` reveal **nothing** — information-theoretically, not merely computationally. [Original paper](https://dl.acm.org/doi/10.1145/359168.359176) | [THREAT-MODEL.md](THREAT-MODEL.md) |

## Keys, seeds and addresses

| Term | Meaning | More detail |
|---|---|---|
| **Entropy** | A measure of unpredictability. Here 256 bits, the BIP-39 maximum, yielding 24 words | [ENTROPY.md](ENTROPY.md) |
| **Seed** | The 64 bytes output by PBKDF2, the root of the entire BIP-32 key tree | [ENTROPY.md](ENTROPY.md) |
| **Mnemonic** | 24 words encoding 256 bits of entropy plus an 8-bit checksum | [ENTROPY.md](ENTROPY.md) |
| **Passphrase (the "25th word")** | Arbitrary text that enters the **salt** of PBKDF2. Any string yields a valid wallet — there is no such thing as an "incorrect passphrase" | [ENTROPY.md](ENTROPY.md) |
| **Master fingerprint** | Four bytes identifying the root key. Used for cross-checking; it does **not** depend on the derivation scheme | [VERIFY.md](VERIFY.md) |
| **CKDpriv** | The child private key derivation function in BIP-32 | [ENTROPY.md](ENTROPY.md) |
| **Hardened derivation** | A branch of the tree where the index is ≥ 2³¹. Leaking the extended public key does **not** expose the children | [ENTROPY.md](ENTROPY.md) |
| **xpub** | An extended public key. Under a non-hardened scheme, leaking it exposes the public keys of every address in the branch | [ENTROPY.md](ENTROPY.md) |
| **ECDLP** | The elliptic curve discrete logarithm problem — what the key's security rests on | [ENTROPY.md](ENTROPY.md) |
| **`ecrecover`** | The EVM operation that recovers a public key from a signature. This is why an address loses its hash barrier after its first outgoing transaction | [ENTROPY.md](ENTROPY.md) |

## Randomness and how it is checked

| Term | Meaning | More detail |
|---|---|---|
| **CSPRNG** | A cryptographically secure pseudorandom number generator | [ENTROPY.md](ENTROPY.md) |
| **DRBG** | A deterministic random bit generator. `randomBytes` and `webcrypto` lead into the **same** DRBG inside OpenSSL | [ENTROPY.md](ENTROPY.md) |
| **TRNG** | A hardware generator driven by a physical noise source | [COMPARISON.md](COMPARISON.md) |
| **PRNG** | A pseudorandom generator with no cryptographic guarantees. Substituting a PRNG for the TRNG is the essence of the Coldcard bug | [COMPARISON.md](COMPARISON.md) |
| **Min-entropy** | The worst-case measure of unpredictability: `−log₂` of the most likely outcome's probability. This, not Shannon entropy, is what matters | [ENTROPY.md](ENTROPY.md) |
| **Health test** | A runtime check of an entropy source. It catches **catastrophic** failure but cannot tell a good CSPRNG from a bad one | [ENTROPY.md](ENTROPY.md) |
| **Monobit** | A test of the balance between zeros and ones; the threshold is a deviation over 5σ | [ENTROPY.md](ENTROPY.md) |
| **Repetition Count** | A stuck-bit test: 5 identical bytes in a row | [ENTROPY.md](ENTROPY.md) |
| **Adaptive Proportion** | A degenerate-distribution test: a value appearing ≥13 times in a window of 512 | [ENTROPY.md](ENTROPY.md) |
| **χ² (chi-squared)** | A goodness-of-fit statistic. For dice, df = 5; a warning is printed at p < 0.001 | [ENTROPY.md](ENTROPY.md) |
| **Pairwise probe distinctness** | Comparing two OS-path probes. A match proves catastrophic duplicate/stubbed output; a mismatch proves neither independence nor absence of cloning | [ENTROPY.md](ENTROPY.md) |
| **Diceware** | A method of generating a passphrase from dice rolls; one word ≈ 12.9 bits | [ENTROPY.md](ENTROPY.md) |

## Attacks and limits

| Term | Meaning | More detail |
|---|---|---|
| **Landauer's limit** | The minimum energy for one irreversible bit switch: `kT·ln2` ≈ 2.87×10⁻²¹ J at 300 K. Counting to 2²⁵⁶ costs ~3.3×10⁵⁶ J — about two billion Suns. **The argument does not apply at the 2¹²⁸ level** | [ENTROPY.md](ENTROPY.md) |
| **Grover's algorithm** | Quantum search with a quadratic speed-up: 2²⁵⁶ → 2¹²⁸. Parallelises poorly | [ENTROPY.md](ENTROPY.md) |
| **Shor's algorithm** | A quantum algorithm that solves ECDLP **completely** in polynomial time. Mnemonic length does not help here | [ENTROPY.md](ENTROPY.md) |
| **Pollard's rho** | The classical attack on ECDLP with √n complexity; the source of secp256k1's 128-bit level | [ENTROPY.md](ENTROPY.md) |
| **Birthday paradox** | Gives 2⁸⁰ for finding *some* pair of addresses. A preimage of **your** address is 2¹⁶⁰ | [ENTROPY.md](ENTROPY.md) |
| **Offline cracking** | Attacking copied ciphertext with no rate limiting. The threat model of the MetaMask vault | [METAMASK.md](METAMASK.md) |
| **hashcat** | A GPU password-cracking tool; the source of the measurements in the strength tables | [METAMASK.md](METAMASK.md) |
| **Rubber-hose attack** | Coercing someone into revealing a secret. Cryptography does not address it | [THREAT-MODEL.md](THREAT-MODEL.md) |

## SLIP-39 and threshold backup

| Term | Meaning | More detail |
|---|---|---|
| **Share** | One mnemonic string from a set. It cannot recover the wallet alone; SLIP-39's 4-byte digest means the literal textbook zero-information claim does not apply (about 224 bits remain for our 256-bit secret) | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Threshold** | The minimum number of shares needed to restore. Our default is 2 of 3 | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Admissible subset** | Any set of shares satisfying the threshold. The tool verifies recovery from **every** such set before printing | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Master secret** | The secret being split. Here it is BIP-39 entropy; Trezor reads it as a BIP-32 seed — hence the incompatibility | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Round-trip** | The "split → combine → matches the original" check. It verifies what it was handed, not what you meant to split | [THREAT-MODEL.md](THREAT-MODEL.md) |

## Runtime and build

| Term | Meaning | More detail |
|---|---|---|
| **Node permission model** | `--permission` and the `--allow-*` flags: network, subprocesses, workers and disk writes denied at the runtime level. [Documentation](https://nodejs.org/api/permissions.html) | [BUILD.md](BUILD.md) |
| **SEA** | Single Executable Application — Node's mechanism for producing one executable file. [Documentation](https://nodejs.org/api/single-executable-applications.html) | [BUILD.md](BUILD.md) |
| **`mainFormat: "module"`** | The SEA key without which an ESM entry point dies with `SyntaxError` | [BUILD.md](BUILD.md) |
| **`execArgvExtension: "none"`** | The SEA key that stops `NODE_OPTIONS` from **extending** the baked-in flags. Under the `"env"` default the sandbox is removed by an environment variable | [BUILD.md](BUILD.md) |
| **Reproducible build** | The property that the same sources yield a byte-identical artifact. [Definition](https://reproducible-builds.org/docs/definition/) | [VERIFY.md](VERIFY.md) |
| **Lockfile / integrity** | A file pinning exact dependency versions and hashes; the basis of a verifiable install | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **postinstall** | A script npm runs after installing a package. Denied by the `--ignore-scripts` flag | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **`codesign`** | The macOS code signing utility. An ad-hoc signature embeds the **filename** as an identifier, so renaming changes the hash | [BUILD.md](BUILD.md) |
| **Gatekeeper / quarantine** | The macOS mechanism that silently kills a downloaded unsigned binary: exit 137, empty output | [VERIFY.md](VERIFY.md) |
| **Notarisation** | Apple's binary review at $99/year, bound to a legal entity. Not used: it contradicts the pseudonymity of the signatures | [VERIFY.md](VERIFY.md) |

## Isolation and the trusted path

| Term | Meaning | More detail |
|---|---|---|
| **Namespace / cgroup** | Linux kernel mechanisms that isolate containers **from each other**, but not from the host | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **`vmmap`** | The macOS utility that maps a process's memory. Works **without root** for processes under your UID | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **`mlock`** | The system call that pins pages in RAM. Node cannot do it, so the seed may reach swap | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Swap** | Paging memory out to disk. Encrypted under FileVault — a mitigation, not a guarantee | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Confidential computing** | The class of technologies that treat the hypervisor as hostile | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **AMD SEV-SNP** | Guest memory encrypted with keys the hypervisor does not hold, plus protection against page substitution | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Intel TDX** | Removing the hypervisor from the trusted computing base | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Secure Enclave** | Apple's isolated coprocessor. No API is provided for executing arbitrary code | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Trusted path problem** | Even a perfect enclave must **show** you 24 words through the host's framebuffer. That is the leak point | [THREAT-MODEL.md](THREAT-MODEL.md) |

## Terms from the MetaMask analysis

| Term | Meaning | More detail |
|---|---|---|
| **Vault** | The encrypted blob holding the mnemonic on disk. Its key is derived from the password and salt **alone** | [METAMASK.md](METAMASK.md) |
| **TOPRF** | Threshold oblivious pseudorandom function; the basis of the social login scheme. Not audited by us | [METAMASK.md](METAMASK.md) |
| **CSP** | Content Security Policy — the policy preventing the extension from executing remote scripts | [METAMASK.md](METAMASK.md) |
| **LevelDB / IndexedDB** | The two places the vault ciphertext lives. Clearing one does not remove the other | [METAMASK.md](METAMASK.md) |
| **Cure53** | The audit firm that reviewed `@scure/bip39` in January 2022 | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **OWASP** | The organisation whose 2023 recommendation explains the choice of 600,000 PBKDF2 iterations | [METAMASK.md](METAMASK.md) |
| **Instant Replay** | The iTerm2 feature that records session contents to disk even without an explicit save | [THREAT-MODEL.md](THREAT-MODEL.md) |
| **Accessibility API** | The macOS interface that lets a process read keystrokes and the contents of other windows | [THREAT-MODEL.md](THREAT-MODEL.md) |

---

<sub>Part of **HEATDEATH** — an offline BIP-39 / EVM seed generator that proves its
properties instead of claiming them.<br>
Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE), the same terms as the code it documents.<br>
Russian version: [Русский](../ru/GLOSSARY.md). Editing one language version obliges
you to update the other — see [CONTRIBUTING.md](../../CONTRIBUTING.md).</sub>
