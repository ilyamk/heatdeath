# Entropy and strength

> Where the entropy comes from, why 256 bits cannot be brute-forced, what a quantum
> computer actually changes, and what a passphrase is for.

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/ENTROPY.md) · [📖 Glossary](GLOSSARY.md)

---

**Contents**

- [1. Entropy sources](#1-entropy-sources)
- [2. Strength of the entropy](#2-strength-of-the-entropy)
- [3. Post-quantum resistance](#3-post-quantum-resistance)
- [4. The BIP-39 passphrase, the "25th word"](#4-the-bip-39-passphrase-the-25th-word)

---

## 1. Entropy sources

### Multi-source entropy with health tests

Two required OS paths plus optional dice. Each is normalised through SHA-256 with a
domain separator and combined with **XOR**.

Why XOR: the result is unpredictable if **at least one** input is unpredictable.
Adding a source physically cannot weaken the result. Replacing a source would make
you hostage to the dice; concatenation with truncation could discard part of the OS
entropy.

**Being honest about independence.** `crypto.randomBytes` uses OpenSSL and the
second path reads `/dev/urandom` directly. They are different software paths, not
proof of independent physical entropy: unequal probes cannot detect a cloned VM or
an attacker-known generator. **Dice are the only source independent of the machine.**

Catastrophic-output tests inspired by SP 800-90B, on a 4 KiB probe from each path:

| Test | Threshold | What it catches |
|---|---|---|
| Repetition Count | 5 identical bytes in a row | stuck bits, a zeroed buffer |
| Adaptive Proportion | a value ≥13 times in a window of 512 | degenerate distribution |
| Monobit | deviation >5σ | a biased source |
| Pairwise probe distinctness | any match at all | **catastrophic duplicate wiring or a stubbed output** |

The last row is the most valuable. Two "independent" sources returning identical
bytes is never a coincidence.

**Being honest about their power:** they catch only **catastrophic** failure. They
cannot distinguish a good CSPRNG from AES-CTR under a key the attacker knows.
Passing is not proof of quality; failing is proof of breakage.

### Dice (`--dice`)

A minimum of 128 d6 rolls = 331 bits ≥ 256. Input is hidden and only the counter is
echoed. A χ² statistic (df = 5) is computed: at p < 0.001 a warning about a possibly
biased die is printed — a warning specifically, because thanks to XOR a bad die
cannot weaken the result.

This is the only defence against a hypothetically compromised OS CSPRNG.

---

## 2. Strength of the entropy

The chain:

```
3 OS sources + dice  → XOR of domain-separated SHA-256 → 256 bits
        ↓ BIP-39                24 words, 2^256 checksum-valid
        ↓ PBKDF2-HMAC-SHA512 x2048   (this is NOT strengthening, see below)
        ↓ BIP-32                secp256k1, 128-bit security level
```

**2048 PBKDF2 iterations are not a defence.** That is microseconds. It is precisely
why brain wallets were drained en masse: a weak KDF input cannot be rescued.
Everything rests on the entropy of the input — the one place that is hardened
hardest here.

**Brute-forcing the mnemonic (2^256).** Landauer's limit at 300 K: `kT·ln2` =
2.87×10⁻²¹ J per bit switch. Simply counting to 2^256: 1.16×10⁷⁷ × 2.87×10⁻²¹ ≈
**3.3×10⁵⁶ J**. The full mass-energy of the Sun is 1.79×10⁴⁷ J. You would need about
**two billion Suns**, annihilated entirely — roughly 3% of the stellar mass of the
Milky Way. This is not "expensive", it is physically forbidden.

**Attacking the key (2^128).** The real security level of secp256k1 is 128 bits
(Pollard's rho, √n, with no gain from memory). Here the argument is
**computational**, not energetic: the entire Bitcoin network (~10²¹ ops/s) would
need 3.4×10³⁸ operations, taking ~10.8 billion years — against a universe 13.8
billion years old. And that is generously biased in the attacker's favour: one rho
operation is an elliptic curve point addition, not SHA-256d, a difference of
10⁴–10⁵.

*The energy argument is deliberately not used for 2^128:* by Landauer that is
~271 TWh, which on the scale of world energy production does not look prohibitive.
The two levels must never be conflated.

**Address collisions.** An EVM address is 160 bits. The birthday paradox gives 2^80
for finding *some* pair. A preimage for **your specific** address is 2^160. The
difference is fundamental.

**Where this honestly breaks.** Shor's algorithm does not speed up brute force — it
solves ECDLP outright. On EVM the public key is recoverable from the signature of
any outgoing transaction (`ecrecover`), so before the first spend an address is
protected by a 160-bit hash, and after it only by ECDLP. No such computer exists,
nor anything close. That is exactly why public keys are hidden by default here.

**Conclusion: entropy is not the weak link under any reasonable margin. The weak
link is the machine and the human.** Everything listed in the [threat
model](THREAT-MODEL.md) is cheaper than 128 bits.

---

## 3. Post-quantum resistance

The short answer: **a seed generator cannot fix EVM's quantum exposure. That is a
blockchain-level problem.** All that can be done here is three levers, and all three
are already pulled.

### Why phrase length does not decide this

Shor's algorithm does not speed up brute force — it solves the elliptic curve
discrete logarithm problem **completely**, in polynomial time, as soon as the public
key is exposed.

On EVM the public key is recoverable from the signature of **any** outgoing
transaction (`ecrecover`). Therefore:

- while an address has never spent, only a 160-bit hash is public;
- after the first outgoing transaction, the key itself is public, forever.

The length of the mnemonic has no bearing on this. 24 words against 12 buys nothing
here.

### The three levers that do exist

**1. 256 bits of entropy (24 words).** Two different goals must not be conflated.
Recovering the *exact original mnemonic* from a 256-bit space takes about 2¹²⁸
Grover queries. Stealing funds from a known **unspent EVM address** is bounded by
the 160-bit address: a 256-bit mnemonic space contains about 2⁹⁶ colliding keys, so
Grover finds any usable collision in about 2⁸⁰ queries. A 12-word wallet, whose
mnemonic space is only 2¹²⁸, is instead searched as its unique original in about
2⁶⁴ queries. Thus 24 words improve this particular theft bound from ~2⁶⁴ to ~2⁸⁰,
not to ~2¹²⁸. After a public key is exposed, Shor dominates and mnemonic length
does not help.

**2. Public keys are hidden by default.** Printing the public key of an address that
has never spent voluntarily strips its 160-bit hash barrier. Only addresses are
needed to cross-check against a wallet, which is why `--show-public` exists but is
off.

**3. `--scheme=account` is an underrated post-quantum argument.** Under the
`metamask` scheme every address grows from a single extended public key: leaking
that xpub exposes the public keys of **all** addresses, including ones that never
spent, and all of them lose the hash barrier at once. Under the hardened scheme
`m/44'/60'/i'/0/0` no xpub does this.

### The operational rule

**Do not reuse an address after its first outgoing transaction.** Its public key is
exposed forever, and this is the one variable you control. Once you have sent from
an address, treat it as "hot" and keep the remaining balance on a new one.

### What we deliberately do not do

- **Post-quantum transaction signatures.** These would require ERC-4337 with a
  PQ verifier on the contract side. That is outside the scope of a key generator,
  and bolting on something that merely resembles it would be theatre.
- **"Post-quantum seed encryption".** A BIP-39 passphrase on top of our scheme is
  already adequate: Grover cuts a 256-bit symmetric key to 128, which remains out of
  reach.

### Where post-quantum cryptography is genuinely applied

**In release signing.** A signature has to outlive the artifact, and the artifact
lives for years. The `dist/SHA256SUMS` manifest is signed by three schemes resting
on three different hardness assumptions:

| Scheme | Basis | Signature size |
|---|---|---|
| Ed25519 | elliptic curves — broken by Shor | 64 B |
| ML-DSA-87 (FIPS 204) | module lattices, NIST's primary choice | 4,627 B |
| SLH-DSA-SHA2-128s (FIPS 205) | hash functions only — the most conservative assumption | 7,856 B |

All three are generated and verified through `node:crypto` — no new dependencies
were introduced. To check: `npm run verify-release`.

If lattices are one day broken, SLH-DSA remains: it needs nothing but a strong hash
function.

---

## 4. The BIP-39 passphrase, the "25th word"

### How it works

A passphrase is **not a word from the wordlist**. It is arbitrary text that goes
into the **salt** of the key derivation function:

```
seed = PBKDF2-HMAC-SHA512(
         password   = mnemonic,
         salt       = "mnemonic" + passphrase,   <- here
         iterations = 2048, dkLen = 64 )
```

The consequence you must understand before setting one: **any string yields a valid
wallet.** There is no such thing as an "incorrect passphrase" — a typo silently
opens a different, empty wallet. Measured on one and the same phrase:

| passphrase | master fingerprint |
|---|---|
| `""` (empty) | `0xc185b076` |
| `" "` (a space) | `0x0ac72d85` |
| `"dog"` | `0x911c8333` |
| `"Dog"` | `0xe6a3e18f` |
| `"dog "` | `0xf55a7a12` |

Case and whitespace are significant. None of these produces an error.

### What it gives you

**One thing, but an important one: protection if the paper is found.** Without a
passphrase the paper *is* the wallet. With one, whoever finds it gets 24 words and
an empty wallet.

### What it does NOT give you

For a newly generated wallet HEATDEATH accepts only printable ASCII (space through
`~`). This avoids normalization, keyboard-layout and wallet-compatibility traps.
Verification, splitting, combining and existing-wallet export retain well-formed
Unicode recovery support, normalize it with NFKD, and require fingerprint/address
confirmation. This policy does not alter BIP-39 or any existing wallet.

**Entropy.** The seed is already 256 bits, and the strength ceiling is the 128 bits
imposed by the curve. A passphrase does not raise it.

**And it gives almost nothing if it is weak.** BIP-39 stretches it with only 2048
PBKDF2 iterations — microseconds. An attacker holding your 24 words brute-forces the
passphrase cheaply. Measured on this machine:

```
one core, Node:               190 attempts/s
8 cores:                    1,523 attempts/s
GPU rig (estimate, x1000): ~190,000 attempts/s
```

The GPU multiplier is a conservative order-of-magnitude estimate, not a measurement.

Only a documented random selection process can justify a search-space estimate.
Software cannot infer entropy or cracking time from the resulting text: repeated,
patterned and human-chosen strings routinely fool character-class estimators.
The following figures are examples for independently uniform sampling, not scores
the program assigns to entered text:

| Passphrase | Bits | Survives |
|---|---|---|
| one dictionary word | 17 | **0.3 seconds** |
| a word + 2 digits | 23 | **26 seconds** |
| 3 Diceware words | 39 | 14 days |
| 8 random `a-z0-9` | 41 | 86 days |
| **4 Diceware words** | 52 | **285 years** |
| 5 Diceware words | 65 | 2×10⁶ years |
| 12 random ASCII | 79 | 4×10¹⁰ years |

**The threshold of meaningfulness is 4 Diceware words or 12 random characters.**
Anything weaker creates the feeling of protection rather than protection.

### Compatibility: important for MetaMask users

**MetaMask does not support BIP-39 passphrases.** If you set one, importing those 24
words into MetaMask opens an **empty** wallet without the passphrase — and that
looks exactly like theft.
Sources: [MetaMask community
discussion](https://community.metamask.io/t/does-metamask-support-bip39-passphrases-i-e-13th-or-25th-word/4313),
[explanation of the
mechanics](https://blofin.com/en/academy/education/bip39-passphrase-25th-word).

Supported by: Ledger, Trezor, Rabby, MyEtherWallet.

### The practical conclusion

| Situation | Recommendation |
|---|---|
| Spending wallet, to be imported into MetaMask | **Empty passphrase.** Otherwise it simply will not open |
| Savings, paper in a safe | Empty or strong — but never "a weak one just in case" |
| The paper is stored where it could be found | **4+ Diceware words**, stored SEPARATELY from the paper |

And the part worth reading twice: **a passphrase cannot be recovered by anything.**
Forget it and the funds are gone forever, regardless of what is written on the
paper. SLIP-39 shares do not carry it either: they restore the entropy only.

---

## References and further reading

- [BIP-39 — mnemonic, checksum, PBKDF2 and the role of the passphrase](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-32 — hierarchical deterministic wallets, CKDpriv and hardened derivation](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-44 — the structure of `m/44'/60'/0'/0/i` paths](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [SLIP-39 — threshold backup, RS1024, the Feistel network](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
- [RFC 8018 (PKCS #5 v2.1) — the definition of PBKDF2](https://www.rfc-editor.org/rfc/rfc8018)
- [NIST SP 800-90B — entropy source assessment, min-entropy, health tests](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf)
- [Landauer R., "Irreversibility and Heat Generation in the Computing Process", IBM J. Res. Dev. 5(3), 1961 — the origin of the `kT·ln2` limit](https://ieeexplore.ieee.org/document/5392446)
- [Landauer R., "Information is Physical", Physics Today 44(5), 23 (1991)](https://physicstoday.scitation.org/doi/10.1063/1.881299)
- [Grover L., "A fast quantum mechanical algorithm for database search", 1996 — the quadratic search speed-up](https://arxiv.org/abs/quant-ph/9605043)
- [Shor P., "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms", 1995 — why ECDLP falls entirely](https://arxiv.org/abs/quant-ph/9508027)
- [FIPS 204 — ML-DSA, lattice-based post-quantum signatures](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [FIPS 205 — SLH-DSA, signatures resting on hash functions only](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)

---

<sub>Part of **HEATDEATH** — an offline BIP-39 / EVM seed generator that proves its
properties instead of claiming them.<br>
Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE), the same terms as the code it documents.<br>
Russian version: [Русский](../ru/ENTROPY.md). Editing one language version obliges
you to update the other — see [CONTRIBUTING.md](../../CONTRIBUTING.md).</sub>
