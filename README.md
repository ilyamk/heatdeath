<div align="center">

# ☄️ HEATDEATH

**A verifiable offline ceremony for Safe cold/recovery owners and EVM backups.**

Critical generation and recovery properties are independently testable commands,
not marketing promises.

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Runtime deps](https://img.shields.io/badge/runtime%20deps-0-brightgreen)](NOTICE.md)
[![Guard](https://img.shields.io/badge/capability%20guard-6%2F6%20denied-brightgreen)](#-what-makes-this-different)
[![Self-test](https://img.shields.io/badge/self--test-22%20groups-brightgreen)](#-what-makes-this-different)
[![Build](https://img.shields.io/badge/build-reproducible-brightgreen)](docs/en/VERIFY.md)
[![Signatures](https://img.shields.io/badge/signed-Ed25519%20%2B%20ML--DSA%20%2B%20SLH--DSA-blueviolet)](#-verify-before-you-trust)
[![CI](https://github.com/ilyamk/heatdeath/actions/workflows/ci.yml/badge.svg)](https://github.com/ilyamk/heatdeath/actions/workflows/ci.yml)
[![Security analysis](https://github.com/ilyamk/heatdeath/actions/workflows/security-analysis.yml/badge.svg)](https://github.com/ilyamk/heatdeath/actions/workflows/security-analysis.yml)
[![Reproducibility](https://github.com/ilyamk/heatdeath/actions/workflows/reproducible-build.yml/badge.svg)](https://github.com/ilyamk/heatdeath/actions/workflows/reproducible-build.yml)

[Quick start](#-quick-start) ·
[Safe owner ceremony](docs/en/SAFE-OWNER.md) ·
[Why this exists](#-the-problem) ·
[What it does not do](#-where-this-loses) ·
[Full docs](README.en.md) ·
[Русская версия](README.ru.md)

<br>

<img src="img/heatdeath_banner.png" alt="HEATDEATH — an offline BIP-39 / EVM seed generator" width="100%">

</div>

---

> ### “Information is physical.”
> — **Rolf Landauer**, *Physics Today* **44**(5), 23 (1991)

Erasing one bit at 300 K costs *kT*·ln2 = 2.87×10⁻²¹ J. **Counting** to 2²⁵⁶ — merely
counting, computing nothing — costs 3.3×10⁵⁶ J: about **two billion Suns, annihilated**
whole. That is the floor under a 24-word phrase. Not a promise, not a company's word,
not a security review. Thermodynamics. The name is the argument.

*This is the classical bound and only that. Grover's algorithm attacks a different
problem, and the energy argument does not carry there —* [`docs/en/ENTROPY.md`](docs/en/ENTROPY.md)
*works through both and states where each one stops.*

---

## 🎯 The problem

A seed phrase is a bearer instrument. Whoever reads it owns the funds — instantly,
irreversibly, with no recovery and no support line.

So the tool that creates one has to be trustworthy. In practice, almost none are,
and the failures are not theoretical:

| Incident | What broke | Cost |
|:--|:--|:--|
| **Profanity** (2022) | 32-bit CPRNG seed | **~$160M** (Wintermute) |
| **Milk Sad** (CVE-2023-39910) | Mersenne Twister from 32 bits of system time | Exploited in the wild |
| **Trust Wallet extension** (2023) | ~32 bits of entropy | **~$30M** at risk |
| **Coldcard** (2026) | `rng_get()` resolved to a software PRNG, not the hardware TRNG | ~40 bits. **A firmware update does not repair an already-created seed** |
| **Fake Electrum builds** | Lookalike domains, ads outranking the real site | **~$24.6M** since 2018 |

Every one of these looked fine from the outside. **The question is not whether a
generator claims to be secure — it is whether you can check.**

---

## ✨ What makes this different

Not features. Checks you can run yourself, right now.

| | Guarantee | Verify it |
|:--:|:--|:--|
| 🧪 | **Known-answer vectors gate the output.** BIP-39, EIP-55, BIP-32 and a wordlist SHA-256 run *before any secret exists*. One mismatch and nothing is printed. | `npm run self-test` → 22 groups |
| ♊ | **Two independent implementations must agree.** BIP-39 encoding, PBKDF2 and BIP-32 CKDpriv are computed twice — via `@scure`, and again on bare `node:crypto`. Disagreement is a refusal. | included in the self-test |
| 🔒 | **Least privilege for trusted code.** Node's Permission Model denies network, DNS, subprocesses, workers and filesystem writes. Source checkouts get repository read access; a verified release bundle gets only `/dev/urandom`. It is a capability guard, not a malicious-code sandbox. **Needs Node 26 LTS:** the network scope arrived in Node 25, and on an older runtime `prove-guard` reports the two network probes as *not enforced* instead of printing a proof it did not earn. | `npm run prove-guard` → `6/6 denied` |
| 🎲 | **Two required OS entropy paths.** OpenSSL `randomBytes` and a direct `/dev/urandom` read are XORed after domain-separated SHA-256 and catastrophic-output tests. Optional physical dice are the only source independent of the machine. Unequal samples do not prove independence. | printed at generation |
| 🚫 | **Refuses to run where secrecy is impossible.** SSH session, attached debugger, redirected stdin or stdout — hard stop, before a secret exists. | try it |
| ✍️ | **Catches the mistake that actually loses money.** The wizard blanks the screen and makes you type the phrase back from paper, comparing word by word. | `npm run wizard` |
| 🧩 | **Threshold backup, verified before it is shown.** SLIP-39 2-of-3, checked against 45 official Trezor vectors and recovered from *every* admissible subset. | `npm run split` |
| 🔁 | **Reproducible and signed.** Two builds produce an identical hash. The manifest carries three signatures on three different hardness assumptions. | `npm run verify-release` |

> These vectors are not decoration. They caught a real bug in this codebase: the
> GF(256) tables were generated by doubling instead of multiplying by `x+1`, so
> `3 × 7` returned `1` instead of `9`. A second implementation written by the same
> author would have repeated the same mistake and agreed with itself.

---

## 🚀 Quick start

> **Read [`docs/en/SAFE-OWNER.md`](docs/en/SAFE-OWNER.md) before creating an owner for a Safe.**
> The steps below are the shape of it, not a substitute for it.

### Safe/DAO: rehearse first

```sh
npm run rehearse:safe-owner   # public fixture; never fund its address
npm run doctor                # readiness report; creates no secret
npm run safe-owner            # one cold/recovery owner
```

This profile creates one owner only. Never derive several Safe owners from one
phrase. It does not deploy a Safe or sign transactions, and importing the phrase
into an online wallet ends its cold status.

### 1 · Get it and check it — while still online

Use **Node 26 LTS** (`.node-version`). Secret-capable commands refuse to start on an
older Node because its Permission Model cannot deny network access; the diagnostics
below still run and say so.

```sh
git clone https://github.com/ilyamk/heatdeath.git && cd heatdeath
npm ci --ignore-scripts        # exact lockfile, no install scripts
npm run self-test              # must end: Self-test OK
npm run prove-guard            # must end: 6/6 capability probes denied
```

If either line differs, **stop.** That is the check working.

### 2 · Prepare the machine

The attack is on your scrollback, not on the mathematics.

- 🛜 **Wi-Fi, Ethernet, Bluetooth, AirDrop — off**
- 🖥️ **iTerm2 → Settings → General → Magic → disable Instant Replay**
  *(it writes your session to disk even when you never saved it)*
- 📋 **Quit clipboard managers** — Raycast, Paste, Alfred
- 🚪 Close browsers and messengers; don't run inside `tmux`
- 📄 **Paper and pen in front of you**

### 3 · Generate

```sh
npm run wizard
```

Six guided steps. Roll a handful of dice if you have them — 128 rolls is about
22 throws with six dice — or answer `no` and get 256 bits from the OS.
Both give a secure wallet; dice cover the one case where the OS RNG is the thing
that is broken.

### 4 · Prove your paper is right

The wizard clears the screen and asks you to type the phrase back **from the paper**:

```
MISMATCH at word 5.
Your paper is wrong; the generated phrase is correct. Fix the paper:
   5. correct: drive   you typed: abandon
```

A single misread word that still passes the checksum happens about **1 in 256**,
and is discovered years later, when it is a total loss. This step is why the
wizard exists.

### 5 · Survive losing the paper

```sh
npm run split -- --shares=2of3
```

Three shares in three different physical places. Any two restore the wallet.
One default share is insufficient to recover the wallet, but SLIP-39's four-byte
digest leaks up to roughly 32 bits of information. For this tool's 256-bit secret,
about 224 bits of uncertainty remain — computationally infeasible, but not the
literal zero-information property of textbook Shamir sharing.

### 6 · Before you move real money

```sh
npm run verify        # type it from paper again; confirm fingerprint + index 1
```

Import into your wallet, confirm the addresses match, send a small amount,
send it back. **Then** fund it.

---

## 🔍 Verify before you trust

You should not take this page's word for any of it.

```sh
npm run build                                                  # rebuild/test from this checkout
npm run verify-release -- --trusted-keys=/independent/key/dir  # complete downloaded release
npm run self-test:verified                                     # run only after that release verifies
```

The checked-out source and a published release are separate trust domains. Normal
commands run the checkout and visibly warn that it is not release-signature
verified. `:verified` commands never fall back: they require the complete signed
release asset set in `dist/` and refuse stale or partial manifests.

Signed with **Ed25519**, **ML-DSA-87** (FIPS 204, lattices) and
**SLH-DSA-SHA2-128s** (FIPS 205, hash-based — the most conservative assumption
available). If lattices fall, the hash-based signature still stands.

> **A signature proves integrity against *these* keys, not that the keys are the
> ones you meant to trust.** If the public keys arrived in the same download as
> the artifact, that is circular. Pin the fingerprints from somewhere else.

---

## ⚖️ Where this loses

These limitations are structural. They follow from the execution environment and
are not removed by further development.

- **Dedicated air-gapped hardware beats this, categorically.** SeedSigner runs on
  a board with no Wi-Fi or Bluetooth silicon and wipes RAM on power loss. This runs
  inside macOS, with a network stack, swap, Spotlight and a hundred daemons.
  `--permission` constrains *this process* and nothing else on the machine.
- **No third party has audited this tool.** The dependencies are audited;
  ~4,350 lines by one author are not.
- **The cross-check is one author, one language, one process.** It catches a
  swapped dependency. It cannot catch a shared misreading of the specification.
- **Neither the self-test nor the health tests would have caught the Coldcard bug.**
  The vectors exercise *derivation*; that failure was in the *entropy* path.
  Only dice would have helped.
- **No container, VM or enclave fixes any of this.** Software on a machine cannot
  protect a computation from that machine — [the full argument, with measurements](docs/en/THREAT-MODEL.md).

**For amounts whose loss would hurt: generate on a hardware wallet, and use this
offline in `--verify` mode as the independent second implementation.** That is the
role SeedSigner's own documentation assigns to a second tool.

---

## 📚 Documentation

Every document exists in English and in Russian, and the two trees mirror each
other file for file.

| | |
|:--|:--|
| [**QUICKSTART.en.md**](QUICKSTART.en.md) | The full procedure — including Tails, VMs and 1Password |
| [docs/en/SAFE-OWNER.md](docs/en/SAFE-OWNER.md) | Safe/DAO cold-owner rehearsal, ceremony and recovery check |
| [docs/en/COMMERCIAL.md](docs/en/COMMERCIAL.md) | Design partners, support/SLA and commercial embedding |
| [**README.en.md**](README.en.md) | Complete reference, every claim with its measurement |
| [docs/en/THREAT-MODEL.md](docs/en/THREAT-MODEL.md) | What is closed, what cannot be, and why containers do not help |
| [docs/en/ENTROPY.md](docs/en/ENTROPY.md) | Entropy, the strength proof, post-quantum analysis |
| [docs/en/METAMASK.md](docs/en/METAMASK.md) | Where *your* MetaMask is weakest — traced through its source |
| [docs/en/COMPARISON.md](docs/en/COMPARISON.md) | Measured against every comparable open-source project |
| [docs/en/VERIFY.md](docs/en/VERIFY.md) | Checking signatures, reproducing the build |
| [docs/en/BUILD.md](docs/en/BUILD.md) | Building it yourself |
| [docs/en/RELEASE.md](docs/en/RELEASE.md) | Maintainer release and offline-signing ceremony |
| [docs/en/GLOSSARY.md](docs/en/GLOSSARY.md) | Every specialist term, with the document that explains it |

🇷🇺 **Русская документация:** [README.ru.md](README.ru.md) ·
[QUICKSTART.md](QUICKSTART.md) · [docs/ru/](docs/ru/)

---

## 🛠️ All commands

```
npm run wizard           guided end-to-end setup — start here
npm run rehearse:safe-owner  public Safe cold-owner rehearsal
npm run doctor           inspect readiness without creating a secret
npm run safe-owner       create one Safe cold/recovery owner
npm run self-test        every known-answer and negative test
npm run generate         create a wallet directly
npm run verify           re-derive from a phrase you type
npm run split            split into SLIP-39 shares
npm run combine          restore from shares
npm run op-export        stage everything into 1Password (see the caveats)
npm run prove-guard      watch the trusted-code guard deny net / exec / write
npm run build            reproducible build
npm run verify-release   hashes and all three signatures
npm run self-test:verified  require and execute a complete signed release
```

These normal commands execute the current source checkout and print an unsigned-source
warning. Use their `:verified` variants only with a complete downloaded release;
they fail closed rather than trusting the checkout or an incomplete manifest.

Secrets are read with echo disabled and are **never** accepted as command-line
arguments — argv is visible to every process via `ps` and lands in shell history.

---

## 📄 License

**AGPL-3.0-or-later** — Copyright © 2026 ILIA MAKSIMENKA.

Use it, read it, modify it, run it, freely. **Distribute a derivative and you
must publish your source under AGPL-3.0**, with your changes and the copyright
notices intact. Section 13 extends that to network services.

The choice is deliberate: this tool's only real defence is that people can read
it, so it has to stay readable. A closed fork of a seed generator — unauditable,
with no obligation to disclose what changed — is exactly the artifact the rest of
this documentation argues against.

**Commercial licensing and support/SLA** are available if AGPL does not fit or a
team needs a reviewed ceremony. See [commercial use](docs/en/COMMERCIAL.md). Contributions are
accepted under the CLA in [CONTRIBUTING.md](CONTRIBUTING.md).
Third-party notices: [NOTICE.md](NOTICE.md).

---

<div align="center">

**This program comes with absolutely no warranty.**
It generates keys that control money. You carry that risk.

</div>
