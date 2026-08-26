# Comparison with open-source projects

> An honest comparison against open-source seed generators — including the section
> naming who beats us, and on which axis.

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/COMPARISON.md) · [📖 Glossary](GLOSSARY.md)

---

**Contents**

- [Software generators: we win every column here](#software-generators-we-win-every-column-here)
- [Hardware projects: here we lose](#hardware-projects-here-we-lose)
- [The incidents that make all of this matter](#the-incidents-that-make-all-of-this-matter)
- [Cross-checking against third-party tools](#cross-checking-against-third-party-tools)
- [Who should use what](#who-should-use-what)

---

Metadata was collected through `api.github.com` on 2026-08-25. The date is the
`pushed_at` field (last push to the repository), a good but not exact substitute for
the date of the last commit to the main branch.

**Caveats that must stay in this document.** Some of this was taken from search
summaries rather than from primary sources, and is marked **[unconfirmed]**. In
particular: dice support in iancoleman/bip39 is widely known from the live tool, but
the page's JavaScript was not read, so the row is marked. A document where the
unverified turns into the confident is the place where people lose money.

---

## Software generators: we win every column here

| | Us | iancoleman/bip39 | cast wallet | bitcoinjs/bip39 | python-mnemonic | bip_utils | python-slip39 |
|---|---|---|---|---|---|---|---|
| Stars | — | 4,298 | 10,573 | 1,179 | 953 | 383 | 86 |
| Last push | — | 2024-04 | 2026-08 | 2026-01 | 2024-08 | 2026-08 | 2026-01 |
| Vectors **at runtime, before any secret** | **yes** | no | no | no | no | no | no |
| Second independent implementation | **yes** | no | no | no | no | no | no |
| Wordlist SHA-256 check | **yes** | no | no | no | no | no | no |
| Trusted-code capability guard | **yes, 6/6** | no | no | no | no | no | no |
| Environment checks (SSH, debugger) | **yes** | no | no | no | no | no | no |
| Entropy health tests | **yes** | no | no | no | no | no | no |
| Dice | **yes, ≥128** | yes [unconf.] | no | no | no | no | no |
| Verify mode with repair hints | **yes** | partial | no | no | no | no | no |
| Entropy round-trip | **yes** | no | no | no | no | no | no |
| SLIP-39 | **yes** | no | no | no | no | no | yes |
| Secrets never in argv | **yes** | n/a | **no** | n/a | n/a | n/a | yes |
| Default word count | **24** | 12/24 | **12** | — | — | — | — |
| Reproducible build | **yes** | no | — | — | — | — | no |

### What exactly we do better, project by project

**[iancoleman/bip39](https://github.com/iancoleman/bip39)** — 4,298 stars, MIT. The
benchmark of the genre and a genuinely good project. But the runtime is a browser:
extensions inject into `file://`, the page is cached, and a heap of JavaScript ends
up in swap. There are no runtime vectors, no cross-check, no sandbox and no
environment checks. No pushes since April 2024, 226 open issues, and a swarm of
clone domains the project cannot control.

> On issue #693, "uneven entropy distribution": this is a false alarm. 9,600 valid
> phrases out of 150,000 is 6.4% against the 6.25% expected from a 4-bit checksum.
> That is a checksum pass rate, not a bias. Do not use it as an argument.

**`cast wallet new-mnemonic`** (Foundry, 10,573 stars) — the closest mainstream EVM
equivalent. It accepts `--entropy` as a **command-line argument**: visible to every
process through `ps` and written into shell history. It defaults to 12 words and one
account, and prints the mnemonic to stdout. Fine for development keys, wrong for
savings.

**[bitcoinjs/bip39](https://github.com/bitcoinjs/bip39),
[scure-bip39](https://github.com/paulmillr/scure-bip39),
[rust-bip39](https://github.com/rust-bitcoin/rust-bip39),
[eth-account](https://github.com/ethereum/eth-account)** — these are libraries, not
tools. They have no entropy policy, no verify mode and no opinion whatsoever about
the environment they run in. Comparing them to us is not quite fair: we use
`@scure/bip39` internally and add everything listed above on top of it.

**[trezor/python-mnemonic](https://github.com/trezor/python-mnemonic)** — the
reference BIP-39 implementation, and the host of the canonical `vectors.json` that
everyone tests against. Its quiet push date reflects a finished specification, not
abandonment. The vectors live in the tests, not in the generation path.

**[python-slip39](https://github.com/pjkundert/python-slip39)** — the closest
functional equivalent for backup: SLIP-39, printable PDF cards, compatibility with
Trezor and Ledger. Where we are better: we provide SLIP-39 **and** keep MetaMask
compatibility (the shares carry BIP-39 entropy), we verify recovery from **every**
admissible subset **before** the shares are shown, and we accept dice. What we lack:
printable PDF cards and BIP-38.

---

## Hardware projects: here we lose

| | SeedSigner | Krux | Coldcard | Passport | Jade |
|---|---|---|---|---|---|
| Stars | 1,242 | 363 | 774 | 88 | 487 |
| Last push | 2026-08 | 2026-08 | 2026-08 | 2026-08 | 2026-08 |
| Radio silicon | **none in hardware** | none | none | none | present |
| RAM wiped on power loss | **yes** | — | — | — | — |
| Reproducible build | yes (since 0.7.0) | yes (CI) | — | yes [unconf.] | yes |
| Formal audit | not claimed | **no, stated openly** | — | — | — |
| Dice | yes | yes (D6, D20 [unconf.]) | **yes, dice-only mode** | — | — |

**This is a categorical loss and no amount of code fixes it.** SeedSigner is a Pi
Zero that physically has no Wi-Fi and no Bluetooth, is stateless, and moves all
input and output through QR codes. Our process lives inside macOS with a network
stack, swap, Spotlight, Time Machine and a hundred daemons. `--permission`
constrains **our** process and nothing else.

**What we nonetheless do better:** our cross-check is **mandatory and
unskippable**. In SeedSigner's case
([docs/dice_verification.md](https://github.com/SeedSigner/seedsigner/blob/main/docs/dice_verification.md))
verification against two third-party web tools is a documented manual procedure that
most people will skip. Their approach is *more independent* in principle; ours is
the one that actually gets performed.

**Coldcard: its dice-only mode is reproducible and we have no equivalent.** That is
a deliberate decision rather than an oversight: we XOR dice with OS entropy, which
protects you if **either** source is broken. A dice-only mode buys reproducibility
at the cost of giving up that insurance — justified for closed firmware that cannot
be read, and redundant where the source is readable.

**[unconfirmed]** The avalanche-noise TRNG in Passport, the dice hashing details in
Krux, and whether any hardware project runs vectors at runtime — all of this comes
from reviews and summaries, not from primary sources.

---

## The incidents that make all of this matter

**[documented]** All of these are real losses caused by predictable generation:

| Incident | What broke | Cost |
|---|---|---|
| **Profanity** (2022-09) | Vanity address generator, 32-bit CPRNG seed | ~$160M (Wintermute) |
| **Milk Sad** (CVE-2023-39910) | `bx seed`: Mersenne Twister from 32 bits of system time | hundreds of victims |
| **Trust Wallet extension** (2023) | ~32 bits of entropy | ~$30M at risk |
| **Coldcard** | `rng_get()` resolved to a software PRNG instead of the TRNG: ~40 bits on Mk2/Mk3 (firmware 4.0.1–4.1.9), ~72 on Mk4/Mk5/Q. **A firmware update does not repair an already-created seed** | the [vendor](https://blog.coinkite.com/entropy-technical-backgrounder/) names no figure |
| **Fake Electrum builds** | Clone domains, ads outranking the real site, fake "updates" | ~$24.6M since 2018 |

Coldcard is the most instructive. Closed firmware from a respected vendor, and the
substitution lived for years **precisely because nobody could look inside**. Those
unaffected were the ones who used ≥50 of their own dice rolls or a strong
passphrase.

**The conclusion that concerns us directly: our principal defences would not have
detected that bug.** The vectors exercise the *derivation* path, and what broke was
the *entropy* path. The health tests would not have helped either: the output of a
weak PRNG passes monobit and adaptive proportion without trouble. Neither would the
pairwise-distinctness check between sources — a weak PRNG returns different bytes on
every call. Only dice would have saved you.

The Electrum case is why we sign releases with three schemes and publish a
reproduction recipe: a well-known tool attracts counterfeit builds.

---

## Cross-checking against third-party tools

Our cross-check was written by one author, in one language, in one process. It will
not catch a shared misreading of the specification. Only foreign code closes that
gap:

1. Generate a phrase with our tool and write the addresses down.
2. **On a separate offline machine**, open
   [bip39-standalone.html](https://github.com/iancoleman/bip39/releases) by Ian
   Coleman. Enter the phrase, select the ETH coin and the path `m/44'/60'/0'/0`. The
   addresses must match.
3. Or import into a hardware wallet and compare there.
4. Delete the phrase from the second tool and close it.

SeedSigner recommends the same procedure to its users, for the same reason: a
divergence between implementations is only caught by comparing against someone
else's.

**Never enter a real phrase on an online site.** Not on any of them.

---

## Who should use what

**Large amounts.** Generate on dedicated hardware — a Coldcard in dice-only mode
(~99 rolls, verified through `rolls.py` under Tails), a SeedSigner with dice, or a
Passport. Run our tool offline in `--verify` mode as an independent second
implementation confirming the EVM addresses.

**Backup, regardless of how you generated.** SLIP-39 through `npm run split`, or
[python-slip39](https://github.com/pjkundert/python-slip39) if you want printable
cards. Losing the paper is more likely than any attack.

**Our niche.** Development and test keys, and the case where you want a paper seed
produced by ~4,350 lines of code you can read end to end, on a machine you
physically control, with no browser and without buying hardware. Within that niche it
meets the listed requirements more completely than the other projects reviewed.

---

## References and further reading

- [BIP-39 — mnemonic codes for deterministic wallets](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [SLIP-39 — Shamir secret sharing over mnemonic shares](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
- [Krux — open firmware for hardware signing on inexpensive boards](https://github.com/selfcustody/krux)
- [Coldcard — hardware wallet firmware, sources published](https://github.com/Coldcard/firmware)
- [Blockstream Jade — open-source hardware wallet](https://github.com/Blockstream/Jade)
- [Foundation Passport — open-source hardware wallet](https://github.com/Foundation-Devices/passport2)
- [Foundry — `cast wallet new-mnemonic`, a generator inside the toolchain](https://github.com/foundry-rs/foundry)
- [bip_utils — a widely used Python BIP-39/32/44 library](https://github.com/ebellocchia/bip_utils)
- [Milk Sad (CVE-2023-39910) — analysis of the weak PRNG in libbitcoin-explorer](https://milksad.info/)
- [Profanity — the original 1inch disclosure: a 32-bit seed and a ~$160M loss](https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool/)

---

<sub>Part of **HEATDEATH** — an offline BIP-39 / EVM seed generator that proves its
properties instead of claiming them.<br>
Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE), the same terms as the code it documents.<br>
Russian version: [Русский](../ru/COMPARISON.md). Editing one language version obliges
you to update the other — see [CONTRIBUTING.md](../../CONTRIBUTING.md).</sub>
