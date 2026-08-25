# What actually happens inside your MetaMask

> A source-level analysis of MetaMask: what it gets right, where its weakest point
> is, and what you can fix in under a minute.

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/METAMASK.md) · [📖 Glossary](GLOSSARY.md)

---

**Contents**

- [1. The good news: generation really is local](#1-the-good-news-generation-really-is-local)
- [2. The one thing you must check yourself](#2-the-one-thing-you-must-check-yourself)
- [3. The weakest point: the vault rests on a single password](#3-the-weakest-point-the-vault-rests-on-a-single-password)
- [4. What it costs to crack your password](#4-what-it-costs-to-crack-your-password)
- [5. What to do in one minute](#5-what-to-do-in-one-minute)
- [6. Why stealers aim exactly here](#6-why-stealers-aim-exactly-here)
- [7. Summary](#7-summary)

---

This is a source-level analysis. The goal is to show **exactly where** the extension
is weakest, so that you understand what this tool does and does not give you.

Provenance is marked: **[code]** — file read, line numbers given; **[doc]** — a
linked document or advisory; **[unconfirmed]** — could not be established.

Reference commits: `MetaMask/metamask-extension` @ `1d57eff` (v13.46.0),
`MetaMask/accounts` @ `c6a32ba`.

---

## 1. The good news: generation really is local

**[code]** The full chain from clicking "Create a new wallet":

```
ui/pages/onboarding-flow/onboarding-flow.tsx:278   FirstTimeFlowType.create
  → ui/store/actions.ts:1153                       createNewVaultAndGetSeedPhrase
  → app/scripts/services/legacy-background-api-service.ts:3920   (port, not network)
  → @metamask/keyring-controller KeyringController.ts:1004 → :2992
  → @metamask/eth-hd-keyring hd-keyring.ts:141     generateRandomMnemonic()
  → @metamask/scure-bip39 src/index.ts:36          strength = 128 by default
  → @noble/hashes 1.3.3 src/utils.ts:236           crypto.getRandomValues
```

**12 words / 128 bits, and getting 24 out of the extension is structurally
impossible.** `generateRandomMnemonic()` takes no parameters, and
`createNewVaultAndKeychain` passes only `{ type: hd }`. There is no point anywhere
in the chain through which 256 bits could be requested.

**[code]** `randomBytes` has **no fallback branch**: if Web Crypto is unavailable it
throws rather than degrading to `Math.random`. That exact degradation is what sank
Profanity.

**[code]** The extension's CSP is `script-src 'self' 'wasm-unsafe-eval'`: a remote
script cannot execute, and all cryptography lives inside the CRX.

**[code] Telemetry cannot carry secrets, and this is enforced by an allowlist.**
`maskObject` in `shared/lib/object.utils.ts:50-67` replaces anything not marked
`true` with *a string naming the type*. In the mask, `keyrings: false` means the
string `"object"` is what leaves; `vault` is absent from the mask entirely, so the
string `"string"` leaves. Not even the ciphertext reaches Sentry.

**[doc]** Audit: Least Authority, "MetaMask Extension: Seed Phrase Implementation
Security Audit Report", 2022-07-29 — a dedicated audit of exactly this path. The
findings concerned operational security, not the RNG.

### 12 words is not the weakness

The practical security level of secp256k1 is ~128 bits regardless (Pollard's rho).
Brute-forcing a 12-word phrase costs ~2¹³⁹ operations against ~2¹²⁸ for attacking
the public key — meaning a rational attacker will not touch the phrase at all. The
difference between 12 and 24 words shows up only against Grover, and only on an
address that has never spent. More detail: [ENTROPY.md](ENTROPY.md).

---

## 2. The one thing you must check yourself

**If you signed in with Google or Apple during setup, that was the `socialCreate`
path, and an encrypted copy of your phrase sits on MetaMask's servers.**

**[code]** Generation on that path is byte-for-byte the same and equally local, but
afterwards `createSeedPhraseBackup` → `SeedlessOnboardingController.ts:639` is
called, where the phrase is encrypted with a key derived from your password and
uploaded.

**[unconfirmed]** The path was not traced as far as the HTTP call itself, and the
TOPRF scheme has not been audited by us. The claim "MetaMask cannot decrypt your
copy" is therefore **not confirmed** here — it rests on the properties of TOPRF and
on the strength of your password.

> **A check that needs no source reading:** if you were shown 12 words, made to
> write them down and then quizzed on them, and you did **not** use a social login,
> that was the `create` path and nothing left your machine.

---

## 3. The weakest point: the vault rests on a single password

**[code]** Only ciphertext reaches disk (`vault: { persist: true }`,
`keyrings: { persist: false }`), but the mnemonic itself is inside it.

| Parameter | Value | Source |
|---|---|---|
| KDF | PBKDF2-HMAC-SHA256 via WebCrypto | `browser-passworder/src/index.ts:338-351` |
| Iterations | **600,000** | `metamask-controller.js:1008`, `encryptorFactory(600_000)` |
| Cipher | AES-GCM, 256-bit key | `src/index.ts:42`, `:351` |
| Salt | 32 random bytes, stored in the clear beside it | `src/index.ts:415` |
| IV | 16 fresh random bytes | `src/index.ts:123` |
| Device binding | **entirely absent** | `keyFromPassword(password, salt)` |

**The key is derived from the password and the salt, and from nothing else.** No
Keychain, no Secure Enclave, no TPM, no machine fingerprint, no server-side
component. **The file is portable and crackable offline:** copy it to any other
machine and it decrypts exactly the same.

The best evidence of the threat model MetaMask accepted is its own
[vault-decryptor](https://metamask.github.io/vault-decryptor): a static page on
GitHub Pages that needs nothing but the file and the password. No device binding, no
attestation, no rate limiting.

**[code]** A subtlety that gets misquoted: the library default is **900,000**, and
MetaMask deliberately lowers it to 600,000 (the OWASP 2023 figure). Blog posts
citing 900k are not describing your wallet.

**[code] Old vaults are re-encrypted automatically** the first time you enter your
password, starting with v11.8.0 (2024-01-31). `submitPassword()` checks
`#isNewEncryptionAvailable()`. The cached key lives in `chrome.storage.session` and
does not survive a browser restart, so anyone who has restarted Chrome even once
since January 2024 is already upgraded. To check: if the vault JSON has a
`keyMetadata` field it is 600k; if not, 10k.

**[code]** The ciphertext lives in **two places**: `Local Extension Settings`
(LevelDB) and a mirror in IndexedDB (`persistence-manager.ts`, database
`metamask-storage-service`). Clearing one directory does not remove the other.

**[unconfirmed]** The exact path `~/Library/Application Support/Google/Chrome/
<Profile>/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/` is Chrome
behaviour, not something read out of MetaMask's sources.

---

## 4. What it costs to crack your password

**[doc]** hashcat measurements on **a single RTX 4090**; two independent modes agree
within 5%, so linear scaling is legitimate. The table is for a rack of eight cards,
and the times are **expected** values (half the search space):

| Password | at 10k iterations | at 600k |
|---|---|---|
| Dictionary + rules (33 bits) | 12 minutes | 12 hours |
| Large dictionary (40 bits) | 21 hours | 51 days |
| 8 random `a-z0-9` (41 bits) | 2.4 days | 145 days |
| **4 Diceware words / 10 random chars (52 bits)** | 8.5 years | **510 years** |
| 5 Diceware words (65 bits) | 66,000 years | 4M years |

**600k iterations buy roughly 5.9 bits of password strength.** That is not a
substitute for entropy. The threshold of real security is **5 Diceware words or 12
random characters**.

**[doc]** Stock hashcat **cannot do** 600k: in modes 26600/26610 the value 10,000 is
hardcoded and a rebuild is required. Trivial for a competent attacker, a real
barrier for a commodity one.

---

## 5. What to do in one minute

**[code] Auto-lock is off by default.**
`shared/constants/preferences.ts:13` sets `DEFAULT_AUTO_LOCK_TIME_LIMIT = 0`, and
the controller documents that at zero no timer is created. Out of the box the wallet
stays unlocked for the rest of the browser session.

**Settings → Security & Privacy → Auto-lock timer → 5–15 minutes.** The cheapest
action on this entire list.

**[code]** On lock, references to the keys are dropped (`setLocked()`), but this is
**not zeroisation**: JavaScript strings are immutable, the bytes stay on the heap and
may reach swap.

---

## 6. Why stealers aim exactly here

**[doc]** The `Local Extension Settings` directory is an explicit target for
AMOS/Atomic (the [Objective-See
analysis](https://objective-see.org/blog/blog_0x88.html) contains the hardcoded ID
`nkbihfbeogaeaoehlefnkodbefgpgknn` with the comment `# MetaMask`), Lumma, RedLine
and K1w1.

The mechanics matter: **they cannot decrypt it.** They harvest ciphertext in bulk,
ship it to a C2, and the cracking happens offline — with a wordlist **personalised
from the browser passwords and clipboard contents collected on the same host in the
same pass**. This is why password reuse here is catastrophic.

**The consequence: if the machine was compromised, treat the seed as compromised and
move the funds, regardless of how strong your password was.** Changing the password
does not help: the attacker holds a snapshot of the *old* ciphertext.

---

## 7. Summary

| | |
|---|---|
| Generation | Fine. Local, 128 bits from the OS CSPRNG, no RNG degradation |
| 12 words | Not the weak point — the ceiling is set by the curve, not the phrase length |
| Telemetry | Cannot carry secrets, enforced by an allowlist in code |
| **Vault** | **The weak point. One password, a portable file, offline cracking, two copies on disk** |
| Auto-lock | **Off by default** |
| Social login | An encrypted copy on servers; its cryptography has not been verified by us |

This is a reasonable model for a **hot** wallet and an unacceptable one for savings.
Separate the two: a small spending balance in the extension, and savings on a
separate seed phrase generated offline with this tool or with a hardware wallet.

---

## References and further reading

- [MetaMask Extension — the source code the line numbers in this document refer to](https://github.com/MetaMask/metamask-extension)
- [`@metamask/browser-passworder` — password-based vault encryption](https://github.com/MetaMask/browser-passworder)
- [`@metamask/scure-bip39` — the fork of the audited BIP-39 implementation](https://github.com/MetaMask/scure-bip39)
- [`@noble/hashes` — the source of `randomBytes` in the generation chain](https://github.com/paulmillr/noble-hashes)
- [`@scure/bip39` — the original, audited by Cure53](https://github.com/paulmillr/scure-bip39)
- [BIP-39 — the standard MetaMask follows](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [MetaMask — official privacy and security documentation](https://support.metamask.io/privacy-and-security/)

---

<sub>Part of **HEATDEATH** — an offline BIP-39 / EVM seed generator that proves its
properties instead of claiming them.<br>
Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE), the same terms as the code it documents.<br>
Russian version: [Русский](../ru/METAMASK.md). Editing one language version obliges
you to update the other — see [CONTRIBUTING.md](../../CONTRIBUTING.md).</sub>
