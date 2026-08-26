# HEATDEATH

[Русская версия](README.ru.md) · [Landing page](README.md)

An offline generator of recovery phrases and EVM keys that **proves** its
properties instead of claiming them.

One readable 300 KB file - a built bundle with no runtime dependencies
(the source tree has five, all by the same author). Generates a 24-word BIP-39
phrase from 256 bits of entropy and derives Ethereum addresses. Compatible with
MetaMask, Rabby, Trust, Ledger, Rainbow — with anything that understands BIP-39.

```sh
npm ci --ignore-scripts
npm run self-test        # 21 groups of checks, including negative ones
npm run prove-sandbox    # the runtime denies network, process spawning and writes
npm run generate:dice    # generation
npm run verify           # check what you wrote down on paper
```

If this is your first time here — **[QUICKSTART.en.md](QUICKSTART.en.md)**, step
by step and without theory.

---

## What makes this different

Every line below is checked by a command, not by a promise.

| Property | How to check it |
|---|---|
| **Vectors run before any secret exists** | `npm run self-test`. If even one reference vector fails to match, the tool refuses to generate. |
| **Two independent implementations** | BIP-39, PBKDF2 and BIP-32 CKDpriv are computed twice: through `@scure` and through bare `node:crypto`. A divergence = refusal. |
| **Sandbox at the runtime level** | `npm run prove-sandbox` → `6/6 capability probes denied`. All six: network, DNS, subprocesses, workers, disk writes and reads outside the package directory - forbidden by Node, not by the author's conscience. |
| **Multi-source entropy** | Three OS sources plus dice, XOR of domain-separated hashes, health tests in the style of NIST SP 800-90B. |
| **Refusal in a dangerous environment** | SSH, an attached debugger, a redirected stdout — refusal. tmux, root, a cloud-synced directory — warning. |
| **`--verify` against transcription errors** | Expands abbreviations from 3 letters, suggests corrections by Levenshtein distance. A transcription error is the number one cause of losses. |
| **SLIP-39 with no single point of failure** | `npm run split` → 2-of-3 shares. 45 official Trezor vectors and recovery from **every** valid subset. |
| **Reproducible build and PQ signatures** | Two builds → one SHA-256. The manifest is signed with Ed25519, ML-DSA-87 and SLH-DSA. |

---

## Comparison

The full table is in [docs/en/COMPARISON.md](docs/en/COMPARISON.md) (in Russian). In short:

| Project | Where we are better |
|---|---|
| [iancoleman/bip39](https://github.com/iancoleman/bip39) | Not a browser: no extensions injecting themselves into `file://`, no page cache. Vectors at runtime, cross-checking of implementations, a sandbox, environment checks. The project has had no pushes since 04.2024 and has 226 open issues. |
| `cast wallet new-mnemonic` (Foundry) | It accepts `--entropy` **as a command-line argument** — that is visible in `ps` and ends up in the shell history. It gives 12 words against our 24. No vectors at runtime, no sandbox. |
| [bitcoinjs/bip39](https://github.com/bitcoinjs/bip39), [scure-bip39](https://github.com/paulmillr/scure-bip39) | These are libraries: they have no entropy policy, no verification mode and no opinion about the environment they run in. We use `@scure` internally and add everything listed above. |
| [trezor/python-mnemonic](https://github.com/trezor/python-mnemonic) | The BIP-39 reference, but also a library: the vectors live in the tests, not in the generation path. |
| [python-slip39](https://github.com/pjkundert/python-slip39) | We give you SLIP-39 **and** keep MetaMask compatibility, and we check recovery from every subset before printing the shares. It has no dice input. |
| [bip_utils](https://github.com/ebellocchia/bip_utils) | Broader in coin coverage, but with no environment guarantees, no vectors at runtime and no cross-checking. |
| SeedSigner, Krux, Coldcard, Passport | **This is where we lose — see the next section.** Our only advantage: cross-checking is mandatory and cannot be skipped, whereas their verification against a third tool is a manual procedure that most people will skip. |

### Where we lose

The limitations below are structural: they follow from the chosen execution
environment and are not removed by further development. The full treatment, with
measurements, is in [COMPARISON.md](docs/en/COMPARISON.md).

| Limitation | Substance |
|---|---|
| **Operating system attack surface** | A dedicated device wins categorically. SeedSigner runs on a board with no radio silicon at all and wipes RAM when power is removed. Our process runs inside macOS with a network stack, swap and system services. `--permission` restricts our process and does not affect the rest of the machine. |
| **No external audit** | The dependencies have been audited: `@scure/bip39` was reviewed by Cure53 in January 2022, funded by the Ethereum Foundation. The tool itself, around 4,350 lines, has had no external review. |
| **The cross-check is limited by nature** | One author, one language, one process. It detects a substituted dependency and a transcription error, but it will not detect a shared misconception: if the derivation rule were understood wrongly, both implementations would encode the same error and agree. |
| **Transaction signing is not implemented** | If the seed is imported into MetaMask on a connected machine, a significant part of the security obtained is lost there. The limitation does not apply if the seed stays in a hardware wallet or in cold storage. |
| **A Coldcard-class bug would go undetected** | The vectors check the derivation path, whereas the failure occurred in the entropy path. The health tests also pass the output of a weak PRNG. Only dice provided detection. |

### What to do with large amounts

Generate the seed on dedicated hardware (Coldcard in "dice only" mode,
SeedSigner, Passport), and **run our tool offline in `--verify` mode** as an
independent second implementation confirming the EVM addresses. SeedSigner's own
documentation assigns the same role to a second tool.

---

## Documentation

| | |
|---|---|
| [QUICKSTART.en.md](QUICKSTART.en.md) | The step-by-step procedure: running from Tails and from a virtual machine, transfer through 1Password |
| [docs/en/THREAT-MODEL.md](docs/en/THREAT-MODEL.md) | What is covered, what cannot be covered, real-world loss cases. **Also there — why neither Docker, nor a container, nor a virtual machine solves the problem** |
| [docs/en/ENTROPY.md](docs/en/ENTROPY.md) | Entropy, the strength proof, the post-quantum section |
| [docs/en/METAMASK.md](docs/en/METAMASK.md) | A code-level analysis of MetaMask: exactly where your wallet is weakest |
| [docs/en/COMPARISON.md](docs/en/COMPARISON.md) | The full comparison with open-source projects |
| [docs/en/VERIFY.md](docs/en/VERIFY.md) | Verifying the signatures and reproducing the build |
| [docs/en/BUILD.md](docs/en/BUILD.md) | Building it yourself |
| [docs/en/RELEASE.md](docs/en/RELEASE.md) | Maintainer release and offline-signing ceremony |
| [docs/en/GLOSSARY.md](docs/en/GLOSSARY.md) | Every specialist term used across these documents, each pointing at the document that explains it |

The same documents in Russian live in [docs/ru/](docs/ru/); the two trees mirror
each other file for file.

---

## Commands

```
npm run wizard           step-by-step wizard — start here
npm run self-test        all reference and negative tests
npm run generate         a new wallet
npm run generate:dice    the same plus dice and screen wiping (recommended)
npm run generate:account Ledger Live scheme: addresses are not linked by one xpub
npm run verify           check a phrase against paper
npm run split            split the phrase into SLIP-39 shares
npm run combine          restore the phrase from shares
npm run prove-sandbox    show the runtime refusals
npm run build            reproducible build of the artifacts
npm run verify-release   verify the hashes and the three signatures
```

These commands execute the current source checkout and therefore print an
unsigned-source warning. A complete downloaded release can instead be run with
the corresponding `:verified` command, for example `npm run self-test:verified`;
that mode never falls back to source.

Options: `--dice`, `--scheme=metamask|account`, `--accounts=N`, `--shares=2of3`,
`--group-threshold=N`, `--show-public`, `--show-private`, `--wipe-screen`, `--qr`.

### `--qr` — checking addresses without retyping

Prints the list of addresses as QR codes, so you can compare it against what the
wallet shows after import without typing 42 hex characters eleven times. An
error during this check is the most frequent real-world failure of the whole
procedure.

**What will never end up there:** the phrase, the entropy, the seed, the private
keys, the SLIP-39 shares — and the extended public key as well. A leak of a
single account-xpub reveals the public keys of every address under it, including
ones that have never spent (see [docs/en/ENTROPY.md](docs/en/ENTROPY.md) (in Russian)),
and a photographed QR code is machine-readable, unlike a photographed list. The
function takes an **array of addresses** and checks each one against the EVM
address mask — that is a structural guarantee, not discipline.

**What it is not.** It is not an independent check. To check the derivation
independently, a second device has to **perform** it, and for that it needs the
seed. Transferring the addresses transfers the result of the very computation we
are checking — it cannot check itself. Real independent verification is
described in
[docs/en/COMPARISON.md](docs/en/COMPARISON.md#cross-checking-against-third-party-tools) (in Russian).

Secrets are read interactively with hidden echo and are **never** accepted as a
command-line argument: argv is visible to any process through `ps` and is written
into the shell history.

---

## `npm run wizard` — step-by-step mode

Walks you through the whole procedure in six steps: environment check → entropy →
passphrase → generation → **mandatory verification** → backup shares. Nothing can
be skipped.

The key step is the fifth one. The wizard **removes the phrase from the screen**
and asks you to type it in from paper, then compares it word by word in memory:

```
  MISMATCH at word 5.
  Your paper is wrong; the generated phrase is correct. Fix the paper:
     5. correct: drive   you typed: abandon
```

This is stronger than the manual path, where you are asked to compare addresses
by eye — exactly the kind of check a tired person does badly. A transcription
error that passes the BIP-39 checksum happens roughly once in 256 and is
discovered years later.

The screen is cleared **only after** you confirm that the phrase has been written
down, and the `show` command brings it back at any moment. Until the mismatch is
resolved, nothing is lost.

**The wizard contains no cryptography of its own.** Every operation in it is a
call to an already existing function covered by the self-test: `assertRuntime`,
`selfTest`, `collectEntropy`, `crossCheck`, `primaryAccounts`,
`splitSecretIntoShares`. It cannot weaken any of the guarantees, because it
implements none of them — it only removes the possibility of skipping a step. It
does not print private keys at all.

---

## `npm run op-export` — a staging buffer in 1Password

A separate command that in one action puts everything generated into **one**
1Password item: the 24 words, the private and public keys of the first three
addresses and all three SLIP-39 shares. The point is the moment of creation: not
to retype a dozen secrets by hand, but to move them onward and **delete the
item**.

### What you need to install

The integration requires **two** things — the 1Password app itself and its CLI:

```sh
brew install --cask 1password          # the app, if you do not have it yet
brew install --cask 1password-cli      # the CLI (provides the `op` command)
op --version                           # check: it should print a version
```

Then **enable the integration in the app**: 1Password → Settings → Developer →
"Integrate with 1Password CLI". Without that checkbox `op` cannot reach the
vault, and the command will fail.

Check that the pairing works before you run the export:

```sh
op vault list
```

The app will ask for confirmation (Touch ID). If the vault list appeared —
everything is ready. No token is stored on disk in the process: `op` goes through
the app, and that is a safer path than service tokens.

### How to use it

```sh
npm run op-export:dry     # rehearsal: op shows a preview and writes nothing
npm run op-export         # for real
```

**Start with `:dry`.** It goes the whole way to the end and should finish with the
line `DRY RUN succeeded - op accepted the item and wrote NOTHING`. The sequence of
questions in the rehearsal and in the real run is deliberately identical: a
rehearsal that skips steps rehearses the wrong thing.

### Two modes

The command asks at the very beginning:

```
new or existing?
```

#### `new` — create a wallet and store it right away

The normal scenario. Nothing needs to be created in advance. The order of steps:

1. Offers to roll the dice (you may decline — then it will be 256 bits from the
   OS sources).
2. Asks for a BIP-39 passphrase and estimates its strength.
3. Generates the wallet, runs a round-trip and a cross-check with two
   implementations.
4. **Shows the 24 words and waits until you confirm that you have written them
   down on paper.**
5. Splits the entropy into three SLIP-39 shares and checks all three
   combinations.
6. Puts everything into one 1Password item and prints the command to delete it.

The order here is deliberate: **paper before 1Password.** You will delete the
item; the paper stays.

A caveat the command states itself: with `new`, the seed is born inside a process
running at 5/6. Generating through `npm run wizard` at the full 6/6 is also
possible — but then you have to type the phrase in here by hand, and that carries
its own portion of exposure. There is no free option.

#### `existing` — store an already created wallet

For the case where you already have the phrase. You type the 24 words in from
paper (input is hidden, abbreviations from 3 letters are expanded, typos get
suggestions). After that it is all the same: passphrase, cross-check, shares,
item.

Before writing, the command prints the **master fingerprint** and the **address
at index 1** — check them against what you recorded at creation time. One
incorrectly transcribed word that passes the checksum gives a different valid
wallet, and you would have stored someone else's in 1Password.

### What goes into the item

17 fields: a warning note, the 24 words, the passphrase status, the fingerprint,
the derivation path, three fields each (address, public and private key) for the
first three addresses, and three SLIP-39 shares. The number of addresses is
changed with the `--accounts=N` flag.

### How the secret gets into `op`

Only through the **stdin of the child process**. Measured on macOS:

| Channel | Visible to other processes |
|---|---|
| `argv` | **YES**, with plain `ps` |
| environment variable | **YES**, via `ps -E` under the same uid |
| temporary file | sits on disk until it is deleted |
| **stdin pipe** | **NO** — lives in kernel memory |

Only the vault name and the output format are passed in the command-line
arguments. Not one secret value in argv, in the environment or in a file —
verified by measurement: 0 occurrences of the marker in `ps` across all
processes.

**Why there is a `cat` in the chain.** Node gives the child process a **socket**,
not a real pipe, and `op` does not accept that kind of input — it answers
`provide the item category with '--category' flag`, which looks like a JSON
problem and is not one. Measured:

| Feeding method | What `op` sees | Result |
|---|---|---|
| `echo … \| op` | FIFO | works |
| `op … < file` | a regular file | refusal |
| Node `spawn` with `"pipe"` | **a socket** | **refusal** |
| Node `spawn` + `mkfifo` | FIFO | works |

A FIFO would have worked, but it requires write permission on the file system and
leaves behind a path that another process can open. So the shell builds the pipe
instead: our socket feeds `cat`, and `cat` feeds `op` through a real pipe. The
vault name is passed as a positional argument so that it cannot be substituted
into the command string.

### What vectors this adds — and what has been done about them

| Vector | State |
|---|---|
| Secret in `argv` | Eliminated. Verified: **0 occurrences** of the marker in `ps` across all processes |
| Secret in environment variables | Eliminated. Verified: absent from the child's environment |
| Secret in a temporary file | Never created at all |
| Injection through the vault name | Eliminated: the path to `op` and the vault name are passed as positional `$1`/`$2`, they are not interpolated into a string |
| Substitution of `sh` and `cat` through `PATH` | Eliminated: absolute `/bin/sh` and `/bin/cat`. Both are flagged `restricted` — **SIP does not let even root replace them** |
| Substitution of `op` itself | **Remains.** `op` lives in a user-writable directory. Mitigation: the path is resolved once and **printed to you** — `ok op 2.39.0 at /opt/homebrew/bin/op`. Check that it is where you expect it to be |
| An undiagnosable failure | Eliminated: `op`'s message is shown, but held back if it contains any of the values being passed |

### What remains, and it is not about transport

- **`op` is someone else's unrestricted program with network access**, and your
  whole wallet lands on its stdin. Our runtime does not restrict it in any way.
  That is a property of the idea itself, not of the implementation.
- **The secret is held in memory by three processes** instead of one: ours,
  `cat`, `op`. `cat` is trivial and protected by SIP, but it is still one more
  copy.
- **The seed goes to 1Password's servers** in encrypted form and settles in their
  local cache.

### What this costs

Running `op` requires `--allow-child-process`, so the command works at **5/6**
instead of 6/6, and our runtime does not restrict the `op` it launched at all —
it is someone else's program with its own permissions and its own network. The
difference is visible:

```sh
npm run prove-sandbox                 # 6/6 denied
npm run op-export                     # 5/6, subprocess ALLOWED
```

That is exactly why this is a **separate command**: generation and the wizard keep
the full sandbox, and the boundary stays where it can be seen.

### What you need to understand

> **Three shares in one vault is not a threshold backup.** It is a secret in one
> place, only with the appearance of layering. For a short-lived buffer that is
> acceptable; for storage it is not.
>
> The item itself contains this warning in its notes, and the command prints a
> ready-made line to delete it. **Delete it** as soon as you have distributed the
> contents: the shares to three different physical places, the phrase onto paper.
>
> And the seed leaves your machine: 1Password syncs it to their servers in
> encrypted form and decrypts it on every device where you unlock the vault.

If what you need is **storage** rather than a buffer — keep **one** SLIP-39 share
in 1Password. Below the threshold a share gives nothing, and a compromise of the
vault is then harmless.

---

## Why a container or a virtual machine will not help

The short answer: **you cannot protect a computation from the machine that
executes it by software means.** Containers and hypervisors isolate the **host
from the guest**, and we need the opposite.

Measured on this machine: container processes are not visible in the macOS `ps` —
the namespace works. But the VM's memory sits in the `com.docker.virtualization`
process under your UID, and `vmmap` enumerates **126 readable regions** without
root.

The technology that actually solves this (AMD SEV-SNP, Intel TDX) is not
available on Apple Silicon — and even it would not close the output path: the 24
words have to be shown to you on a screen, and the screen is controlled by the
host.

The circle is broken only by a device **with its own screen**. The full analysis
with all the options and measurements:
[docs/en/THREAT-MODEL.md](docs/en/THREAT-MODEL.md#why-no-container-docker-or-virtual-machine-saves-you) (in Russian).

---

## Why there is no graphical interface here

In short: a GUI breaks three properties that in this project are the only ones
**proven by a command** rather than promised.

| What breaks | Exactly how |
|---|---|
| **Verifiability of the install** | `npm ci --ignore-scripts` stops working: GUI frameworks download the runtime with a postinstall script. A pinned lock file with integrity hashes loses its meaning. |
| **The sandbox** | Electron needs subprocesses, workers, disk writes and network — exactly what `--permission` forbids. You cannot lift that selectively: `6/6 denied` would turn into `0/6`. |
| **The runtime** | A webview is a browser. We argue our advantage over iancoleman/bip39 on the grounds that we do not run in a browser; a GUI would turn that argument against us. |

The price in numbers: right now it is **5 packages, about 2.9 MB, all from one author**,
and `@scure/bip39` among them has passed a Cure53 audit. A minimal GUI brings in a
tree orders of magnitude larger, where nobody has reviewed anything.

And there is an argument stronger than the technical ones: an interface attracts
exactly the people who are least prepared to carry out an offline procedure. It
will not turn off their Wi-Fi, will not disable iTerm2 Instant Replay and will not
stop them taking a screenshot — it will lower the barrier to entry without
lowering a single real risk. For someone who needs a GUI, the honest answer is a
hardware wallet, not a window on top of a Node script.

The text interface, meanwhile, can and should be improved — without new
dependencies. `--qr` was built for exactly that. More detail:
[docs/en/THREAT-MODEL.md](docs/en/THREAT-MODEL.md#deliberately-not-implemented) (in Russian).

---

## Passphrase — what the "25th word" gives you

An optional string you can set at generation time. Technically it is **not a word
from the wordlist** but arbitrary text that goes into the salt:

```
seed = PBKDF2-HMAC-SHA512(
         password = mnemonic,
         salt     = "mnemonic" + passphrase,   ← here
         iterations = 2048 )
```

### The main point: what happens if the 24 words leak

| | The paper was found, no passphrase set | The paper was found, passphrase set |
|---|---|---|
| What the finder gets | **Your entire wallet** | 24 words and **a different, empty** wallet |
| What else they need | Nothing | To guess the passphrase |
| What you do | Move the funds immediately | You have time, if the passphrase is strong |

That is the **only** thing a passphrase gives you. Without it the paper is the
wallet: whoever reads the 24 words is the owner.

### How reliable this is — measured

BIP-39 stretches with only **2048 PBKDF2 iterations**. That is microseconds, which
means almost no protection against brute force. If the attacker has your 24 words,
they guess the passphrase cheaply. Measured on a MacBook Pro M5:

```
one core:                                    190 attempts/s
8 cores:                                   1 523 attempts/s
GPU farm (order-of-magnitude estimate): ~190 000 attempts/s
```

| Passphrase | Bits | Holds for |
|---|---|---|
| a single dictionary word | 16.6 | **less than a second** |
| two **random** words | 25.8 | **3 minutes** |
| three random words | 38.7 | 14 days |
| **four random words** | **51.6** | **~290 years** |
| five random words | 64.5 | ~2×10⁶ years |

Check it yourself: `2^bits / 2 / 190000` seconds. The bits carry a decimal for
exactly that reason - round them to whole numbers and you get different
figures and conclude the table is lying. The durations are given to one
significant figure, because the guess rate is an order-of-magnitude estimate
and three significant figures in the output would promise more than the input
supports.

**"Random" here means chosen by lot, not by you.** The 12.9 bits per word is
Diceware: a word picked with dice from a list of 7776. Four words you thought
up yourself are worth considerably less, and the tool cannot tell the
difference - it does not know where you got them.

**The threshold is 4 random words.** The tool evaluates what you enter and warns
if the result comes to less than 50 bits.

### Three things to know before you set one

**1. There is no such thing as a wrong passphrase.** Any string gives a valid
wallet. A typo will silently open a different, empty one — without a single error
message. Case and spaces are significant:

| passphrase | fingerprint |
|---|---|
| `""` | `0xc185b076` |
| `"dog"` | `0x911c8333` |
| `"Dog"` | `0xe6a3e18f` |
| `"dog "` | `0xf55a7a12` |

**2. MetaMask does not support it.** If you set a passphrase, importing those 24
words into MetaMask will open an **empty** wallet without it. It looks like the
funds were stolen. Ledger, Trezor, Rabby and MyEtherWallet do support it.

**3. Nothing can recover it.** Forget it and the funds are lost forever, whatever
is written on the paper. The SLIP-39 shares do not carry it either.

### Bottom line

| Situation | Answer |
|---|---|
| A spending wallet, imported into MetaMask | **Empty.** Otherwise it will not open |
| Savings, paper in a safe | Empty, or 4+ words. There is nothing in between |
| Paper somewhere it could be found | **4+ random words**, stored **separately** from the paper |

A short passphrase is the worst of the three options: it cannot protect the paper,
but it can perfectly well lose you the funds if you forget it. The detailed
analysis: [docs/en/ENTROPY.md](docs/en/ENTROPY.md) (in Russian).

---

## SLIP-39: backup shares

A single piece of paper with 24 words is a single point of failure, and losing it
is more likely than falling victim to any attack in our threat model.

```sh
npm run split -- --shares=2of3            # three shares, any two restore it
npm run split -- --shares=2of3,3of5       # two independent groups: any one
                                          # group restores it on its own
npm run combine                           # restore
```

`npm run split` prints the master fingerprint and the address at index 1 **before** it
shows the shares. Check them against what you wrote down at generation time: one
incorrectly transcribed word that passes the checksum (roughly 1 in 256) gives a
different valid wallet, and you would end up with a flawless backup of someone
else's wallet.

Below the threshold, shares give **nothing** — not "less protection", but
literally zero information about the secret.

> **Our shares carry the BIP-39 ENTROPY, not the BIP-32 seed.**
> Trezor and the reference `shamir-mnemonic` treat the recovered master secret as
> the seed directly. Verified on the official vectors: 15 of 15. From the same
> shares, the two readings give **different wallets**. Restore through
> `npm run combine`.
>
> Compatibility is confirmed by measurement, not asserted: the Trezor reference
> implementation reads our shares and returns exactly the same 32 bytes.
>
> **The shares do not contain the BIP-39 passphrase.** If you set a 25th word, the
> shares on their own will restore nothing — store it separately.

The `slip39.mjs` module does **not** have a second independent implementation.
That is a deliberate departure, justified in the file header: in its place there
are 45 official Trezor vectors (15 valid and 30 required to fail), a SHA-256 check
of the wordlist and recovery from **every** valid subset. It was exactly these
vectors that caught a real bug in my GF(256) arithmetic: the tables were being
built by multiplying by 2 instead of x+1. A second implementation by the same
author would have repeated the same mistake and agreed with itself.

---

## Integrity

```sh
npm run build
npm run verify-release -- --trusted-keys=/absolute/independent/key-directory
npm run self-test:verified
```

`verify-release` is intentionally a check of a complete downloaded release, not of
an arbitrary source checkout. It requires the bundle, deterministic source archive,
SBOM, provenance, recipe and all three signatures; the SEA is optional unless
`--require-all` is supplied. Normal commands execute reviewed checkout source and
warn accordingly. `:verified` commands require this release preflight and never
fall back to unsigned source.

The manifest is signed with three schemes resting on three different hardness
assumptions: **Ed25519**, **ML-DSA-87** (FIPS 204, lattices) and
**SLH-DSA-SHA2-128s** (FIPS 205, hash functions only — the most conservative
assumption available).

The signatures are pseudonymous. They prove that the artifact has not changed
since it was signed by the key holder, and they say **nothing** about who that is.

Public key fingerprints (SHA-256 of the DER SPKI):

| Scheme | Fingerprint |
|---|---|
| `ed25519` | `463c3b401b66d9dd8faf17ec042c9f41ae939745cf081a9babed18aa21cee4aa` |
| `ml-dsa-87` | `4afa05402782d13b99b1a385f1f3bf4afa4da341224a693a27dc116015a16b99` |
| `slh-dsa-sha2-128s` | `73297ec0f483ebe8184783599a3d9627da7febca8645396ecc0e56a5efbf44af` |

`npm run verify-release` prints the same values — compare them.

**An honest caveat about circularity.** This table lives in the same repository as
the artifacts. Whoever substituted the release would substitute the table too. The
README is at least a different file from `dist/SHA256SUMS` and the signatures,
so a tamperer would have to alter both; this is the best that is achievable
inside a single repository, but the circle is only truly broken by comparing the
fingerprints against a source you obtained **by a different route**: from another
mirror, from an acquaintance, from a pinned message. If the only thing you have
seen is this repository, the signature proves internal integrity and nothing more.

**The binary is secondary, and that is a matter of principle.** The primary
artifact is the readable `.mjs`. Inside the binary the source sits in plain text
(`strings` pulls it out), the sandbox flags can be patched, and `--prove-sandbox`
in a patched build will print the same `6/6`. Self-attestation by an artifact the
attacker controls proves nothing. On top of that, 144 MB **freeze Node v26.5.0**:
every future CVE in V8 stays in the binary until it is rebuilt, whereas when you
run from source the patches arrive through your package manager.

On macOS a downloaded binary gets quarantined, and Gatekeeper kills it silently —
exit 137, empty output:

```sh
xattr -d com.apple.quarantine ./heatdeath
```

---

## License

**AGPL-3.0-or-later** ([LICENSE](LICENSE)).

Use it, read it, modify it, run it — freely, including at work. But if you
**distribute** it or a derivative work, you are obliged to publish your own source
code under AGPL-3.0, together with your changes and with the copyright notices
preserved. Section 13 extends the same rule to network use.

The choice is deliberate. The only real protection this tool has is that it can be
read. A proprietary fork of a recovery-phrase generator that cannot be inspected
and is under no obligation to disclose what was changed in it is exactly the
artifact this documentation argues against in every other section.

**Commercial license.** If AGPL-3.0 does not suit you — usually because you want to
embed this in a product you do not intend to open-source — a separate commercial license
is available. Open an issue.

All bundled third-party components are under MIT or the three-clause BSD, both
GPL-compatible. The full list and their notices: [NOTICE.md](NOTICE.md).

---

## Responsibility

The tool has not undergone a third-party audit. For amounts whose loss would
matter to you, generate the seed on a hardware wallet and use this tool to verify
the addresses independently.
