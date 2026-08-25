# Threat model

> What this tool closes, what it cannot close in principle, and why neither Docker,
> nor a virtual machine, nor an encrypted container helps here.

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/THREAT-MODEL.md) · [📖 Glossary](GLOSSARY.md)

---

**Contents**

- [Areas that technically cannot be closed](#areas-that-technically-cannot-be-closed)
- [Why no container, Docker or virtual machine saves you](#why-no-container-docker-or-virtual-machine-saves-you)
- [Deliberately not implemented](#deliberately-not-implemented)
- [Preparing the terminal](#preparing-the-terminal)

---

## Areas that technically cannot be closed

Not one of the items below can be closed by this code. They are closed by procedure,
by hardware, or by nothing at all.

### Inside the process

| Area | Why it cannot be closed |
|---|---|
| **Mnemonic in memory** | JavaScript strings are immutable. `phrase` cannot be overwritten; it lives until GC. The only radical solution is a hardware wallet, where the seed never enters general-purpose memory. |
| **Intermediate copies on the heap** | GC moves and copies objects. No `fill(0)` can guarantee that every copy was erased. |
| **No `mlock`** | Node cannot pin pages in RAM. The seed may reach swap. On macOS swap is encrypted under FileVault — a mitigation, not a guarantee. |
| **Memory dumps** | A crash dump or a crash report may contain the seed. |
| **Debugging under the same UID** | Node's permission model protects against what *this* process does, not against what is done *to* it. Code running under your UID can attach to the process. |

### Around the process

| Area | Why it cannot be closed |
|---|---|
| **Terminal scrollback** | The tool does not control your emulator. iTerm2 Instant Replay writes the session to disk even when you saved nothing. `--wipe-screen` clears only the current terminal. |
| **Session logging** | `script(1)`, `tmux pipe-pane`, `expect` — an `isTTY` check does not stop them and cannot. This is demonstrated, not assumed. |
| **Keyloggers and the Accessibility API** | Any process under the same UID can read keystrokes and window contents. Hidden input protects against a shoulder, not against malware. |
| **Screenshots and screen recording** | Screen Sharing, Zoom, screen recording, Continuity. |
| **Compromised OS or firmware** | If the kernel, OpenSSL or Node itself was replaced before launch, checking integrity from the inside is meaningless. Hence the value of dice: they are the one thing independent of the machine. |
| **Compromised Node or npm** | The cross-check catches a substituted `@scure`/`@noble`. It does **not** catch a substituted `node:crypto` or a substituted Node binary — both paths use them. |
| **Physical security of the paper** | Theft, fire, water, a shoulder. Partly closed by a BIP-39 passphrase stored separately. |
| **Rubber-hose attack** | No cryptography protects against it. |

### Risks that SLIP-39 itself introduces

Splitting into shares removes a single point of failure and **adds its own** — it is
a trade, not a free improvement.

| Risk | Why it exists |
|---|---|
| **Shares do not carry the BIP-39 passphrase** | They restore the entropy only. If you set a 25th word, the shares alone restore nothing. Store it separately, and remember that a forgotten 25th word loses the funds irrecoverably. |
| **You split the wrong wallet** | A single miscopied word that still passes the checksum (~1 in 256) yields a different valid wallet. The internal round-trip will not catch this: it verifies the entropy it was handed. This is why `--split` prints the fingerprint and the index-1 address — **compare them before you distribute the shares**. |
| **Shares kept next to each other** | Two shares of a 2-of-3 in one drawer are one share with extra steps. A threshold protects only under physical separation. |
| **Our shares ≠ a Trezor seed** | We split BIP-39 entropy; Trezor reads the master secret directly as a BIP-32 seed (verified, 15/15 vectors). The same shares yield two different wallets. Restore through `npm run combine`. |
| **Foreign shares with a SLIP-39 passphrase** | Our `--combine` expects shares from our `--split` (no SLIP-39 passphrase). A set created elsewhere with a passphrase decrypts to different bytes, produces a plausible-looking phrase and **will not be detected** — the SLIP-39 digest verifies the encrypted secret. The only safeguard is comparing the fingerprint. |
| **An implementation without a second, independent one** | `slip39.mjs` was written by hand. The compensation is 45 official Trezor vectors, a wordlist SHA-256 check, and recovery from every admissible subset. Those vectors already caught one real bug in the GF(256) arithmetic. |

---

## Why no container, Docker or virtual machine saves you

This is the most frequent question about the tool, and the answer is definite:
**software cannot protect a computation from the machine executing it.** Not
"difficult", not "not implemented yet" — structurally impossible. Whoever controls
the processor, the memory and the I/O controls the result.

Every option usually proposed is examined below, with measurements.

### The direction of isolation is the opposite of the one you need

Virtual machines and containers protect the **host from the guest**: malware inside
does not get out. Our problem is the reverse — protecting the **guest from the
host**. In that direction they do not work by construction, not by oversight.

### Docker: isolation between guests, not from the host

Docker Desktop on macOS is Linux inside a virtual machine. Measured on a real
container:

```
container processes visible in macOS `ps`:          0     <- namespace isolation works
the VM process com.docker.virtualization:           uid 501, your user
readable regions of its memory through vmmap:       126
```

The container is invisible **from another container** — and that is real, working
isolation. But all of its memory lies inside a process owned by your account, and
`vmmap` maps it without root. Namespaces and cgroups were never designed as a
boundary against the host, and Docker's developers have never claimed otherwise.

### An "encrypted container" is about something else

Encryption protects data **at rest**. For code to execute, the data must be
decrypted into RAM, and the host sees RAM. LUKS, an encrypted disk image, FileVault
— all of these save you from a stolen powered-off laptop and give you nothing
against a live compromised macOS.

### UTM and any hypervisor

| Mechanism | Why the host sees the guest |
|---|---|
| Guest memory | A memory region inside the hypervisor process under your UID. `vmmap <pid>` maps it without root |
| Snapshots | A snapshot writes the guest's RAM to a file on the host disk — seed included |
| Input | Keystrokes pass through the host's input stack |
| Display | The VM window is screenshotted like any other |
| Guest disk | An ordinary file in the host filesystem |

**What a VM does give you, if the host is clean:** a disposable OS with no
accumulated extensions, clipboard managers or sync agents; hard absence of network
(simply do not add an adapter); no traces after deletion. That is a real improvement
over an everyday session — but not a security boundary. One rule is mandatory:
**never snapshot a VM that contains a seed.**

### The technology that genuinely solves this — and why it is not here

The category is called confidential computing and it exists in earnest. **AMD
SEV-SNP** and **Intel TDX** treat the hypervisor as hostile: guest memory is
encrypted with keys the hypervisor does not hold, and SEV-SNP catches page
substitution through a Reverse Map Table. TDX removes the hypervisor from the
trusted base entirely.

Two reasons this is not the answer:

**1. These are x86 technologies.** They do not exist on Apple Silicon — `sysctl`
knows neither SGX, nor SEV, nor TDX. ARM CCA does not ship in consumer devices. A
Secure Enclave is present in a Mac, but Apple provides no API for executing
arbitrary code inside it.

**2. Even a perfect TEE does not close this task.** This is the main argument, and
it does not depend on hardware:

1. You enter dice rolls — they travel **through the host's input stack**.
2. The enclave computes the seed in encrypted memory. Here everything is fine.
3. The enclave must **show you 24 words**, or you cannot write them down. The output
   travels **through the host's framebuffer** to your screen.

A compromised host reads the secret on the way out. The enclave protected the
computation but not the path to your eyes. This is the classic trusted path problem,
and consumer hardware does not provide one.

And connecting to a confidential VM in the cloud sends the seed over the network to
your local terminal. Our tool refuses to run over SSH for exactly this reason. The
circle closes.

### What breaks the circle

**A device with its own screen.** The secret is displayed on a screen your computer
does not control. This is not an excuse and not an advertisement — it is the
engineering answer to precisely this problem, and it is why hardware wallets have
their own displays and their own buttons.

| Level | What it removes | Cost |
|---|---|---|
| **A device with its own screen** — SeedSigner, Coldcard (dice-only mode), Passport | The general-purpose OS and the entire output path | ~$50–200 |
| **Tails from USB on a separate x86 machine** | The installed OS — it is not running | Needs a second computer, not Apple Silicon |
| **UTM / Docker on a clean Mac** | The accumulated cruft of the system, but not the system | Free |
| **An ordinary macOS session** | — | Baseline |

Procedures for the two middle options are in
[QUICKSTART.en.md](../../QUICKSTART.en.md#first-decide-where-to-run-it).

### Conclusion

The categories are exhausted. There is no software-only solution for a compromised
machine; confidential computing is unavailable on Apple Silicon and would not close
the output path anyway; MPC and HSM schemes are no longer self-custody with a paper
phrase but trust in a vendor and an attestation chain.

**Hence this tool's threat model: "the machine is clean at the moment of
generation".** Everything else is built around that assumption: disconnect the
network, close what is unnecessary, generate, write to paper, verify, wipe the
screen, shut the machine down. If the assumption is false, not one line of our code
helps — and saying so plainly is more honest than pretending a virtual machine
window is protection.

For amounts whose loss would matter to you: generate the seed on a device with its
own screen, and use this tool offline in `npm run verify` mode as an independent
second implementation for comparing addresses.

---

## Deliberately not implemented

### A graphical interface

The reason is not asceticism. A GUI breaks exactly the three properties that are the
only ones here **provable by a command** rather than promised.

**1. Installation stops being verifiable.** The procedure starts with
`npm ci --ignore-scripts` — a ban on postinstall scripts. No GUI framework installs
under that ban: Electron's npm package is a stub that downloads the Chromium runtime
afterwards, as a separate fetch. Removing `--ignore-scripts` nullifies the point of
a pinned lockfile with integrity hashes.

**2. The sandbox dies entirely.** Everything our permission model forbids is
required by a GUI framework:

```
subprocess: execSync    ERR_ACCESS_DENIED    <- renderer processes
worker thread           ERR_ACCESS_DENIED    <- required
file write              ERR_ACCESS_DENIED    <- caches and profiles
network: dns lookup     ERR_ACCESS_DENIED    <- Chromium's network stack
```

This is not a setting that can be loosened selectively: `--permission` would have to
be removed altogether, and `6/6 capability probes denied` would become `0/6`.

**3. The runtime becomes a browser.** In [COMPARISON.md](COMPARISON.md) we justify
our advantage over iancoleman/bip39 on the grounds that its "runtime is a browser:
extensions inject into `file://`, the page is cached, and a heap of JavaScript ends
up in swap". A webview GUI makes us exactly that, and the argument turns against us.

**The cost in numbers.** Today: **5 packages, 3.6 MB, all from one author**, and of
those `@scure/bip39` passed a Cure53 audit (January 2022) plus a self-audit in April
2026 — on precisely the 2.2.0 version we pin. I will not claim an audit for the
other four. A minimal GUI brings in a transitive tree orders of magnitude larger, in
which nobody has checked anything.

**The argument that outweighs the technical ones.** An interface attracts exactly
the users least prepared to carry out an offline procedure. It will not turn off
Wi-Fi, will not disable iTerm2 Instant Replay, will not make anyone write on paper
and will not prevent a screenshot. It lowers the barrier to entry without lowering a
single real risk — and a tidy window creates a feeling of safety that is not there.
For someone who needs a GUI, the honest answer is **a hardware wallet**, not a
window on top of a Node script.

**What instead.** The text interface can and should be improved without a single new
dependency: coloured warnings through ANSI codes, word-by-word phrase entry with
wordlist hints, a step-by-step mode. `--qr` is a completed part of that work: it
removes the main source of error when comparing addresses, and added nothing to the
dependency tree.

### Everything else

- **Writing to a file in any form.** The permission model forbids writes
  deliberately: there must exist no path by which the seed reaches disk.
- **Balance checks, ENS, anything from the network.** The network is denied by the
  runtime.

---

## Preparing the terminal

This is not a formality: the attack will be on your scrollback, not on 128 bits.

- **iTerm2 → Settings → General → Magic → disable Instant Replay** (it writes the
  session contents to disk), Profiles → Terminal → uncheck Unlimited scrollback
- quit clipboard managers (Raycast Clipboard History, Paste, Alfred)
- do not run inside `tmux`/`screen`
- close browsers and messengers
- turn off Wi-Fi, Ethernet, Bluetooth, Screen Sharing, AirDrop, Continuity
- make sure the directory is excluded from Time Machine and cloud backups

---

## References and further reading

- [Node.js Permission Model — the boundary the tool imposes on itself](https://nodejs.org/api/permissions.html)
- [SLIP-39 — the specification, including the risks of threshold schemes](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
- [Shamir A., "How to Share a Secret", CACM 22(11), 1979 — the original paper](https://dl.acm.org/doi/10.1145/359168.359176)
- [Tails — the amnesic operating system that boots from removable media](https://tails.net/)
- [Whonix — an OS built around isolation and anonymity](https://www.whonix.org/)
- [UTM — the macOS hypervisor examined in the virtual machine section](https://mac.getutm.app/)
- [Docker — official security documentation: isolation between containers, not from the host](https://docs.docker.com/engine/security/)
- [AMD SEV-SNP — confidential computing that treats the hypervisor as hostile](https://www.amd.com/en/developer/sev.html)
- [Intel TDX — removing the hypervisor from the trusted base](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html)
- [Apple Secure Enclave — why arbitrary code cannot be executed inside it](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)

---

<sub>Part of **HEATDEATH** — an offline BIP-39 / EVM seed generator that proves its
properties instead of claiming them.<br>
Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE), the same terms as the code it documents.<br>
Russian version: [Русский](../ru/THREAT-MODEL.md). Editing one language version
obliges you to update the other — see [CONTRIBUTING.md](../../CONTRIBUTING.md).</sub>
