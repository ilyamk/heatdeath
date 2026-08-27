# Quick start

[Русская версия / Russian original](QUICKSTART.md)

Step by step, without theory. If you want to understand *why* each step is the
way it is — [docs/en/THREAT-MODEL.md](docs/en/THREAT-MODEL.md) (in Russian).

Time: about 30 minutes. You will need a die and paper.

---

## Safe/DAO cold owner: rehearse first

If your goal is one cold or recovery owner for a Safe, use the dedicated profile
instead of the general wallet wizard. The rehearsal contains public test data only.

```sh
npm run rehearse:safe-owner
npm run doctor
npm run safe-owner
```

Read [docs/en/SAFE-OWNER.md](docs/en/SAFE-OWNER.md) before the real command. Generate
every Safe owner independently. This command does not deploy a Safe or sign a transaction.

---

## First decide WHERE to run it

This decision matters more than every other one in this document. The tool is an
ordinary process on your machine: it has no container of its own and no virtual
machine of its own. Node's permission model stops it from reaching outward
(network, writes, subprocesses), but it **does not stop other programs from
looking inside it**.

| Option | What it gives | What it does not give |
|---|---|---|
| **Dedicated hardware** — SeedSigner, Coldcard, Passport | The seed never enters a general-purpose OS at all. No radios, no other processes | You have to buy it; our tool is used only for verification |
| **A separate x86 laptop with Tails on USB** | The installed OS **is not running at all**, nothing is written to disk | **Does not work on your Mac** — see below |
| **UTM on a clean Mac** | A clean, disposable OS with no accumulated junk, guaranteed absence of network, nothing left behind after the VM is deleted | **Not a boundary against macOS itself** — see below |
| **An ordinary macOS session** | Fast | Baseline level: everything in [docs/en/THREAT-MODEL.md](docs/en/THREAT-MODEL.md) (in Russian) |

---

## The Tails option: bypassing the installed OS entirely

**You have an M5 Max, and Tails will not run on it.** Tails requires
[64-bit x86-64](https://tails.net/doc/about/requirements/), and their
documentation says outright that it does not work on "Mac computers with an Apple
processor (M1, M2, and so on)". You need **a different computer**: any x86-64 PC
or an old Intel Mac.

The point of this option is that at that moment the system installed on the disk
**is not executing at all**. A compromise of macOS stops mattering, because macOS
is not running.

### What you will need

- An x86-64 computer (not Apple Silicon)
- A USB stick of 8 GB or more for Tails
- A second stick for our tool
- A die and paper

### Preparation (can be done on the Mac, while still online)

1. Download the Tails image from [tails.net](https://tails.net) and **verify the
   signature** following the instructions on their site. This is not a formality:
   a substituted Tails image is exactly the scenario everything else is being done
   for.
2. Write it to the first stick.
3. Put the following on the second stick:
   - the v2.2 `heatdeath-linux-x64` release binary;
   - the signed `SHA256SUMS` and the independently trusted public-key
     fingerprints used to verify that release;
   - optionally `heatdeath.mjs` and the exact Node linux-x64 archive if you prefer
     to run the readable primary artifact instead.

Verify the complete release while still online by following
[docs/en/VERIFY.md](docs/en/VERIFY.md), then record the expected Linux binary
SHA-256 separately. The native artifact removes Node installation from the
offline ceremony; the readable `.mjs` bundle remains the primary audit target.

### Generation

1. Boot the x86 computer from the Tails stick. **Do not set up Persistent
   Storage** — the amnesia is the whole point of Tails.
2. Turn off the network in Tails (it can also start without it on its own).
3. Plug in the second stick, copy the binary to Tails' temporary filesystem and
   compare it with the hash from the signed manifest:

```sh
cp /media/amnesia/*/heatdeath-linux-x64 /tmp/heatdeath-linux-x64
sha256sum /tmp/heatdeath-linux-x64
chmod 0755 /tmp/heatdeath-linux-x64
```

4. Run the embedded self-test, then the appropriate ceremony. The SEA already
   embeds the strict permission-model flags:

```sh
/tmp/heatdeath-linux-x64 --self-test
/tmp/heatdeath-linux-x64 --wizard --dice
```

For a Safe cold/recovery owner, use `--safe-owner` instead of `--wizard --dice`.

5. From there it is as usual: dice, writing on paper, the mandatory check.
6. Shut the computer down. Tails has saved nothing: RAM is wiped at shutdown and
   the disk was never touched.

---

## The UTM option: useful, but it is NOT a security boundary

The short answer to "will a VM be a protected container against the rest of
macOS": **no, not in that direction.**

A virtual machine protects the **host from the guest**. We need the opposite — to
protect the guest from the host. A VM does not do that, and here is specifically
why:

- **The guest's RAM is a region of memory inside the UTM process**, which runs
  under your user account. Measured on this machine: the memory map of any process
  with the same UID can be taken from outside with the ordinary `vmmap` utility,
  without root. The seed inside the VM sits in memory that is accessible to the
  host.
- **A VM snapshot writes the guest's memory to a file on the host's disk** —
  together with the seed.
- **Keystrokes go through the host's input**, and the VM window can be
  screenshotted like any other.
- **The guest's disk image is an ordinary file** in your file system.

So if macOS is compromised, the VM gives you almost nothing.

### When UTM does make sense after all

If the host is clean, a VM is a **noticeable improvement** over an everyday
session:

- a clean OS with no accumulated extensions, clipboard managers or sync agents;
- the network is cut off hard — simply do not add a network adapter to the VM
  configuration;
- nothing is left behind: delete the VM and you have deleted everything.

### How to set it up if you go this way

1. Guest OS: any Linux for arm64 (Debian, Ubuntu). Installing Tails inside a VM is
   pointless — its amnesia protects against a host, and in this arrangement there
   is none.
2. In the VM configuration: **remove the network adapter**, turn off the shared
   clipboard and shared folders, turn off directory sharing.
3. Transfer the bundle into the guest once — through a disk image or a temporary
   shared folder that you then disconnect.
4. **Never take a snapshot** of a VM that has the seed in it: a snapshot writes the
   guest's memory to the host's disk.
5. Inside the guest it is as usual: `node --permission ... heatdeath.mjs --wizard --dice`.
6. Once the phrase is written down on paper, delete the VM entirely.

> The honest bottom line on isolation: UTM removes *the accumulated junk of your
> working system*, but it does not remove *the system itself*. The only option
> that removes it completely is not running it: Tails on a separate x86 machine, or
> dedicated hardware.

---

## The simplest path

```sh
npm run wizard
```

The wizard walks through all the steps below in order and will not let you skip
the verification. The rest of this document is the same thing done by hand, if you
prefer the control.

---

## Step 1. While you are still online

A separate local directory, **not** synced with iCloud, Dropbox or Google Drive.

```sh
git clone https://github.com/ilyamk/heatdeath.git
cd heatdeath
rm -rf node_modules
npm ci --ignore-scripts
npm audit --omit=dev
npm run self-test
npm run prove-sandbox
```

The expected result: `Self-test OK` and `6/6 capability probes denied`.
If something is off — **do not continue**.

Save the file hashes separately (for example, photograph the screen with a phone
that then takes no part in the generation):

```sh
shasum -a 256 generate.mjs slip39.mjs package.json package-lock.json
```

---

## Step 2. Prepare the terminal

This is not a formality. What gets attacked is the scrollback, not the
cryptography.

- **iTerm2 → Settings → General → Magic → turn off Instant Replay.**
  It writes the contents of the session to disk even if you saved nothing.
- In the same place: Profiles → Terminal → uncheck "Unlimited scrollback".
- Quit clipboard managers: Raycast Clipboard History, Paste, Alfred.
- Do not run this inside `tmux` or `screen`.
- Close browsers and messengers.
- Make sure the directory is not covered by Time Machine.

---

## Step 3. Disconnect everything

Wi-Fi, Ethernet, Bluetooth, AirDrop, Screen Sharing, Continuity.

The tool will warn you if it sees interfaces that are up, but checking is your
job.

---

## Step 4. Generate

```sh
npm run generate:dice
```

1. Roll the die **at least 128 times** and enter the results as the digits 1–6.
   Input is hidden; only the counter is echoed back.

   > **This is a real physical die, not generation by the system.** That is the
   > whole point: the numbers do not come from the computer. Do not roll them one
   > at a time — throw a handful of 5–6 dice and read them left to right, and then
   > 128 rolls is about 22 throws with six dice, or 26 with five, which is 5–7 minutes.
   >
   > You can enter them **in batches**: press Enter after a handful, the counter
   > updates, carry on. Nothing is lost between batches. `cancel` on an empty line
   > switches to automatic mode.
   >
   > **Declining the dice is fine.** Then you get 256 bits from three OS sources,
   > and that is a fully secure wallet. The dice close one specific scenario: a
   > broken or backdoored RNG in the OS itself. They are mixed in by XOR and cannot
   > make the result worse.
2. At the passphrase question, press Enter (empty = a standard wallet). If you
   decide to set one — read the warning in full: a forgotten passphrase means the
   irrecoverable loss of the funds.
3. **Copy the 24 words onto paper by hand.** Do not photograph them. Do not copy
   them. Do not enter them anywhere except the next step.
4. Check what you wrote against the `read-back` line.
5. Write down separately the `master fingerprint` and the address at **index 1**.

> Why index 1 and not 0: for both derivation schemes the path at `i = 0` is
> literally the same, and the fingerprint does not depend on the scheme. Neither of
> them will distinguish the `metamask` scheme from `account`. Index 1 will.

---

## Step 5. Check that you wrote it down correctly

Do not skip this. A transcription error is the most frequent cause of real losses,
far ahead of any attack.

```sh
npm run verify
```

Enter the phrase **from the paper**, not from the screen. Both the fingerprint and
the address at index 1 must match.

If the tool says a word is not in the wordlist, it will suggest the nearest ones.
If it says the checksum does not match while all the words are correct, then the
**order** of the words is wrong.

---

## Step 6. Protect the paper against loss

A single piece of paper is a single point of failure.

```sh
npm run split -- --shares=2of3
```

You get three shares. Any two restore the wallet, one gives **nothing**.
Distribute them across three different physical places. Two shares in one drawer
is one share with extra steps.

Check that the shares work **before you rely on them**:

```sh
npm run combine
```

Enter any two shares and confirm that you get the same phrase and the same
address.

---

## Step 6b (optional). Transfer through 1Password

If you use 1Password and do not want to retype a dozen secrets by hand, there is a
command that puts everything generated into a single item — as a **staging buffer
for the moment of creation**, which you then delete.

### What to install in advance

```sh
brew install --cask 1password          # the app, if you do not have it yet
brew install --cask 1password-cli      # the CLI, provides the `op` command
op --version                           # check
```

Then, in the app: **1Password → Settings → Developer → "Integrate with 1Password
CLI"**. Without that checkbox nothing will work.

Confirm that the pairing is alive — the app will ask for Touch ID:

```sh
op vault list
```

### The rehearsal first

```sh
npm run op-export:dry
```

It goes the whole way and should finish with the line
`DRY RUN succeeded - op accepted the item and wrote NOTHING`. It writes nothing.
The questions are the same as in the real run.

### Two modes

The command will ask `new or existing?`

| Mode | When |
|---|---|
| **`new`** | You do not have a wallet yet. The command will generate one itself (with dice, if you want), show the phrase, **wait until you have written it down on paper**, split it into SLIP-39 shares and store everything |
| **`existing`** | You already have the phrase. You type the 24 words in from paper; after that it is the same |

In both cases the **master fingerprint** and the **address at index 1** are printed
before the write — compare them with what you recorded.

### The real run

```sh
npm run op-export
```

1Password will ask for confirmation. At the end the command prints a ready-made
line to delete the item.

### What you need to understand

> **Three SLIP-39 shares in one vault is not a threshold backup.** It is a secret
> in one place. For a short-lived buffer that is acceptable; for storage it is not.
>
> **Delete the item** as soon as you have distributed the contents: the shares to
> three different physical places, the phrase onto paper.
>
> The seed leaves your machine in the process: 1Password syncs it to their servers
> in encrypted form.
>
> The command works at **5/6** instead of 6/6, because it has to launch `op`, and
> our runtime does not restrict `op` in any way. That is why it is a separate
> command — generation and the wizard keep the full sandbox.

If what you need is **storage** rather than a buffer, keep **one** SLIP-39 share in
1Password. Below the threshold a share gives nothing, and a compromise of the vault
is harmless.

A detailed analysis of the vectors:
[README](README.en.md#what-vectors-this-adds--and-what-has-been-done-about-them).

---

## Step 7. Cover your tracks

```sh
clear && printf '\e[3J'
```

Close the terminal window entirely. Shut the Mac down.

---

## Step 8. Before you move money

1. Import the phrase into MetaMask or Rabby. The addresses must match the ones you
   wrote down.
2. Move a small amount. Confirm that it is visible and that you can send it back.
3. Only after that move meaningful amounts.

---

## What you must not do

- Photograph the phrase or the shares.
- Store them in notes, a password manager, the cloud, a messenger — anywhere in
  digital form.
- Enter the phrase on any website. Not one. Ever.
- Use the same seed for a "hot" wallet and for savings.

## If the amount is serious

A hardware wallet takes your computer's entire threat model off the table: the
seed never ends up in the memory of a general-purpose machine. Generate it there,
and use this tool in `npm run verify` mode to confirm the addresses independently.
More detail — [docs/en/COMPARISON.md](docs/en/COMPARISON.md) (in Russian).
