# Licensing and third-party content

## This project

**AGPL-3.0-or-later.** The full text is in [LICENSE](LICENSE).

What that means in practice:

- Use it, read it, modify it, run it - freely, including at work.
- **Distribute it or a derivative, and you must release your source under
  AGPL-3.0 too**, with your changes, and keep the copyright notices.
- Section 13 extends that to network use: run a modified version as a service
  and users of that service must be offered its source. (This particular
  program denies itself network access entirely, so section 13 only bites on
  derivatives that add it.)

The choice is deliberate. This is a tool whose only real defence is that
people can read it, so it must stay readable; and a proprietary fork of a
seed generator - unauditable, with no obligation to publish what was changed -
is precisely the artifact this project argues against everywhere else in its
documentation.

### Copyright holder

**Copyright (C) 2026 ILIA MAKSIMENKA.**

A named individual, deliberately. Copyright arises from authorship whatever
name is used, but two things need an identifiable holder, and both are things
this project intends to do:

- **Enforcement.** A demand letter carries weight only if the sender can be
  identified, and a court needs a real party. GitHub's DMCA process, which is
  the practical lever against a fork that strips these notices, requires a
  statement under penalty of perjury - it cannot be filed anonymously.
- **Selling a commercial licence.** Contracts and payments do not happen
  under a pseudonym.

What does not depend on the name, and is the stronger protection day to day:
the dated public commit history, the reproducible build, and the signed
manifest. Anyone can copy the code; nobody can retroactively manufacture the
record of it being written. In a dispute over authorship those carry more
weight than a notice line.

### What a fork must do

Forking is allowed and cannot be prevented - AGPL-3.0 permits it, and GitHub's
Terms of Service grant every user the right to fork a public repository
independently of whatever licence it carries. What the fork is BOUND by is
this, and it is spelled out here so nobody can plead confusion:

| Obligation | Source |
|---|---|
| Keep the LICENSE file and every copyright notice, including the per-file headers | AGPL-3.0 §4, §5 |
| **State prominently that you modified the files, and when** | AGPL-3.0 §5(a) - the one most often skipped |
| Release your modified version under AGPL-3.0, with source. A public repository is distribution | AGPL-3.0 §5(c) |
| Offer source to users if you run a modified version as a network service | AGPL-3.0 §13 |
| Keep NOTICE.md and the third-party notices it reproduces | MIT and BSD terms of the embedded material |

What a fork may **not** do: relicense under MIT, ship a closed-source
derivative, remove the author's name, or sell a proprietary version.

What a fork **may** do, and this is not a loophole but the point of the
licence: use it commercially, charge money for it, run a paid service on it -
provided the source stays available under AGPL-3.0.

**Stripping these notices is a different matter from a licence dispute.** It is
direct copyright infringement, and it is the one case where a DMCA takedown on
GitHub applies. GitHub does not adjudicate open-source licence disputes and
will not act on "they did not publish their changes"; it does act on removed
copyright notices.

### Commercial licensing

AGPL-3.0 is deliberately unsuitable for shipping a closed product. If that is
what you need, a separate commercial licence is available - it lifts the
copyleft obligations for your use, on agreed terms.

To start that conversation, open an issue on the repository titled
`commercial licence`, or write to the address published on the repository's
profile.

> **Maintainer: fill this in before publishing.** Replace the line above with
> a real contact route. An offer with no way to accept it is not an offer, and
> a company that cannot reach you will either use something else or use this
> without asking.

Contributions are accepted under the CLA in [CONTRIBUTING.md](CONTRIBUTING.md),
which is what keeps this option open: without it, a single merged pull request
would remove the ability to license the affected code commercially.

### Compatibility

Every third-party component below is MIT or three-clause BSD. Both are
GPL-compatible, so combining them into an AGPL-3.0 work is permitted, and
their notices are preserved here as their terms require.

---

# Third-party content

This project embeds material from other projects. Their licences apply to
those parts, and are unaffected by the AGPL-3.0 terms above.

## SLIP-39 wordlist and test vectors

`slip39.mjs` embeds the canonical 1024-word SLIP-39 English wordlist, and
`slip39-vectors.json` is a verbatim copy of the reference test vectors.

Both come from **[trezor/python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic)**,
the reference implementation of SLIP-0039, licensed **MIT**.
Copyright (c) 2018 Andrew R. Kozlik, SatoshiLabs.

They are reproduced unmodified. The wordlist's SHA-256 is checked at runtime
against `bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3`;
a mismatch aborts the tool.

Specification: [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md).

## QR error-correction and alignment tables

`qr.mjs` contains two tables that were transcribed programmatically from
**[python-qrcode](https://github.com/lincolnloop/python-qrcode)** rather than
typed by hand: the Reed-Solomon block structure per version and error-
correction level, and the alignment-pattern centre coordinates.

Both are data defined by the QR specification, **ISO/IEC 18004** - they are
facts of the standard, not authored expression. python-qrcode was used as a
convenient, correct transcription source, because typing 320 block-structure
numbers by eye is a guaranteed source of silent corruption.

python-qrcode is BSD-licensed, and its notice is reproduced here as its terms
require:

> Copyright (c) 2011, Lincoln Loop
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
>
> * Redistributions of source code must retain the above copyright notice,
>   this list of conditions and the following disclaimer.
> * Redistributions in binary form must reproduce the above copyright notice,
>   this list of conditions and the following disclaimer in the documentation
>   and/or other materials provided with the distribution.
> * Neither the package name nor the names of its contributors may be used to
>   endorse or promote products derived from this software without specific
>   prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
> AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
> ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
> LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
> CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
> SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
> INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
> CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.

The QR encoder itself in `qr.mjs` shares no code with python-qrcode; it was
written independently and is validated against python-qrcode's output, which
is a different relationship entirely.

## BIP-39 English wordlist

Supplied at runtime by `@scure/bip39` (MIT, Paul Miller). Its SHA-256 is
checked against `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`,
the value published with BIP-39.

## Runtime dependencies

All MIT, all pinned with integrity hashes in `package-lock.json`:

| Package | Version | Author |
|---|---|---|
| `@noble/curves` | 2.2.0 | Paul Miller |
| `@noble/hashes` | 2.2.0 | Paul Miller |
| `@scure/base` | 2.2.0 | Paul Miller |
| `@scure/bip32` | 2.2.0 | Paul Miller |
| `@scure/bip39` | 2.2.0 | Paul Miller |

`@scure/bip39` was audited by Cure53 in January 2022 (funded by the Ethereum
Foundation) and self-audited in April 2026 at version 2.2.0 — the version
pinned here.

## Test vectors from specifications

- BIP-39 official vectors (the "abandon … art" 256-bit case, passphrase
  `TREZOR`) — from the BIP-39 specification.
- EIP-55 checksum vectors — from the EIP-55 specification.
- Hardhat development mnemonic (`test test … junk`) and its account 0 —
  a publicly known development vector. **Never use it for real funds.**
