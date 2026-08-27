# Safe cold/recovery owner ceremony

[← All documentation](../../README.en.md#documentation) · [🇷🇺 Русский](../ru/SAFE-OWNER.md) · [📖 Glossary](GLOSSARY.md)

HEATDEATH creates one EOA at `m/44'/60'/0'/0/0` for use as a cold or rarely
used recovery owner of a Safe. It does not deploy or inspect the Safe, choose the
Safe threshold, or sign a transaction. Importing the phrase into an online wallet
ends its cold status.

## Safety rules

- Generate every Safe owner from an independent seed, preferably on independent hardware.
- Never derive several owners from this phrase. That would turn several apparent
  approvals into one compromised root secret.
- For high-value primary signers, dedicated hardware generated on its own trusted
  display remains stronger than a general-purpose computer.
- Support, maintainers and design-partner sessions must never see a real phrase,
  share, private key, funded address or wallet balance.

## Rehearse before using a real key

The rehearsal uses the official public 24-word zero-entropy vector and a pinned
public owner address. Every screen says `PUBLIC TEST DATA - NEVER FUND`.

```sh
npm run rehearse:safe-owner
```

Nothing in this mode is secret. Do not type any real seed or passphrase into it.

## Run the ceremony

Use a clean physical machine, disable its network and session recording, then run:

```sh
npm run doctor
npm run safe-owner
```

The flow requires the Node Permission Model, runs the full self-test, offers physical
dice, performs an independent derivation cross-check, clears the phrase before a
mandatory paper read-back, and prints one checksummed owner address plus an address-only QR.

An empty BIP-39 passphrase is the operationally simpler default for a team recovery
key. If one is set, store it separately: SLIP-39 shares do not contain it, and losing
it destroys access permanently.

The optional 2-of-3 shares carry the BIP-39 entropy, not a Trezor-native SLIP-39 seed.
Restore them with HEATDEATH's `combine` command.

## Independent check before Safe setup

End the first session. In a fresh offline session, type the phrase from paper:

```sh
npm run verify -- --accounts=1 --qr
```

Confirm the fixed path, master fingerprint and complete checksummed address. A second
person should compare that address with the owner being added to Safe. Test the
organisation's recovery process before the Safe holds meaningful funds.

If the key is ever activated, document when, why and where its phrase was imported.
After import into a networked wallet it is no longer a cold owner; replace it in the
Safe according to the organisation's approved procedure.

---

<sub>Part of **HEATDEATH**. Copyright © 2026 ILIA MAKSIMENKA. Distributed under
[AGPL-3.0-or-later](../../LICENSE). Russian version: [Русский](../ru/SAFE-OWNER.md).</sub>
