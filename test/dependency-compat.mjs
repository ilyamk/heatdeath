// Upgrade oracle: compare the currently installed crypto packages against an
// explicitly supplied previous node_modules tree. With no argument it is a
// harmless no-op so `node --test` can discover this file.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { secp256k1 as currentSecp } from "@noble/curves/secp256k1.js";
import { keccak_256 as currentKeccak } from "@noble/hashes/sha3.js";
import { HDKey as CurrentHDKey } from "@scure/bip32";
import {
  entropyToMnemonic as currentEntropyToMnemonic,
  mnemonicToEntropy as currentMnemonicToEntropy,
  mnemonicToSeedSync as currentMnemonicToSeed,
} from "@scure/bip39";
import { wordlist as currentWords } from "@scure/bip39/wordlists/english.js";

const oldModules = process.argv[2];
if (oldModules) {
  const load = (relative) => import(pathToFileURL(path.join(oldModules, relative)));
  const [{ secp256k1: oldSecp }, { keccak_256: oldKeccak }, { HDKey: OldHDKey },
    oldBip39, { wordlist: oldWords }] = await Promise.all([
      load("@noble/curves/secp256k1.js"),
      load("@noble/hashes/sha3.js"),
      load("@scure/bip32/index.js"),
      load("@scure/bip39/index.js"),
      load("@scure/bip39/wordlists/english.js"),
    ]);

  assert.deepEqual(currentWords, oldWords, "BIP-39 English wordlist changed");
  const paths = [
    "m/44'/60'/0'/0/0", "m/44'/60'/0'/0/5",
    "m/44'/60'/1'/0/0", "m/44'/60'/7'/0/0",
  ];
  let cases = 0;
  for (const size of [16, 20, 24, 28, 32]) {
    for (let i = 0; i < 40; i += 1) {
      const entropy = createHash("sha256").update(`heatdeath-compat/${size}/${i}`)
        .digest().subarray(0, size);
      const currentMnemonic = currentEntropyToMnemonic(entropy, currentWords);
      const oldMnemonic = oldBip39.entropyToMnemonic(entropy, oldWords);
      assert.equal(currentMnemonic, oldMnemonic);
      assert.deepEqual(
        Buffer.from(currentMnemonicToEntropy(currentMnemonic, currentWords)),
        Buffer.from(oldBip39.mnemonicToEntropy(oldMnemonic, oldWords)),
      );
      const passphrase = i % 2 ? "unicode café 😀" : "TREZOR";
      const currentSeed = currentMnemonicToSeed(currentMnemonic, passphrase);
      const oldSeed = oldBip39.mnemonicToSeedSync(oldMnemonic, passphrase);
      assert.deepEqual(Buffer.from(currentSeed), Buffer.from(oldSeed));

      const currentMaster = CurrentHDKey.fromMasterSeed(currentSeed);
      const oldMaster = OldHDKey.fromMasterSeed(oldSeed);
      assert.equal(currentMaster.fingerprint, oldMaster.fingerprint);
      for (const derivationPath of paths) {
        const currentNode = currentMaster.derive(derivationPath);
        const oldNode = oldMaster.derive(derivationPath);
        assert.deepEqual(Buffer.from(currentNode.privateKey), Buffer.from(oldNode.privateKey));
        assert.deepEqual(Buffer.from(currentNode.publicKey), Buffer.from(oldNode.publicKey));
        assert.deepEqual(
          Buffer.from(currentSecp.getPublicKey(currentNode.privateKey, false)),
          Buffer.from(oldSecp.getPublicKey(oldNode.privateKey, false)),
        );
        assert.deepEqual(
          Buffer.from(currentKeccak(currentNode.publicKey)),
          Buffer.from(oldKeccak(oldNode.publicKey)),
        );
        currentNode.wipePrivateData();
        oldNode.wipePrivateData();
      }
      currentMaster.wipePrivateData();
      oldMaster.wipePrivateData();
      Buffer.from(currentSeed).fill(0);
      Buffer.from(oldSeed).fill(0);
      cases += 1;
    }
  }
  process.stdout.write(
    `dependency compatibility: ${cases} mnemonic/seed cases and ` +
      `${cases * paths.length} BIP-32/secp256k1/Keccak derivations matched\n`,
  );
}
