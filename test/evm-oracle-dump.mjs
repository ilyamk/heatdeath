import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";

if (!process.argv.includes("--oracle")) process.exit(0);

const phrase = "test test test test test test test test test test test junk";
const master = HDKey.fromMasterSeed(mnemonicToSeedSync(phrase));
const checksum = (lower) => {
  const digest = bytesToHex(keccak_256(new TextEncoder().encode(lower)));
  return `0x${[...lower].map((character, index) =>
    Number.parseInt(digest[index], 16) >= 8 ? character.toUpperCase() : character).join("")}`;
};

for (const account of [0, 1, 2, 7, 31, 255]) {
  for (const index of [0, 1, 5, 17]) {
    const path = `m/44'/60'/${account}'/0/${index}`;
    const key = master.derive(path).privateKey;
    const publicKey = secp256k1.getPublicKey(key, false);
    const address = checksum(bytesToHex(keccak_256(publicKey.slice(1)).slice(-20)));
    process.stdout.write(`${path}|0x${bytesToHex(key)}|${address}\n`);
  }
}
