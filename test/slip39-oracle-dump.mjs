import { createHash } from "node:crypto";
import { splitSecretIntoShares } from "../slip39.mjs";

if (!process.argv.includes("--oracle")) process.exit(0);

let counter = 0;
const rng = (length) => {
  const output = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    const block = createHash("sha256")
      .update(`heatdeath/slip39-oracle/${counter++}`)
      .digest();
    offset += block.copy(output, offset);
  }
  return output;
};

const secret = createHash("sha256").update("heatdeath/slip39/master-secret").digest();
const groups = splitSecretIntoShares({
  secret,
  groupThreshold: 2,
  groups: [
    { threshold: 1, count: 1 },
    { threshold: 2, count: 3 },
    { threshold: 2, count: 3 },
  ],
  identifier: 0x1234,
  extendable: true,
  iterationExponent: 1,
  rng,
});

process.stdout.write(JSON.stringify({
  secret: secret.toString("hex"),
  mnemonics: [groups[0][0], groups[1][0], groups[1][1]],
}));
