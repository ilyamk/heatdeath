import { combineShares } from "../slip39.mjs";

if (!process.argv.includes("--oracle")) process.exit(0);

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
if (!Array.isArray(payload.mnemonics)) throw new Error("mnemonics array required");
process.stdout.write(Buffer.from(combineShares(payload.mnemonics)).toString("hex"));
