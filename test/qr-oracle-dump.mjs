import { encodeQR } from "../qr.mjs";

if (process.argv.length > 2) {
  const [text, versionRaw, ecc, maskRaw] = process.argv.slice(2);
  const symbol = encodeQR(text, {
    ecc,
    mask: Number(maskRaw),
    version: Number(versionRaw),
  });
  process.stdout.write(JSON.stringify({
    size: symbol.size,
    modules: Array.from(symbol.modules, Boolean),
  }));
}
