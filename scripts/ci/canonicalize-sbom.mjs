#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { validateSpdxSbom } from "../../build/release-lib.mjs";
import { readReleaseConfig } from "../../build/release-config.mjs";

const [input, output, commit, epoch] = process.argv.slice(2);
if (!input || !output || !/^[0-9a-f]{40}$/.test(commit ?? "") ||
    !/^\d+$/.test(epoch ?? "")) {
  throw new Error("usage: canonicalize-sbom INPUT OUTPUT COMMIT EPOCH");
}
const root = path.resolve(import.meta.dirname, "../..");
const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const packageLock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
const config = readReleaseConfig(root);
const sbom = JSON.parse(fs.readFileSync(input, "utf8"));

validateSpdxSbom(sbom, { packageJson, packageLock });
sbom.documentNamespace =
  `https://github.com/ilyamk/heatdeath/releases/tag/${config.tag}#spdx-${commit}`;
sbom.creationInfo = {
  created: new Date(Number(epoch) * 1000).toISOString(),
  creators: [`Tool: npm/cli-${config.npmVersion}`],
};
validateSpdxSbom(sbom, { packageJson, packageLock });
fs.writeFileSync(output, `${JSON.stringify(sbom, null, 2)}\n`, { flag: "wx" });
