import fs from "node:fs";
import path from "node:path";

export function readReleaseConfig(root = path.resolve(import.meta.dirname, "..")) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  if (!/^\d+\.\d+\.\d+$/.test(pkg.version)) {
    throw new Error("package version must be an exact stable semantic version");
  }
  if (!/^npm@\d+\.\d+\.\d+$/.test(pkg.packageManager ?? "")) {
    throw new Error("packageManager must pin one exact npm version");
  }
  const nodeVersion = fs.readFileSync(path.join(root, ".node-version-release"), "utf8").trim();
  if (!/^\d+\.\d+\.\d+$/.test(nodeVersion)) {
    throw new Error(".node-version-release must contain one exact Node version");
  }
  const esbuild = pkg.devDependencies?.esbuild;
  if (!/^\d+\.\d+\.\d+$/.test(esbuild ?? "")) {
    throw new Error("esbuild must be an exact devDependency");
  }
  const version = pkg.version;
  const sourceArchive = `heatdeath-v${version}-source.tar.gz`;
  const sbom = `heatdeath-v${version}.spdx.json`;
  return Object.freeze({
    version,
    tag: `v${version}`,
    nodeVersion: `v${nodeVersion}`,
    npmVersion: pkg.packageManager.slice("npm@".length),
    esbuild,
    sourceArchive,
    sbom,
    allowedArtifacts: new Set([
      "heatdeath.mjs", "heatdeath", sourceArchive, sbom,
      "SOURCE-PROVENANCE.json", "BUILD-RECIPE.txt",
    ]),
    requiredArtifacts: [
      "heatdeath.mjs", sourceArchive, sbom,
      "SOURCE-PROVENANCE.json", "BUILD-RECIPE.txt",
    ],
  });
}
