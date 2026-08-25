#!/usr/bin/env bash
#
# Deterministic release build.
#
# Two artifacts are produced, and the ORDER OF TRUST between them matters:
#
#   dist/heatdeath.mjs   ~276 KB, human-readable, no node_modules.
#                            THIS IS THE PRIMARY ARTIFACT. It is what the
#                            security argument rests on: you can read it.
#
#   dist/heatdeath       ~144 MB single executable. A CONVENIENCE for
#                            people without Node. It contains the same source
#                            as plain text and can be patched by anyone who
#                            has it; treat it as unverified until you have
#                            reproduced its SHA-256 yourself.
#
# Determinism notes, each learned by measurement rather than assumption:
#   * esbuild must run from the repository root with a RELATIVE entry path.
#     An absolute path leaks build-machine directories into the bundle as
#     comments and makes the hash machine-specific.
#   * The SEA output filename is fixed. Ad-hoc codesign embeds the filename
#     as the signing identifier, so renaming changes the binary's bytes.
#   * `node --build-sea` output is bit-identical across runs on the same
#     Node build; the pinned version below is part of the recipe.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ESBUILD_VERSION="0.25.0"
NODE_EXPECTED="v26.5.0"

echo "==> environment"
node_version="$(node -v)"
echo "    node:    ${node_version}"
echo "    esbuild: ${ESBUILD_VERSION}"
if [ "${node_version}" != "${NODE_EXPECTED}" ]; then
  echo "    WARNING: recipe pins ${NODE_EXPECTED}; your binary hash will differ."
fi

echo "==> self-test from source (gate: never ship an untested build)"
node generate.mjs --self-test >/dev/null
echo "    ok"

echo "==> bundle (relative entry path, from repo root)"
mkdir -p dist
npx --yes "esbuild@${ESBUILD_VERSION}" generate.mjs \
  --bundle --platform=node --format=esm \
  --outfile=dist/heatdeath.mjs >/dev/null
echo "    dist/heatdeath.mjs  $(wc -c < dist/heatdeath.mjs) bytes"

echo "==> verify the bundle standalone (no node_modules in scope)"
tmp="$(mktemp -d)"
cp dist/heatdeath.mjs "$tmp/"
( cd "$tmp" && node heatdeath.mjs --self-test >/dev/null )
rm -rf "$tmp"
echo "    ok"

echo "==> single executable"
( cd build && node --build-sea sea.json >/dev/null )
codesign --remove-signature dist/heatdeath 2>/dev/null || true
codesign --sign - dist/heatdeath
echo "    dist/heatdeath      $(wc -c < dist/heatdeath) bytes"

echo "==> verify the binary enforces its sandbox"
denied="$(./dist/heatdeath --prove-sandbox 2>&1 | grep -oE '[0-9]+/[0-9]+ capability' | head -1)"
echo "    ${denied} probes denied"
case "${denied}" in
  6/6*) ;;
  *) echo "    FATAL: sandbox not fully enforced"; exit 1 ;;
esac

echo "==> verify NODE_OPTIONS cannot loosen it (execArgvExtension: none)"
rm -f /tmp/heatdeath-sandbox-probe
NODE_OPTIONS="--allow-fs-write=/tmp" ./dist/heatdeath --prove-sandbox >/dev/null 2>&1
if [ -f /tmp/heatdeath-sandbox-probe ]; then
  echo "    FATAL: sandbox escaped via NODE_OPTIONS"; exit 1
fi
echo "    ok - environment cannot extend the baked-in flags"

echo "==> manifest"
( cd dist && shasum -a 256 heatdeath.mjs heatdeath > SHA256SUMS )
cat dist/SHA256SUMS | sed 's/^/    /'

cat > dist/BUILD-RECIPE.txt <<RECIPE
Reproduce this release
======================

  1. Install Node ${NODE_EXPECTED} (the exact build matters for the binary hash).
  2. git checkout the tag this release was cut from.
  3. rm -rf node_modules && npm ci --ignore-scripts
  4. ./build/build.sh
  5. ( cd dist && shasum -a 256 -c SHA256SUMS )

The .mjs bundle is reproducible on any machine with the same esbuild version
(${ESBUILD_VERSION}); it contains no absolute paths and no timestamps.

The single executable embeds the Node ${NODE_EXPECTED} runtime, so its hash is
reproducible only against that same Node build for the same platform
(darwin/arm64).

If step 5 fails, DO NOT USE THE ARTIFACT. Read the source instead: the .mjs
bundle is the primary artifact precisely because it needs no build to audit.
RECIPE
echo "    dist/BUILD-RECIPE.txt"

echo
echo "Build complete. Sign with:  npm run sign"
