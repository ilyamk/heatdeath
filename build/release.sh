#!/usr/bin/env bash
# Strict release build. This succeeds only from the clean, annotated version
# tag under the exact SEA runtime/platform recorded in provenance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VERSION="$(node -p 'require("./package.json").version')"
TAG="v$VERSION"
NODE_EXPECTED="v$(tr -d '[:space:]' < .node-version-release)"
NPM_EXPECTED="$(node -p 'require("./package.json").packageManager.split("@")[1]')"
SOURCE_ARCHIVE="heatdeath-v${VERSION}-source.tar.gz"
SBOM="heatdeath-v${VERSION}.spdx.json"

if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
  echo "FATAL: release builds require a clean worktree" >&2
  exit 1
fi
if [ "$(git cat-file -t "refs/tags/$TAG" 2>/dev/null || true)" != "tag" ]; then
  echo "FATAL: $TAG must exist as an annotated tag" >&2
  exit 1
fi
commit="$(git rev-parse HEAD)"
if [ "$(git rev-parse "$TAG^{commit}")" != "$commit" ]; then
  echo "FATAL: $TAG does not point to HEAD" >&2
  exit 1
fi
if [ "$(node -v)" != "$NODE_EXPECTED" ] || [ "$(uname -s)" != "Darwin" ] || \
   [ "$(uname -m)" != "arm64" ]; then
  echo "FATAL: SEA release requires Node $NODE_EXPECTED on darwin/arm64" >&2
  exit 1
fi
if [ "$(npm --version)" != "$NPM_EXPECTED" ]; then
  echo "FATAL: release requires npm $NPM_EXPECTED" >&2
  exit 1
fi

./build/build.sh

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
node scripts/ci/create-source-archive.mjs "dist/$SOURCE_ARCHIVE" "$TAG"
npm sbom --sbom-format=spdx > "$tmp_dir/sbom.json"
source_epoch="$(git show -s --format=%ct "$TAG^{commit}")"
node scripts/ci/canonicalize-sbom.mjs \
  "$tmp_dir/sbom.json" "dist/$SBOM" "$commit" "$source_epoch"

(cd build && node --build-sea sea.json >/dev/null)
codesign --remove-signature dist/heatdeath 2>/dev/null || true
codesign --sign - dist/heatdeath

guard_output="$(./dist/heatdeath --prove-guard 2>&1)"
if ! printf '%s\n' "$guard_output" | grep -q '6/6 capability probes denied'; then
  echo "FATAL: SEA capability guard proof failed" >&2
  exit 1
fi

cp build/BUILD-RECIPE.txt dist/BUILD-RECIPE.txt
node_binary="$(command -v node)"
node_hash="$(shasum -a 256 "$node_binary" | awk '{print $1}')"
source_hash="$(shasum -a 256 "dist/$SOURCE_ARCHIVE" | awk '{print $1}')"
sbom_hash="$(shasum -a 256 "dist/$SBOM" | awk '{print $1}')"
node build/release-provenance.mjs \
  "$commit" "$node_hash" "$SOURCE_ARCHIVE" "$source_hash" \
  "$SBOM" "$sbom_hash" "$NPM_EXPECTED"

(cd dist && shasum -a 256 \
  heatdeath.mjs heatdeath "$SOURCE_ARCHIVE" "$SBOM" \
  SOURCE-PROVENANCE.json BUILD-RECIPE.txt > SHA256SUMS)

echo "release artifacts built but NOT signed"
echo "sign each scheme explicitly with npm run sign-release -- --scheme=... --key=/external/..."
