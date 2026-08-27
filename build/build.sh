#!/usr/bin/env bash
# Developer build: deterministic bundle plus tests. It deliberately does not
# produce, sign, or overwrite release provenance.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ "$(./node_modules/.bin/esbuild --version)" != "0.28.2" ]; then
  echo "FATAL: local esbuild must be exactly 0.28.2" >&2
  exit 1
fi

node --test
node generate.mjs --self-test >/dev/null
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p dist
./node_modules/.bin/esbuild generate.mjs \
  --bundle --platform=node --format=esm --outfile=dist/heatdeath.mjs \
  --metafile="$tmp_dir/esbuild-metafile.json"
node build/check-core-boundary.mjs "$tmp_dir/esbuild-metafile.json"

cp dist/heatdeath.mjs "$tmp_dir/"
(cd "$tmp_dir" && node heatdeath.mjs --self-test >/dev/null)
echo "developer bundle verified: dist/heatdeath.mjs"
