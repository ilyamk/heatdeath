#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
npm run build >/dev/null
first="$(shasum -a 256 dist/heatdeath.mjs | awk '{print $1}')"
npm run build >/dev/null
second="$(shasum -a 256 dist/heatdeath.mjs | awk '{print $1}')"
if [[ "$first" != "$second" ]]; then
  echo "FATAL: repeated bundle builds differ: $first != $second" >&2
  exit 1
fi
echo "repeated bundle build is byte-identical: $first"
