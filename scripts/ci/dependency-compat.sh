#!/usr/bin/env bash
# Compare the current crypto dependency outputs against an independently
# installed base revision. This turns test/dependency-compat.mjs from its
# discovery-safe no-op into a real upgrade gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
BASE_REF="${1:-HEAD}"

git cat-file -e "$BASE_REF^{commit}"
tmp_dir="$(mktemp -d)"
cleanup() {
  if [[ "$tmp_dir" == "${TMPDIR:-/tmp}"/* || "$tmp_dir" == /tmp/* || "$tmp_dir" == /private/tmp/* || "$tmp_dir" == /var/folders/* ]]; then
    chmod -R u+w "$tmp_dir" 2>/dev/null || true
    rm -rf -- "$tmp_dir"
  fi
}
trap cleanup EXIT

git archive "$BASE_REF" | tar -x -C "$tmp_dir"
(cd "$tmp_dir" && npm ci --ignore-scripts)
node test/dependency-compat.mjs "$tmp_dir/node_modules"
