#!/usr/bin/env bash
# Pin wasm-bindgen-cli to the wasm-bindgen *crate* version in Cargo.lock.
# A newer CLI against an older crate emits a schema-version mismatch and
# `npm run build` never writes frontend/dist.
#
# Always resolve Cargo.lock from the repo root (this file lives in scripts/),
# never from the caller's cwd. `cd frontend && npm run build` sources this
# helper; looking at ./Cargo.lock there installs an empty --version and
# deletes a working wasm-bindgen binary.
set -euo pipefail

_weissman_repo_root() {
  local src="${BASH_SOURCE[0]:-$0}"
  (cd "$(dirname "$src")/.." && pwd)
}

wanted_wasm_bindgen_cli() {
  local lock
  lock="${WEISSMAN_CARGO_LOCK:-$(_weissman_repo_root)/Cargo.lock}"
  python3 - "$lock" <<'PY'
import re
import sys
from pathlib import Path
lock = Path(sys.argv[1])
if not lock.is_file():
    raise SystemExit(f"Cargo.lock not found at {lock}")
text = lock.read_text()
m = re.search(r'(?m)^name = "wasm-bindgen"\nversion = "([^"]+)"', text)
if not m:
    raise SystemExit("wasm-bindgen crate version not found in Cargo.lock")
print(m.group(1))
PY
}

ensure_wasm_bindgen_cli() {
  local wanted have=""
  wanted="$(wanted_wasm_bindgen_cli)"
  if [[ -z "$wanted" ]]; then
    echo "ERROR: could not resolve wasm-bindgen version from Cargo.lock" >&2
    return 1
  fi
  if command -v wasm-bindgen >/dev/null 2>&1; then
    have="$(wasm-bindgen --version 2>/dev/null | awk '{print $NF}')"
  fi
  if [[ "$have" != "$wanted" ]]; then
    echo "Installing wasm-bindgen-cli ${wanted} (have: ${have:-none})..."
    cargo install wasm-bindgen-cli --version "$wanted" --locked --force
  fi
  command -v wasm-bindgen
}
