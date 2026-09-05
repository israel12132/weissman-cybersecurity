#!/usr/bin/env bash
# Pin wasm-bindgen-cli to the wasm-bindgen *crate* version in Cargo.lock.
# A newer CLI against an older crate emits a schema-version mismatch and
# `npm run build` never writes frontend/dist.
set -euo pipefail

wanted_wasm_bindgen_cli() {
  python3 - <<'PY'
import re
from pathlib import Path
text = Path("Cargo.lock").read_text()
m = re.search(r'(?m)^name = "wasm-bindgen"\nversion = "([^"]+)"', text)
if not m:
    raise SystemExit("wasm-bindgen crate version not found in Cargo.lock")
print(m.group(1))
PY
}

ensure_wasm_bindgen_cli() {
  local wanted have=""
  wanted="$(wanted_wasm_bindgen_cli)"
  if command -v wasm-bindgen >/dev/null 2>&1; then
    have="$(wasm-bindgen --version 2>/dev/null | awk '{print $NF}')"
  fi
  if [[ "$have" != "$wanted" ]]; then
    echo "Installing wasm-bindgen-cli ${wanted} (have: ${have:-none})..."
    cargo install wasm-bindgen-cli --version "$wanted" --locked --force
  fi
  command -v wasm-bindgen
}
