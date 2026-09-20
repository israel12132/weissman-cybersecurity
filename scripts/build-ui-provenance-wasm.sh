#!/usr/bin/env bash
# Compile weissman-ui-provenance to WASM for forensic Command Center badge verification.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/frontend/src/wasm"
TARGET="wasm32-unknown-unknown"

if ! rustup target list --installed | grep -q "^${TARGET}$"; then
  echo "Adding Rust target ${TARGET}..."
  rustup target add "${TARGET}"
fi

echo "Building weissman-ui-provenance for WASM..."
cargo build -p weissman-ui-provenance --release --target "${TARGET}" --features wasm

WASM_PATH="$ROOT/target/${TARGET}/release/weissman_ui_provenance.wasm"
if [[ ! -f "$WASM_PATH" ]]; then
  echo "ERROR: WASM artifact not found at $WASM_PATH" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

# Resolve a wasm-bindgen CLI that matches the crate version pinned in Cargo.lock.
# shellcheck source=scripts/lib/ensure-wasm-bindgen.sh
source "$ROOT/scripts/lib/ensure-wasm-bindgen.sh"

"$BINDGEN" "$WASM_PATH" \
  --out-dir "$OUT_DIR" \
  --target web \
  --no-typescript \
  --out-name weissman_ui_provenance

echo "WASM provenance module written to $OUT_DIR"
