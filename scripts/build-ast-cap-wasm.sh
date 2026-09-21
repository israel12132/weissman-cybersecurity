#!/usr/bin/env bash
# Compile weissman-ast-cap to WASM for AstTreeViewer mutation capping.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/frontend/src/wasm"
TARGET="wasm32-unknown-unknown"

if ! rustup target list --installed | grep -q "^${TARGET}$"; then
  rustup target add "${TARGET}"
fi

cargo build -p weissman-ast-cap --release --target "${TARGET}" --features wasm

WASM_PATH="$ROOT/target/${TARGET}/release/weissman_ast_cap.wasm"
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
  --out-name weissman_ast_cap

echo "WASM ast-cap module written to $OUT_DIR"
