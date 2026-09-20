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

# Pin wasm-bindgen-cli to the Cargo.lock crate version (0.2.122); a mismatched CLI
# breaks the build with a bindgen schema-version error. See build-ui-provenance-wasm.sh.
WB_VER="0.2.122"
if command -v wasm-bindgen >/dev/null 2>&1 && wasm-bindgen --version 2>/dev/null | grep -qF "${WB_VER}"; then
  BINDGEN="$(command -v wasm-bindgen)"
else
  cargo install wasm-bindgen-cli --locked --version "${WB_VER}" --force
  BINDGEN="$(command -v wasm-bindgen || true)"
fi

"$BINDGEN" "$WASM_PATH" \
  --out-dir "$OUT_DIR" \
  --target web \
  --no-typescript \
  --out-name weissman_ast_cap

echo "WASM ast-cap module written to $OUT_DIR"
