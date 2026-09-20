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

# wasm-bindgen-cli MUST match the wasm-bindgen crate version pinned in Cargo.lock
# (0.2.122). A newer CLI emits an incompatible bindgen schema and the build fails with
# "rust Wasm file schema version ... this binary schema version ...". Same pin as
# deploy/frontend.Dockerfile (enforced by scripts/test_launcher_contract.sh). Reinstall
# if the on-PATH CLI is a different version so a stale/cached binary cannot silently
# reintroduce the drift.
WB_VER="0.2.122"
if command -v wasm-bindgen >/dev/null 2>&1 && wasm-bindgen --version 2>/dev/null | grep -qF "${WB_VER}"; then
  BINDGEN=wasm-bindgen
else
  echo "Installing wasm-bindgen-cli ${WB_VER}..."
  cargo install wasm-bindgen-cli --locked --version "${WB_VER}" --force
  BINDGEN="$(command -v wasm-bindgen || true)"
fi

if [[ -z "${BINDGEN:-}" ]]; then
  echo "ERROR: wasm-bindgen-cli ${WB_VER} required. Run: cargo install wasm-bindgen-cli --version ${WB_VER}" >&2
  exit 1
fi

"$BINDGEN" "$WASM_PATH" \
  --out-dir "$OUT_DIR" \
  --target web \
  --no-typescript \
  --out-name weissman_ui_provenance

echo "WASM provenance module written to $OUT_DIR"
