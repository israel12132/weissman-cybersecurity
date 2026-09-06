#!/usr/bin/env bash
# Install/reuse wasm-bindgen-cli at the exact wasm-bindgen crate version in Cargo.lock.
# An unpinned `cargo install` picks crates.io latest and then fails WASM codegen with
# "schema version mismatch" against the compiled .wasm (0.2.122 crate vs 0.2.128 CLI).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$ROOT/Cargo.lock"
VERSION="$(awk '
  $0 == "name = \"wasm-bindgen\"" { hit = 1; next }
  hit && $1 == "version" {
    gsub(/"/, "", $3)
    print $3
    exit
  }
' "$LOCK")"
if [[ -z "${VERSION}" ]]; then
  echo "ERROR: wasm-bindgen version not found in $LOCK" >&2
  exit 1
fi
HAVE=""
if command -v wasm-bindgen >/dev/null 2>&1; then
  HAVE="$(wasm-bindgen --version 2>/dev/null | awk '{print $NF}')"
fi
if [[ "$HAVE" != "$VERSION" ]]; then
  echo "Installing wasm-bindgen-cli ${VERSION} (have: ${HAVE:-none})..." >&2
  cargo install wasm-bindgen-cli --locked --force --version "$VERSION" >&2
fi
# stdout is captured as the binary path — keep diagnostics on stderr only.
hash -r 2>/dev/null || true
BIN="$(command -v wasm-bindgen || true)"
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  BIN="${CARGO_HOME:-$HOME/.cargo}/bin/wasm-bindgen"
fi
if [[ ! -x "$BIN" ]]; then
  echo "ERROR: wasm-bindgen ${VERSION} not found after install" >&2
  exit 1
fi
printf '%s\n' "$BIN"
