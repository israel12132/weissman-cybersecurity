#!/usr/bin/env bash
# Source from a WASM build script (after ROOT is set). Exports BINDGEN: a wasm-bindgen CLI whose
# version matches the `wasm-bindgen` crate pinned in Cargo.lock.
#
# wasm-bindgen's ABI ("schema") is unstable: the CLI must match the crate version the .wasm was
# compiled against exactly, or it aborts with "linked against a different bindgen format".
# `cargo install wasm-bindgen-cli` (no --version) installs the newest release, so a fresh CI runner
# — or a developer whose global CLI moved on — broke `npm run build` the moment upstream published
# a newer CLI than the lock pins. Resolve the version from Cargo.lock instead and install that
# exact CLI under target/ (cached with the rest of the build) when nothing on PATH matches.
set -euo pipefail

: "${ROOT:?ROOT must point at the repository root before sourcing ensure-wasm-bindgen.sh}"

WASM_BINDGEN_VERSION="$(awk '
  /^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, "", $3); print $3; exit }
' "$ROOT/Cargo.lock")"
if [[ -z "$WASM_BINDGEN_VERSION" ]]; then
  echo "ERROR: could not read the wasm-bindgen version from $ROOT/Cargo.lock" >&2
  exit 1
fi

bindgen_matches() {
  local bin="$1"
  [[ -n "$bin" && -x "$bin" ]] || return 1
  [[ "$("$bin" --version 2>/dev/null | awk '{print $2}')" == "$WASM_BINDGEN_VERSION" ]]
}

PINNED_ROOT="$ROOT/target/wasm-bindgen-cli/$WASM_BINDGEN_VERSION"
BINDGEN=""
if bindgen_matches "$(command -v wasm-bindgen || true)"; then
  BINDGEN="$(command -v wasm-bindgen)"
elif bindgen_matches "$PINNED_ROOT/bin/wasm-bindgen"; then
  BINDGEN="$PINNED_ROOT/bin/wasm-bindgen"
else
  echo "Installing wasm-bindgen-cli ${WASM_BINDGEN_VERSION} (matches Cargo.lock) into ${PINNED_ROOT}..."
  cargo install wasm-bindgen-cli --version "$WASM_BINDGEN_VERSION" --locked --root "$PINNED_ROOT"
  BINDGEN="$PINNED_ROOT/bin/wasm-bindgen"
fi

if ! bindgen_matches "$BINDGEN"; then
  echo "ERROR: wasm-bindgen ${WASM_BINDGEN_VERSION} is required (Cargo.lock pin); got: $("$BINDGEN" --version 2>&1)" >&2
  exit 1
fi
export BINDGEN
