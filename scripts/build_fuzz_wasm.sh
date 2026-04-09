#!/usr/bin/env bash
# Build fuzz_core for wasm32-unknown-unknown (Cloudflare Workers / Lambda@Edge experiments).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
rustup target add wasm32-unknown-unknown 2>/dev/null || true
RUSTFLAGS='-C opt-level=s' cargo build -p fuzz_core --target wasm32-unknown-unknown --release
mkdir -p fuzz_core/pkg
cp -f target/wasm32-unknown-unknown/release/fuzz_core.wasm fuzz_core/pkg/fuzz_core_bg.wasm
echo "Built: fuzz_core/pkg/fuzz_core_bg.wasm"
echo "ABI version export: fuzz_core_wasm_abi_version (see fuzz_core/src/lib.rs)"
