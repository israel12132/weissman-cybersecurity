#!/usr/bin/env bash
# Package weissman-agent release binaries for /install/agent.sh download endpoints.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[weissman] building weissman-agent (release)..."
cargo build -p weissman-agent --release

BIN="target/release/weissman-agent"
if [[ ! -f "$BIN" ]]; then
  echo "error: $BIN not found" >&2
  exit 1
fi

install_one() {
  local platform="$1"
  local dest="bin/agents/${platform}/weissman-agent"
  mkdir -p "bin/agents/${platform}"
  cp "$BIN" "$dest"
  chmod 755 "$dest"
  echo "  -> $dest ($(wc -c < "$dest") bytes)"
}

echo "[weissman] installing agent binaries..."
install_one "linux-x86_64-gnu"
install_one "linux-aarch64-gnu"
install_one "linux-x86_64-musl"
install_one "linux-aarch64-musl"

echo "[weissman] agent binaries ready under bin/agents/"
