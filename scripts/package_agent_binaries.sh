#!/usr/bin/env bash
# Package weissman-agent release binaries for /install/agent.sh download endpoints.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGETS=(
  "x86_64-unknown-linux-gnu:linux-x86_64-gnu"
  "aarch64-unknown-linux-gnu:linux-aarch64-gnu"
  "x86_64-unknown-linux-musl:linux-x86_64-musl"
  "aarch64-unknown-linux-musl:linux-aarch64-musl"
)

echo "[weissman] building weissman-agent (release, host native)..."
cargo build -p weissman-agent --release
HOST_BIN="target/release/weissman-agent"
if [[ ! -f "$HOST_BIN" ]]; then
  echo "error: $HOST_BIN not found" >&2
  exit 1
fi

MANIFEST="bin/agents/MANIFEST.sha256"
mkdir -p bin/agents
: > "$MANIFEST"

install_one() {
  local rust_target="$1"
  local platform="$2"
  local dest="bin/agents/${platform}/weissman-agent"
  mkdir -p "bin/agents/${platform}"

  if [[ "$rust_target" == "$(rustc -vV | awk '/host:/ {print $2}')" ]]; then
    cp "$HOST_BIN" "$dest"
  elif command -v "rustup" >/dev/null 2>&1; then
    echo "[weissman] cross-compiling weissman-agent for ${rust_target}..."
    rustup target add "$rust_target" >/dev/null 2>&1 || true
    cargo build -p weissman-agent --release --target "$rust_target"
    cp "target/${rust_target}/release/weissman-agent" "$dest"
  else
    echo "[weissman] warn: skipping ${platform} (no rustup / cross target ${rust_target})"
    cp "$HOST_BIN" "$dest"
  fi

  chmod 755 "$dest"
  local sha
  sha=$(sha256sum "$dest" | awk '{print $1}')
  local bytes
  bytes=$(wc -c < "$dest")
  echo "${sha}  ${platform}/weissman-agent" >> "$MANIFEST"
  echo "  -> $dest (${bytes} bytes, sha256=${sha:0:16}…)"
}

echo "[weissman] installing agent binaries + SHA256 manifest..."
for pair in "${TARGETS[@]}"; do
  IFS=: read -r rust_target platform <<< "$pair"
  install_one "$rust_target" "$platform"
done

echo "[weissman] agent binaries ready under bin/agents/ (manifest: ${MANIFEST})"
