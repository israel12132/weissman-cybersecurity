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
  "x86_64-pc-windows-gnu:windows-x86_64-msvc"
  "x86_64-apple-darwin:macos-x86_64"
  "aarch64-apple-darwin:macos-aarch64"
)

# linux-gnu links tss-esapi-sys (pkg-config: tss2-sys / tss2-esys / tss2-mu /
# tss2-tctildr). Install libtss2-dev on the build host first. linux-musl is
# cfg-gated off tss-esapi and stays free of libtss2.
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
  local bin_name="weissman-agent"
  if [[ "$platform" == windows-* ]]; then
    bin_name="weissman-agent.exe"
  fi
  local dest="bin/agents/${platform}/${bin_name}"
  mkdir -p "bin/agents/${platform}"

  if [[ "$rust_target" == "$(rustc -vV | awk '/host:/ {print $2}')" ]]; then
    if [[ "$bin_name" == *.exe ]]; then
      cp "$HOST_BIN" "$dest" 2>/dev/null || {
        echo "[weissman] warn: skipping ${platform} — host binary is not a Windows PE" >&2
        rmdir "bin/agents/${platform}" 2>/dev/null || true
        return 0
      }
    else
      cp "$HOST_BIN" "$dest"
    fi
  elif command -v "rustup" >/dev/null 2>&1; then
    echo "[weissman] cross-compiling weissman-agent for ${rust_target}..."
    rustup target add "$rust_target" >/dev/null 2>&1 || true
    if ! cargo build -p weissman-agent --release --target "$rust_target"; then
      echo "[weissman] warn: skipping ${platform} — cross-build ${rust_target} failed; refusing to publish a wrong-arch binary" >&2
      rmdir "bin/agents/${platform}" 2>/dev/null || true
      return 0
    fi
    local built="target/${rust_target}/release/weissman-agent"
    if [[ "$bin_name" == *.exe ]]; then
      built="target/${rust_target}/release/weissman-agent.exe"
    fi
    if [[ ! -f "$built" ]]; then
      echo "[weissman] warn: skipping ${platform} — ${built} missing after build" >&2
      rmdir "bin/agents/${platform}" 2>/dev/null || true
      return 0
    fi
    cp "$built" "$dest"
  else
    echo "[weissman] warn: skipping ${platform} — cannot cross-build ${rust_target} (no rustup); refusing to publish a wrong-arch binary" >&2
    rmdir "bin/agents/${platform}" 2>/dev/null || true
    return 0
  fi

  chmod 755 "$dest" 2>/dev/null || true
  local sha
  sha=$(sha256sum "$dest" | awk '{print $1}')
  local bytes
  bytes=$(wc -c < "$dest")
  echo "${sha}  ${platform}/${bin_name}" >> "$MANIFEST"
  echo "  -> $dest (${bytes} bytes, sha256=${sha:0:16}…)"

  # Cosign blob signature (optional). Installer verifies when .sig is published
  # or WEISSMAN_REQUIRE_COSIGN=1. Keyless/OIDC is out of band; file key here.
  if [[ -n "${COSIGN_KEY:-}" ]] && command -v cosign >/dev/null 2>&1; then
    echo "[weissman] signing ${dest} with cosign sign-blob"
    cosign sign-blob --yes --key "$COSIGN_KEY" --output-signature "${dest}.sig" "$dest"
    echo "  -> ${dest}.sig"
  elif [[ "${WEISSMAN_REQUIRE_COSIGN:-}" == "1" ]]; then
    echo "error: WEISSMAN_REQUIRE_COSIGN=1 but COSIGN_KEY/cosign missing" >&2
    exit 1
  fi
}

echo "[weissman] installing agent binaries + SHA256 manifest..."
for pair in "${TARGETS[@]}"; do
  IFS=: read -r rust_target platform <<< "$pair"
  install_one "$rust_target" "$platform"
done

echo "[weissman] agent binaries ready under bin/agents/ (manifest: ${MANIFEST})"

if [[ -f "bin/agents/windows-x86_64-msvc/weissman-agent.exe" ]]; then
  bash "$ROOT/scripts/package_windows_msi.sh" \
    "bin/agents/windows-x86_64-msvc/weissman-agent.exe" \
    "bin/agents/windows-x86_64-msvc" || true
fi
