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
  local dest="bin/agents/${platform}/weissman-agent"
  mkdir -p "bin/agents/${platform}"

  if [[ "$rust_target" == "$(rustc -vV | awk '/host:/ {print $2}')" ]]; then
    cp "$HOST_BIN" "$dest"
  elif command -v "rustup" >/dev/null 2>&1; then
    echo "[weissman] cross-compiling weissman-agent for ${rust_target}..."
    rustup target add "$rust_target" >/dev/null 2>&1 || true
    extra_flags=()
    if [[ "$rust_target" == *"-linux-musl" ]]; then
      # Fully static: no glibc version pin on old workstations.
      extra_flags=(-C target-feature=+crt-static)
    fi
    RUSTFLAGS="${RUSTFLAGS:-} ${extra_flags[*]}" cargo build -p weissman-agent --release --target "$rust_target"
    cp "target/${rust_target}/release/weissman-agent" "$dest"
  else
    # Do NOT fall back to copying the host binary here: that would publish a
    # wrong-architecture ELF under ${platform}/ and hash it into MANIFEST.sha256,
    # so the installer's SHA-256 integrity check would PASS on a binary that
    # cannot exec on the target host. Skip the platform entirely instead — the
    # server then returns its existing 404 for this platform rather than a
    # broken binary that vouches for itself.
    echo "[weissman] warn: skipping ${platform} — cannot cross-build ${rust_target} (no rustup); refusing to publish a wrong-arch binary" >&2
    rmdir "bin/agents/${platform}" 2>/dev/null || true
    return 0
  fi

  chmod 755 "$dest"
  local sha
  sha=$(sha256sum "$dest" | awk '{print $1}')
  local bytes
  bytes=$(wc -c < "$dest")
  echo "${sha}  ${platform}/weissman-agent" >> "$MANIFEST"
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
