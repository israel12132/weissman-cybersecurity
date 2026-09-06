#!/usr/bin/env bash
# Verify weissman-agent musl builds are fully static (no glibc DT_NEEDED).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail=0

check() {
  local bin="$1"
  if [[ ! -f "$bin" ]]; then
    echo "skip (missing): $bin"
    return 0
  fi
  echo "== $bin"
  file "$bin" || true
  if command -v ldd >/dev/null 2>&1; then
    if ldd "$bin" 2>&1 | grep -qiE 'not a dynamic executable|statically linked'; then
      echo "  static: yes"
      return 0
    fi
    echo "  ERROR: $bin is dynamically linked:" >&2
    ldd "$bin" >&2 || true
    fail=1
    return 1
  fi
  if command -v readelf >/dev/null 2>&1; then
    if readelf -d "$bin" 2>/dev/null | grep -q NEEDED; then
      echo "  ERROR: $bin has DT_NEEDED entries (not fully static)" >&2
      readelf -d "$bin" | grep NEEDED >&2 || true
      fail=1
      return 1
    fi
    echo "  static: yes (no DT_NEEDED)"
  fi
}

check "$ROOT/bin/agents/linux-x86_64-musl/weissman-agent"
check "$ROOT/bin/agents/linux-aarch64-musl/weissman-agent"
check "$ROOT/target/x86_64-unknown-linux-musl/release/weissman-agent"
check "$ROOT/target/x86_64-unknown-linux-musl/debug/weissman-agent"

if [[ "$fail" -ne 0 ]]; then
  echo "weissman-agent musl binary is not fully static" >&2
  exit 1
fi
echo "ok: musl agent binaries that exist are fully static"
