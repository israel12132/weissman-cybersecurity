#!/usr/bin/env bash
# Build a Windows MSI when WiX (candle/light or wixl) is available.
# Always emits a zip of weissman-agent.exe + install.ps1 when the PE exists.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PE="${1:-$ROOT/bin/agents/windows-x86_64-msvc/weissman-agent.exe}"
OUT_DIR="${2:-$ROOT/bin/agents/windows-x86_64-msvc}"
mkdir -p "$OUT_DIR"
if [[ ! -f "$PE" ]]; then
  echo "error: Windows PE not found at $PE — build with scripts/package_agent_binaries.sh first" >&2
  exit 1
fi
cp -f "$ROOT/scripts/agent/install.ps1" "$OUT_DIR/install.ps1"
ZIP="$OUT_DIR/weissman-agent-windows-x86_64.zip"
(cd "$(dirname "$PE")" && zip -q -j "$ZIP" "$(basename "$PE")" install.ps1) || {
  python3 - "$PE" "$OUT_DIR/install.ps1" "$ZIP" <<'PY'
import zipfile, sys
z = zipfile.ZipFile(sys.argv[3], "w")
z.write(sys.argv[1], "weissman-agent.exe")
z.write(sys.argv[2], "install.ps1")
z.close()
PY
}
echo "[weissman] windows zip: $ZIP"

MSI="$OUT_DIR/weissman-agent.msi"
WXS="$ROOT/scripts/agent/weissman-agent.wxs"
STAGE="$(mktemp -d)"
cp "$PE" "$STAGE/weissman-agent.exe"
cp "$WXS" "$STAGE/weissman-agent.wxs"
if command -v wixl >/dev/null 2>&1; then
  (cd "$STAGE" && wixl -o "$MSI" weissman-agent.wxs) && echo "[weissman] MSI: $MSI"
elif command -v candle >/dev/null 2>&1 && command -v light >/dev/null 2>&1; then
  (cd "$STAGE" && candle weissman-agent.wxs && light -out "$MSI" weissman-agent.wixobj) && echo "[weissman] MSI: $MSI"
else
  echo "[weissman] WiX not installed — zip is the Windows package. Install wixl or WiX candle/light to emit $MSI" >&2
fi
rm -rf "$STAGE"
