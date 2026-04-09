#!/usr/bin/env bash
# Build Vite dashboard to frontend/dist for production (served by Rust at /command-center/).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/frontend"
if [[ -f package-lock.json ]]; then
  npm ci
else
  npm install
fi
npm run build
echo "[weissman] Built static UI: $ROOT/frontend/dist"
echo "[weissman] Run weissman-server or 'fingerprint_engine serve' from repo root, or set WEISSMAN_STATIC=$ROOT/frontend/dist"
