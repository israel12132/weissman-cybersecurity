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
echo "[weissman] Built Command Center: $ROOT/frontend/dist"
echo "[weissman] Built flagship site: $ROOT/frontend/dist-www"
