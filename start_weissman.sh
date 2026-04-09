#!/bin/bash
# Weissman — single Rust HTTP entrypoint (`weissman-server`). No Python web/Celery.

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [ -f ".env" ]; then
  set -a
  source .env
  set +a
  echo "[*] Loaded .env"
fi

mkdir -p data
export WEISSMAN_STATIC="${WEISSMAN_STATIC:-$ROOT/frontend/dist}"
export PORT="${PORT:-8000}"

RUST_BIN="$ROOT/target/release/weissman-server"
if [ ! -x "$RUST_BIN" ]; then
  echo "[*] Building weissman-server (workspace release)..."
  (cd "$ROOT" && cargo build --release -p weissman-server 2>&1) || {
    echo "[!] Build failed. Install Rust: https://rustup.rs"
    exit 1
  }
fi
[ ! -x "$RUST_BIN" ] && RUST_BIN="$ROOT/target/debug/weissman-server"

if [ ! -f "frontend/dist/index.html" ] && [ -d "frontend" ]; then
  echo "[*] Building frontend (npm run build)..."
  (cd frontend && npm run build 2>/dev/null) || echo "[*] Frontend build skipped; API-only."
fi

echo ""
echo "=============================================="
echo "  WEISSMAN — weissman-server (production path)"
echo "=============================================="
echo "  http://localhost:$PORT"
echo "  DATABASE_URL must be set (Postgres)"
echo "  Ctrl+C to stop"
echo "=============================================="
echo ""

exec "$RUST_BIN"
