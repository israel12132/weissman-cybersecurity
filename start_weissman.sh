#!/bin/bash
# Weissman — single Rust HTTP entrypoint (`weissman-server`). No Python web/Celery.

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# Load env WITHOUT clobbering anything the caller already exported, so
#   DATABASE_URL=... PORT=9999 ./start_weissman.sh
# works. (`set -a; source .env` did the opposite: every KEY=value in the file overwrote
# the caller's value, and PRODUCTION.env.template ships PORT=8000 + empty DATABASE_URL.)
load_env_file() {
  local file="$1"
  [ -f "$file" ] || return 1
  local line key val
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    key=${line%%=*}
    val=${line#*=}
    # skip malformed / non-identifier keys (comments handled above)
    case "$key" in *[!A-Za-z0-9_]*|'') continue ;; esac
    # caller-exported value wins
    [ -n "${!key+x}" ] || export "$key=$val"
  done < "$file"
  echo "[*] Loaded $file (existing environment wins)"
}

# Prefer a dedicated bare-metal env file. Do NOT auto-source the repo-root .env: that file
# is written by start_weissman_live.sh for the DOCKER stack — it sets WEISSMAN_ENV=production
# and WEISSMAN_COOKIE_SECURE=1 but leaves DATABASE_URL/REDIS_URL/WEISSMAN_MIGRATE_URL empty
# (those are supplied per-container by compose), so sourcing it here yields a server that
# fails production guards or points at nothing.
ENV_FILE="${WEISSMAN_ENV_FILE:-$ROOT/.env.local}"
if [ -f "$ENV_FILE" ]; then
  load_env_file "$ENV_FILE"
elif [ -f "$ROOT/.env" ]; then
  echo "[!] Not sourcing $ROOT/.env — it is the Docker-stack env from start_weissman_live.sh" >&2
  echo "    (WEISSMAN_ENV=production with empty DATABASE_URL/REDIS_URL). For a bare-metal run," >&2
  echo "    export DATABASE_URL yourself, or put local overrides in .env.local (or set WEISSMAN_ENV_FILE)." >&2
fi

if [ -z "${DATABASE_URL:-}" ]; then
  echo "[!] DATABASE_URL is not set — weissman-server needs a reachable Postgres." >&2
  echo "    e.g. DATABASE_URL=postgres://user:pass@localhost:5432/weissman ./start_weissman.sh" >&2
  exit 1
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

if [ -d "frontend" ] && [ "${WEISSMAN_SKIP_FRONTEND_BUILD:-0}" != "1" ]; then
  if [ ! -f "frontend/dist/index.html" ]; then
    echo "[*] Building frontend (npm run build)..."
    # Do NOT swallow the error: a failed UI build must be loud, not a silent downgrade to
    # an API-only server the banner still advertises as the Command Center.
    if ! (cd frontend && npm run build); then
      echo "[!] Frontend build FAILED. Fix it, or set WEISSMAN_SKIP_FRONTEND_BUILD=1 to run API-only on purpose." >&2
      exit 1
    fi
  else
    echo "[*] frontend/dist present — set WEISSMAN_SKIP_FRONTEND_BUILD=1 to skip, or 'rm -rf frontend/dist' to force a rebuild."
  fi
fi

echo ""
echo "=============================================="
echo "  WEISSMAN — weissman-server (production path)"
echo "=============================================="
echo "  http://localhost:$PORT"
echo "  DATABASE_URL is set: ${DATABASE_URL%%@*}@…"
echo ""
echo "  NOTE: this path runs the HTTP server ONLY — no weissman-worker."
echo "  Scans will ENQUEUE but not execute until a worker runs. For the full"
echo "  stack (worker + Redis + Postgres + gateway) use ./start_weissman_live.sh."
echo "  Ctrl+C to stop"
echo "=============================================="
echo ""

exec "$RUST_BIN"
