#!/bin/bash
# Weissman — full Rust app runtime: weissman-server + weissman-worker, one command. No Python
# web/Celery. Needs a reachable Postgres (DATABASE_URL) and Redis (REDIS_URL); for the
# Docker-managed infra stack use ./start_weissman_live.sh.

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

# Build profile: release by default (production path). WEISSMAN_USE_DEBUG_BUILD=1 uses the faster
# debug build and existing target/debug binaries — handy for local iteration.
if [ "${WEISSMAN_USE_DEBUG_BUILD:-0}" = "1" ]; then
  BUILD_DIR="debug"
  CARGO_PROFILE_FLAG=""
else
  BUILD_DIR="release"
  CARGO_PROFILE_FLAG="--release"
fi

# The worker executes queued scans; without it the server enqueues jobs that never run. Start both
# unless explicitly opted out (WEISSMAN_SKIP_WORKER=1 for an API-only server on purpose).
RUN_WORKER=1
[ "${WEISSMAN_SKIP_WORKER:-0}" = "1" ] && RUN_WORKER=0

# Build server (+ worker) in one cargo invocation so a full app comes up from a clean checkout.
BUILD_PKGS=(-p weissman-server)
[ "$RUN_WORKER" = "1" ] && BUILD_PKGS+=(-p weissman-worker)
RUST_BIN="$ROOT/target/$BUILD_DIR/weissman-server"
WORKER_BIN="$ROOT/target/$BUILD_DIR/weissman-worker"
NEED_BUILD=0
[ ! -x "$RUST_BIN" ] && NEED_BUILD=1
{ [ "$RUN_WORKER" = "1" ] && [ ! -x "$WORKER_BIN" ]; } && NEED_BUILD=1
if [ "$NEED_BUILD" = "1" ]; then
  echo "[*] Building ${BUILD_PKGS[*]} ($BUILD_DIR)..."
  # shellcheck disable=SC2086
  (cd "$ROOT" && cargo build $CARGO_PROFILE_FLAG "${BUILD_PKGS[@]}" 2>&1) || {
    echo "[!] Build failed. Install Rust: https://rustup.rs"
    exit 1
  }
fi

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

# Start the worker in the background and make sure it dies with this script (Ctrl+C, or the
# server exiting), so `start_weissman.sh` never leaves an orphaned worker behind.
WORKER_PID=""
cleanup() {
  if [ -n "$WORKER_PID" ] && kill -0 "$WORKER_PID" 2>/dev/null; then
    echo ""
    echo "[*] Stopping weissman-worker (pid $WORKER_PID)..."
    kill "$WORKER_PID" 2>/dev/null || true
    wait "$WORKER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [ "$RUN_WORKER" = "1" ]; then
  if [ -x "$WORKER_BIN" ]; then
    echo "[*] Starting weissman-worker in background (executes queued scans)..."
    "$WORKER_BIN" &
    WORKER_PID=$!
  else
    echo "[!] weissman-worker binary not found at $WORKER_BIN — scans will enqueue but not run." >&2
  fi
fi

echo ""
echo "=============================================="
echo "  WEISSMAN — full app runtime (server + worker)"
echo "=============================================="
echo "  http://localhost:$PORT/command-center/"
echo "  DATABASE_URL is set: ${DATABASE_URL%%@*}@…"
if [ "$RUN_WORKER" = "1" ] && [ -n "$WORKER_PID" ]; then
  echo "  weissman-worker: running (pid $WORKER_PID) — scans execute"
else
  echo "  weissman-worker: NOT running — scans enqueue only"
fi
echo ""
echo "  Prereqs: a reachable Postgres (DATABASE_URL) and Redis (REDIS_URL)."
echo "  For the Docker-managed stack (Postgres + Redis + gateway) use ./start_weissman_live.sh."
echo "  WEISSMAN_SKIP_WORKER=1 for API-only · WEISSMAN_USE_DEBUG_BUILD=1 for a faster debug build."
echo "  Ctrl+C to stop both."
echo "=============================================="
echo ""

# Run the server in the FOREGROUND (not exec) so the EXIT trap fires and reaps the worker.
"$RUST_BIN"
