#!/usr/bin/env bash
# Start Postgres + Redis, build server/worker, run migrations via server boot.
# Usage: ./scripts/run_e2e_stack.sh [start|stop|status]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PG_NAME="${WEISSMAN_PG_CONTAINER:-weissman-postgres}"
REDIS_NAME="${WEISSMAN_REDIS_CONTAINER:-weissman-redis}"
PG_PORT="${WEISSMAN_PG_PORT:-5432}"
REDIS_PORT="${WEISSMAN_REDIS_PORT:-6379}"
SERVER_PORT="${WEISSMAN_E2E_PORT:-8000}"
PID_DIR="${ROOT}/.e2e-stack"
SERVER_PID="${PID_DIR}/weissman-server.pid"
WORKER_PID="${PID_DIR}/weissman-worker.pid"
LOG_DIR="${PID_DIR}/logs"

mkdir -p "$PID_DIR" "$LOG_DIR"

load_env() {
  if [[ -f "$ROOT/.env" ]]; then
    set -a
    # shellcheck disable=SC1091
    source "$ROOT/.env"
    set +a
  fi
  export DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@127.0.0.1:${PG_PORT}/weissman}"
  export WEISSMAN_AUTH_DATABASE_URL="${WEISSMAN_AUTH_DATABASE_URL:-$DATABASE_URL}"
  export WEISSMAN_MIGRATE_URL="${WEISSMAN_MIGRATE_URL:-postgres://postgres:postgres@127.0.0.1:${PG_PORT}/weissman}"
  export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:${REDIS_PORT}/0}"
  export PORT="${PORT:-$SERVER_PORT}"
  export WEISSMAN_BILLING_STRICT="${WEISSMAN_BILLING_STRICT:-0}"
  export WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD="${WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD:-1}"
  export RUST_LOG="${RUST_LOG:-warn,weissman=info,async_jobs=info}"
}

start_infra() {
  if ! docker info >/dev/null 2>&1; then
    echo "Docker not available — start dockerd first" >&2
    exit 1
  fi
  if ! docker ps -a --format '{{.Names}}' | grep -qx "$PG_NAME"; then
    docker run -d --name "$PG_NAME" \
      -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=weissman \
      -p "${PG_PORT}:5432" pgvector/pgvector:pg16
  elif [[ "$(docker inspect -f '{{.State.Running}}' "$PG_NAME" 2>/dev/null || echo false)" != true ]]; then
    docker start "$PG_NAME" >/dev/null
  fi
  if ! docker ps -a --format '{{.Names}}' | grep -qx "$REDIS_NAME"; then
    docker run -d --name "$REDIS_NAME" -p "${REDIS_PORT}:6379" redis:7-alpine
  elif [[ "$(docker inspect -f '{{.State.Running}}' "$REDIS_NAME" 2>/dev/null || echo false)" != true ]]; then
    docker start "$REDIS_NAME" >/dev/null
  fi
  echo "Waiting for Postgres on :${PG_PORT}..."
  for _ in $(seq 1 40); do
    if docker exec "$PG_NAME" pg_isready -U postgres -d weissman >/dev/null 2>&1; then
      echo "Postgres ready"
      return 0
    fi
    sleep 1
  done
  echo "Postgres failed to become ready" >&2
  exit 1
}

stop_procs() {
  for f in "$WORKER_PID" "$SERVER_PID"; do
    if [[ -f "$f" ]]; then
      pid="$(cat "$f")"
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
      fi
      rm -f "$f"
    fi
  done
}

start_migrations() {
  load_env
  echo "Applying database migrations..."
  if ! WEISSMAN_MIGRATE_URL="${WEISSMAN_MIGRATE_URL}" cargo run -q -p weissman-db --example run_migrate; then
    echo "Database migrations failed" >&2
    exit 1
  fi
}

start_apps() {
  load_env
  start_migrations
  if [[ -z "${WEISSMAN_JWT_SECRET:-}" || -z "${WEISSMAN_ADMIN_PASSWORD:-}" ]]; then
    echo "Set WEISSMAN_JWT_SECRET and WEISSMAN_ADMIN_PASSWORD in .env" >&2
    exit 1
  fi
  echo "Building weissman-server + weissman-worker..."
  cargo build -p weissman-db -p weissman-server -p weissman-worker --quiet
  stop_procs
  echo "Starting weissman-server on :${PORT}..."
  env -u WEISSMAN_MIGRATE_URL "$ROOT/target/debug/weissman-server" >"$LOG_DIR/server.log" 2>&1 &
  echo $! >"$SERVER_PID"
  echo "Starting weissman-worker..."
  # Large-stack engine threads are spawned per job; default Tokio worker stack is sufficient.
  "$ROOT/target/debug/weissman-worker" >"$LOG_DIR/worker.log" 2>&1 &
  echo $! >"$WORKER_PID"
  echo "Waiting for /api/health..."
  for _ in $(seq 1 90); do
    if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
      echo "Stack ready — server :${PORT}, logs in ${LOG_DIR}"
      return 0
    fi
    sleep 1
  done
  echo "Server failed health check — tail ${LOG_DIR}/server.log" >&2
  tail -40 "$LOG_DIR/server.log" >&2 || true
  exit 1
}

cmd="${1:-start}"
case "$cmd" in
  start)
    start_infra
    start_apps
    ;;
  stop)
    stop_procs
    ;;
  status)
    load_env
    curl -sf "http://127.0.0.1:${PORT}/api/health" && echo || echo "server down"
    docker ps --filter "name=${PG_NAME}|${REDIS_NAME}" --format '{{.Names}}\t{{.Status}}' || true
    ;;
  *)
    echo "Usage: $0 [start|stop|status]" >&2
    exit 1
    ;;
esac
