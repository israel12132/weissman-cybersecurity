#!/bin/bash
# =============================================================================
# Weissman — one command local stack
# =============================================================================
# Starts Docker Postgres + Redis (host ports), then weissman-server + weissman-worker
# on the host. Scans enqueue AND execute. Command Center is served from frontend/dist.
#
# Usage:
#   ./start_weissman.sh              # start everything
#   ./start_weissman.sh stop         # stop server + worker (containers keep running)
#   ./start_weissman.sh status       # docker + HTTP health
#   WEISSMAN_START_DRY_RUN=1 ./start_weissman.sh   # print the plan, start nothing
#
# Production/customer Docker (nginx :80, in-container binaries):
#   ./start_weissman_live.sh --url https://your.domain
# =============================================================================
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

CMD="${1:-start}"
case "$CMD" in
  start|stop|status|help|-h|--help) ;;
  *)
    echo "[!] unknown command: $CMD (try: start | stop | status)" >&2
    exit 1
    ;;
esac
if [[ "$CMD" == "help" || "$CMD" == "-h" || "$CMD" == "--help" ]]; then
  sed -n '2,16p' "$0" | sed 's/^# \?//'
  exit 0
fi

DRY_RUN=0
case "${WEISSMAN_START_DRY_RUN:-0}" in 1|true|yes|TRUE|YES) DRY_RUN=1 ;; esac

PG_NAME="${WEISSMAN_PG_CONTAINER:-weissman-postgres}"
REDIS_NAME="${WEISSMAN_REDIS_CONTAINER:-weissman-redis}"
PG_PORT="${WEISSMAN_PG_PORT:-5432}"
REDIS_PORT="${WEISSMAN_REDIS_PORT:-6379}"
PG_IMAGE="${WEISSMAN_PG_IMAGE:-pgvector/pgvector:pg16}"
REDIS_IMAGE="${WEISSMAN_REDIS_IMAGE:-redis:7-alpine}"
PID_DIR="${ROOT}/data"
SERVER_PID_FILE="${PID_DIR}/weissman-server.pid"
WORKER_PID_FILE="${PID_DIR}/weissman-worker.pid"
WORKER_LOG="${PID_DIR}/weissman-worker.log"
SERVER_LOG="${PID_DIR}/weissman-server.log"
DEFAULT_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/weissman"
DEFAULT_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}/0"

# Snapshot caller-exported keys BEFORE loading files (empty counts as set).
caller_has() { [ -n "${!1+x}" ]; }
CALLER_DATABASE_URL=0; caller_has DATABASE_URL && CALLER_DATABASE_URL=1
CALLER_REDIS_URL=0; caller_has REDIS_URL && CALLER_REDIS_URL=1
CALLER_MIGRATE_URL=0; caller_has WEISSMAN_MIGRATE_URL && CALLER_MIGRATE_URL=1
CALLER_WEISSMAN_ENV=0; caller_has WEISSMAN_ENV && CALLER_WEISSMAN_ENV=1
CALLER_COOKIE=0; caller_has WEISSMAN_COOKIE_SECURE && CALLER_COOKIE=1
CALLER_PUBLIC=0; caller_has WEISSMAN_PUBLIC_BASE_URL && CALLER_PUBLIC=1
CALLER_PORT=0; caller_has PORT && CALLER_PORT=1

DOCKER_STACK_ENV=0

# Load KEY=value without clobbering caller-exported keys. Skip empty values so the
# Docker-stack .env from start_weissman_live.sh (DATABASE_URL=) cannot wipe a URL.
load_env_file() {
  local file="$1"
  [ -f "$file" ] || return 1
  local line key val
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in export\ *) line="${line#export }" ;; esac
    key=${line%%=*}
    val=${line#*=}
    case "$key" in *[!A-Za-z0-9_]*|'') continue ;; esac
    case "$val" in
      \"*\") val=${val#\"}; val=${val%\"} ;;
      \'*\') val=${val#\'}; val=${val%\'} ;;
    esac
    [ -n "$val" ] || continue
    [ -n "${!key+x}" ] || export "$key=$val"
  done < "$file"
  echo "[*] Loaded $file (existing environment wins; empty values skipped)"
}

file_is_docker_stack_env() {
  local f="$1"
  [ -f "$f" ] || return 1
  grep -qE '^WEISSMAN_ENV=production[[:space:]]*$' "$f" || return 1
  local db
  db="$(grep -E '^DATABASE_URL=' "$f" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  [ -z "${db// }" ]
}

url_host_is_local() {
  local u="${1:-}"
  case "$u" in
    *127.0.0.1*|*localhost*|*\[::1\]*) return 0 ;;
    *) return 1 ;;
  esac
}

port_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"
  else
    (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1
  fi
}

gen_secret() {
  openssl rand -base64 48 | tr -d '\n/'
}

gen_password() {
  openssl rand -base64 32 | tr -d '/+=' | head -c 24
}

# --- env assembly -------------------------------------------------------------
load_env_files() {
  local primary="${WEISSMAN_ENV_FILE:-$ROOT/.env.local}"
  if [ -f "$primary" ]; then
    load_env_file "$primary"
    file_is_docker_stack_env "$primary" && DOCKER_STACK_ENV=1
  fi
  # Always also load repo .env for JWT/admin secrets. Empty DATABASE_URL is skipped.
  if [ -f "$ROOT/.env" ] && [ "$ROOT/.env" != "$primary" ]; then
    if file_is_docker_stack_env "$ROOT/.env"; then
      DOCKER_STACK_ENV=1
      echo "[*] $ROOT/.env is the Docker-stack file (empty DATABASE_URL) — loading secrets only, then starting local Docker datastores."
    fi
    load_env_file "$ROOT/.env"
  fi
}

apply_local_defaults() {
  export PORT="${PORT:-8000}"

  if [ -z "${DATABASE_URL:-}" ]; then
    export DATABASE_URL="$DEFAULT_DATABASE_URL"
  fi
  if [ -z "${WEISSMAN_MIGRATE_URL:-}" ]; then
    export WEISSMAN_MIGRATE_URL="$DATABASE_URL"
  fi
  if [ -z "${WEISSMAN_AUTH_DATABASE_URL:-}" ]; then
    export WEISSMAN_AUTH_DATABASE_URL="$DATABASE_URL"
  fi
  if [ -z "${REDIS_URL:-}" ]; then
    export REDIS_URL="$DEFAULT_REDIS_URL"
  fi

  # Docker-stack .env sets WEISSMAN_ENV=production + COOKIE_SECURE=1 for HTTPS compose.
  # A host HTTP server on :8000 cannot use Secure cookies; production guards would also
  # refuse the local postgres:postgres URL path if other secrets were incomplete.
  local force_prod=0
  case "${WEISSMAN_FORCE_PRODUCTION:-0}" in 1|true|yes) force_prod=1 ;; esac
  if [ "$force_prod" -eq 0 ]; then
    if [ "$CALLER_WEISSMAN_ENV" -eq 0 ] && [ "$DOCKER_STACK_ENV" -eq 1 ]; then
      export WEISSMAN_ENV=development
    fi
    if [ "$CALLER_COOKIE" -eq 0 ] && [ "${WEISSMAN_ENV:-}" != "production" ]; then
      export WEISSMAN_COOKIE_SECURE=0
    fi
    if [ "$CALLER_PUBLIC" -eq 0 ] && [ "$DOCKER_STACK_ENV" -eq 1 ]; then
      export WEISSMAN_PUBLIC_BASE_URL="http://127.0.0.1:${PORT}"
    fi
  fi

  export WEISSMAN_ENV="${WEISSMAN_ENV:-development}"
  export WEISSMAN_COOKIE_SECURE="${WEISSMAN_COOKIE_SECURE:-0}"
  export WEISSMAN_BILLING_STRICT="${WEISSMAN_BILLING_STRICT:-0}"
  export WEISSMAN_PUBLIC_BASE_URL="${WEISSMAN_PUBLIC_BASE_URL:-http://127.0.0.1:${PORT}}"
  export WEISSMAN_STATIC="${WEISSMAN_STATIC:-$ROOT/frontend/dist}"
  export WEISSMAN_ADMIN_EMAIL="${WEISSMAN_ADMIN_EMAIL:-admin@localhost}"

  # Prevent weissman-db::env_bootstrap from re-loading the Docker-stack .env and
  # wiping DATABASE_URL / flipping WEISSMAN_ENV back to production.
  export WEISSMAN_SKIP_DOTENV=1
}

ensure_runtime_secrets() {
  if [ -z "${WEISSMAN_JWT_SECRET:-}" ]; then
    export WEISSMAN_JWT_SECRET="$(gen_secret)"
    echo "[*] Generated WEISSMAN_JWT_SECRET (not persisted — set it in .env.local to keep sessions across restarts)"
  fi
  if [ -z "${WEISSMAN_ADMIN_PASSWORD:-}" ]; then
    export WEISSMAN_ADMIN_PASSWORD="$(gen_password)"
    echo "[*] Generated WEISSMAN_ADMIN_PASSWORD=${WEISSMAN_ADMIN_PASSWORD} (save this; put it in .env.local)"
  fi
  if [ -z "${WEISSMAN_JOB_ORCHESTRATOR_SECRET:-}" ]; then
    export WEISSMAN_JOB_ORCHESTRATOR_SECRET="$(gen_secret)"
    echo "[*] Generated WEISSMAN_JOB_ORCHESTRATOR_SECRET (server and worker share this for the job bus)"
  fi
}

print_plan() {
  echo "PLAN docker_postgres=${PG_NAME}"
  echo "PLAN docker_redis=${REDIS_NAME}"
  echo "PLAN pg_image=${PG_IMAGE}"
  echo "PLAN pg_port=${PG_PORT}"
  echo "PLAN redis_port=${REDIS_PORT}"
  echo "PLAN DATABASE_URL=${DATABASE_URL}"
  echo "PLAN REDIS_URL=${REDIS_URL}"
  echo "PLAN WEISSMAN_MIGRATE_URL=${WEISSMAN_MIGRATE_URL}"
  echo "PLAN WEISSMAN_ENV=${WEISSMAN_ENV}"
  echo "PLAN WEISSMAN_COOKIE_SECURE=${WEISSMAN_COOKIE_SECURE}"
  echo "PLAN WEISSMAN_PUBLIC_BASE_URL=${WEISSMAN_PUBLIC_BASE_URL}"
  echo "PLAN PORT=${PORT}"
  echo "PLAN SKIP_DOTENV=${WEISSMAN_SKIP_DOTENV}"
  echo "PLAN docker_stack_env=${DOCKER_STACK_ENV}"
  if [ "${WEISSMAN_SKIP_WORKER:-0}" = "1" ]; then echo "PLAN worker=0"; else echo "PLAN worker=1"; fi
}

# --- Docker -------------------------------------------------------------------
ensure_docker() {
  if docker info >/dev/null 2>&1; then
    echo "[*] Docker daemon is up"
    return 0
  fi
  echo "[*] Docker daemon not running — starting dockerd..."
  if ! command -v dockerd >/dev/null 2>&1; then
    echo "[!] dockerd is not installed. Install Docker Engine, then re-run ./start_weissman.sh" >&2
    exit 1
  fi
  sudo dockerd >/tmp/weissman-dockerd.log 2>&1 &
  local i
  for i in $(seq 1 50); do
    sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
    if docker info >/dev/null 2>&1; then
      echo "[*] Docker daemon is up"
      return 0
    fi
    sleep 0.4
  done
  echo "[!] Docker failed to start. Last dockerd log:" >&2
  tail -30 /tmp/weissman-dockerd.log >&2 || true
  exit 1
}

container_exists() {
  docker ps -a --format '{{.Names}}' | grep -qx "$1"
}

container_running() {
  [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = "true" ]
}

ensure_postgres() {
  url_host_is_local "${DATABASE_URL:-}" || {
    echo "[*] DATABASE_URL is not local — not starting Docker Postgres"
    return 0
  }
  if container_exists "$PG_NAME"; then
    if ! container_running "$PG_NAME"; then
      echo "[*] Starting existing container $PG_NAME..."
      docker start "$PG_NAME" >/dev/null
    else
      echo "[*] $PG_NAME already running"
    fi
  elif port_listening "$PG_PORT"; then
    echo "[*] Port ${PG_PORT} is already listening — using host Postgres (no new container)"
    return 0
  else
    echo "[*] Creating $PG_NAME ($PG_IMAGE) on 127.0.0.1:${PG_PORT}..."
    docker run -d --name "$PG_NAME" \
      --restart unless-stopped \
      -e POSTGRES_USER=postgres \
      -e POSTGRES_PASSWORD=postgres \
      -e POSTGRES_DB=weissman \
      -p "127.0.0.1:${PG_PORT}:5432" \
      "$PG_IMAGE" >/dev/null
  fi
  echo "[*] Waiting for Postgres on :${PG_PORT}..."
  local i
  for i in $(seq 1 60); do
    if container_exists "$PG_NAME" && docker exec "$PG_NAME" pg_isready -U postgres -d weissman >/dev/null 2>&1; then
      echo "[*] Postgres ready"
      return 0
    fi
    if command -v pg_isready >/dev/null 2>&1 && pg_isready -h 127.0.0.1 -p "$PG_PORT" -U postgres >/dev/null 2>&1; then
      echo "[*] Postgres ready (host)"
      return 0
    fi
    sleep 1
  done
  echo "[!] Postgres did not become ready" >&2
  docker logs --tail 50 "$PG_NAME" >&2 || true
  exit 1
}

ensure_redis() {
  url_host_is_local "${REDIS_URL:-}" || {
    echo "[*] REDIS_URL is not local — not starting Docker Redis"
    return 0
  }
  if container_exists "$REDIS_NAME"; then
    if ! container_running "$REDIS_NAME"; then
      echo "[*] Starting existing container $REDIS_NAME..."
      docker start "$REDIS_NAME" >/dev/null
    else
      echo "[*] $REDIS_NAME already running"
    fi
  elif port_listening "$REDIS_PORT"; then
    echo "[*] Port ${REDIS_PORT} is already listening — using host Redis (no new container)"
    return 0
  else
    echo "[*] Creating $REDIS_NAME ($REDIS_IMAGE) on 127.0.0.1:${REDIS_PORT}..."
    docker run -d --name "$REDIS_NAME" \
      --restart unless-stopped \
      -p "127.0.0.1:${REDIS_PORT}:6379" \
      "$REDIS_IMAGE" >/dev/null
  fi
  echo "[*] Waiting for Redis on :${REDIS_PORT}..."
  local i
  for i in $(seq 1 40); do
    if container_exists "$REDIS_NAME" && docker exec "$REDIS_NAME" redis-cli ping 2>/dev/null | grep -q PONG; then
      echo "[*] Redis ready"
      return 0
    fi
    sleep 0.5
  done
  echo "[!] Redis did not become ready" >&2
  docker logs --tail 30 "$REDIS_NAME" >&2 || true
  exit 1
}

# --- binaries -----------------------------------------------------------------
resolve_bin() {
  local name="$1"
  local profile="${WEISSMAN_BUILD_PROFILE:-}"
  if [ "$profile" = "release" ] && [ -x "$ROOT/target/release/$name" ]; then
    echo "$ROOT/target/release/$name"
    return
  fi
  if [ "$profile" = "debug" ] && [ -x "$ROOT/target/debug/$name" ]; then
    echo "$ROOT/target/debug/$name"
    return
  fi
  if [ -x "$ROOT/target/release/$name" ]; then
    echo "$ROOT/target/release/$name"
    return
  fi
  if [ -x "$ROOT/target/debug/$name" ]; then
    echo "$ROOT/target/debug/$name"
    return
  fi
  echo ""
}

ensure_binaries() {
  local server worker need=()
  server="$(resolve_bin weissman-server)"
  worker="$(resolve_bin weissman-worker)"
  [ -n "$server" ] || need+=(weissman-server)
  if [ "${WEISSMAN_SKIP_WORKER:-0}" != "1" ]; then
    [ -n "$worker" ] || need+=(weissman-worker)
  fi
  if [ "${#need[@]}" -eq 0 ]; then
    SERVER_BIN="$server"
    WORKER_BIN="$worker"
    return 0
  fi
  local profile="${WEISSMAN_BUILD_PROFILE:-debug}"
  echo "[*] Building ${need[*]} (cargo build -p … --${profile})..."
  local args=(build)
  [ "$profile" = "release" ] && args+=(--release)
  local p
  for p in "${need[@]}"; do args+=(-p "$p"); done
  (cd "$ROOT" && cargo "${args[@]}") || {
    echo "[!] Build failed. Install Rust: https://rustup.rs" >&2
    exit 1
  }
  SERVER_BIN="$(resolve_bin weissman-server)"
  WORKER_BIN="$(resolve_bin weissman-worker)"
  [ -x "$SERVER_BIN" ] || { echo "[!] weissman-server binary missing after build" >&2; exit 1; }
}

ensure_frontend() {
  [ -d "$ROOT/frontend" ] || return 0
  [ "${WEISSMAN_SKIP_FRONTEND_BUILD:-0}" = "1" ] && return 0
  if [ -f "$ROOT/frontend/dist/index.html" ]; then
    echo "[*] frontend/dist present — set WEISSMAN_SKIP_FRONTEND_BUILD=1 to skip, or rm -rf frontend/dist to rebuild."
    return 0
  fi
  echo "[*] Building frontend (npm run build)..."
  if ! (cd "$ROOT/frontend" && npm run build); then
    echo "[!] Frontend build FAILED. Fix it, or set WEISSMAN_SKIP_FRONTEND_BUILD=1 to run API-only on purpose." >&2
    exit 1
  fi
}

pid_alive() {
  local f="$1"
  [ -f "$f" ] || return 1
  local pid
  pid="$(cat "$f" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

stop_stack() {
  local f pid
  for f in "$SERVER_PID_FILE" "$WORKER_PID_FILE"; do
    if pid_alive "$f"; then
      pid="$(cat "$f")"
      echo "[*] Stopping pid $pid ($f)"
      kill "$pid" 2>/dev/null || true
      local i
      for i in $(seq 1 20); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.2
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$f"
  done
  echo "[*] Server/worker stopped. Docker Postgres/Redis left running (data persists)."
}

status_stack() {
  echo "Docker:"
  if docker info >/dev/null 2>&1; then
    docker ps --filter "name=${PG_NAME}" --filter "name=${REDIS_NAME}" --format '  {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
  else
    echo "  daemon down"
  fi
  echo "Processes:"
  if pid_alive "$SERVER_PID_FILE"; then echo "  server pid $(cat "$SERVER_PID_FILE") running"; else echo "  server not running"; fi
  if pid_alive "$WORKER_PID_FILE"; then echo "  worker pid $(cat "$WORKER_PID_FILE") running"; else echo "  worker not running"; fi
  local port="${PORT:-8000}"
  if curl -sf "http://127.0.0.1:${port}/api/health" >/dev/null 2>&1; then
    echo "  health: ok  http://127.0.0.1:${port}/api/health"
  else
    echo "  health: down"
  fi
}

WORKER_PID=""
SERVER_CHILD=""
cleanup() {
  trap - EXIT INT TERM
  if [ -n "${WORKER_PID:-}" ] && kill -0 "$WORKER_PID" 2>/dev/null; then
    kill "$WORKER_PID" 2>/dev/null || true
    wait "$WORKER_PID" 2>/dev/null || true
  fi
  if [ -n "${SERVER_CHILD:-}" ] && kill -0 "$SERVER_CHILD" 2>/dev/null; then
    kill "$SERVER_CHILD" 2>/dev/null || true
    wait "$SERVER_CHILD" 2>/dev/null || true
  fi
  rm -f "$SERVER_PID_FILE" "$WORKER_PID_FILE"
}

start_stack() {
  mkdir -p "$PID_DIR"
  if pid_alive "$SERVER_PID_FILE"; then
    echo "[!] weissman-server already running (pid $(cat "$SERVER_PID_FILE")). ./start_weissman.sh stop" >&2
    exit 1
  fi
  if port_listening "${PORT}"; then
    echo "[!] Port ${PORT} is already in use. Stop the other process or set PORT=…" >&2
    exit 1
  fi

  trap cleanup EXIT INT TERM

  if [ "${WEISSMAN_SKIP_WORKER:-0}" != "1" ]; then
    echo "[*] Starting weissman-worker..."
    : >"$WORKER_LOG"
    "$WORKER_BIN" >>"$WORKER_LOG" 2>&1 &
    WORKER_PID=$!
    echo "$WORKER_PID" >"$WORKER_PID_FILE"
    sleep 0.4
    if ! kill -0 "$WORKER_PID" 2>/dev/null; then
      echo "[!] weissman-worker exited immediately. Tail of ${WORKER_LOG}:" >&2
      tail -40 "$WORKER_LOG" >&2 || true
      exit 1
    fi
  else
    echo "[*] WEISSMAN_SKIP_WORKER=1 — scans will enqueue but not execute"
  fi

  echo ""
  echo "=============================================="
  echo "  WEISSMAN — local stack (Docker + host)"
  echo "=============================================="
  echo "  Command Center : http://127.0.0.1:${PORT}/command-center/"
  echo "  API health     : http://127.0.0.1:${PORT}/api/health"
  echo "  Postgres       : ${PG_NAME}  ${DATABASE_URL%%@*}@…"
  echo "  Redis          : ${REDIS_NAME}  ${REDIS_URL}"
  echo "  Admin email    : ${WEISSMAN_ADMIN_EMAIL}"
  echo "  Worker         : $([ "${WEISSMAN_SKIP_WORKER:-0}" = "1" ] && echo skipped || echo "pid ${WORKER_PID}  log ${WORKER_LOG}")"
  echo ""
  echo "  Ctrl+C stops server + worker. Docker datastores keep running."
  echo "  Full in-container prod stack: ./start_weissman_live.sh"
  echo "=============================================="
  echo ""

  "$SERVER_BIN" &
  SERVER_CHILD=$!
  echo "$SERVER_CHILD" >"$SERVER_PID_FILE"

  local i
  for i in $(seq 1 90); do
    if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
      echo "[*] weissman-server healthy on :${PORT}"
      break
    fi
    if ! kill -0 "$SERVER_CHILD" 2>/dev/null; then
      echo "[!] weissman-server exited before becoming healthy" >&2
      wait "$SERVER_CHILD" || true
      exit 1
    fi
    sleep 1
    if [ "$i" -eq 90 ]; then
      echo "[!] Timed out waiting for /api/health" >&2
      exit 1
    fi
  done

  wait "$SERVER_CHILD"
}

# --- dispatch -----------------------------------------------------------------
load_env_files
apply_local_defaults

if [ "$DRY_RUN" -eq 1 ]; then
  print_plan
  exit 0
fi

case "$CMD" in
  stop)
    stop_stack
    exit 0
    ;;
  status)
    status_stack
    exit 0
    ;;
esac

ensure_runtime_secrets
ensure_docker
ensure_postgres
ensure_redis
ensure_binaries
ensure_frontend
start_stack
