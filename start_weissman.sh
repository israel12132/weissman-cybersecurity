#!/usr/bin/env bash
# =============================================================================
# Weissman — one command that starts the FULL stack after a pull
# =============================================================================
# Postgres · Redis · weissman-server · weissman-worker · Command Center UI
#
# Usage (from the repo root, e.g. ~/weissman-cybersecurity):
#   ./start_weissman.sh --pull     # unstick git, pull main, then start everything
#   ./start_weissman.sh            # start everything (already on latest main)
#   ./start_weissman.sh stop
#   ./start_weissman.sh status
#   ./start_weissman.sh logs
#
# Auto-picks how to run:
#   systemd  — units weissman-server / weissman-worker are installed
#   local    — cargo is on PATH (Docker Postgres/Redis + host binaries)
#   live     — Docker Compose full stack (no host Rust required)
# Override with --live / --local / --systemd or WEISSMAN_START_MODE=.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# rustup installs cargo here; a fresh login shell on Pop!_OS often misses it.
if [[ -f "${HOME}/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  . "${HOME}/.cargo/env"
fi

RUN_DIR="${ROOT}/.weissman-run"
PID_DIR="${RUN_DIR}"
LOG_DIR="${RUN_DIR}/logs"
SERVER_PID="${PID_DIR}/weissman-server.pid"
WORKER_PID="${PID_DIR}/weissman-worker.pid"
PG_NAME="${WEISSMAN_PG_CONTAINER:-weissman-postgres}"
REDIS_NAME="${WEISSMAN_REDIS_CONTAINER:-weissman-redis}"
PG_PORT="${WEISSMAN_PG_PORT:-5432}"
REDIS_PORT="${WEISSMAN_REDIS_PORT:-6379}"

CMD=start
DO_PULL=0
PULL_ONLY=0
MODE="${WEISSMAN_START_MODE:-auto}"
LIVE_ARGS=()

usage() {
  cat <<'USAGE'
Weissman — start the full stack (Postgres, Redis, weissman-server, weissman-worker, Command Center).

Usage:
  ./start_weissman.sh [--pull] [start] [flags]  pull (optional) then start everything
  ./start_weissman.sh --pull-only               unstick git + pull main, then exit
  ./start_weissman.sh stop                      stop server + worker (data stays)
  ./start_weissman.sh status                    show what is running + /api/health
  ./start_weissman.sh logs                      follow server/worker or compose logs

Flags:
  --pull                 abort a stuck merge, stash local edits, checkout main, pull
  --pull-only            same git repair as --pull, then exit without starting
  --live, --docker       force Docker Compose stack (start_weissman_live.sh)
  --local                force host binaries + Docker Postgres/Redis
  --systemd              force systemd unit restart
  --url https://host     passed through to the Docker live launcher
  --email admin@host     passed through to the Docker live launcher
  --no-monitoring        passed through to the Docker live launcher
  --no-build             passed through to the Docker live launcher
  -h, --help             this message

After a laptop pull (Pop!_OS, no host cargo, no systemd units):
  ./start_weissman.sh --pull
USAGE
}

log()  { printf '[weissman] %s\n' "$*"; }
die()  { log "ERROR: $*" >&2; exit 1; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      start|stop|status|logs)
        CMD="$1"
        shift
        ;;
      --pull)
        DO_PULL=1
        shift
        ;;
      --pull-only)
        DO_PULL=1
        PULL_ONLY=1
        shift
        ;;
      --live|--docker)
        MODE=live
        shift
        ;;
      --local)
        MODE=local
        shift
        ;;
      --systemd)
        MODE=systemd
        shift
        ;;
      --url|--email)
        [[ $# -ge 2 ]] || die "$1 requires a value"
        LIVE_ARGS+=("$1" "$2")
        shift 2
        ;;
      --no-monitoring|--no-build)
        LIVE_ARGS+=("$1")
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown flag: $1 (try --help)"
        ;;
    esac
  done
}

have_cmd() {
  # Test hooks so contract tests can simulate a laptop without cargo/systemd.
  if [[ "${WEISSMAN_TEST_HIDE_CARGO:-0}" == "1" && "$1" == cargo ]]; then return 1; fi
  if [[ "${WEISSMAN_TEST_HIDE_SYSTEMD:-0}" == "1" && "$1" == systemctl ]]; then return 1; fi
  command -v "$1" >/dev/null 2>&1
}

systemd_units_installed() {
  have_cmd systemctl || return 1
  systemctl cat weissman-server.service >/dev/null 2>&1
}

docker_ok() {
  have_cmd docker && docker info >/dev/null 2>&1
}

ensure_docker() {
  docker_ok && return 0
  have_cmd docker || die "Docker is not installed — install Docker Desktop / docker.io, then re-run"

  log "Docker daemon is not running — starting it..."
  if have_cmd systemctl; then
    sudo systemctl start docker 2>/dev/null || true
  fi
  if ! docker_ok && have_cmd dockerd; then
    # Last resort on hosts where the unit name differs (AGENTS.md Pop!_OS note).
    sudo dockerd >/tmp/weissman-dockerd.log 2>&1 &
    sleep 3
  fi
  if [[ -S /var/run/docker.sock ]] && ! docker_ok; then
    sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
  fi
  docker_ok || die "Docker daemon did not start. On Pop!_OS run: sudo systemctl start docker"
}

detect_mode() {
  if [[ "$MODE" != auto ]]; then
    return 0
  fi
  if systemd_units_installed; then
    MODE=systemd
  elif have_cmd cargo; then
    MODE=local
  elif have_cmd docker; then
    MODE=live
  else
    die "need Docker (recommended) or Rust cargo to start Weissman"
  fi
}

# ── git ──────────────────────────────────────────────────────────────────────

git_in_progress() {
  [[ -f "$ROOT/.git/MERGE_HEAD" ]] \
    || [[ -d "$ROOT/.git/rebase-merge" ]] \
    || [[ -d "$ROOT/.git/rebase-apply" ]] \
    || [[ -f "$ROOT/.git/CHERRY_PICK_HEAD" ]]
}

pull_latest_main() {
  [[ -d "$ROOT/.git" ]] || die "not a git checkout — cannot --pull"

  if [[ -f "$ROOT/.git/MERGE_HEAD" ]]; then
    log "Aborting unfinished merge so main can be updated..."
    git merge --abort || die "git merge --abort failed — run git status"
  fi
  if [[ -d "$ROOT/.git/rebase-merge" || -d "$ROOT/.git/rebase-apply" ]]; then
    log "Aborting unfinished rebase so main can be updated..."
    git rebase --abort || die "git rebase --abort failed — run git status"
  fi
  if [[ -f "$ROOT/.git/CHERRY_PICK_HEAD" ]]; then
    log "Aborting unfinished cherry-pick so main can be updated..."
    git cherry-pick --abort || die "git cherry-pick --abort failed — run git status"
  fi

  if ! git diff --quiet || ! git diff --cached --quiet; then
    local stamp
    stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    log "Stashing local edits so git pull can proceed (recover with: git stash pop)..."
    git stash push -m "weissman-start auto-stash ${stamp}"
  fi

  log "Fetching origin/main..."
  git fetch origin main
  if ! git checkout main; then
    log "checkout main still blocked — stashing remaining local edits and retrying..."
    git stash push -m "weissman-start auto-stash-retry $(date -u +%Y-%m-%dT%H:%M:%SZ)" || true
    git checkout main || die "git checkout main failed — run git status"
  fi
  if git merge-base --is-ancestor HEAD origin/main && git pull --ff-only origin main; then
    log "main is up to date with origin/main ($(git rev-parse --short HEAD))"
    return 0
  fi
  # Laptop checkouts that started a merge, or picked up a stray local commit, must
  # still be able to start the stack. Dirty files are already stashed; unique local
  # commits remain in reflog.
  log "main is not a fast-forward of origin/main — resetting to origin/main"
  log "Recover discarded commits with: git reflog"
  git reset --hard origin/main
  log "main is at origin/main ($(git rev-parse --short HEAD))"
}

# ── env (local / systemd host binaries) ──────────────────────────────────────

load_env_file() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  local line key val
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in ''|'#'*) continue ;; esac
    key=${line%%=*}
    val=${line#*=}
    case "$key" in *[!A-Za-z0-9_]*|'') continue ;; esac
    [[ -n "${!key+x}" ]] || export "$key=$val"
  done < "$file"
  log "Loaded $file (existing environment wins)"
}

ensure_local_env() {
  local env_file="${WEISSMAN_ENV_FILE:-$ROOT/.env.local}"
  if [[ ! -f "$env_file" ]]; then
    log "Creating $env_file for the local stack..."
    umask 077
    cat >"$env_file" <<EOF
# Generated by start_weissman.sh — local/dev only. Do not commit.
WEISSMAN_ENV=development
WEISSMAN_COOKIE_SECURE=0
WEISSMAN_BILLING_STRICT=0
WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=1
PORT=8000
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:${PG_PORT}/weissman
WEISSMAN_AUTH_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:${PG_PORT}/weissman
WEISSMAN_MIGRATE_URL=postgres://postgres:postgres@127.0.0.1:${PG_PORT}/weissman
REDIS_URL=redis://127.0.0.1:${REDIS_PORT}/0
WEISSMAN_JWT_SECRET=$(openssl rand -base64 48 | tr -d '\n')
WEISSMAN_JOB_ORCHESTRATOR_SECRET=$(openssl rand -base64 48 | tr -d '\n')
WEISSMAN_RAG_PROVENANCE_SECRET=$(openssl rand -hex 32)
WEISSMAN_ADMIN_EMAIL=${WEISSMAN_ADMIN_EMAIL:-admin@localhost}
WEISSMAN_ADMIN_PASSWORD=${WEISSMAN_ADMIN_PASSWORD:-weissman-local-admin}
WEISSMAN_PUBLIC_BASE_URL=http://127.0.0.1:8000
EOF
  fi
  load_env_file "$env_file" || true

  # Never source a Docker-stack .env: start_weissman_live.sh writes WEISSMAN_ENV=production
  # with empty DATABASE_URL (compose injects URLs). That boots a server that dies in guards.
  if [[ -z "${DATABASE_URL:-}" ]]; then
    export DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/weissman"
  fi
  export WEISSMAN_AUTH_DATABASE_URL="${WEISSMAN_AUTH_DATABASE_URL:-$DATABASE_URL}"
  export WEISSMAN_MIGRATE_URL="${WEISSMAN_MIGRATE_URL:-$DATABASE_URL}"
  export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:${REDIS_PORT}/0}"
  export PORT="${PORT:-8000}"
  export WEISSMAN_STATIC="${WEISSMAN_STATIC:-$ROOT/frontend/dist}"
  export WEISSMAN_ENV="${WEISSMAN_ENV:-development}"
  export WEISSMAN_COOKIE_SECURE="${WEISSMAN_COOKIE_SECURE:-0}"
  export WEISSMAN_BILLING_STRICT="${WEISSMAN_BILLING_STRICT:-0}"
  # Release binaries fail-closed on HMAC. Debug `cargo build` may fall back; still
  # mint a dedicated 64-hex so a later --release local binary does not JWT-fallback.
  if [[ -z "${WEISSMAN_RAG_PROVENANCE_SECRET:-}" || ! "${WEISSMAN_RAG_PROVENANCE_SECRET}" =~ ^[0-9a-fA-F]{64}$ ]]; then
    WEISSMAN_RAG_PROVENANCE_SECRET="$(openssl rand -hex 32)"
    export WEISSMAN_RAG_PROVENANCE_SECRET
  fi
}

# ── local Docker datastores ──────────────────────────────────────────────────

container_running() {
  docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null | grep -qx true
}

ensure_container() {
  local name="$1"
  shift
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    if ! container_running "$name"; then
      log "Starting existing container $name..."
      docker start "$name" >/dev/null
    fi
  else
    log "Creating container $name..."
    docker run -d --name "$name" "$@"
  fi
}

start_local_infra() {
  ensure_docker
  ensure_container "$PG_NAME" \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_DB=weissman \
    -p "${PG_PORT}:5432" \
    pgvector/pgvector:pg16
  ensure_container "$REDIS_NAME" \
    -p "${REDIS_PORT}:6379" \
    redis:7-alpine

  log "Waiting for Postgres on :${PG_PORT}..."
  local i
  for i in $(seq 1 40); do
    if docker exec "$PG_NAME" pg_isready -U postgres -d weissman >/dev/null 2>&1; then
      log "Postgres ready"
      return 0
    fi
    sleep 1
  done
  die "Postgres in $PG_NAME did not become ready"
}

# ── local processes ──────────────────────────────────────────────────────────

stop_pidfile() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  local pid
  pid="$(cat "$file")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    local i
    for i in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.2
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$file"
}

stop_local_procs() {
  stop_pidfile "$WORKER_PID"
  stop_pidfile "$SERVER_PID"
}

build_local() {
  have_cmd cargo || die "cargo not found — use ./start_weissman.sh --live (Docker) or install rustup"
  have_cmd npm || die "npm not found — install Node 20+"

  log "Building weissman-server + weissman-worker..."
  cargo build -p weissman-server -p weissman-worker

  if [[ "${WEISSMAN_SKIP_FRONTEND_BUILD:-0}" == "1" ]]; then
    [[ -f "$ROOT/frontend/dist/index.html" ]] || die "frontend/dist missing and WEISSMAN_SKIP_FRONTEND_BUILD=1"
    return 0
  fi
  if [[ ! -f "$ROOT/frontend/dist/index.html" ]] \
     || find frontend/src frontend/package.json frontend/index.html \
          -newer frontend/dist/index.html 2>/dev/null | grep -q .; then
    log "Building Command Center (npm run build)..."
    (cd frontend && { [[ -d node_modules ]] || npm ci; } && npm run build) \
      || die "frontend build failed"
  else
    log "frontend/dist is current — skipping UI rebuild"
  fi
}

pick_bin() {
  local name="$1"
  if [[ -x "$ROOT/target/debug/$name" ]]; then
    printf '%s\n' "$ROOT/target/debug/$name"
  elif [[ -x "$ROOT/target/release/$name" ]]; then
    printf '%s\n' "$ROOT/target/release/$name"
  else
    die "missing $name binary — cargo build failed?"
  fi
}

start_local_apps() {
  mkdir -p "$PID_DIR" "$LOG_DIR"
  ensure_local_env
  build_local
  stop_local_procs

  local server_bin worker_bin
  server_bin="$(pick_bin weissman-server)"
  worker_bin="$(pick_bin weissman-worker)"

  log "Starting weissman-worker..."
  "$worker_bin" >"$LOG_DIR/worker.log" 2>&1 &
  echo $! >"$WORKER_PID"

  log "Starting weissman-server on :${PORT}..."
  "$server_bin" >"$LOG_DIR/server.log" 2>&1 &
  echo $! >"$SERVER_PID"

  log "Waiting for http://127.0.0.1:${PORT}/api/health ..."
  local i
  for i in $(seq 1 90); do
    if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
      print_local_banner
      return 0
    fi
    if [[ -f "$SERVER_PID" ]] && ! kill -0 "$(cat "$SERVER_PID")" 2>/dev/null; then
      tail -40 "$LOG_DIR/server.log" >&2 || true
      die "weissman-server exited — see $LOG_DIR/server.log"
    fi
    sleep 1
  done
  tail -40 "$LOG_DIR/server.log" >&2 || true
  die "server did not become healthy — see $LOG_DIR/server.log"
}

print_local_banner() {
  cat <<EOF

================================================================================
  WEISSMAN — full local stack is running
================================================================================
  Command Center : http://127.0.0.1:${PORT}/command-center/login
  API health     : http://127.0.0.1:${PORT}/api/health
  Admin email    : ${WEISSMAN_ADMIN_EMAIL:-admin@localhost}
  Logs           : ${LOG_DIR}
  Stop           : ./start_weissman.sh stop
  Status         : ./start_weissman.sh status
================================================================================

EOF
}

cmd_start_local() {
  start_local_infra
  start_local_apps
  if [[ -t 1 && "${WEISSMAN_DETACH:-0}" != "1" ]]; then
    log "Ctrl+C stops server + worker (Postgres/Redis stay up)."
    trap 'log "Stopping..."; stop_local_procs; exit 0' INT TERM
    wait
  fi
}

# ── systemd ──────────────────────────────────────────────────────────────────

cmd_start_systemd() {
  if have_cmd cargo; then
    log "Building release binaries before systemd restart..."
    cargo build --release -p weissman-server -p weissman-worker
    if [[ -d /opt/weissman/app/bin ]]; then
      sudo install -m 0755 "$ROOT/target/release/weissman-server" /opt/weissman/app/bin/weissman-server
      sudo install -m 0755 "$ROOT/target/release/weissman-worker" /opt/weissman/app/bin/weissman-worker
    fi
    if [[ "${WEISSMAN_SKIP_FRONTEND_BUILD:-0}" != "1" && -d frontend ]]; then
      (cd frontend && { [[ -d node_modules ]] || npm ci; } && npm run build) || die "frontend build failed"
      if [[ -d /opt/weissman/app/frontend/dist ]]; then
        sudo rsync -a --delete frontend/dist/ /opt/weissman/app/frontend/dist/
      fi
    fi
  else
    log "cargo not on PATH — restarting installed systemd units as-is"
  fi
  sudo systemctl restart weissman-server weissman-worker
  sudo systemctl --no-pager --full status weissman-server weissman-worker || true
  log "systemd units restarted"
}

# ── live (Docker Compose) ────────────────────────────────────────────────────

cmd_start_live() {
  ensure_docker
  [[ -x "$ROOT/start_weissman_live.sh" ]] || die "missing start_weissman_live.sh"
  log "Starting full Docker stack (Postgres, Redis, API, worker, gateway)..."
  exec "$ROOT/start_weissman_live.sh" start "${LIVE_ARGS[@]}"
}

cmd_stop_live() {
  "$ROOT/start_weissman_live.sh" stop
}

cmd_status_live() {
  "$ROOT/start_weissman_live.sh" status
}

cmd_logs_live() {
  "$ROOT/start_weissman_live.sh" logs
}

# ── dispatch ─────────────────────────────────────────────────────────────────

cmd_status_local() {
  ensure_local_env
  local port="${PORT:-8000}"
  if curl -sf "http://127.0.0.1:${port}/api/health"; then
    echo
    log "API: healthy on :${port}"
  else
    log "API: down on :${port}"
  fi
  if docker_ok; then
    docker ps --filter "name=${PG_NAME}" --filter "name=${REDIS_NAME}" \
      --format '  {{.Names}}  {{.Status}}' || true
  fi
  if [[ -f "$SERVER_PID" ]] && kill -0 "$(cat "$SERVER_PID")" 2>/dev/null; then
    log "server pid $(cat "$SERVER_PID")"
  else
    log "server process: not running"
  fi
  if [[ -f "$WORKER_PID" ]] && kill -0 "$(cat "$WORKER_PID")" 2>/dev/null; then
    log "worker pid $(cat "$WORKER_PID")"
  else
    log "worker process: not running"
  fi
}

cmd_logs_local() {
  mkdir -p "$LOG_DIR"
  if have_cmd tail; then
    tail -n 80 -F "$LOG_DIR/server.log" "$LOG_DIR/worker.log"
  else
    die "tail not found"
  fi
}

parse_args "$@"
detect_mode

if [[ "${WEISSMAN_START_DRY_RUN:-0}" == "1" ]]; then
  printf 'mode=%s cmd=%s pull=%s pull_only=%s\n' "$MODE" "$CMD" "$DO_PULL" "$PULL_ONLY"
  exit 0
fi

if [[ "$CMD" == start && -d "$ROOT/.git" && "$DO_PULL" -eq 0 ]] && git_in_progress; then
  die "unfinished git merge/rebase — run: ./start_weissman.sh --pull"
fi

if [[ "$DO_PULL" -eq 1 ]]; then
  pull_latest_main
  if [[ "$PULL_ONLY" -eq 1 ]]; then
    log "Pull finished — not starting ( --pull-only ). Start with: ./start_weissman.sh"
    exit 0
  fi
fi

case "$CMD-$MODE" in
  start-live)    cmd_start_live ;;
  start-local)   cmd_start_local ;;
  start-systemd) cmd_start_systemd ;;
  stop-live)     cmd_stop_live ;;
  stop-local)    stop_local_procs; log "Stopped local server + worker (Postgres/Redis left running)." ;;
  stop-systemd)  sudo systemctl stop weissman-server weissman-worker ;;
  status-live)   cmd_status_live ;;
  status-local)  cmd_status_local ;;
  status-systemd)
    systemctl --no-pager --full status weissman-server weissman-worker || true
    curl -sf http://127.0.0.1:8000/api/health && echo || log "API: down"
    ;;
  logs-live)     cmd_logs_live ;;
  logs-local)    cmd_logs_local ;;
  logs-systemd)  sudo journalctl -u weissman-server -u weissman-worker -f ;;
  *)
    die "internal error: cmd=$CMD mode=$MODE"
    ;;
esac
