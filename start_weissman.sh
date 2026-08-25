#!/usr/bin/env bash
# =============================================================================
# Weissman — bare-metal launcher: one command, real datastores, real server.
# =============================================================================
# ./start_weissman_live.sh is the DOCKER path (full stack behind an Nginx gateway).
# This is the HOST-PROCESS path: it resolves — or provisions — Postgres and Redis, fills in
# whatever secret is still missing, builds weissman-server + weissman-worker, and runs them
# in the foreground behind a live health gate.
#
# It used to do none of that. Whenever the repo `.env` came from the Docker stack it printed
# "DATABASE_URL is not set" and exited 1 — and the workaround it suggested
# (`DATABASE_URL=… ./start_weissman.sh`) did not work either, because the server re-read that
# same `.env` at boot and replayed its blank DATABASE_URL over the exported one.
#
# Usage:
#   ./start_weissman.sh                 resolve/provision datastores, build, run server+worker
#   ./start_weissman.sh --help
#
# Flags:
#   --no-worker            HTTP API only (scans enqueue but never execute)
#   --no-provision         never create containers — fail with instructions instead
#   --no-docker-start      use Docker only if the daemon is already up; never start it
#   --no-frontend-build    run against an existing frontend/dist instead of rebuilding it
#   --debug                cargo debug profile (fast rebuilds, slower runtime)
#   -h, --help             this message
#
# Anything the caller exports wins:
#   DATABASE_URL=… REDIS_URL=… PORT=9999 ./start_weissman.sh
#
# Config precedence, first non-empty wins:
#   caller's shell  >  $WEISSMAN_ENV_FILE  >  .env.local  >  .env
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

LOCAL_ENV_FILE="${WEISSMAN_LOCAL_ENV_FILE:-$ROOT/.env.local}"
PG_CONTAINER="${WEISSMAN_PG_CONTAINER:-weissman-postgres}"
REDIS_CONTAINER="${WEISSMAN_REDIS_CONTAINER:-weissman-redis}"
# pgvector, not stock postgres:16 — migration 20260608130000 runs `CREATE EXTENSION vector`.
PG_IMAGE="${WEISSMAN_PG_IMAGE:-pgvector/pgvector:pg16}"
REDIS_IMAGE="${WEISSMAN_REDIS_IMAGE:-redis:7-alpine}"
PG_DB="${WEISSMAN_PG_DB:-weissman}"
PG_HOST_PORT="${WEISSMAN_PG_PORT:-5432}"
REDIS_HOST_PORT="${WEISSMAN_REDIS_PORT:-6379}"

WITH_WORKER="${WEISSMAN_WITH_WORKER:-1}"
PROVISION="${WEISSMAN_PROVISION:-1}"
DOCKER_AUTOSTART="${WEISSMAN_DOCKER_AUTOSTART:-1}"
SKIP_FRONTEND_BUILD="${WEISSMAN_SKIP_FRONTEND_BUILD:-0}"
BUILD_PROFILE="${WEISSMAN_BUILD_PROFILE:-release}"
DOCKERD_LOG="${WEISSMAN_DOCKERD_LOG:-/tmp/weissman-dockerd.log}"

GENERATED_ADMIN_PASSWORD=""
DB_SOURCE=""
REDIS_SOURCE=""
RESOLVED_PG_URL=""
RESOLVED_PG_ENDPOINT=""
RESOLVED_REDIS_URL=""
SERVER_BIN=""
WORKER_BIN=""
WORKER_PID=""
HEALTH_PID=""
DOCKER_AVAILABLE=0
DOCKER_START_METHOD=""
DOCKER_CMD=(docker)

log()  { printf '[weissman] %s\n' "$*"; }
warn() { printf '[weissman] WARN: %s\n' "$*" >&2; }
die()  { printf '[weissman] ERROR: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Hide the password in any DSN before it reaches a terminal or a log.
redact_dsn() {
  printf '%s' "${1:-}" | sed -E 's#(://[^:/@]+):[^@]*@#\1:***@#'
}

usage() {
  cat <<'USAGE'
Weissman — bare-metal launcher (host processes, not Docker).

Usage:
  ./start_weissman.sh [flags]

Flags:
  --no-worker            HTTP API only (scans enqueue but never execute)
  --no-provision         never create containers — fail with instructions instead
  --no-docker-start      use Docker only if the daemon is already up; never start it
  --no-frontend-build    run against an existing frontend/dist instead of rebuilding it
  --debug                cargo debug profile (fast rebuilds, slower runtime)
  -h, --help             this message

When Docker is installed but its daemon is down, the launcher starts it (systemctl, then
service(8), then dockerd) and waits for it to answer before giving up on containers.

Datastores are discovered in this order, and only created as a last resort:
  DATABASE_URL / REDIS_URL you exported  >  the Docker stack's own containers  >  a container
  this launcher created earlier  >  Postgres/Redis already listening on this host  >  new
  containers

Config precedence, first non-empty wins:
  caller's shell  >  $WEISSMAN_ENV_FILE  >  .env.local  >  .env

For the full production stack (gateway, TLS-ready, monitoring): ./start_weissman_live.sh
USAGE
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-worker)         WITH_WORKER=0; shift ;;
      --no-provision)      PROVISION=0; shift ;;
      --no-docker-start)   DOCKER_AUTOSTART=0; shift ;;
      --no-frontend-build) SKIP_FRONTEND_BUILD=1; shift ;;
      --debug)             BUILD_PROFILE=debug; shift ;;
      -h|--help)           usage; exit 0 ;;
      *)                   die "unknown flag: $1 (try --help)" ;;
    esac
  done
}

# ─────────────────────────────────────────────────────────────────────────────
# Configuration files
# ─────────────────────────────────────────────────────────────────────────────

# Load KEY=value pairs without clobbering anything already set, so
# `DATABASE_URL=… PORT=9999 ./start_weissman.sh` works. A BLANK value in a file means "not
# configured here" — PRODUCTION.env.template ships DATABASE_URL=, REDIS_URL= and friends empty
# because Compose supplies them per container — so blanks are skipped rather than exported as
# an empty value that every later check would read as "already set".
load_env_file() {
  local file="$1" line key val
  [ -f "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    case "$line" in ''|'#'*) continue ;; esac
    line=${line#export }
    key=${line%%=*}
    val=${line#*=}
    case "$key" in *[!A-Za-z0-9_]*|'') continue ;; esac
    case "$val" in
      \"*\") val=${val#\"}; val=${val%\"} ;;
      \'*\') val=${val#\'}; val=${val%\'} ;;
    esac
    [ -n "${val//[[:space:]]/}" ] || continue
    [ -z "${!key:-}" ] || continue
    export "$key=$val"
  done < "$file"
  log "loaded ${file} (anything already set wins)"
}

load_config() {
  if [ -n "${WEISSMAN_ENV_FILE:-}" ]; then
    load_env_file "$WEISSMAN_ENV_FILE" \
      || die "WEISSMAN_ENV_FILE=$WEISSMAN_ENV_FILE does not exist"
  fi
  load_env_file "$LOCAL_ENV_FILE" || true
  # The repo `.env` belongs to the Docker stack (WEISSMAN_ENV=production, secrets generated by
  # start_weissman_live.sh, datastore URLs blank because Compose injects them per container).
  # Reusing its secrets is what keeps ONE identity across both launchers: the same admin
  # password logs into either. Its blanks are skipped above; this launcher resolves the
  # datastores itself.
  load_env_file "$ROOT/.env" || true

  # weissman-server and weissman-worker load those same files again at boot
  # (weissman-db/src/env_bootstrap.rs). Tell them the process environment is authoritative, or
  # they replay the file over everything resolved here — that is how `PORT=9999
  # ./start_weissman.sh` used to bind :8000 anyway.
  export WEISSMAN_ENV_PROCESS_WINS=1
}

is_production() {
  local v
  for v in "${WEISSMAN_ENV:-}" "${RUST_ENV:-}" "${NODE_ENV:-}" "${APP_ENV:-}" "${RAILS_ENV:-}"; do
    case "$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')" in
      production|prod) return 0 ;;
    esac
  done
  return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Secrets — generated once into .env.local (0600), never regenerated
# ─────────────────────────────────────────────────────────────────────────────

# NOTE for everything below: never end a random-source pipeline with `head -c`. Closing the pipe
# kills the producer with SIGPIPE, `set -o pipefail` turns that into exit 141, and `set -e` then
# aborts the launcher mid-bootstrap — which is exactly how a fresh clone ended up with an empty
# WEISSMAN_ADMIN_PASSWORD and no way to log in. Bound the INPUT, then slice in the shell.
rand_b64() {
  local raw
  if have openssl; then
    raw="$(openssl rand -base64 48)"
  else
    raw="$(head -c 96 /dev/urandom | base64)"
  fi
  raw="${raw//[$'\n'\/+=]/}"
  printf '%s' "${raw:0:48}"
}

# URL-safe alphabet: these values end up inside postgres:// DSNs, where '+' and '=' need
# percent-encoding and break authentication in confusing ways when they do not get it.
rand_alnum() {
  local n="${1:-32}" out=""
  while [ "${#out}" -lt "$n" ]; do
    out+="$(LC_ALL=C tr -dc 'A-Za-z0-9' <<<"$(head -c $((n * 4)) /dev/urandom | base64)")"
  done
  printf '%s' "${out:0:n}"
}

rand_hex32() {
  if have openssl; then openssl rand -hex 32
  else od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; fi
}

env_local_write() {
  local key="$1" val="$2"
  if [ ! -f "$LOCAL_ENV_FILE" ]; then
    {
      echo "# Weissman bare-metal overrides — generated by start_weissman.sh."
      echo "# Loaded before the Docker stack's .env; anything exported in your shell still wins."
      echo "# Real secrets: keep this file out of version control (it is gitignored)."
    } >"$LOCAL_ENV_FILE"
  fi
  chmod 600 "$LOCAL_ENV_FILE"
  printf '%s=%s\n' "$key" "$val" >>"$LOCAL_ENV_FILE"
  export "$key=$val"
}

# Generate only what nothing supplied. A value inherited from .env (i.e. from the Docker stack)
# stays exactly where it is — never copied into a second file on disk.
ensure_secret() {
  local key="$1" value="$2"
  [ -z "${!key:-}" ] || return 0
  env_local_write "$key" "$value"
  log "generated $key -> ${LOCAL_ENV_FILE##*/}"
}

ensure_secrets() {
  ensure_secret WEISSMAN_JWT_SECRET "$(rand_b64)"
  ensure_secret WEISSMAN_METRICS_TOKEN "$(rand_b64)"
  ensure_secret WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET "$(rand_b64)"
  # Server signs job envelopes, worker verifies them: one shared value or every job is rejected.
  ensure_secret WEISSMAN_JOB_ORCHESTRATOR_SECRET "$(rand_b64)"
  # Dedicated secrets-at-rest keys. Without them the vaults derive from WEISSMAN_JWT_SECRET —
  # the token-signing key — so one leak both mints tokens and decrypts every stored secret.
  ensure_secret WEISSMAN_INTEGRATIONS_VAULT_KEY "$(rand_b64)"
  ensure_secret WEISSMAN_VAULT_KEY "$(rand_hex32)"
  ensure_secret WEISSMAN_ADMIN_EMAIL "admin@localhost"

  if [ -z "${WEISSMAN_ADMIN_PASSWORD:-}" ]; then
    GENERATED_ADMIN_PASSWORD="$(rand_alnum 24)"
    env_local_write WEISSMAN_ADMIN_PASSWORD "$GENERATED_ADMIN_PASSWORD"
    log "generated WEISSMAN_ADMIN_PASSWORD -> ${LOCAL_ENV_FILE##*/}"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Reachability helpers
# ─────────────────────────────────────────────────────────────────────────────

tcp_open() {
  local host="$1" port="$2" secs="${3:-2}"
  if have timeout; then
    timeout "$secs" bash -c "exec 3<>/dev/tcp/${host}/${port}" 2>/dev/null
  else
    (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Docker
# ─────────────────────────────────────────────────────────────────────────────

# Run one command as root. Prompts only on a terminal — a non-interactive run (CI, systemd,
# an IDE task) must fail fast instead of blocking forever on an invisible password prompt.
sudo_run() {
  if [ "$(id -u)" = 0 ]; then "$@"; return; fi
  have sudo || return 1
  if sudo -n true 2>/dev/null; then sudo "$@"; return; fi
  if [ -t 0 ]; then
    log "sudo is required to: $*"
    sudo "$@"
    return
  fi
  return 1
}

# Every Docker call goes through here, because the working invocation may be `sudo docker`.
dk() { "${DOCKER_CMD[@]}" "$@"; }

# Does a daemon answer, and how do we reach it? Never prompts: `sudo -n` succeeds only with
# passwordless sudo or a still-valid timestamp from the daemon start below.
docker_responds() {
  if command docker info >/dev/null 2>&1; then
    DOCKER_CMD=(docker)
    return 0
  fi
  # Daemon alive, socket not readable by this user — the classic post-install state before
  # `usermod -aG docker`. Use sudo for this run rather than pretending Docker is absent.
  if [ "$(id -u)" != 0 ] && have sudo && sudo -n docker info >/dev/null 2>&1; then
    DOCKER_CMD=(sudo -n docker)
    return 0
  fi
  return 1
}

start_docker_daemon() {
  if have systemctl && systemctl list-unit-files 2>/dev/null | grep -q '^docker\.'; then
    log "Docker daemon is down — starting it with systemctl"
    sudo_run systemctl start docker.socket >/dev/null 2>&1 || true
    if sudo_run systemctl start docker >/dev/null 2>&1; then
      DOCKER_START_METHOD=systemctl
      return 0
    fi
  fi
  if have service; then
    log "Docker daemon is down — starting it with service(8)"
    if sudo_run service docker start >/dev/null 2>&1; then
      DOCKER_START_METHOD=service
      return 0
    fi
  fi
  if have dockerd; then
    # No usable init system (plain container images, some CI runners). AGENTS.md documents
    # `sudo dockerd &` for exactly this case.
    log "no init system started Docker — launching dockerd directly (log: ${DOCKERD_LOG})"
    if sudo_run sh -c "dockerd >>'${DOCKERD_LOG}' 2>&1 &"; then
      DOCKER_START_METHOD=dockerd
      return 0
    fi
  fi
  return 1
}

wait_for_docker() {
  local deadline=$((SECONDS + ${1:-60}))
  while ((SECONDS < deadline)); do
    if docker_responds; then return 0; fi
    sleep 1
  done
  return 1
}

# Resolve Docker once: present and answering, started by us, or genuinely unavailable. Sets
# DOCKER_AVAILABLE, which every later container decision reads.
ensure_docker() {
  DOCKER_START_METHOD=""
  if ! have docker; then
    log "Docker CLI not installed — using host datastores only"
    return 1
  fi
  if docker_responds; then
    DOCKER_AVAILABLE=1
    [ "${DOCKER_CMD[0]}" = sudo ] \
      && warn "Docker only answers through sudo — add yourself to the docker group to avoid it: sudo usermod -aG docker ${USER:-\$USER} && newgrp docker"
    log "Docker daemon is up"
    return 0
  fi
  if [ "$DOCKER_AUTOSTART" != 1 ]; then
    warn "Docker daemon is not responding and --no-docker-start was given — using host datastores only"
    return 1
  fi
  if ! start_docker_daemon; then
    warn "could not start the Docker daemon (tried systemctl, service, dockerd) — falling back to host datastores"
    return 1
  fi
  local waited=$SECONDS
  if ! wait_for_docker "${WEISSMAN_DOCKER_WAIT:-60}"; then
    warn "Docker was started via ${DOCKER_START_METHOD} but never answered — falling back to host datastores$([ "$DOCKER_START_METHOD" = dockerd ] && echo " (see ${DOCKERD_LOG})")"
    return 1
  fi
  DOCKER_AVAILABLE=1
  log "Docker daemon is up (started via ${DOCKER_START_METHOD} in $((SECONDS - waited))s)"
  return 0
}

docker_ok() { [ "$DOCKER_AVAILABLE" = 1 ]; }

container_exists()  { dk inspect "$1" >/dev/null 2>&1; }
container_running() { [ "$(dk inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = true ]; }

# The `|| true` on these three: `head` closing the pipe early SIGPIPEs the producer, and with
# pipefail + set -e that aborts the launcher instead of yielding an empty answer. Callers already
# treat empty as "unknown".
container_env_value() {
  dk inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" 2>/dev/null \
    | sed -n "s/^$2=//p" | head -1 || true
}

container_published_port() {
  dk port "$1" "$2/tcp" 2>/dev/null | head -1 | sed 's/.*://' || true
}

container_ip() {
  dk inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$1" 2>/dev/null \
    | awk '{print $1}'
}

compose_project() {
  printf '%s' "${COMPOSE_PROJECT_NAME:-$(basename "$ROOT" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')}"
}

# The Compose stack's container for a service, restricted to THIS project so an unrelated
# postgres from some other compose project is never adopted as the Weissman database.
# `all=1` also matches a stopped container — that one holds the operator's real data, so it is
# worth starting instead of provisioning an empty one beside it.
compose_container() {
  local service="$1" all="${2:-0}" args=(ps)
  [ "$all" = 1 ] && args+=(-a)
  dk "${args[@]}" --filter "label=com.docker.compose.project=$(compose_project)" \
                  --filter "label=com.docker.compose.service=${service}" \
                  --format '{{.Names}}' 2>/dev/null | head -1 || true
}

# host:port at which a container is reachable FROM THIS HOST: its published port when it has
# one, else its bridge IP (Linux). Empty when the container is only on an internal network.
container_endpoint() {
  local name="$1" internal_port="$2" published ip
  published="$(container_published_port "$name" "$internal_port")"
  if [ -n "$published" ] && tcp_open 127.0.0.1 "$published"; then
    printf '127.0.0.1:%s' "$published"
    return 0
  fi
  ip="$(container_ip "$name")"
  if [ -n "$ip" ] && tcp_open "$ip" "$internal_port"; then
    printf '%s:%s' "$ip" "$internal_port"
    return 0
  fi
  return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Postgres
# ─────────────────────────────────────────────────────────────────────────────

# Real credential test when psql exists; TCP-only when it does not (the server then reports any
# authentication failure itself, naming the DSN it used).
pg_reachable() {
  local url="$1" hostport
  if have psql; then
    # -w: never prompt for a password. Without it a DSN that needs one blocks the launcher on
    # an invisible prompt instead of simply failing the probe.
    PGCONNECT_TIMEOUT=5 psql -w "$url" -tAc 'SELECT 1' >/dev/null 2>&1
    return
  fi
  hostport="$(printf '%s' "$url" | sed -E 's#^[a-z]+://[^@]*@##; s#[/?].*$##')"
  tcp_open "${hostport%%:*}" "${hostport##*:}"
}

pg_create_database_if_missing() {
  local admin_url="$1" db="$2"
  have psql || return 0
  if PGCONNECT_TIMEOUT=5 psql -w "$admin_url" -tAc \
       "SELECT 1 FROM pg_database WHERE datname = '${db}'" 2>/dev/null | grep -q 1; then
    return 0
  fi
  log "creating database '${db}'"
  PGCONNECT_TIMEOUT=5 psql -w "$admin_url" -c "CREATE DATABASE \"${db}\"" >/dev/null 2>&1
}

# Build a DSN for a Postgres container from the container's own environment — no guessing.
adopt_pg_container() {
  local name="$1" endpoint user pass db
  container_running "$name" || return 1
  endpoint="$(container_endpoint "$name" 5432)" || return 1
  user="$(container_env_value "$name" POSTGRES_USER)"; user="${user:-postgres}"
  pass="$(container_env_value "$name" POSTGRES_PASSWORD)"
  db="$(container_env_value "$name" POSTGRES_DB)"; db="${db:-$PG_DB}"
  [ -n "$pass" ] || return 1
  RESOLVED_PG_URL="postgres://${user}:${pass}@${endpoint}/${db}"
  RESOLVED_PG_ENDPOINT="$endpoint"
  pg_reachable "$RESOLVED_PG_URL"
}

start_or_create_pg_container() {
  local err
  if container_exists "$PG_CONTAINER"; then
    if ! container_running "$PG_CONTAINER"; then
      log "starting existing container ${PG_CONTAINER}"
      dk start "$PG_CONTAINER" >/dev/null || return 1
    fi
  else
    [ "$PROVISION" = 1 ] || return 1
    log "provisioning Postgres ${PG_CONTAINER} (${PG_IMAGE}) on 127.0.0.1:${PG_HOST_PORT}"
    # Report what Docker actually said. Guessing ("is the port free?") sent operators hunting
    # for a port conflict when the real answer was a pull failure or an unwritable image store.
    if ! err="$(dk run -d --name "$PG_CONTAINER" \
                  -e POSTGRES_USER=postgres -e "POSTGRES_PASSWORD=$(rand_alnum 32)" \
                  -e "POSTGRES_DB=${PG_DB}" \
                  -p "127.0.0.1:${PG_HOST_PORT}:5432" "$PG_IMAGE" 2>&1 >/dev/null)"; then
      warn "docker could not create ${PG_CONTAINER}: ${err}"
      # A half-created container would masquerade as "exists" on the next run.
      dk rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
      return 1
    fi
  fi
  local i
  for ((i = 0; i < 60; i++)); do
    if dk exec "$PG_CONTAINER" pg_isready -U postgres >/dev/null 2>&1; then
      adopt_pg_container "$PG_CONTAINER" && return 0
      # pg_isready alone is not enough to stop waiting: during first-boot initdb the entrypoint
      # runs a socket-only server that already answers it. Only once the published port is
      # reachable is a failure definitely about credentials rather than startup.
      if container_endpoint "$PG_CONTAINER" 5432 >/dev/null 2>&1; then
        warn "${PG_CONTAINER} is accepting connections but its credentials did not work: remove it with 'docker rm -f ${PG_CONTAINER}', or set DATABASE_URL"
        return 1
      fi
    fi
    sleep 1
  done
  warn "${PG_CONTAINER} did not become ready — check: docker logs ${PG_CONTAINER}"
  return 1
}

# The stack's own Postgres, including a stopped one: it holds the operator's real data, so it
# is always the better answer than an empty container beside it.
adopt_stack_pg() {
  local name
  name="$(compose_container postgres 1)"
  [ -n "$name" ] || return 1
  if ! container_running "$name"; then
    log "the Docker stack's Postgres (${name}) is stopped — starting it"
    dk start "$name" >/dev/null 2>&1 || return 1
    local i
    for ((i = 0; i < 60; i++)); do
      dk exec "$name" pg_isready >/dev/null 2>&1 && break
      sleep 1
    done
  fi
  if adopt_pg_container "$name"; then
    DB_SOURCE="Docker stack container ${name}"
    return 0
  fi
  warn "the Docker stack's Postgres (${name}) is running but not reachable from this host — it publishes no port. This run uses a SEPARATE datastore; for the stack's own data use ./start_weissman_live.sh"
  return 1
}

# Credentials worth trying against a Postgres already listening on this host. Nothing is
# invented: they are the Compose values from .env, plus the two stock local setups.
host_pg_candidates() {
  local db="${POSTGRES_DB:-$PG_DB}"
  if [ -n "${POSTGRES_USER:-}" ] && [ -n "${POSTGRES_PASSWORD:-}" ]; then
    printf 'postgres://%s:%s@127.0.0.1:%s/%s\n' \
      "$POSTGRES_USER" "$POSTGRES_PASSWORD" "$PG_HOST_PORT" "$db"
  fi
  printf 'postgres://postgres:postgres@127.0.0.1:%s/%s\n' "$PG_HOST_PORT" "$db"
  printf 'postgres://postgres@127.0.0.1:%s/%s\n' "$PG_HOST_PORT" "$db"
  printf 'postgres://%s@127.0.0.1:%s/%s\n' "${USER:-postgres}" "$PG_HOST_PORT" "$db"
}

# Only ever adopts a host Postgres when psql can PROVE the credentials work. Without psql a
# TCP probe cannot tell "right password" from "wrong password", and adopting on a guess would
# hand the operator an authentication error from deep inside the server instead of a clear one.
adopt_host_pg() {
  have psql || return 1
  local candidate admin
  while read -r candidate; do
    [ -n "$candidate" ] || continue
    admin="${candidate%/*}/postgres"
    pg_reachable "$admin" || continue
    pg_create_database_if_missing "$admin" "${candidate##*/}"
    pg_reachable "$candidate" || continue
    RESOLVED_PG_URL="$candidate"
    RESOLVED_PG_ENDPOINT="127.0.0.1:${PG_HOST_PORT}"
    return 0
  done < <(host_pg_candidates)
  return 1
}

use_resolved_pg() {
  export DATABASE_URL="$RESOLVED_PG_URL"
  export WEISSMAN_MIGRATE_URL="${WEISSMAN_MIGRATE_URL:-$RESOLVED_PG_URL}"
}

# Say it out loud rather than quietly building a system on a guessable database password. Not
# fatal: on a laptop it is a reasonable local setup, and the real floor is enforced by the
# server itself (security_startup.rs) — but it must never pass unremarked.
warn_weak_db_password() {
  local pass="${1#*://}"
  pass="${pass%%@*}"
  case "${pass#*:}" in
    postgres|password|changeme|weissman|admin|123456)
      warn "the database password in DATABASE_URL is trivially guessable — acceptable on a laptop, never on a host anyone else can reach"
      ;;
  esac
}

# The Compose stack keeps weissman_app / weissman_auth / weissman_ro separate, with passwords in
# .env. Reuse those roles instead of running everything as the superuser, so a bare-metal
# process against the stack's database gets exactly the privileges the migrations designed.
use_stack_pg_roles() {
  local endpoint="$RESOLVED_PG_ENDPOINT" db="${POSTGRES_DB:-$PG_DB}"
  export WEISSMAN_MIGRATE_URL="${WEISSMAN_MIGRATE_URL:-$RESOLVED_PG_URL}"
  if [ -n "${DB_APP_PASSWORD:-}" ]; then
    export DATABASE_URL="postgres://${DB_APP_USER:-weissman_app}:${DB_APP_PASSWORD}@${endpoint}/${db}"
  else
    export DATABASE_URL="$RESOLVED_PG_URL"
  fi
  if [ -n "${DB_AUTH_PASSWORD:-}" ] && [ -z "${WEISSMAN_AUTH_DATABASE_URL:-}" ]; then
    export WEISSMAN_AUTH_DATABASE_URL="postgres://${DB_AUTH_USER:-weissman_auth}:${DB_AUTH_PASSWORD}@${endpoint}/${db}"
  fi
  if [ -n "${DB_RO_PASSWORD:-}" ] && [ -z "${WEISSMAN_READ_ONLY_DATABASE_URL:-}" ]; then
    export WEISSMAN_READ_ONLY_DATABASE_URL="postgres://${DB_RO_USER:-weissman_ro}:${DB_RO_PASSWORD}@${endpoint}/${db}"
  fi
}

resolve_postgres() {
  if [ -n "${DATABASE_URL:-}" ]; then
    DB_SOURCE="configured DATABASE_URL"
    if ! pg_reachable "$DATABASE_URL"; then
      # A stopped container we own is the common case; start it and re-check before blaming
      # the operator's configuration.
      if docker_ok && container_exists "$PG_CONTAINER" && ! container_running "$PG_CONTAINER"; then
        log "starting ${PG_CONTAINER} for the configured DATABASE_URL"
        dk start "$PG_CONTAINER" >/dev/null || true
        sleep 3
      fi
      pg_reachable "$DATABASE_URL" \
        || die "DATABASE_URL is set but Postgres did not answer at $(redact_dsn "$DATABASE_URL") — start it, or unset DATABASE_URL to let this launcher resolve one"
    fi
    export WEISSMAN_MIGRATE_URL="${WEISSMAN_MIGRATE_URL:-$DATABASE_URL}"
    warn_weak_db_password "$DATABASE_URL"
    return 0
  fi

  if docker_ok; then
    if adopt_stack_pg; then
      use_stack_pg_roles
      return 0
    fi
    if container_exists "$PG_CONTAINER" && start_or_create_pg_container; then
      DB_SOURCE="container ${PG_CONTAINER}"
      use_resolved_pg
      return 0
    fi
  fi

  if tcp_open 127.0.0.1 "$PG_HOST_PORT" && adopt_host_pg; then
    DB_SOURCE="host Postgres on 127.0.0.1:${PG_HOST_PORT}"
    use_resolved_pg
    warn_weak_db_password "$DATABASE_URL"
    return 0
  fi

  if tcp_open 127.0.0.1 "$PG_HOST_PORT"; then
    die "$(cat <<EOF
something is listening on 127.0.0.1:${PG_HOST_PORT}, but no credentials this launcher could
verify were accepted$(have psql || echo " (psql is not installed, so credentials cannot be tested here)").
Point it at the database explicitly:

  DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:${PG_HOST_PORT}/${PG_DB} ./start_weissman.sh

or give the local server a password login:

  sudo -u postgres psql -c "ALTER ROLE postgres PASSWORD 'choose-one'"
EOF
)"
  fi

  if docker_ok && start_or_create_pg_container; then
    DB_SOURCE="container ${PG_CONTAINER}"
    use_resolved_pg
    persist_resolved DATABASE_URL "$DATABASE_URL"
    return 0
  fi

  die "$(cat <<EOF
no Postgres is reachable and none could be created$([ "$PROVISION" = 1 ] || echo " (--no-provision)"). Pick one:

  * Docker      : start the daemon and re-run — this launcher creates ${PG_CONTAINER} itself
  * Full stack  : ./start_weissman_live.sh
  * Own server  : DATABASE_URL=postgres://USER:PASSWORD@HOST:5432/${PG_DB} ./start_weissman.sh
EOF
)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Redis
# ─────────────────────────────────────────────────────────────────────────────

urlencode() {
  local s="${1:-}" out="" c i
  for ((i = 0; i < ${#s}; i++)); do
    c=${s:i:1}
    case "$c" in
      [A-Za-z0-9._~-]) out+="$c" ;;
      *) out+="$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s' "$out"
}

# Same shape docker-compose.prod.yml feeds the server: redis://:PASSWORD@host:port/0.
redis_url_for() {
  local endpoint="$1" pass="${2:-}"
  if [ -n "$pass" ]; then
    printf 'redis://:%s@%s/0' "$(urlencode "$pass")" "$endpoint"
  else
    printf 'redis://%s/0' "$endpoint"
  fi
}

# host, port and percent-decoded password of a redis:// URL, into REDIS_P_*.
redis_parse_url() {
  local rest="${1#redis://}" hostport
  REDIS_P_PASS=""
  case "$rest" in
    *@*)
      REDIS_P_PASS="${rest%%@*}"
      REDIS_P_PASS="${REDIS_P_PASS#*:}"
      REDIS_P_PASS="$(printf '%b' "${REDIS_P_PASS//%/\\x}")"
      rest="${rest#*@}"
      ;;
  esac
  hostport="${rest%%[/?]*}"
  REDIS_P_HOST="${hostport%%:*}"
  REDIS_P_PORT="${hostport##*:}"
  [ "$REDIS_P_PORT" != "$REDIS_P_HOST" ] || REDIS_P_PORT=6379
  [ -n "$REDIS_P_HOST" ]
}

# Speak RESP directly, so a host without redis-cli still gets a real answer instead of a TCP
# handshake that says nothing about authentication. QUIT makes the server close the socket, so
# the read returns immediately rather than idling until a timeout.
redis_resp_ping() {
  local host="$1" port="$2" pass="${3:-}" reply
  exec 3<>"/dev/tcp/${host}/${port}" 2>/dev/null || return 1
  {
    [ -z "$pass" ] || printf 'AUTH %s\r\n' "$pass"
    printf 'PING\r\nQUIT\r\n'
  } >&3
  reply="$(timeout 3 cat <&3 2>/dev/null || true)"
  exec 3<&- 2>/dev/null || true
  exec 3>&- 2>/dev/null || true
  case "$reply" in
    *NOAUTH*|*WRONGPASS*|*"ERR "*) return 1 ;;
  esac
  case "$reply" in
    *PONG*) return 0 ;;
  esac
  return 1
}

# Ask Redis itself, by parts.
#
# Two traps this avoids. First, redis-cli reports "AUTH failed: WRONGPASS …" on STDERR and then
# pings anyway, exiting 0 with PONG on stdout — so reading only stdout calls a rejected
# credential healthy, which is how a password-less container got handed the Docker stack's
# password and only failed later, inside the server. Second, redis-cli 7 does not authenticate
# from the `redis://:password@host` URL form at all (empty username), although that is exactly
# the form docker-compose.prod.yml feeds the server and redis-rs accepts. Probing by parts,
# with the password in REDISCLI_AUTH (never argv, where `ps` would show it), sidesteps both.
redis_ping_parts() {
  local host="$1" port="$2" pass="${3:-}" out
  if have redis-cli; then
    if [ -n "$pass" ]; then
      out="$(REDISCLI_AUTH="$pass" redis-cli -h "$host" -p "$port" ping 2>&1 || true)"
    else
      out="$(redis-cli -h "$host" -p "$port" ping 2>&1 || true)"
    fi
    case "$out" in
      *NOAUTH*|*WRONGPASS*|*"AUTH failed"*|*"ERR "*) return 1 ;;
    esac
    case "$out" in
      *PONG*) return 0 ;;
    esac
    return 1
  fi
  redis_resp_ping "$host" "$port" "$pass"
}

redis_reachable() {
  redis_parse_url "$1" || return 1
  redis_ping_parts "$REDIS_P_HOST" "$REDIS_P_PORT" "$REDIS_P_PASS"
}

# Which credential does THIS Redis actually accept? The Compose stack runs with
# requirepass ${REDIS_PASSWORD}; a container this launcher created may have no password at all.
# Probing both beats assuming, and the answer is verified before anything depends on it.
redis_resolve_endpoint() {
  local endpoint="$1" host="${1%%:*}" port="${1##*:}"
  if [ -n "${REDIS_PASSWORD:-}" ] && redis_ping_parts "$host" "$port" "$REDIS_PASSWORD"; then
    RESOLVED_REDIS_URL="$(redis_url_for "$endpoint" "$REDIS_PASSWORD")"
    return 0
  fi
  if redis_ping_parts "$host" "$port" ""; then
    RESOLVED_REDIS_URL="$(redis_url_for "$endpoint" "")"
    return 0
  fi
  return 1
}

# A Redis container started by this launcher carries its own password in argv
# (`--requirepass X`). Recovering it from the container means a rotated — or deleted — .env
# cannot orphan a container that is running perfectly well.
container_redis_password() {
  dk inspect -f '{{range .Config.Cmd}}{{println .}}{{end}}' "$1" 2>/dev/null \
    | awk '/^--requirepass$/ { found = 1; next } found { print; exit }' || true
}

adopt_redis_container() {
  local name="$1" endpoint pass
  container_running "$name" || return 1
  endpoint="$(container_endpoint "$name" 6379)" || return 1
  pass="$(container_redis_password "$name")"
  if [ -n "$pass" ] && redis_ping_parts "${endpoint%%:*}" "${endpoint##*:}" "$pass"; then
    RESOLVED_REDIS_URL="$(redis_url_for "$endpoint" "$pass")"
    return 0
  fi
  redis_resolve_endpoint "$endpoint"
}

start_or_create_redis_container() {
  local err
  if container_exists "$REDIS_CONTAINER"; then
    if ! container_running "$REDIS_CONTAINER"; then
      log "starting existing container ${REDIS_CONTAINER}"
      dk start "$REDIS_CONTAINER" >/dev/null || return 1
    fi
  else
    [ "$PROVISION" = 1 ] || return 1
    log "provisioning Redis ${REDIS_CONTAINER} (${REDIS_IMAGE}) on 127.0.0.1:${REDIS_HOST_PORT}"
    # Carry the deployment's own password onto the container we create, rather than leaving a
    # second, unauthenticated Redis beside a stack that requires one.
    local -a auth=()
    [ -z "${REDIS_PASSWORD:-}" ] || auth=(--requirepass "$REDIS_PASSWORD")
    if ! err="$(dk run -d --name "$REDIS_CONTAINER" \
                  -p "127.0.0.1:${REDIS_HOST_PORT}:6379" "$REDIS_IMAGE" \
                  ${auth[@]+"${auth[@]}"} 2>&1 >/dev/null)"; then
      warn "docker could not create ${REDIS_CONTAINER}: ${err}"
      dk rm -f "$REDIS_CONTAINER" >/dev/null 2>&1 || true
      return 1
    fi
  fi
  local i
  for ((i = 0; i < 30; i++)); do
    adopt_redis_container "$REDIS_CONTAINER" && return 0
    # Once the port answers, waiting longer cannot change the answer — say what is wrong
    # instead of burning the rest of the timeout in silence.
    if container_endpoint "$REDIS_CONTAINER" 6379 >/dev/null 2>&1; then
      warn "${REDIS_CONTAINER} is up but rejected every credential available (it was created with a different password): remove it with 'docker rm -f ${REDIS_CONTAINER}', or set REDIS_URL"
      return 1
    fi
    sleep 1
  done
  return 1
}

resolve_redis() {
  if [ -n "${REDIS_URL:-}" ]; then
    REDIS_SOURCE="configured REDIS_URL"
    redis_reachable "$REDIS_URL" \
      || die "REDIS_URL is set but Redis did not answer at $(redact_dsn "$REDIS_URL") — start it, or unset REDIS_URL to let this launcher resolve one"
    return 0
  fi

  local stack_redis=""
  if docker_ok; then
    stack_redis="$(compose_container redis 1)"
    if [ -n "$stack_redis" ] && ! container_running "$stack_redis"; then
      log "the Docker stack's Redis (${stack_redis}) is stopped — starting it"
      dk start "$stack_redis" >/dev/null 2>&1 || true
    fi
    if [ -n "$stack_redis" ] && adopt_redis_container "$stack_redis"; then
      REDIS_SOURCE="Docker stack container ${stack_redis}"
      export REDIS_URL="$RESOLVED_REDIS_URL"
      return 0
    fi
    if container_exists "$REDIS_CONTAINER" && start_or_create_redis_container; then
      REDIS_SOURCE="container ${REDIS_CONTAINER}"
      export REDIS_URL="$RESOLVED_REDIS_URL"
      return 0
    fi
  fi

  if tcp_open 127.0.0.1 "$REDIS_HOST_PORT" \
     && redis_resolve_endpoint "127.0.0.1:${REDIS_HOST_PORT}"; then
    REDIS_SOURCE="host Redis on 127.0.0.1:${REDIS_HOST_PORT}"
    export REDIS_URL="$RESOLVED_REDIS_URL"
    return 0
  fi

  if docker_ok && start_or_create_redis_container; then
    REDIS_SOURCE="container ${REDIS_CONTAINER}"
    export REDIS_URL="$RESOLVED_REDIS_URL"
    persist_resolved REDIS_URL "$REDIS_URL"
    return 0
  fi

  # Never invent a Redis. Without one, login lockout and rate limits degrade to per-process
  # memory, which is precisely why production refuses to boot (security_startup.rs).
  if is_production && [ "${WEISSMAN_ALLOW_SINGLE_NODE:-0}" != 1 ]; then
    die "$(cat <<EOF
no Redis is reachable, and this configuration is production (WEISSMAN_ENV=production), where
distributed login lockout and rate limiting are mandatory. Either:

  * start Redis — this launcher creates ${REDIS_CONTAINER} itself when Docker is available
  * REDIS_URL=redis://HOST:6379/0 ./start_weissman.sh
  * WEISSMAN_ALLOW_SINGLE_NODE=1 ./start_weissman.sh   (knowingly accept in-memory state)
EOF
)"
  fi
  REDIS_SOURCE="none — in-process rate limiting"
  warn "no Redis: login lockout, rate limits and the telemetry bus fall back to in-process memory"
}

# Remember a datastore this launcher created, so the next run reconnects to the same data
# instead of provisioning a second one beside it.
persist_resolved() {
  local key="$1" val="$2"
  grep -qE "^${key}=" "$LOCAL_ENV_FILE" 2>/dev/null && return 0
  env_local_write "$key" "$val"
  log "recorded $key in ${LOCAL_ENV_FILE##*/}"
}

# ─────────────────────────────────────────────────────────────────────────────
# Preflight
# ─────────────────────────────────────────────────────────────────────────────

# Mirror fingerprint_engine/src/security_startup.rs, so a production misconfiguration is one
# clear line here instead of a boot refusal on the far side of a long build.
check_production_secrets() {
  is_production || return 0
  local errs=() spec name min val
  for spec in WEISSMAN_JWT_SECRET:48 WEISSMAN_METRICS_TOKEN:32 \
              WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET:32 WEISSMAN_JOB_ORCHESTRATOR_SECRET:32 \
              WEISSMAN_ADMIN_PASSWORD:12; do
    name="${spec%:*}"; min="${spec#*:}"; val="${!name:-}"
    [ "${#val}" -ge "$min" ] || errs+=("${name} must be at least ${min} characters (currently ${#val})")
  done
  [ -n "${WEISSMAN_MIGRATE_URL:-}" ] || errs+=("WEISSMAN_MIGRATE_URL must be set so migrations run at boot")
  # Production forces Secure-only session cookies; the server refuses to boot without them.
  export WEISSMAN_COOKIE_SECURE="${WEISSMAN_COOKIE_SECURE:-1}"
  case "${WEISSMAN_COOKIE_SECURE}" in
    1|true|yes) ;;
    *) errs+=("WEISSMAN_COOKIE_SECURE must be 1 in production (HTTPS-only session cookies)") ;;
  esac
  if [ "${#errs[@]}" -gt 0 ]; then
    printf '[weissman] ERROR: production configuration is incomplete:\n' >&2
    printf '  - %s\n' "${errs[@]}" >&2
    die "fix .env (or .env.local) and re-run"
  fi
}

check_port_free() {
  tcp_open 127.0.0.1 "$PORT" || return 0
  die "port ${PORT} is already in use — stop what is listening (another weissman-server, or ./start_weissman_live.sh stop), or run PORT=8001 ./start_weissman.sh"
}

# ─────────────────────────────────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────────────────────────────────

build_binaries() {
  local dir="$ROOT/target/$BUILD_PROFILE"
  local -a pkgs=(-p weissman-server) profile_flag=() wanted=(weissman-server)
  if [ "$BUILD_PROFILE" = release ]; then
    profile_flag=(--release)
  fi
  if [ "$WITH_WORKER" = 1 ]; then
    pkgs+=(-p weissman-worker)
    wanted+=(weissman-worker)
  fi

  local need_build=0 bin
  for bin in "${wanted[@]}"; do
    [ -x "$dir/$bin" ] || need_build=1
  done
  if [ "$need_build" = 1 ]; then
    have cargo || die "cargo not found — install Rust: https://rustup.rs"
    log "building ${BUILD_PROFILE} binaries (a first build compiles the whole workspace — this is the slow part)"
    cargo build "${profile_flag[@]}" "${pkgs[@]}" || die "cargo build failed"
  else
    log "reusing ${BUILD_PROFILE} binaries in target/${BUILD_PROFILE} (delete them to force a rebuild)"
  fi

  SERVER_BIN="$dir/weissman-server"
  WORKER_BIN="$dir/weissman-worker"
  [ -x "$SERVER_BIN" ] || die "weissman-server is missing after the build: $SERVER_BIN"
}

build_frontend() {
  [ -d "$ROOT/frontend" ] || return 0
  if [ -f "$ROOT/frontend/dist/index.html" ]; then
    log "frontend/dist present — 'rm -rf frontend/dist' to force a rebuild"
    return 0
  fi
  if [ "$SKIP_FRONTEND_BUILD" = 1 ]; then
    warn "frontend build skipped and frontend/dist is empty — this run serves the API only, with no Command Center"
    return 0
  fi
  log "building the Command Center (npm run build)"
  # Do NOT swallow the error: a failed UI build must be loud, not a silent downgrade to an
  # API-only server that the banner still advertises as the Command Center.
  (cd "$ROOT/frontend" && npm run build) \
    || die "frontend build FAILED — fix it, or pass --no-frontend-build to run API-only on purpose"
}

# ─────────────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────────────

cleanup() {
  local pid
  for pid in "$HEALTH_PID" "$WORKER_PID"; do
    [ -n "$pid" ] || continue
    kill -TERM "$pid" 2>/dev/null || true
  done
  if [ -n "$WORKER_PID" ]; then
    wait "$WORKER_PID" 2>/dev/null || true
  fi
}

print_banner() {
  local mode="development"
  is_production && mode="production"
  cat <<EOF

================================================================================
  WEISSMAN — weissman-server is live (${mode}, bare metal)
================================================================================
  Command Center : http://localhost:${PORT}/command-center/
  API health     : http://localhost:${PORT}/api/health
  Admin email    : ${WEISSMAN_ADMIN_EMAIL:-admin@localhost}
EOF
  if [ -n "$GENERATED_ADMIN_PASSWORD" ]; then
    echo "  Admin password : ${GENERATED_ADMIN_PASSWORD}   (SAVE THIS — also in ${LOCAL_ENV_FILE##*/})"
  else
    echo "  Admin password : WEISSMAN_ADMIN_PASSWORD, as configured"
  fi
  cat <<EOF

  Postgres       : ${DB_SOURCE} — $(redact_dsn "${DATABASE_URL:-}")
  Redis          : ${REDIS_SOURCE:-none}
  Worker         : $([ -n "$WORKER_PID" ] && echo "running (pid ${WORKER_PID}) — scans execute" || echo "OFF — scans enqueue but never execute")
EOF
  if is_production; then
    cat <<'EOF'

  NOTE: production keeps session cookies Secure-only. Browsers accept them over
  http://localhost, but NOT over a plain-HTTP LAN address — log in from this host,
  or put TLS in front of the port before sharing it.
EOF
  fi
  cat <<EOF

  Ctrl+C to stop
================================================================================

EOF
}

# Watched from the side so the server keeps the terminal: the banner may only claim the system
# is live once /api/health has actually answered.
watch_health() {
  local url="http://127.0.0.1:${PORT}/api/health" i body
  if ! have curl; then
    print_banner
    return 0
  fi
  for ((i = 0; i < 300; i++)); do
    body="$(curl -sf --max-time 2 "$url" 2>/dev/null || true)"
    if [ -n "$body" ]; then
      print_banner
      log "health: ${body}"
      return 0
    fi
    sleep 1
  done
  warn "/api/health has not answered in 300s — read the server output above"
}

start_worker() {
  [ "$WITH_WORKER" = 1 ] || return 0
  if [ ! -x "$WORKER_BIN" ]; then
    warn "weissman-worker binary not found — scans will enqueue but never execute"
    return 0
  fi
  log "starting weissman-worker (job pipeline)"
  local -a prefix=(sed -e 's/^/[worker] /')
  # Line-buffer when GNU sed is available, or the worker's output only appears in 4 KB bursts.
  if echo | sed -u '' >/dev/null 2>&1; then prefix=(sed -u -e 's/^/[worker] /'); fi
  # Process substitution, not a pipeline: `cmd | prefix &` would make $! the prefixer, and
  # cleanup() would then kill the formatter while leaving the worker running.
  "$WORKER_BIN" > >("${prefix[@]}") 2>&1 &
  WORKER_PID=$!
}

main() {
  parse_args "$@"

  load_config
  ensure_secrets
  # Before any container decision: a stopped daemon is a solvable problem, not a reason to
  # silently ignore the operator's existing stack and its data.
  ensure_docker || true
  resolve_postgres
  resolve_redis
  check_production_secrets

  mkdir -p "$ROOT/data"
  export WEISSMAN_STATIC="${WEISSMAN_STATIC:-$ROOT/frontend/dist}"
  export PORT="${PORT:-8000}"
  check_port_free

  build_frontend
  build_binaries

  trap cleanup EXIT INT TERM
  start_worker
  watch_health &
  HEALTH_PID=$!

  log "starting weissman-server on :${PORT}"
  "$SERVER_BIN"
}

main "$@"
