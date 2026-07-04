#!/usr/bin/env bash
# =============================================================================
# Weissman LIVE — one command, full production stack (אמת לייב)
# =============================================================================
# Starts EVERYTHING required for a real customer deployment:
#   Postgres (pgvector) · Redis · weissman-server · weissman-worker ·
#   Command Center (built React + Nginx gateway) · SQL migrations ·
#   endpoint-agent binaries · Prometheus + Grafana + Alertmanager (default)
#
# Usage:
#   ./start_weissman_live.sh                          # first boot (generates .env secrets)
#   ./start_weissman_live.sh --url https://sec.acme.com
#   ./start_weissman_live.sh stop
#   ./start_weissman_live.sh status
#   ./start_weissman_live.sh logs [service]
#
# Prerequisites: Docker 24+ with Compose v2, 8 GB RAM recommended, ports 80 + 3000 free.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.prod.yml)
COMPOSE=(docker compose "${COMPOSE_FILES[@]}")
PROFILES=(--profile monitoring)

PUBLIC_URL="${WEISSMAN_PUBLIC_BASE_URL:-}"
ADMIN_EMAIL="${WEISSMAN_ADMIN_EMAIL:-admin@localhost}"
WITH_MONITORING=1
SKIP_BUILD=0

if [[ $# -gt 0 && "$1" =~ ^(start|stop|status|logs|reset)$ ]]; then
  CMD="$1"
  shift
else
  CMD=start
fi

log()  { printf '[weissman-live] %s\n' "$*"; }
die()  { log "ERROR: $*" >&2; exit 1; }

gen_secret() {
  openssl rand -base64 48 | tr -d '\n/'
}

gen_password() {
  # Human-copyable admin password (24 chars, no ambiguous symbols).
  openssl rand -base64 32 | tr -d '/+=' | head -c 24
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

parse_args() {
  shift || true
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --url)
        [[ $# -ge 2 ]] || die "--url requires https://your.domain"
        PUBLIC_URL="$2"
        shift 2
        ;;
      --email)
        [[ $# -ge 2 ]] || die "--email requires an address"
        ADMIN_EMAIL="$2"
        shift 2
        ;;
      --no-monitoring)
        WITH_MONITORING=0
        shift
        ;;
      --no-build)
        SKIP_BUILD=1
        shift
        ;;
      -h|--help)
        sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
      *)
        die "unknown flag: $1 (try --help)"
        ;;
    esac
  done
}

check_prereqs() {
  need_cmd docker
  need_cmd openssl
  docker compose version >/dev/null 2>&1 || die "docker compose v2 required"
  docker info >/dev/null 2>&1 || die "Docker daemon not running — start dockerd first"

  if [[ -x "$ROOT/scripts/verify_docker_build_integrity.sh" ]]; then
    "$ROOT/scripts/verify_docker_build_integrity.sh" || die "Docker build context incomplete — fix before deploy"
  fi
  for f in shared/engine_ui_manifests.json shared/engine_requirements.json; do
    [[ -f "$ROOT/$f" ]] || die "missing $f — run: node scripts/sync-engine-ui-manifests.mjs && node scripts/generate_engine_requirements.mjs"
  done

  if [[ "$WITH_MONITORING" -eq 1 ]]; then
    for port in 80 3000; do
      if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${port}\$"; then
        if ! docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":${port}->"; then
          die "port :${port} is already in use — free it or use ./start_weissman_live.sh stop"
        fi
      fi
    done
  else
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ':80$'; then
      if ! docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ':80->'; then
        die "port :80 is already in use"
      fi
    fi
  fi
}

env_get() {
  local key="$1"
  if [[ -f .env ]]; then
    grep -E "^${key}=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true
  fi
}

env_set() {
  local key="$1" val="$2"
  if [[ -f .env ]] && grep -qE "^${key}=" .env; then
    local tmp
    tmp="$(mktemp)"
    awk -v k="$key" -v v="$val" '
      BEGIN { done=0 }
      $0 ~ "^" k "=" { print k "=" v; done=1; next }
      { print }
      END { if (!done) print k "=" v }
    ' .env >"$tmp"
    mv "$tmp" .env
  else
    printf '%s=%s\n' "$key" "$val" >>.env
  fi
}

ensure_env() {
  if [[ ! -f .env ]]; then
    log "Creating .env from PRODUCTION.env.template..."
    cp PRODUCTION.env.template .env
  fi
  chmod 600 .env

  local generated_admin=0

  # --- Production mode (security_startup.rs guards) ---
  env_set WEISSMAN_ENV production
  env_set WEISSMAN_COOKIE_SECURE 1
  env_set WEISSMAN_BILLING_STRICT 0
  # Self-hosted customers run scans without Paddle until billing is configured.
  # Set WEISSMAN_BILLING_STRICT=1 + PADDLE_* in .env when enabling SaaS billing.

  # Remove dev-only bypass flags if present.
  if grep -qE '^WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=' .env; then
    sed -i '/^WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD=/d' .env
  fi

  # --- Compose / DB secrets ---
  local keys=(
    POSTGRES_PASSWORD
    REDIS_PASSWORD
    DB_APP_PASSWORD
    DB_AUTH_PASSWORD
    WEISSMAN_JWT_SECRET
    WEISSMAN_METRICS_TOKEN
    WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET
  )
  for key in "${keys[@]}"; do
    local cur
    cur="$(env_get "$key")"
    if [[ -z "${cur// }" ]]; then
      env_set "$key" "$(gen_secret)"
      log "Generated $key"
    fi
  done

  if [[ -z "$(env_get WEISSMAN_ADMIN_EMAIL)" ]]; then
    env_set WEISSMAN_ADMIN_EMAIL "$ADMIN_EMAIL"
  fi

  local admin_pw
  admin_pw="$(env_get WEISSMAN_ADMIN_PASSWORD)"
  if [[ -z "${admin_pw// }" || "$admin_pw" == "CHANGE_ME_STRONG_PASSWORD" ]]; then
    admin_pw="$(gen_password)"
    env_set WEISSMAN_ADMIN_PASSWORD "$admin_pw"
    generated_admin=1
  fi

  # Monitoring UIs (Grafana :3000, Prometheus :9090) reuse admin credentials unless overridden.
  if [[ -z "$(env_get GRAFANA_ADMIN_PASSWORD)" ]]; then
    env_set GRAFANA_ADMIN_PASSWORD "$(env_get WEISSMAN_ADMIN_PASSWORD)"
  fi

  if [[ -n "$PUBLIC_URL" ]]; then
    env_set WEISSMAN_PUBLIC_BASE_URL "$PUBLIC_URL"
  elif [[ -z "$(env_get WEISSMAN_PUBLIC_BASE_URL)" ]]; then
  # Default: assume TLS terminates in front of this host on :443, gateway on :80.
    env_set WEISSMAN_PUBLIC_BASE_URL "https://localhost"
    log "WEISSMAN_PUBLIC_BASE_URL=https://localhost — pass --url https://your.domain for real deploys"
  fi

  # shellcheck disable=SC1091
  set -a && source .env && set +a

  if [[ "$generated_admin" -eq 1 ]]; then
    ADMIN_PASSWORD_PLAIN="$admin_pw"
  fi
}

validate_env() {
  # shellcheck disable=SC1091
  set -a && source .env && set +a

  local url="${WEISSMAN_PUBLIC_BASE_URL:-}"
  [[ -n "$url" ]] || die "WEISSMAN_PUBLIC_BASE_URL is empty — use --url https://your.domain"

  if [[ "${#WEISSMAN_JWT_SECRET}" -lt 48 ]]; then
    die "WEISSMAN_JWT_SECRET must be >= 48 chars in production (regenerate with: openssl rand -base64 48)"
  fi
  if [[ "${#WEISSMAN_METRICS_TOKEN}" -lt 32 ]]; then
    die "WEISSMAN_METRICS_TOKEN must be >= 32 chars"
  fi
  if [[ "${#WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET}" -lt 32 ]]; then
    die "WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET must be >= 32 chars"
  fi
  if [[ "${#WEISSMAN_ADMIN_PASSWORD}" -lt 12 ]]; then
    die "WEISSMAN_ADMIN_PASSWORD must be >= 12 chars"
  fi

  local weak_frags=(weissman_dev_secret weissman_auth_dev)
  for key in DB_APP_PASSWORD DB_AUTH_PASSWORD POSTGRES_PASSWORD; do
    local val="${!key:-}"
    for frag in "${weak_frags[@]}"; do
      if [[ "$val" == "$frag" ]]; then
        die "$key uses a dev default password — regenerate .env or delete weak values and re-run"
      fi
    done
    if [[ "$key" == POSTGRES_PASSWORD && "$val" == "postgres" ]]; then
      die "POSTGRES_PASSWORD must not be 'postgres' in production"
    fi
  done

  if env_truthy WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD; then
    die "unset WEISSMAN_ALLOW_DEFAULT_ADMIN_PASSWORD for production"
  fi
}

env_truthy() {
  local v
  v="$(env_get "$1")"
  [[ "$v" == "1" || "$v" == "true" || "$v" == "yes" || "$v" == "on" ]]
}

compose_up() {
  local up_args=(up -d)
  if [[ "$SKIP_BUILD" -eq 0 ]]; then
    up_args+=(--build)
  fi
  if [[ "$WITH_MONITORING" -eq 1 ]]; then
    log "Starting full LIVE stack + monitoring (Postgres, Redis, API, Worker, Gateway, Prometheus, Grafana, Alertmanager)..."
    "${COMPOSE[@]}" "${PROFILES[@]}" "${up_args[@]}"
  else
    log "Starting LIVE stack (Postgres, Redis, API, Worker, Gateway)..."
    "${COMPOSE[@]}" "${up_args[@]}"
  fi
}

wait_healthy() {
  log "Waiting for services to become healthy (first boot may take several minutes while images build)..."
  local deadline=$((SECONDS + 900))
  local services=(postgres redis backend worker gateway)
  if [[ "$WITH_MONITORING" -eq 1 ]]; then
    services+=(prometheus grafana alertmanager)
  fi

  while (( SECONDS < deadline )); do
    local all_ok=1
    for svc in "${services[@]}"; do
      local cid status
      cid="$("${COMPOSE[@]}" ps -q "$svc" 2>/dev/null || true)"
      if [[ -z "$cid" ]]; then
        all_ok=0
        break
      fi
      status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo missing)"
      if [[ "$status" != "healthy" && "$status" != "running" ]]; then
        all_ok=0
        break
      fi
    done
    if [[ "$all_ok" -eq 1 ]]; then
      if curl -sf "http://127.0.0.1/api/health" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 5
  done

  log "Timed out — recent backend logs:"
  "${COMPOSE[@]}" logs backend --tail 40 || true
  die "stack did not pass health checks within 15 minutes"
}

verify_live() {
  log "Verifying live endpoints..."
  curl -sf "http://127.0.0.1/api/health" | grep -q '"status"' || die "/api/health failed"
  curl -sf "http://127.0.0.1/command-center/" >/dev/null || die "/command-center/ failed"
  curl -sf "http://127.0.0.1/api/config/public" >/dev/null || die "/api/config/public failed"

  if [[ "$WITH_MONITORING" -eq 1 ]]; then
    curl -sf "http://127.0.0.1:3000/login" >/dev/null || die "Grafana :3000 not reachable"
  fi

  log "All live checks passed."
}

print_banner() {
  # shellcheck disable=SC1091
  set -a && source .env && set +a

  local login_email="${WEISSMAN_ADMIN_EMAIL:-admin@localhost}"
  cat <<EOF

================================================================================
  WEISSMAN LIVE — production stack is running
================================================================================
  Command Center : http://127.0.0.1/command-center/login
  Public URL     : ${WEISSMAN_PUBLIC_BASE_URL}  (set TLS/reverse-proxy to match)
  API health     : http://127.0.0.1/api/health
  Admin email    : ${login_email}
EOF
  if [[ -n "${ADMIN_PASSWORD_PLAIN:-}" ]]; then
    cat <<EOF
  Admin password : ${ADMIN_PASSWORD_PLAIN}  (SAVE THIS — also in .env)
EOF
  else
    cat <<EOF
  Admin password : (see WEISSMAN_ADMIN_PASSWORD in .env)
EOF
  fi
  if [[ "$WITH_MONITORING" -eq 1 ]]; then
    if [[ -x "${ROOT}/scripts/sync_monitoring_admin.sh" ]]; then
      "${ROOT}/scripts/sync_monitoring_admin.sh" all || log "WARN: monitoring credential sync failed (run scripts/sync_monitoring_admin.sh)"
    fi
    cat <<EOF
  Grafana        : http://127.0.0.1:3000  (${login_email} / same as WEISSMAN_ADMIN_PASSWORD)
  Prometheus     : http://127.0.0.1:9090  (${login_email} / same password — health targets UI)
  Status page    : http://127.0.0.1/command-center/status  (uses Command Center login)
EOF
  fi
  cat <<EOF

  Services:
$("${COMPOSE[@]}" "${PROFILES[@]}" ps --format '    - {{.Name}}: {{.Status}}' 2>/dev/null || "${COMPOSE[@]}" ps)

  Stop stack     : ./start_weissman_live.sh stop
  Logs           : ./start_weissman_live.sh logs
  Re-check       : ./start_weissman_live.sh status

  IMPORTANT:
  - Put HTTPS (TLS) in front of :80 before giving users the Public URL.
  - Change the admin password after first login.
  - Authorized targets only — real scans against in-scope assets.
================================================================================

EOF
}

cmd_start() {
  parse_args "$@"
  check_prereqs
  ensure_env
  validate_env
  compose_up
  wait_healthy
  verify_live
  print_banner
}

cmd_reset() {
  log "Full teardown — stopping stack and destroying Postgres/Redis/Grafana/Prometheus volumes..."
  "${COMPOSE[@]}" "${PROFILES[@]}" down -v --remove-orphans 2>/dev/null || "${COMPOSE[@]}" down -v --remove-orphans
  log "Volumes cleared. Re-deploy with: ./start_weissman_live.sh"
}

cmd_stop() {
  log "Stopping Weissman LIVE stack..."
  "${COMPOSE[@]}" "${PROFILES[@]}" down --remove-orphans 2>/dev/null || "${COMPOSE[@]}" down --remove-orphans
  log "Stopped (data volumes preserved — use 'docker compose down -v' to wipe DB)."
}

cmd_status() {
  # shellcheck disable=SC1091
  [[ -f .env ]] && set -a && source .env && set +a
  "${COMPOSE[@]}" "${PROFILES[@]}" ps 2>/dev/null || "${COMPOSE[@]}" ps
  echo ""
  if curl -sf "http://127.0.0.1/api/health" >/dev/null 2>&1; then
    log "API: healthy"
  else
    log "API: down"
  fi
}

cmd_logs() {
  local svc="${1:-}"
  if [[ -n "$svc" ]]; then
    "${COMPOSE[@]}" "${PROFILES[@]}" logs -f "$svc"
  else
    "${COMPOSE[@]}" "${PROFILES[@]}" logs -f
  fi
}

case "$CMD" in
  start) cmd_start "$@" ;;
  stop)  cmd_stop ;;
  reset) cmd_reset ;;
  status) cmd_status ;;
  logs)  cmd_logs "$@" ;;
  *)
    die "unknown command: $CMD (use: start | stop | reset | status | logs)"
    ;;
esac