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
# Prerequisites: Docker 24+ with Compose v2, 8 GB RAM recommended,
# ports 80 + 3000 + 9090 free (9090/3000 only when monitoring is enabled).
# =============================================================================
set -euo pipefail

usage() {
  cat <<'USAGE'
Weissman LIVE — one command, full production stack.

Usage:
  ./start_weissman_live.sh [start] [flags]   first boot / re-deploy (generates .env secrets)
  ./start_weissman_live.sh stop              stop the stack, keep data volumes
  ./start_weissman_live.sh reset             stop AND destroy all data volumes
  ./start_weissman_live.sh status            show container status + API health
  ./start_weissman_live.sh logs [service]    follow logs (all services, or one)

Flags (start only):
  --url https://your.domain   public HTTPS origin the reverse proxy serves (WEISSMAN_PUBLIC_BASE_URL)
  --email admin@your.domain   admin login address (first boot only)
  --no-monitoring             skip Prometheus / Grafana / Alertmanager
  --no-build                  reuse existing images instead of rebuilding
  -h, --help                  this message

Prerequisites: Docker 24+ with Compose v2, 8 GB RAM recommended,
ports 80 + 3000 + 9090 free (3000/9090 only with monitoring enabled).
USAGE
}

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.prod.yml)
COMPOSE=(docker compose "${COMPOSE_FILES[@]}")
# Built by resolve_profiles() once we know which optional stacks are on.
PROFILES=()

PUBLIC_URL="${WEISSMAN_PUBLIC_BASE_URL:-}"
ADMIN_EMAIL="${WEISSMAN_ADMIN_EMAIL:-admin@localhost}"
# Captured from the shell BEFORE .env is sourced. `source .env` would otherwise overwrite an
# operator's `WEISSMAN_OAST_DOMAIN=... ./start_weissman_live.sh` with the template's blank
# line, enabling the oast profile but starting the listener with an empty domain.
OAST_DOMAIN_CLI="${WEISSMAN_OAST_DOMAIN:-}"
WITH_MONITORING=1
# OAST out-of-band listener: on automatically when WEISSMAN_OAST_DOMAIN is set (it needs a
# DNS zone the operator delegates), off otherwise.
WITH_OAST=0
SKIP_BUILD=0

if [[ $# -gt 0 && "$1" =~ ^(start|stop|status|logs|reset)$ ]]; then
  CMD="$1"
  shift
else
  CMD=start
fi

log()  { printf '[weissman-live] %s\n' "$*"; }
die()  { log "ERROR: $*" >&2; exit 1; }

# Recompute PROFILES from the toggles. Compose resolves service names against ENABLED
# profiles only, so `compose ps -q prometheus` without --profile monitoring finds nothing —
# which used to make wait_healthy() spin until timeout even on a healthy stack.
resolve_profiles() {
  # if-blocks (not `cond && action`): a trailing `cond && action` that evaluates false
  # returns 1, which under `set -e` would abort the caller.
  PROFILES=()
  if [[ "$WITH_MONITORING" -eq 1 ]]; then PROFILES+=(--profile monitoring); fi
  if [[ "$WITH_OAST" -eq 1 ]]; then PROFILES+=(--profile oast); fi
  return 0
}

# docker compose with the active profiles applied to every subcommand.
dc() {
  "${COMPOSE[@]}" "${PROFILES[@]}" "$@"
}

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

# Bring the Docker daemon up if the CLI is present but `docker info` fails.
# Cloud / bare-metal boxes often have dockerd installed but not running.
ensure_docker_daemon() {
  if docker info >/dev/null 2>&1; then
    return 0
  fi
  command -v dockerd >/dev/null 2>&1 || die "Docker daemon not running and dockerd is not installed"
  log "Docker daemon not running — starting dockerd..."
  sudo dockerd >/tmp/weissman-dockerd.log 2>&1 &
  local i
  for i in $(seq 1 50); do
    sudo chmod 666 /var/run/docker.sock 2>/dev/null || true
    if docker info >/dev/null 2>&1; then
      log "Docker daemon is up"
      return 0
    fi
    sleep 0.4
  done
  tail -30 /tmp/weissman-dockerd.log >&2 || true
  die "Docker daemon failed to start — see /tmp/weissman-dockerd.log"
}

# NOTE: callers pass only the flags — the leading `start|stop|...` word (when present) is
# already consumed by the dispatcher above. Do NOT shift here: an extra shift silently ate
# the first flag, which made the documented `--url https://your.domain` form die with
# "unknown flag: https://your.domain" and made `--no-monitoring` a no-op.
parse_args() {
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
        usage
        exit 0
        ;;
      *)
        die "unknown flag: $1 (try --help)"
        ;;
    esac
  done
}

# True when something is listening on $1. Returns 2 when we have no way to tell, so the
# caller can warn instead of silently "passing" the check (the old code piped `ss` through
# 2>/dev/null, so a host without iproute2 skipped port detection without saying so).
port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${port}\$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -q ":${port}\$"
  else
    return 2
  fi
}

check_ports_free() {
  # Every port this stack PUBLISHES to the host. 9090 (Prometheus) was missing, so a
  # conflict there only surfaced as a `compose up` failure after .env had been rewritten.
  local ports=(80)
  if [[ "$WITH_MONITORING" -eq 1 ]]; then
    ports+=(3000 9090)
  fi
  # OAST may be enabled via the shell env OR a pre-existing .env; check_ports_free runs
  # before .env is sourced, so consult both (not just the pre-source WITH_OAST latch).
  if [[ "$WITH_OAST" -eq 1 || -n "$OAST_DOMAIN_CLI" || -n "$(env_get WEISSMAN_OAST_DOMAIN)" ]]; then
    # OAST HTTP callback catcher (TCP). The DNS listener is UDP and not pre-checked here.
    local ohp; ohp="$(env_get WEISSMAN_OAST_HTTP_PORT)"
    ports+=("${WEISSMAN_OAST_HTTP_PORT:-${ohp:-9091}}")
  fi

  local unknown=0 port rc
  for port in "${ports[@]}"; do
    port_in_use "$port" && rc=0 || rc=$?
    case "$rc" in
      0)
        # Already ours (a previous run of this stack) is fine; anything else is a conflict.
        if ! docker ps --format '{{.Ports}}' 2>/dev/null | grep -q ":${port}->"; then
          die "port :${port} is already in use — free it or run ./start_weissman_live.sh stop"
        fi
        ;;
      2) unknown=1 ;;
    esac
  done
  if [[ "$unknown" -eq 1 ]]; then
    log "WARN: neither 'ss' nor 'netstat' found — skipping host port pre-check (install iproute2 for a clearer error on conflicts)"
  fi
}

check_prereqs() {
  need_cmd docker
  need_cmd openssl
  # wait_healthy() and verify_live() both probe the stack over HTTP.
  need_cmd curl
  docker compose version >/dev/null 2>&1 || die "docker compose v2 required"
  ensure_docker_daemon

  if [[ -x "$ROOT/scripts/verify_docker_build_integrity.sh" ]]; then
    "$ROOT/scripts/verify_docker_build_integrity.sh" || die "Docker build context incomplete — fix before deploy"
  fi
  for f in shared/engine_ui_manifests.json shared/engine_requirements.json; do
    [[ -f "$ROOT/$f" ]] || die "missing $f — run: node scripts/sync-engine-ui-manifests.mjs && node scripts/generate_engine_requirements.mjs"
  done

  check_ports_free
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
    # Pass the value through the ENVIRONMENT, not `awk -v`: -v applies C-escape processing,
    # so a value containing a backslash (or \n, \t) would be silently corrupted. ENVIRON is
    # taken literally. Keys are safe identifiers (used in the anchored regex).
    WEISSMAN_ENVSET_K="$key" WEISSMAN_ENVSET_V="$val" awk '
      BEGIN { k=ENVIRON["WEISSMAN_ENVSET_K"]; v=ENVIRON["WEISSMAN_ENVSET_V"]; done=0 }
      $0 ~ "^" k "=" { print k "=" v; done=1; next }
      { print }
      END { if (!done) print k "=" v }
    ' .env >"$tmp"
    mv "$tmp" .env
  else
    printf '%s=%s\n' "$key" "$val" >>.env
  fi
}

# Compose interpolates these from DB_* / POSTGRES_* pieces. Writing the full DSNs
# into .env is required so env_file, operators, and /api/ask boot-path all see the
# same values. An empty WEISSMAN_READ_ONLY_DATABASE_URL makes POST /api/ask return 503.
sync_role_database_urls() {
  local db pg_user app_user auth_user ro_user
  local pg_pw app_pw auth_pw ro_pw
  db="$(env_get POSTGRES_DB)"
  db="${db:-weissman}"
  pg_user="$(env_get POSTGRES_USER)"
  pg_user="${pg_user:-postgres}"
  app_user="$(env_get DB_APP_USER)"
  app_user="${app_user:-weissman_app}"
  auth_user="$(env_get DB_AUTH_USER)"
  auth_user="${auth_user:-weissman_auth}"
  ro_user="$(env_get DB_RO_USER)"
  ro_user="${ro_user:-weissman_ro}"
  pg_pw="$(env_get POSTGRES_PASSWORD)"
  app_pw="$(env_get DB_APP_PASSWORD)"
  auth_pw="$(env_get DB_AUTH_PASSWORD)"
  ro_pw="$(env_get DB_RO_PASSWORD)"
  [[ -n "$pg_pw" && -n "$app_pw" && -n "$auth_pw" && -n "$ro_pw" ]] \
    || die "DB role passwords missing after generation — cannot write role-separated DATABASE_URLs"
  env_set DATABASE_URL "postgresql://${app_user}:${app_pw}@postgres:5432/${db}"
  env_set WEISSMAN_AUTH_DATABASE_URL "postgresql://${auth_user}:${auth_pw}@postgres:5432/${db}"
  env_set WEISSMAN_READ_ONLY_DATABASE_URL "postgresql://${ro_user}:${ro_pw}@postgres:5432/${db}"
  env_set WEISSMAN_MIGRATE_URL "postgresql://${pg_user}:${pg_pw}@postgres:5432/${db}"
  log "Wrote DATABASE_URL + WEISSMAN_AUTH_DATABASE_URL + WEISSMAN_READ_ONLY_DATABASE_URL + WEISSMAN_MIGRATE_URL (role-separated, host=postgres)"
}

# Alias LLM env vars so Ask Weissman (NL→SQL) and Supreme Council RAG see one set of keys.
# Never invent an API key. If a key exists without a base URL, default to OpenAI's public API.
wire_llm_env() {
  local llm_url llm_key llm_model openai_key openai_url llm_base_alias nl_model
  llm_url="$(env_get WEISSMAN_LLM_BASE_URL)"
  llm_key="$(env_get WEISSMAN_LLM_API_KEY)"
  llm_model="$(env_get WEISSMAN_LLM_MODEL)"
  openai_key="$(env_get OPENAI_API_KEY)"
  openai_url="$(env_get OPENAI_BASE_URL)"
  llm_base_alias="$(env_get LLM_BASE_URL)"
  nl_model="$(env_get WEISSMAN_NL_QUERY_MODEL)"

  if [[ -z "$llm_key" && -n "$openai_key" ]]; then
    env_set WEISSMAN_LLM_API_KEY "$openai_key"
    llm_key="$openai_key"
    log "Aliased OPENAI_API_KEY → WEISSMAN_LLM_API_KEY"
  fi
  if [[ -z "$openai_key" && -n "$llm_key" ]]; then
    env_set OPENAI_API_KEY "$llm_key"
  fi
  if [[ -z "$llm_url" && -n "$openai_url" ]]; then
    env_set WEISSMAN_LLM_BASE_URL "$openai_url"
    llm_url="$openai_url"
  fi
  if [[ -z "$llm_url" && -n "$llm_base_alias" ]]; then
    env_set WEISSMAN_LLM_BASE_URL "$llm_base_alias"
    llm_url="$llm_base_alias"
  fi
  if [[ -z "$llm_url" && -n "$llm_key" ]]; then
    env_set WEISSMAN_LLM_BASE_URL "https://api.openai.com/v1"
    llm_url="https://api.openai.com/v1"
    log "WEISSMAN_LLM_BASE_URL defaulted to https://api.openai.com/v1 (API key is set)"
  fi
  if [[ -n "$llm_url" ]]; then
    env_set OPENAI_BASE_URL "$llm_url"
    env_set LLM_BASE_URL "$llm_url"
  fi
  if [[ -z "$nl_model" && -n "$llm_model" ]]; then
    env_set WEISSMAN_NL_QUERY_MODEL "$llm_model"
    nl_model="$llm_model"
  fi
  if [[ -z "$llm_url" ]]; then
    log "WARN: WEISSMAN_LLM_BASE_URL is unset — Ask Weissman / Supreme Council will fail closed until you set it (and WEISSMAN_LLM_API_KEY if the provider requires a bearer). Example: WEISSMAN_LLM_BASE_URL=http://host.docker.internal:11434/v1"
  else
    log "LLM wired: WEISSMAN_LLM_BASE_URL=${llm_url}  model=${llm_model:-default}  nl_query_model=${nl_model:-default}"
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
  # Every secret that fingerprint_engine/src/security_startup.rs demands in production must
  # be generated here, or the server and worker fail closed at boot and the stack never
  # becomes healthy. Keep this list in sync with that file's guards.
  local keys=(
    POSTGRES_PASSWORD
    REDIS_PASSWORD
    DB_APP_PASSWORD
    DB_AUTH_PASSWORD
    # Read-only role for "Ask Weissman" (NL->SQL). Required by the prod overlay's
    # WEISSMAN_READ_ONLY_DATABASE_URL; without it /api/ask is 503 and the boot role-sync
    # strips LOGIN from weissman_ro.
    DB_RO_PASSWORD
    WEISSMAN_JWT_SECRET
    WEISSMAN_METRICS_TOKEN
    WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET
    # Zero-trust job bus HMAC (security_startup.rs:146) — required by BOTH server and
    # worker in production, with no JWT fallback.
    WEISSMAN_JOB_ORCHESTRATOR_SECRET
    # Bearer for the OAST correlation API, shared by the listener and the engines. Generated
    # up front so enabling OAST later only needs WEISSMAN_OAST_DOMAIN; unused while OAST off.
    WEISSMAN_OAST_API_KEY
    # Dedicated secrets-at-rest key for MFA seeds and SOAR provider credentials. Without it the
    # vault derives its key from WEISSMAN_JWT_SECRET — the token-signing key, which is shipped to
    # every replica — so one leaked value both mints auth tokens and decrypts every stored
    # secret. security_startup.rs now refuses to boot production without this.
    WEISSMAN_INTEGRATIONS_VAULT_KEY
  )
  for key in "${keys[@]}"; do
    local cur
    cur="$(env_get "$key")"
    if [[ -z "${cur// }" ]]; then
      env_set "$key" "$(gen_secret)"
      log "Generated $key"
    fi
  done

  # CEO genesis vault. Must be exactly 64 hex chars (32 bytes) — ceo::vault::hex32 rejects
  # anything else, so it cannot use gen_secret's base64. Same rationale as
  # WEISSMAN_INTEGRATIONS_VAULT_KEY above: without it the vault key is derived from the
  # token-signing secret.
  if [[ -z "$(env_get WEISSMAN_VAULT_KEY)" ]]; then
    env_set WEISSMAN_VAULT_KEY "$(openssl rand -hex 32)"
    log "Generated WEISSMAN_VAULT_KEY"
  fi

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

  # Monitoring UIs get their OWN generated credential — never a copy of the platform admin
  # password. Grafana is a large third-party app with its own CVE stream and its own exposed
  # login. Copying WEISSMAN_ADMIN_PASSWORD into it (which this did — both values hashed to the
  # same SHA-256 on the live .env) means any Grafana credential disclosure hands over the
  # Weissman platform super-admin account, and vice versa. The blast radius of compromising the
  # dashboard tool should not be the security platform it monitors.
  if [[ -z "$(env_get GRAFANA_ADMIN_PASSWORD)" ]]; then
    env_set GRAFANA_ADMIN_PASSWORD "$(gen_password)"
  fi

  # Role-separated DSNs written into .env so operators (and env_file) see the same
  # URLs compose interpolates. Empty WEISSMAN_READ_ONLY_DATABASE_URL → /api/ask 503.
  sync_role_database_urls
  wire_llm_env

  if [[ -n "$PUBLIC_URL" ]]; then
    env_set WEISSMAN_PUBLIC_BASE_URL "$PUBLIC_URL"
  elif [[ -z "$(env_get WEISSMAN_PUBLIC_BASE_URL)" ]]; then
  # Default: assume TLS terminates in front of this host on :443, gateway on :80.
    env_set WEISSMAN_PUBLIC_BASE_URL "https://localhost"
    log "WEISSMAN_PUBLIC_BASE_URL=https://localhost — pass --url https://your.domain for real deploys"
  fi

  # Persist a shell-provided OAST domain so it survives `source .env` (the template ships a
  # blank line that would otherwise clobber it) and actually reaches the oast container.
  if [[ -n "$OAST_DOMAIN_CLI" ]]; then
    env_set WEISSMAN_OAST_DOMAIN "$OAST_DOMAIN_CLI"
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

  # Read through a local first: `${#VAR}` cannot be combined with `:-`, and a bare
  # `${#VAR}` on a .env that is missing the key would trip `set -u` with an opaque
  # "unbound variable" instead of the explanatory message below.
  require_len() {
    local name="$1" min="$2" hint="${3:-}" val="${!1:-}"
    if (( ${#val} < min )); then
      die "$name must be >= ${min} chars${hint:+ — $hint}"
    fi
  }
  require_len WEISSMAN_JWT_SECRET 48 "regenerate with: openssl rand -base64 48"
  require_len WEISSMAN_METRICS_TOKEN 32
  require_len WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET 32
  # security_startup.rs:146 rejects anything shorter for BOTH weissman-server and
  # weissman-worker; catching it here beats waiting out the health-check timeout.
  require_len WEISSMAN_JOB_ORCHESTRATOR_SECRET 32 "regenerate with: openssl rand -base64 48"
  require_len WEISSMAN_ADMIN_PASSWORD 12

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
  local extras=""
  if [[ "$WITH_MONITORING" -eq 1 ]]; then extras+=" + monitoring"; fi
  if [[ "$WITH_OAST" -eq 1 ]]; then extras+=" + OAST listener"; fi
  log "Starting LIVE stack (Postgres, Redis, API, Worker, Gateway${extras})..."
  dc "${up_args[@]}"
}

# Services this run expects to come up, in the order we report them.
stack_services() {
  printf '%s\n' postgres redis backend worker gateway
  if [[ "$WITH_MONITORING" -eq 1 ]]; then
    printf '%s\n' prometheus grafana alertmanager
  fi
  if [[ "$WITH_OAST" -eq 1 ]]; then
    printf '%s\n' oast
  fi
}

# Dump whatever we know about a service that never became healthy.
diagnose_service() {
  local svc="$1"
  log "--- $svc (last 60 log lines) ---"
  dc logs "$svc" --tail 60 2>&1 || true
}

wait_healthy() {
  # First boot compiles the whole Rust workspace, cargo-installs wasm-bindgen-cli, builds
  # two WASM crates, runs `npm ci` and a Vite production build. On a modest host that is
  # comfortably more than the old 15-minute budget, and blowing the deadline tore down an
  # otherwise-fine deploy. Default to 45 minutes; override for slower or faster machines.
  local timeout="${WEISSMAN_BOOT_TIMEOUT:-2700}"
  log "Waiting up to $((timeout / 60)) min for services to become healthy (first boot builds images — this is the slow part)..."

  local deadline=$((SECONDS + timeout))
  local services
  mapfile -t services < <(stack_services)

  # Track restarts per service so a container that is crash-looping fails fast with its
  # logs instead of silently eating the whole timeout: a looping container alternates
  # between "restarting" and "running", and the old check accepted "running".
  declare -A restarts=()
  local stalled_svc="" stalled_reason=""

  while (( SECONDS < deadline )); do
    local all_ok=1
    stalled_svc="" stalled_reason=""

    local svc
    for svc in "${services[@]}"; do
      local cid state health running restarting count
      cid="$(dc ps -q "$svc" 2>/dev/null || true)"
      if [[ -z "$cid" ]]; then
        all_ok=0; stalled_svc="$svc"; stalled_reason="no container yet"
        break
      fi

      # One inspect, several fields — cheaper and race-free versus several calls.
      IFS='|' read -r state health running restarting count < <(
        docker inspect -f \
          '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.Running}}|{{.State.Restarting}}|{{.RestartCount}}' \
          "$cid" 2>/dev/null || echo 'missing|none|false|false|0'
      )

      if [[ "${restarts[$svc]:-0}" != "$count" && "${restarts[$svc]:-unset}" != "unset" ]]; then
        log "WARN: $svc restarted (count $count) — it is probably failing at startup"
      fi
      restarts["$svc"]="$count"

      # A container that has restarted repeatedly is not "slow", it is broken.
      if (( count >= 3 )); then
        log "ERROR: $svc has restarted ${count} times — aborting early instead of waiting out the timeout."
        diagnose_service "$svc"
        die "$svc is crash-looping; fix the error above and re-run"
      fi

      if [[ "$restarting" == "true" || "$running" != "true" ]]; then
        all_ok=0; stalled_svc="$svc"; stalled_reason="state=$state restarting=$restarting"
        break
      fi
      # With a healthcheck, only "healthy" counts ("starting"/"unhealthy" do not). Without
      # one, a genuinely running, non-restarting container is the best signal available.
      if [[ "$health" != "none" && "$health" != "healthy" ]]; then
        all_ok=0; stalled_svc="$svc"; stalled_reason="health=$health"
        break
      fi
    done

    if [[ "$all_ok" -eq 1 ]]; then
      if curl -sf "http://127.0.0.1/api/health" >/dev/null 2>&1; then
        return 0
      fi
      stalled_svc="gateway"; stalled_reason="containers healthy but http://127.0.0.1/api/health is not answering"
    fi
    sleep 5
  done

  log "Timed out after $((timeout / 60)) min — last blocker: ${stalled_svc:-unknown} (${stalled_reason:-unknown})"
  dc ps || true
  diagnose_service "${stalled_svc:-backend}"
  [[ "${stalled_svc:-backend}" == "backend" ]] || diagnose_service backend
  die "stack did not pass health checks within $((timeout / 60)) minutes (raise WEISSMAN_BOOT_TIMEOUT if the build is simply slow)"
}

verify_live() {
  log "Verifying live endpoints..."
  # /api/health returns a compact JSON body (axum::Json -> serde_json, no spaces) whose
  # success marker is "ok":true — see fingerprint_engine/src/server_handlers_rest.inc.
  # It has NEVER had a "status" key, so the old `grep '"status"'` failed every healthy
  # deploy: wait_healthy passed, then verify_live died one line later and the operator
  # never saw the banner or the generated admin password.
  local health
  health="$(curl -sf "http://127.0.0.1/api/health")" || die "/api/health did not answer"
  grep -q '"ok":true' <<<"$health" || die "/api/health returned an unexpected body: $health"
  # postgres_ok can momentarily read false on a cold pool (2s ping timeout right after
  # migrations); warn rather than abort so a slow first boot is not misread as failure.
  grep -q '"postgres_ok":true' <<<"$health" \
    || log "WARN: backend reports postgres_ok=false — check: ./start_weissman_live.sh logs postgres"

  curl -sf "http://127.0.0.1/command-center/" >/dev/null || die "/command-center/ failed"

  local wid whealth wrunning
  wid="$(dc ps -q worker 2>/dev/null || true)"
  [[ -n "$wid" ]] || die "weissman-worker container is not running"
  wrunning="$(docker inspect -f '{{.State.Running}}' "$wid" 2>/dev/null || echo false)"
  [[ "$wrunning" == "true" ]] || die "weissman-worker is not running"
  whealth="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$wid")"
  if [[ "$whealth" != "healthy" && "$whealth" != "none" ]]; then
    die "weissman-worker health=${whealth} (expected healthy)"
  fi
  log "weissman-worker is running (health=${whealth})"

  # /api/ask requires analyst auth. 401/403 means the route is live and the read-only pool
  # is configured. 503 means WEISSMAN_READ_ONLY_DATABASE_URL did not reach the backend.
  local ask_code
  ask_code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1/api/ask" \
    -H 'Content-Type: application/json' \
    -d '{"question":"how many critical findings?"}' || echo 000)"
  case "$ask_code" in
    503)
      die "/api/ask returned 503 — WEISSMAN_READ_ONLY_DATABASE_URL is not reaching the backend (Ask Weissman disabled)"
      ;;
    401|403)
      log "/api/ask is armed (HTTP ${ask_code} auth required — read-only pool is configured)"
      ;;
    200)
      log "/api/ask answered HTTP 200"
      ;;
    *)
      die "/api/ask unexpected HTTP ${ask_code} — route is not reachable"
      ;;
  esac
  # NOTE: do not probe /api/config/public here — despite the name it is behind auth_guard
  # (not in PUBLIC_ROUTES) and returns 401 unauthenticated, and its body leaks tenant_id.
  # The gateway->backend hop is already exercised by /api/health above.

  if [[ "$WITH_MONITORING" -eq 1 ]]; then
    curl -sf "http://127.0.0.1:3000/login" >/dev/null || die "Grafana :3000 not reachable"
    # Prometheus is behind the basic-auth web config generated during preflight, so an
    # unauthenticated probe must answer 401 and an authenticated one 200. Anything else
    # (connection refused, 200 without auth) means it started without that config — the
    # banner would otherwise advertise a credentialled URL that is open or dead.
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:9090/-/ready" || echo 000)"
    case "$code" in
      401) : ;;
      000) die "Prometheus :9090 not reachable — check: ./start_weissman_live.sh logs prometheus" ;;
      200) log "WARN: Prometheus :9090 is answering WITHOUT authentication — regenerate monitoring/prometheus-web.generated.yml (scripts/sync_monitoring_admin.sh prometheus) and restart it" ;;
      *)   log "WARN: Prometheus :9090 returned HTTP ${code} (expected 401 behind basic auth)" ;;
    esac
  fi

  log "All live checks passed."
  log "System Ready"
}

print_banner() {
  # shellcheck disable=SC1091
  set -a && source .env && set +a

  local login_email="${WEISSMAN_ADMIN_EMAIL:-admin@localhost}"
  local base="${WEISSMAN_PUBLIC_BASE_URL%/}"
  cat <<EOF

================================================================================
  WEISSMAN LIVE — System Ready
================================================================================
  Command Center : ${base}/command-center/login   (the URL users log in at)
  Local access   : http://127.0.0.1/command-center/  (this host only)
  API health     : http://127.0.0.1/api/health
  Ask Weissman   : POST http://127.0.0.1/api/ask  (login required; read-only role is configured)
  LLM            : ${WEISSMAN_LLM_BASE_URL:-UNSET — set WEISSMAN_LLM_BASE_URL in .env for Council / NL→SQL}
  Admin email    : ${login_email}
EOF
  # Production forces Secure-only session cookies (WEISSMAN_COOKIE_SECURE=1). Browsers do
  # not send Secure cookies over plain http:// (except sometimes localhost), so logging in
  # over anything but HTTPS silently fails to keep a session — and sends the password in
  # cleartext. Warn loudly when the configured origin is not https.
  case "$base" in
    https://*)
      # Checking only the configured string is self-defeating: this launcher DEFAULTS
      # WEISSMAN_PUBLIC_BASE_URL to https://localhost, so the scheme test below always passed and
      # the warning could never fire — while the gateway served plain HTTP the whole time. That is
      # exactly the state the live deployment was found in (COOKIE_SECURE=1, base URL https://,
      # no 443 listener anywhere), where a browser silently discards the Secure session cookie and
      # login never persists.
      #
      # So probe it. If the configured HTTPS origin does not actually answer, say so.
      if ! curl -skf --max-time 4 -o /dev/null "${base%/}/api/health" 2>/dev/null; then
        cat <<EOF

  !! WARNING: WEISSMAN_PUBLIC_BASE_URL is $base but nothing answers HTTPS there.
     Session cookies are Secure-only in production, so a browser will DISCARD the session
     cookie over plain http:// and login will never persist — the app looks broken, not
     misconfigured. Either terminate TLS in front of the gateway, or re-run with
     --url http://your-host and set WEISSMAN_COOKIE_SECURE=0 to accept cleartext knowingly.
EOF
      fi
      ;;
    *)
      cat <<EOF

  !! WARNING: WEISSMAN_PUBLIC_BASE_URL is not HTTPS ($base).
     Session cookies are Secure-only in production, so login will NOT persist over http
     except on this host's loopback, and the admin password would cross the wire in clear.
     Put TLS in front of :80 and re-run with --url https://your.domain before real use.
EOF
      ;;
  esac
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
    cat <<EOF
  Grafana        : http://127.0.0.1:3000  (${login_email} / same as WEISSMAN_ADMIN_PASSWORD)
  Prometheus     : http://127.0.0.1:9090  (${login_email} / same password — health targets UI)
  Status page    : http://127.0.0.1/command-center/status  (uses Command Center login)
EOF
  fi
  cat <<EOF

  Services:
$(dc ps --format '    - {{.Name}}: {{.Status}}' 2>/dev/null || dc ps)

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

# Must run BEFORE compose_up. docker-compose.yml bind-mounts
# monitoring/prometheus-web.generated.yml, which is gitignored and therefore absent from a
# fresh clone — and the Docker daemon materialises a missing bind source as a DIRECTORY.
# Prometheus then gets a directory as its --web.config.file and never starts. Generating
# the file first makes that impossible. (This used to run inside print_banner, i.e. after
# the stack was already up and after verify_live had "confirmed" monitoring worked.)
preflight_monitoring() {
  [[ "$WITH_MONITORING" -eq 1 ]] || return 0
  [[ -x "${ROOT}/scripts/sync_monitoring_admin.sh" ]] || {
    log "WARN: scripts/sync_monitoring_admin.sh missing or not executable — Prometheus will start unauthenticated"
    return 0
  }
  log "Generating Prometheus basic-auth config..."
  "${ROOT}/scripts/sync_monitoring_admin.sh" prometheus \
    || die "could not generate monitoring/prometheus-web.generated.yml — Prometheus would start without authentication (re-run scripts/sync_monitoring_admin.sh prometheus to see the error)"
}

cmd_start() {
  parse_args "$@"
  # OAST needs a DNS zone the operator delegates, so it is opt-in via WEISSMAN_OAST_DOMAIN.
  # Peek the shell env before .env exists so port checks line up on first boot.
  if [[ -n "${WEISSMAN_OAST_DOMAIN:-}" ]]; then WITH_OAST=1; fi
  check_prereqs
  ensure_env
  # ensure_env sources .env, which may itself define WEISSMAN_OAST_DOMAIN.
  if [[ -n "$(env_get WEISSMAN_OAST_DOMAIN)" ]]; then WITH_OAST=1; fi
  resolve_profiles
  if [[ "$WITH_OAST" -eq 0 ]]; then
    log "OAST listener disabled (WEISSMAN_OAST_DOMAIN unset) — blind SSRF/XXE/Log4Shell callbacks will not be correlated. Set WEISSMAN_OAST_DOMAIN to a delegated zone to enable."
  fi
  validate_env
  preflight_monitoring
  compose_up
  wait_healthy
  verify_live
  # Grafana keeps credentials in its own volume, so its password can only be aligned once
  # the container is actually running — unlike the Prometheus config, which must exist first.
  if [[ "$WITH_MONITORING" -eq 1 && -x "${ROOT}/scripts/sync_monitoring_admin.sh" ]]; then
    "${ROOT}/scripts/sync_monitoring_admin.sh" grafana \
      || log "WARN: Grafana credential sync failed — run: scripts/sync_monitoring_admin.sh grafana"
  fi
  print_banner
}

# For non-start commands: infer which optional stacks are present from .env so
# ps / logs / down operate on their containers too.
resolve_optional_stacks_from_env() {
  if [[ -n "$(env_get WEISSMAN_OAST_DOMAIN)" ]]; then WITH_OAST=1; fi
  resolve_profiles
}

cmd_reset() {
  resolve_optional_stacks_from_env
  # `reset` sits one word away from `start` in the same dispatcher and destroys every
  # customer scan, finding, and audit record. Make it deliberate.
  if [[ -t 0 && "${WEISSMAN_ASSUME_YES:-0}" != "1" ]]; then
    log "This DESTROYS all Postgres/Redis/Grafana/Prometheus data for this deployment."
    read -r -p "[weissman-live] Type 'destroy' to confirm: " reply
    [[ "$reply" == "destroy" ]] || die "aborted — nothing was deleted"
  elif [[ "${WEISSMAN_ASSUME_YES:-0}" != "1" ]]; then
    die "refusing to destroy data non-interactively — re-run with WEISSMAN_ASSUME_YES=1 if that is really what you want"
  fi
  log "Full teardown — stopping stack and destroying Postgres/Redis/Grafana/Prometheus volumes..."
  dc down -v --remove-orphans
  log "Volumes cleared. Re-deploy with: ./start_weissman_live.sh"
}

cmd_stop() {
  resolve_optional_stacks_from_env
  log "Stopping Weissman LIVE stack..."
  dc down --remove-orphans
  log "Stopped (data volumes preserved — use './start_weissman_live.sh reset' to wipe the DB)."
}

cmd_status() {
  if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
  fi
  resolve_optional_stacks_from_env
  dc ps
  echo ""
  if curl -sf "http://127.0.0.1/api/health" >/dev/null 2>&1; then
    log "API: healthy"
  else
    log "API: down"
  fi
}

cmd_logs() {
  [[ -f .env ]] && { set -a; source .env; set +a; }
  resolve_optional_stacks_from_env
  local svc="${1:-}"
  if [[ -n "$svc" ]]; then
    dc logs -f "$svc"
  else
    dc logs -f
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