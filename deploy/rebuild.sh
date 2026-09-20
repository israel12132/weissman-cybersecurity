#!/usr/bin/env bash
# deploy/rebuild.sh — rebuild and roll out new Weissman code without a visible outage.
#
# WHY THIS EXISTS
# ./start_weissman.sh and ./start_weissman_live.sh are "start everything" launchers: they
# rebuild and then restart the WHOLE stack, and that restart is the outage a visitor sees.
# This script does the smallest thing that puts new code in front of visitors, and reports
# how long the origin was actually away:
#
#   compose   docker compose build (slow, nothing restarts) → recreate ONLY backend, worker
#             and worker-soar with --no-deps → recreate the gateway with --no-deps ONLY when
#             its image id changed → wait for HTTP 200 from /api/health through the published
#             gateway address (WEISSMAN_GATEWAY_BIND/PORT from .env) → summary.
#   systemd   cargo build --release + Command Center build → install binaries + dist →
#             restart weissman-server / weissman-worker → wait for /api/health → summary.
#
# THE CONTINUITY PAGE IS AUTOMATIC. Every gateway layer serves the branded page whenever the
# origin cannot answer (502/504/connection failure) and stops the moment it answers again;
# the page polls /api/health and reloads on the first genuine 200. Nothing here switches it
# on. The maintenance FLAG (deploy/maintenance/maintenance-mode.sh) is a separate, opt-in
# extra that only ANNOUNCES a window (the page then reads "Planned maintenance"). This script
# sets it only when asked (--with-maintenance-flag / WEISSMAN_REBUILD_MAINTENANCE_FLAG=1),
# and then clears it on every exit path — success, failure, Ctrl+C — so the site can never be
# left stuck in maintenance by a rollout that stopped half way.
#
# Usage (from anywhere; the script finds the checkout):
#   deploy/rebuild.sh                              auto-detect compose vs systemd, roll out
#   deploy/rebuild.sh --dry-run                    print the plan, run nothing
#   deploy/rebuild.sh --mode compose|systemd       force the topology
#   deploy/rebuild.sh --with-maintenance-flag      also announce the window (opt-in)
#   deploy/rebuild.sh --timeout 600                wait up to N s for /api/health (default 300)
#
# Environment:
#   WEISSMAN_REBUILD_MAINTENANCE_FLAG=1   same as --with-maintenance-flag
#   WEISSMAN_MAINTENANCE_STATE_DIR        where the flag lives. compose: the directory the
#                                         gateway bind-mounts (.env, default
#                                         deploy/maintenance/state); systemd: the installed
#                                         page's state dir, /opt/weissman/maintenance/state
#   WEISSMAN_HEALTH_URL                   override the URL that is polled for 200
#   WEISSMAN_GATEWAY_BIND / _PORT         compose: published gateway address (read from .env)
#   WEISSMAN_SKIP_FRONTEND_BUILD=1        systemd: skip the Command Center build
#   INSTALL_ROOT                          systemd: install root (default /opt/weissman/app)
#
# No sudo beyond what start_weissman.sh already uses on the systemd path (install, rsync,
# systemctl). The compose path uses the docker CLI as the current user, like the launcher.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# rustup installs cargo here; a fresh login shell often misses it (same as start_weissman.sh).
if [[ -f "${HOME:-/nonexistent}/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  . "${HOME}/.cargo/env"
fi

MODE=auto
DRY_RUN=0
WITH_FLAG=0
[[ "${WEISSMAN_REBUILD_MAINTENANCE_FLAG:-0}" == "1" ]] && WITH_FLAG=1
TIMEOUT=300

MM_SH="$ROOT/deploy/maintenance/maintenance-mode.sh"
FLAG_SET=0            # 1 while THIS run holds the flag up (the only state the trap clears)
DOWN_SECS=0           # seconds the origin was seen away, summed over the rollout steps
RECREATED=()          # what actually restarted, for the summary
BG_PID=""             # background rollout step, killed by the trap
T_START=$SECONDS
HEALTH_URL=""         # what "back" means: this URL answering 200
ORIGIN_URL=""         # the Rust origin itself (systemd: what nginx/Caddy proxy to)
STALL_CHECK=:         # per-mode hook run once a second while the origin is still away
BACKEND_OK_AT=-1      # compose: SECONDS when the backend container first reported healthy
NUDGED=0              # compose: nginx reloaded once to re-resolve the backend address
WORK="$(mktemp -d "${TMPDIR:-/tmp}/weissman-rebuild.XXXXXX")"
STEP_LOG="$WORK/step.log"
STEP_RC="$WORK/step.rc"

log()  { printf '[rebuild] %s\n' "$*"; }
warn() { printf '[rebuild] WARN: %s\n' "$*" >&2; }
die()  { printf '[rebuild] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Weissman — rebuild and roll out new code without a visible outage.

Usage:
  deploy/rebuild.sh [--mode compose|systemd] [--dry-run] [--with-maintenance-flag] [--timeout N]

Options:
  --mode compose|systemd    force the topology (default: auto — compose when the Docker
                            stack is running, else systemd when weissman-server.service exists)
  --dry-run                 print the plan and exit without changing anything
  --with-maintenance-flag   also announce the window with deploy/maintenance/maintenance-mode.sh
                            (opt-in; env WEISSMAN_REBUILD_MAINTENANCE_FLAG=1). The continuity
                            page appears automatically either way — this only adds the
                            "Planned maintenance" wording. Cleared on every exit path.
  --timeout N               seconds to wait for HTTP 200 from /api/health (default 300)
  -h, --help                this message

What happens by default:
  compose : build images → recreate backend/worker/worker-soar (--no-deps) → recreate the
            gateway only if its image changed → wait for /api/health 200 → summary
  systemd : cargo build --release + Command Center → install → restart units → wait → summary
USAGE
}

fmt_secs() {
  local s=$1
  if (( s >= 60 )); then printf '%dm %02ds' $((s / 60)) $((s % 60)); else printf '%ds' "$s"; fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Last assignment wins, like the launcher's env_get; surrounding quotes are dropped.
env_get() {
  local val=""
  if [[ -f .env ]]; then
    val="$(grep -E "^${1}=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true)"
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
  fi
  printf '%s' "$val"
}

# ── argument parsing ─────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)      [[ $# -ge 2 ]] || { usage >&2; die "--mode needs compose or systemd"; }; MODE="$2"; shift 2 ;;
    --mode=*)    MODE="${1#--mode=}"; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --with-maintenance-flag) WITH_FLAG=1; shift ;;
    --timeout)   [[ $# -ge 2 ]] || { usage >&2; die "--timeout needs a number of seconds"; }; TIMEOUT="$2"; shift 2 ;;
    --timeout=*) TIMEOUT="${1#--timeout=}"; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           usage >&2; printf '[rebuild] ERROR: unknown flag: %s\n' "$1" >&2; exit 2 ;;
  esac
done
case "$MODE" in auto|compose|systemd) ;; *) printf '[rebuild] ERROR: --mode must be compose or systemd (got %s)\n' "$MODE" >&2; exit 2 ;; esac
[[ "$TIMEOUT" =~ ^[0-9]+$ && "$TIMEOUT" -gt 0 ]] || { printf '[rebuild] ERROR: --timeout must be a positive number of seconds\n' >&2; exit 2; }

# ── maintenance flag (opt-in) ────────────────────────────────────────────────

flag_state_dir() {
  if [[ -n "${WEISSMAN_MAINTENANCE_STATE_DIR:-}" ]]; then
    printf '%s' "$WEISSMAN_MAINTENANCE_STATE_DIR"
  elif [[ "$MODE" == compose ]]; then
    # Must be the very directory docker-compose.yml bind-mounts into the gateway, or nginx
    # never sees the flag. The compose default is ./deploy/maintenance/state.
    local d; d="$(env_get WEISSMAN_MAINTENANCE_STATE_DIR)"
    d="${d:-./deploy/maintenance/state}"
    # Compose resolves a relative path against the project dir; make it absolute so the
    # sudo fallback in run_flag cannot resolve it against a different cwd.
    [[ "$d" == /* ]] || d="$ROOT/${d#./}"
    printf '%s' "$d"
  else
    # LAYOUT: deploy/maintenance/install.sh puts the page at /opt/weissman/maintenance and
    # the state dir beside it; deploy/nginx-weissman.conf and deploy/Caddyfile read there.
    printf '%s' "/opt/weissman/maintenance/state"
  fi
}

# maintenance-mode.sh, as this user when the state dir is writable, else through sudo
# (on a VPS the dir is root-owned unless install.sh was given WEISSMAN_MAINTENANCE_OWNER).
run_flag() {
  local dir; dir="$(flag_state_dir)"
  if [[ ( -d "$dir" && -w "$dir" ) || ( ! -e "$dir" && -w "$(dirname "$dir")" ) ]]; then
    WEISSMAN_MAINTENANCE_STATE_DIR="$dir" bash "$MM_SH" "$@" >/dev/null
  else
    sudo env WEISSMAN_MAINTENANCE_STATE_DIR="$dir" bash "$MM_SH" "$@" >/dev/null
  fi
}

flag_on() {
  (( WITH_FLAG == 1 )) || return 0
  if [[ ! -f "$MM_SH" ]]; then
    warn "deploy/maintenance/maintenance-mode.sh not found — rolling out without the announcement (the page still appears automatically)"
    WITH_FLAG=0
    return 0
  fi
  if run_flag on --reason "Platform update in progress"; then
    FLAG_SET=1
    log "Announced window: maintenance flag ON in $(flag_state_dir) (cleared automatically when the origin is back)"
  else
    warn "could not set the maintenance flag — rolling out without the announcement"
    WITH_FLAG=0
  fi
}

flag_off() {
  (( FLAG_SET == 1 )) || return 0
  FLAG_SET=0
  if run_flag off; then
    log "Maintenance flag cleared"
  else
    warn "could not clear the maintenance flag — run: WEISSMAN_MAINTENANCE_STATE_DIR=$(flag_state_dir) $MM_SH off"
  fi
}

cleanup() {
  local rc=$?
  trap - EXIT
  if [[ -n "$BG_PID" ]]; then kill "$BG_PID" 2>/dev/null || true; fi
  if (( FLAG_SET == 1 )); then
    (( rc == 0 )) || warn "rollout stopped early (exit $rc) — clearing the maintenance flag so the site is not left announced"
    flag_off
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ── health probing ───────────────────────────────────────────────────────────

resolve_health_url() {
  # The Rust origin itself: PORT from the unit env (deploy/systemd/weissman.env.example),
  # 8000 by default — what deploy/nginx-weissman.conf and deploy/Caddyfile proxy to.
  ORIGIN_URL="http://127.0.0.1:${PORT:-8000}/api/health"
  if [[ -n "${WEISSMAN_HEALTH_URL:-}" ]]; then
    HEALTH_URL="$WEISSMAN_HEALTH_URL"
    return 0
  fi
  if [[ "$MODE" == compose ]]; then
    # The published gateway address: compose maps ${WEISSMAN_GATEWAY_BIND:-127.0.0.1}:
    # ${WEISSMAN_GATEWAY_PORT:-80} → gateway:8080. Shell env wins over .env, as in compose.
    local bind port
    bind="${WEISSMAN_GATEWAY_BIND:-$(env_get WEISSMAN_GATEWAY_BIND)}"; bind="${bind:-127.0.0.1}"
    port="${WEISSMAN_GATEWAY_PORT:-$(env_get WEISSMAN_GATEWAY_PORT)}"; port="${port:-80}"
    case "$bind" in 0.0.0.0|'::'|'[::]'|'*') bind=127.0.0.1 ;; esac
    if [[ "$bind" == *:* && "$bind" != \[* ]]; then bind="[$bind]"; fi
    HEALTH_URL="http://${bind}:${port}/api/health"
  else
    # nginx/Caddy sit in front of the origin with a public hostname this script does not
    # know, so the origin is polled directly. WEISSMAN_HEALTH_URL overrides (see
    # systemd_stall_check for how the announced-window flag is handled in that case).
    HEALTH_URL="$ORIGIN_URL"
  fi
}

# Prints the HTTP status code of $1 (default HEALTH_URL); 000 when nothing answers. Only a
# 200 counts as "back": the gateway's own branded 503 is the continuity page doing its job.
probe() {
  curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 4 \
    -H 'Accept: application/json' "${1:-$HEALTH_URL}" 2>/dev/null || true
}

# Run "$@" in the background while probing once a second, so the first failed probe — not
# the moment the command returned — marks the start of the unreachable window. Sets T_FAIL
# (SECONDS of the first failure, -1 when the origin never missed a probe). Dies with the
# command's last output when it fails.
run_while_probing() {
  local label="$1"; shift
  local code rc
  T_FAIL=-1
  rm -f "$STEP_RC"; : >"$STEP_LOG"
  ( set +e; "$@" >"$STEP_LOG" 2>&1; echo $? >"$STEP_RC" ) &
  BG_PID=$!
  while [[ ! -f "$STEP_RC" ]]; do
    code="$(probe)"
    if [[ "$code" != 200 && "$T_FAIL" -lt 0 ]]; then T_FAIL=$SECONDS; fi
    sleep 1
  done
  wait "$BG_PID" 2>/dev/null || true
  BG_PID=""
  rc="$(cat "$STEP_RC")"
  if [[ "$rc" != 0 ]]; then
    tail -n 30 "$STEP_LOG" >&2 || true
    die "$label failed (exit $rc) — see the output above; the site keeps serving the continuity page until the origin is back"
  fi
}

# Poll until /api/health answers 200 or TIMEOUT passes. $1 = SECONDS at which the origin was
# first seen away (-1 = not yet). Adds the unreachable window to DOWN_SECS.
wait_until_up() {
  local t_fail="$1" code deadline=$((SECONDS + TIMEOUT)) reported=0
  while :; do
    code="$(probe)"
    if [[ "$code" == 200 ]]; then
      if (( t_fail >= 0 )); then DOWN_SECS=$((DOWN_SECS + SECONDS - t_fail)); fi
      return 0
    fi
    if (( t_fail < 0 )); then t_fail=$SECONDS; fi
    if (( reported == 0 )); then
      log "Origin away (HTTP $code) — visitors see the continuity page; waiting for $HEALTH_URL → 200 (up to $(fmt_secs "$TIMEOUT"))"
      reported=1
    fi
    $STALL_CHECK
    (( SECONDS < deadline )) || die "origin did not answer 200 at $HEALTH_URL within $(fmt_secs "$TIMEOUT") (last: HTTP $code) — the continuity page stays up until it does; raise --timeout if the start is merely slow"
    sleep 1
  done
}

# ── compose topology ─────────────────────────────────────────────────────────

COMPOSE_FILES=()
PROFILES=()
PROJECT=""
SERVICES=(backend worker)   # worker-soar is added only when it already has a container

dc() { docker compose "${COMPOSE_FILES[@]}" "${PROFILES[@]}" "$@"; }

default_compose_files() {
  COMPOSE_FILES=(-f docker-compose.yml)
  # The launcher always layers the production overlay; match it unless the running stack
  # says otherwise (compose_attach reads the real file list off the containers' labels).
  [[ -f docker-compose.prod.yml ]] && COMPOSE_FILES+=(-f docker-compose.prod.yml)
  return 0
}

svc_cid() {
  docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" \
    --filter "label=com.docker.compose.service=$1" 2>/dev/null | head -1
}

svc_running() {
  local cid; cid="$(svc_cid "$1")"
  [[ -n "$cid" ]] && docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null | grep -qx true
}

compose_stack_running() {
  docker info >/dev/null 2>&1 || return 1
  local cid
  cid="$(dc ps -q backend 2>/dev/null | head -1)" || true
  [[ -n "$cid" ]] && docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null | grep -qx true
}

# Bind to the stack that is actually running: its project name and the exact compose files it
# was created with, so a stack started with plain `docker compose up` is not recreated with
# the production overlay (or the other way round).
compose_attach() {
  local cid files
  cid="$(dc ps -q backend 2>/dev/null | head -1)" || true
  [[ -n "$cid" ]] || die "the Docker stack is not running here — start it with ./start_weissman_live.sh start, then use rebuild.sh for later rollouts"
  PROJECT="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$cid")"
  files="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$cid" 2>/dev/null || true)"
  if [[ -n "$files" ]]; then
    local f ok=1 list=()
    IFS=',' read -r -a list <<<"$files"
    for f in "${list[@]}"; do [[ -f "$f" ]] || ok=0; done
    if (( ok == 1 )); then
      COMPOSE_FILES=()
      for f in "${list[@]}"; do COMPOSE_FILES+=(-f "$f"); done
    fi
  fi
  # worker-soar sits behind `profiles: ["soar"]`; touch it only when the operator runs it.
  if svc_running worker-soar; then
    SERVICES+=(worker-soar)
    PROFILES+=(--profile soar)
  fi
}

# The backend image must ship every checkout migration: a live database that already applied
# one the image lacks makes the new container refuse to boot, and a crash loop is the one
# thing the continuity page cannot fix. Same guard as start_weissman_live.sh; checked BEFORE
# anything is recreated, while the old containers still serve.
assert_image_migrations() {
  local img="$1" host_list image_list missing
  [[ -d crates/weissman-db/migrations ]] || return 0
  host_list="$(find crates/weissman-db/migrations -maxdepth 1 -name '*.sql' -printf '%f\n' | sort)"
  image_list="$(docker run --rm --entrypoint sh "$img" -c 'ls -1 /srv/migrations/*.sql 2>/dev/null | sed "s|.*/||"' 2>/dev/null | sort)" || true
  if [[ -z "$image_list" ]]; then
    warn "could not list /srv/migrations inside $img — skipping the migration check"
    return 0
  fi
  missing="$(comm -23 <(printf '%s\n' "$host_list") <(printf '%s\n' "$image_list") || true)"
  if [[ -n "$missing" ]]; then
    printf '%s\n' "$missing" | sed 's/^/  - /' >&2
    die "$img does not ship the migration files above — the build context was frozen before they existed; nothing was recreated"
  fi
}

# Once a second while the origin is still away after the recreate. Fails fast on a crash
# loop instead of eating the timeout; clears the announced window as soon as the backend is
# healthy (the flag itself answers /api/health with 503, so the wait would otherwise never
# end); and reloads nginx gracefully if the backend is healthy but the gateway still cannot
# reach it — nginx resolves `backend` once at startup, and a recreated container can come
# back on a different address. A reload keeps the listener open, so nothing is dropped.
compose_stall_check() {
  local cid st health rcnt
  cid="$(svc_cid backend)"
  [[ -n "$cid" ]] || return 0
  IFS='|' read -r st health rcnt < <(
    docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}' \
      "$cid" 2>/dev/null || echo 'missing|none|0'
  )
  if [[ "$st" == exited || "$st" == dead ]] || (( rcnt >= 3 )); then
    docker logs --tail 40 "$cid" >&2 2>&1 || true
    die "backend is not starting (state=$st, restarts=$rcnt) — see its log above; the continuity page stays up meanwhile"
  fi
  [[ "$health" == healthy ]] || return 0
  if (( FLAG_SET == 1 )); then
    log "Backend is healthy — clearing the announced window"
    flag_off
    BACKEND_OK_AT=$SECONDS
    return 0
  fi
  if (( BACKEND_OK_AT < 0 )); then BACKEND_OK_AT=$SECONDS; fi
  if (( NUDGED == 0 && SECONDS - BACKEND_OK_AT >= 10 )); then
    NUDGED=1
    log "Backend is healthy but the gateway still cannot reach it — reloading nginx (graceful, re-resolves the backend address)"
    dc exec -T gateway nginx -s reload >/dev/null 2>&1 || true
  fi
}

plan_compose() {
  local files="" f flag_line
  for f in "${COMPOSE_FILES[@]}"; do [[ "$f" == -f ]] || files+="${files:+ + }${f#"$ROOT"/}"; done
  cat <<PLAN
[rebuild] plan — dry run, nothing is executed
  mode           : compose  (${files})
  health check   : $HEALTH_URL  (timeout $(fmt_secs "$TIMEOUT"))
  1. docker compose build                        the slow part; the running stack keeps serving
  2. check the backend image ships every checkout migration (aborts BEFORE any recreate)
  3. recreate gateway --no-deps                  only if its image id changed
  4. recreate backend worker [worker-soar] --no-deps (worker-soar only when it already runs)
  5. wait for HTTP 200 from /api/health through the gateway; while the origin is away
     visitors get the continuity page automatically (503 + Retry-After, auto-reload on 200)
  6. summary: elapsed time and how long the origin was unreachable
PLAN
  if (( WITH_FLAG == 1 )); then
    flag_line="ON before step 4 in $(flag_state_dir) (the page reads \"Planned maintenance\"), cleared as soon as the backend is healthy and on any failure"
  else
    flag_line="not used — opt in with --with-maintenance-flag to announce a planned window"
  fi
  printf '  maintenance flag: %s\n' "$flag_line"
}

rebuild_compose() {
  have_cmd docker || die "docker is not installed"
  docker info >/dev/null 2>&1 || die "the Docker daemon is not running (start_weissman.sh --live starts it)"
  compose_attach
  STALL_CHECK=compose_stall_check

  local gw_cid gw_tag gw_old gw_new be_cid be_tag
  gw_cid="$(svc_cid gateway)"
  be_cid="$(svc_cid backend)"

  log "Building images (the running stack keeps serving meanwhile)..."
  dc build

  be_tag="$(docker inspect -f '{{.Config.Image}}' "$be_cid" 2>/dev/null || echo weissman-backend:stable)"
  assert_image_migrations "$be_tag"

  # Gateway first, and only when its image really changed: a gateway recreate is the one
  # step that closes the listener for a moment (connection refused, ~1–2 s, no page can
  # cover it), so it is skipped whenever possible. When it does happen it goes first, so the
  # NEW gateway — with the current continuity page — is the one covering the backend window.
  if [[ -n "$gw_cid" ]]; then
    gw_tag="$(docker inspect -f '{{.Config.Image}}' "$gw_cid")"
    gw_old="$(docker inspect -f '{{.Image}}' "$gw_cid")"
    gw_new="$(docker image inspect -f '{{.Id}}' "$gw_tag" 2>/dev/null || echo "$gw_old")"
  else
    gw_old=""; gw_new="new"
  fi
  if [[ "$gw_old" != "$gw_new" ]]; then
    log "Gateway image changed — recreating gateway (--no-deps)"
    run_while_probing "gateway recreate" dc up -d --no-deps --no-build gateway
    RECREATED+=("gateway")
    wait_until_up "$T_FAIL"
  else
    log "Gateway image unchanged — not touched"
  fi

  flag_on
  log "Recreating ${SERVICES[*]} (--no-deps; the gateway serves the continuity page while the backend restarts)..."
  BACKEND_OK_AT=-1; NUDGED=0
  run_while_probing "service recreate" dc up -d --no-deps --no-build "${SERVICES[@]}"
  RECREATED+=("${SERVICES[@]}")
  wait_until_up "$T_FAIL"
  flag_off
}

# ── systemd topology ─────────────────────────────────────────────────────────

systemd_units_installed() {
  have_cmd systemctl && systemctl cat weissman-server.service >/dev/null 2>&1
}

systemd_stall_check() {
  local st
  st="$(systemctl is-active weissman-server 2>/dev/null || true)"
  if [[ "$st" == failed || "$st" == inactive ]]; then
    sudo journalctl -u weissman-server -n 30 --no-pager >&2 2>/dev/null || true
    die "weissman-server is '$st' after the restart — see the journal above; the gateway keeps serving the continuity page until it starts"
  fi
  # While the flag is up, nginx/Caddy answer 503 for everything — including a public
  # WEISSMAN_HEALTH_URL — so a wait that goes through the host gateway would never end.
  # Clear the announcement as soon as the origin itself answers, then keep waiting for the
  # real 200 through the gateway.
  if (( FLAG_SET == 1 )) && [[ "$HEALTH_URL" != "$ORIGIN_URL" ]] && [[ "$(probe "$ORIGIN_URL")" == 200 ]]; then
    log "Origin answers at $ORIGIN_URL — clearing the announced window"
    flag_off
  fi
}

plan_systemd() {
  local install_root="${INSTALL_ROOT:-/opt/weissman/app}" fe maint flag_line
  if [[ "${WEISSMAN_SKIP_FRONTEND_BUILD:-0}" == "1" ]]; then fe="skipped (WEISSMAN_SKIP_FRONTEND_BUILD=1)"; else fe="npm run build in frontend/"; fi
  if [[ -x deploy/maintenance/install.sh ]]; then
    maint="deploy/maintenance/install.sh --no-build → ${WEISSMAN_MAINTENANCE_ROOT:-/opt/weissman/maintenance} (only when that dir exists; non-fatal)"
  else
    maint="skipped (deploy/maintenance/install.sh not present)"
  fi
  cat <<PLAN
[rebuild] plan — dry run, nothing is executed
  mode           : systemd  (install root $install_root)
  health check   : $HEALTH_URL  (timeout $(fmt_secs "$TIMEOUT"))
  1. cargo build --release -p weissman-server -p weissman-worker   the running units keep serving
  2. Command Center: $fe
  3. sudo install binaries → $install_root/bin, rsync dist → $install_root/frontend/dist (when present)
  4. refresh the installed continuity page: $maint
  5. sudo systemctl restart weissman-server weissman-worker
  6. wait for HTTP 200 from /api/health; nginx/Caddy serve the continuity page automatically
     while the origin is away (502/504/connection refused → page; first 200 → gone)
  7. summary: elapsed time and how long the origin was unreachable
PLAN
  if (( WITH_FLAG == 1 )); then
    flag_line="ON before step 5 in $(flag_state_dir) (\"Planned maintenance\" wording), cleared when the origin is back and on any failure"
  else
    flag_line="not used — opt in with --with-maintenance-flag to announce a planned window"
  fi
  printf '  maintenance flag: %s\n' "$flag_line"
}

rebuild_systemd() {
  systemd_units_installed || die "weissman-server.service is not installed here (deploy/systemd/install-weissman-systemd.sh)"
  STALL_CHECK=systemd_stall_check
  local install_root="${INSTALL_ROOT:-/opt/weissman/app}"

  if have_cmd cargo; then
    log "Building release binaries (the running units keep serving meanwhile)..."
    cargo build --release -p weissman-server -p weissman-worker
    if [[ -d "$install_root/bin" ]]; then
      sudo install -m 0755 "$ROOT/target/release/weissman-server" "$install_root/bin/weissman-server"
      sudo install -m 0755 "$ROOT/target/release/weissman-worker" "$install_root/bin/weissman-worker"
    fi
    if [[ "${WEISSMAN_SKIP_FRONTEND_BUILD:-0}" != "1" && -d frontend ]]; then
      log "Building the Command Center..."
      (cd frontend && { [[ -d node_modules ]] || npm ci; } && npm run build) || die "frontend build failed"
      if [[ -d "$install_root/frontend/dist" ]]; then
        sudo rsync -a --delete frontend/dist/ "$install_root/frontend/dist/"
      fi
    fi
  else
    warn "cargo not on PATH — restarting the installed units as they are"
  fi

  # Keep the installed page in step with the checkout. --no-build only verifies the committed
  # dist (root must not rewrite generated files inside the operator's checkout). Non-fatal:
  # a stale or missing page is a documentation problem, not a reason to abort a rollout.
  local maint_root="${WEISSMAN_MAINTENANCE_ROOT:-/opt/weissman/maintenance}"
  if [[ -x deploy/maintenance/install.sh && -d "$maint_root" ]]; then
    if sudo env WEISSMAN_MAINTENANCE_ROOT="$maint_root" bash deploy/maintenance/install.sh --no-build >/dev/null; then
      log "Continuity page refreshed in $maint_root"
    else
      warn "continuity page not refreshed (run: node deploy/maintenance/build.mjs && sudo deploy/maintenance/install.sh) — continuing"
    fi
  fi

  flag_on
  # The restart runs in the foreground (sudo may prompt), so the window is measured from the
  # restart command: systemd stops the server first thing, and the drain is quick.
  local t0=$SECONDS
  log "Restarting weissman-server + weissman-worker (nginx/Caddy serve the continuity page until the origin answers)..."
  sudo systemctl restart weissman-server weissman-worker
  RECREATED+=("weissman-server" "weissman-worker")
  local t_fail=-1
  if [[ "$(probe)" != 200 ]]; then t_fail=$t0; fi
  wait_until_up "$t_fail"
  flag_off
}

# ── mode detection, plan, run ────────────────────────────────────────────────

detect_mode() {
  [[ "$MODE" == auto ]] || return 0
  if [[ -f docker-compose.yml ]] && have_cmd docker && compose_stack_running; then
    MODE=compose
  elif systemd_units_installed; then
    MODE=systemd
  else
    die "cannot tell how Weissman runs here (no running Docker Compose stack, no weissman-server.service) — pass --mode compose or --mode systemd"
  fi
}

summary() {
  local total=$((SECONDS - T_START))
  log "────────────────────────────────────────────────────────────"
  log "Rollout finished in $(fmt_secs "$total") — $HEALTH_URL answers 200"
  log "Restarted: ${RECREATED[*]:-nothing}"
  if (( DOWN_SECS > 0 )); then
    log "Origin unreachable for $(fmt_secs "$DOWN_SECS") — the continuity page covered that window automatically"
  else
    log "Origin unreachable for 0 s — no probe missed during the rollout"
  fi
  if (( WITH_FLAG == 1 )); then
    log "Announced window: flag was raised for the rollout and is cleared"
  else
    log "Maintenance flag: not used (the page is automatic; --with-maintenance-flag announces a window)"
  fi
}

have_cmd curl || die "curl is required (health checks)"
[[ -f docker-compose.yml ]] && default_compose_files
detect_mode
resolve_health_url

if (( DRY_RUN == 1 )); then
  if [[ "$MODE" == compose ]]; then plan_compose; else plan_systemd; fi
  exit 0
fi

if [[ "$MODE" == compose ]]; then rebuild_compose; else rebuild_systemd; fi
summary
