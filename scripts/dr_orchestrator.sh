#!/usr/bin/env bash
# dr_orchestrator.sh — one entry point for the encrypted DR / PITR lifecycle.
#
# This ties the pieces together so an operator (or a CronJob) runs ONE command and gets the whole
# guarantee, not a pile of half-wired steps:
#
#   cycle    take an ENCRYPTED base backup → prune locally → replicate off-site → prune off-site.
#            Fails closed: with encryption required, a cleartext leak anywhere aborts the cycle.
#   drill    prove recoverability — decrypt + restore the latest backup into a throwaway cluster.
#   restore  the real recovery: pull the latest encrypted backup (+ WAL) from off-site, decrypt,
#            and prepare a replay-ready data dir with an ENCRYPTED restore_command, optionally to
#            a point in time (--target-time). This is what you run when production is gone.
#   status   report the live DR posture: encryption on?, backup age vs RPO, last drill, off-site
#            freshness, RTO/RPO targets — the dashboard an auditor or an on-call asks for.
#   selftest run the crypto engine self-test (no database needed).
#
# Every failure path can page: set WEISSMAN_DR_ALERT_WEBHOOK to a Slack/Alertmanager/webhook URL.
set -uo pipefail   # NOT -e: we handle step failures explicitly so we can alert before exiting.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a; # shellcheck disable=SC1091
  source .env; set +a
fi

# shellcheck source=lib/backup_crypto.sh
source "${ROOT}/scripts/lib/backup_crypto.sh"

BASE_DIR="${WEISSMAN_PITR_BASE_DIR:-/var/backups/weissman/base}"
ARCHIVE_DIR="${WEISSMAN_PITR_ARCHIVE_DIR:-/var/backups/weissman/wal}"
RPO_MINUTES="${WEISSMAN_DR_RPO_MINUTES:-15}"
RTO_HOURS="${WEISSMAN_DR_RTO_HOURS:-4}"
ALERT_WEBHOOK="${WEISSMAN_DR_ALERT_WEBHOOK:-}"

log()  { printf '[dr] %s\n' "$*" >&2; }
warn() { printf '[dr] WARN: %s\n' "$*" >&2; }
die()  { printf '[dr] FATAL: %s\n' "$*" >&2; exit 1; }

# Fire an alert (best-effort) and echo it. Payload is generic JSON that Slack, Alertmanager
# webhook receivers, and most "post a JSON" endpoints accept.
alert() {
  local level="$1"; shift; local msg="$*"
  printf '[dr] ALERT[%s] %s\n' "$level" "$msg" >&2
  [[ -n "$ALERT_WEBHOOK" ]] && command -v curl >/dev/null 2>&1 || return 0
  local host; host="$(hostname 2>/dev/null || echo unknown)"
  local body
  body="$(printf '{"service":"weissman-dr","level":"%s","host":"%s","text":"%s","ts":"%s"}' \
            "$level" "$host" "${msg//\"/\\\"}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
  curl -sf -m 10 -H 'Content-Type: application/json' --data "$body" "$ALERT_WEBHOOK" >/dev/null 2>&1 \
    && log "alert delivered" || warn "alert webhook POST failed"
}

age_of_file_secs() { # newest mtime of a path (dir → newest child); prints seconds-ago or empty
  local p="$1" m
  [[ -e "$p" ]] || return 1
  m="$(find "$p" -maxdepth 0 -printf '%T@\n' 2>/dev/null | cut -d. -f1)"
  [[ -n "$m" ]] || return 1
  echo $(( $(date -u +%s) - m ))
}

human_age() { local s="${1:-}"; [[ -z "$s" ]] && { echo "n/a"; return; }
  if   (( s < 3600 ));  then echo "$((s/60))m ago"
  elif (( s < 86400 )); then echo "$((s/3600))h ago"
  else echo "$((s/86400))d ago"; fi; }

# --- cycle -------------------------------------------------------------------------------
cmd_cycle() {
  log "=== DR cycle starting ($(date -u +%Y-%m-%dT%H:%M:%SZ)) ==="

  # Refuse to even start a production cycle if encryption is required but unavailable, so we alert
  # loudly rather than quietly producing nothing (or, worse, cleartext).
  if wz_backup_encryption_required && ! wz_backup_encryption_active; then
    alert critical "DR cycle ABORTED — encryption REQUIRED but not active (no recipients or age missing). No backup taken."
    die "encryption required but not active"
  fi

  log "--- base backup (encrypted) ---"
  if ! bash "${ROOT}/scripts/backup_pitr_setup.sh" base; then
    alert critical "DR cycle FAILED at base backup — database has NO fresh recovery point."
    die "base backup failed"
  fi

  log "--- local prune ---"
  bash "${ROOT}/scripts/backup_pitr_setup.sh" prune || warn "local prune failed (non-fatal)"

  # Off-site is optional-but-recommended: only run when a target is configured.
  if [[ -n "${WEISSMAN_DR_OFFSITE_URL:-}" ]]; then
    log "--- off-site replication ---"
    if ! bash "${ROOT}/scripts/dr_offsite_sync.sh" push; then
      alert critical "DR cycle: off-site replication FAILED — backup exists only on the primary host."
      die "off-site push failed"
    fi
    bash "${ROOT}/scripts/dr_offsite_sync.sh" prune || warn "off-site prune failed (non-fatal)"
  else
    warn "WEISSMAN_DR_OFFSITE_URL unset — backup is LOCAL ONLY (no geographic redundancy)."
  fi

  # Optional inline drill (default off; nightly job runs the drill separately so a cycle stays fast).
  if [[ "${WEISSMAN_DR_CYCLE_DRILL:-0}" == "1" ]]; then
    log "--- restore drill ---"
    if ! bash "${ROOT}/scripts/backup_restore_verify.sh"; then
      alert critical "DR cycle: restore drill FAILED — latest backup is NOT proven recoverable."
      die "restore drill failed"
    fi
  fi

  log "=== DR cycle OK ==="
  alert info "DR cycle OK — encrypted backup taken$( [[ -n "${WEISSMAN_DR_OFFSITE_URL:-}" ]] && echo ' + replicated off-site' )."
}

# --- drill -------------------------------------------------------------------------------
cmd_drill() {
  log "=== restore drill ==="
  if bash "${ROOT}/scripts/backup_restore_verify.sh"; then
    log "drill PASSED"
  else
    alert critical "DR restore drill FAILED — recoverability is UNPROVEN."
    die "drill failed"
  fi
}

# --- restore (real recovery) -------------------------------------------------------------
cmd_restore() {
  local target_dir="" target_time="" use_local=0 do_start=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target-time) target_time="$2"; shift 2 ;;
      --local)       use_local=1; shift ;;      # restore from local BASE_DIR instead of off-site
      --start)       do_start=1; shift ;;
      --*)           die "unknown flag: $1" ;;
      *)             target_dir="$1"; shift ;;
    esac
  done
  [[ -n "$target_dir" ]] || die "usage: $0 restore <target-dir> [--target-time 'YYYY-MM-DD HH:MM:SS+00'] [--local] [--start]"
  mkdir -p "$target_dir"
  local work="${target_dir%/}/_dr_work"; mkdir -p "$work/wal"
  local datadir="${target_dir%/}/pgdata"

  # 1. Obtain the base backup (off-site by default; local if --local).
  local base_src=""
  if [[ "$use_local" == 1 ]]; then
    base_src="$(readlink -f "${BASE_DIR}/latest" 2>/dev/null || true)"
    [[ -n "$base_src" && -d "$base_src" ]] || die "no local latest base under $BASE_DIR"
    log "using LOCAL base: $base_src"
  else
    [[ -n "${WEISSMAN_DR_OFFSITE_URL:-}" ]] || die "off-site restore needs WEISSMAN_DR_OFFSITE_URL (or pass --local)"
    log "pulling latest base + WAL from off-site…"
    base_src="$(bash "${ROOT}/scripts/dr_offsite_sync.sh" pull "$work" 2>/dev/null | tail -1)"
    [[ -n "$base_src" && -d "$base_src" ]] || die "off-site base pull failed"
    bash "${ROOT}/scripts/dr_offsite_sync.sh" pull-wal "$work/wal" || warn "WAL pull incomplete (PITR replay may stop early)"
  fi

  # 2. Integrity gate before we trust these bytes.
  if ! wz_verify_manifest "$base_src"; then
    local rc=$?; [[ "$rc" == 1 ]] && die "integrity check FAILED on $base_src — refusing to restore tampered backup"
  fi

  # 3. Decrypt + unpack the base into a fresh data dir.
  rm -rf "$datadir"; mkdir -p "$datadir/pg_wal"
  local base_art=""
  if [[ -f "$base_src/base.tar.gz.age" ]]; then base_art="$base_src/base.tar.gz.age"
  elif [[ -f "$base_src/base.tar.gz" ]]; then base_art="$base_src/base.tar.gz"
  else die "no base payload in $base_src"; fi
  log "decrypt + extract base → $datadir"
  wz_decrypt_file "$base_art" | tar -xzf - -C "$datadir" || die "base decrypt/extract failed"
  # Bundled WAL from `-X stream` (enough for crash-consistency; archive WAL extends PITR further).
  for w in "$base_src/pg_wal.tar.gz.age" "$base_src/pg_wal.tar.gz"; do
    [[ -f "$w" ]] && { wz_decrypt_file "$w" | tar -xzf - -C "$datadir/pg_wal" || warn "bundled WAL extract failed"; break; }
  done
  chmod 700 "$datadir" 2>/dev/null || true

  # 4. Wire an ENCRYPTED restore_command so replay can decrypt archived WAL on demand — only the
  #    segment currently being replayed is ever in cleartext, and only on this trusted DR host.
  local identity=""; identity="$(wz_backup_identity_file 2>/dev/null || true)"
  local restore_cmd="${ROOT}/scripts/pitr_restore_wal.sh ${work}/wal ${identity} \"%f\" \"%p\""
  {
    echo ""
    echo "# --- Weissman encrypted PITR recovery (dr_orchestrator.sh) ---"
    echo "restore_command = '${restore_cmd//\'/\'\'}'"
    [[ -n "$target_time" ]] && echo "recovery_target_time = '${target_time}'"
    echo "recovery_target_action = 'promote'"
  } >> "$datadir/postgresql.auto.conf"
  touch "$datadir/recovery.signal"

  log "=== recovery prepared ==="
  log "data dir : $datadir"
  log "archive  : ${work}/wal ($(find "${work}/wal" -type f 2>/dev/null | wc -l | tr -d ' ') segment(s))"
  [[ -n "$target_time" ]] && log "target   : $target_time" || log "target   : latest consistent point (all available WAL)"

  if [[ "$do_start" == 1 ]] && command -v pg_ctl >/dev/null 2>&1; then
    local port="${WEISSMAN_RESTORE_PORT:-55433}"
    log "starting recovered cluster on 127.0.0.1:${port} (pg_ctl)…"
    pg_ctl -D "$datadir" -o "-p ${port} -c listen_addresses=127.0.0.1" -w -t 120 start \
      || die "recovered cluster failed to start — inspect ${datadir}/log"
    log "recovered cluster is UP on 127.0.0.1:${port}. Validate, then repoint DATABASE_URL and promote to production."
  else
    log "next: start Postgres 16 on this data dir to replay + promote, e.g.:"
    log "      pg_ctl -D '$datadir' -o '-p 5432' -w start"
    log "      # then repoint DATABASE_URL/WEISSMAN_MIGRATE_URL and run scripts/go_live_check.sh --live"
  fi
  wz_backup_scratch_cleanup 2>/dev/null || true
}

# --- status ------------------------------------------------------------------------------
cmd_status() {
  echo "===================== Weissman DR / PITR posture ====================="
  # Encryption.
  if wz_backup_encryption_active; then
    echo "encryption        : ACTIVE (age recipient mode, $(wz_backup_recipients_list | wc -l | tr -d ' ') recipient(s))"
  elif wz_backup_encryption_required; then
    echo "encryption        : REQUIRED but NOT ACTIVE  ⚠  (backups would be refused)"
  else
    echo "encryption        : off (dev/CI mode)"
  fi

  # Latest base backup age vs RPO.
  local base_age; base_age="$(age_of_file_secs "${BASE_DIR}/latest" 2>/dev/null || true)"
  local rpo_secs=$(( RPO_MINUTES * 60 ))
  if [[ -n "$base_age" ]]; then
    local flag="OK"; (( base_age > rpo_secs )) && flag="STALE ⚠"
    echo "latest base backup: $(human_age "$base_age")   [RPO target ${RPO_MINUTES}m → ${flag}]"
    local latest; latest="$(readlink -f "${BASE_DIR}/latest")"
    if [[ -f "$latest/base.tar.gz.age" ]]; then echo "  base encrypted  : yes"
    elif [[ -f "$latest/base.tar.gz" ]]; then echo "  base encrypted  : NO ⚠"; fi
  else
    echo "latest base backup: NONE ⚠  (database unrecoverable — run: $0 cycle)"
  fi

  # WAL archive.
  local wal_enc wal_plain
  wal_enc="$(find "$ARCHIVE_DIR" -type f -name '*.age' 2>/dev/null | wc -l | tr -d ' ')"
  wal_plain="$(find "$ARCHIVE_DIR" -type f ! -name '*.age' 2>/dev/null | wc -l | tr -d ' ')"
  echo "WAL archive       : ${wal_enc} encrypted, ${wal_plain} cleartext"
  [[ "${wal_plain}" -gt 0 ]] && wz_backup_encryption_required && echo "  ⚠ cleartext WAL present while encryption REQUIRED"

  # Last restore drill.
  local rv="${BASE_DIR}/.last_restore_verify_ok" erv="${BASE_DIR}/.last_encrypted_restore_verify_ok"
  if [[ -f "$rv" ]]; then
    local age; age=$(( $(date -u +%s) - $(cat "$rv" 2>/dev/null || echo 0) ))
    echo "last restore drill: $(human_age "$age")$( [[ -f "$erv" ]] && echo '   (encrypted decrypt proven)' )"
  else
    echo "last restore drill: never ⚠  (recoverability unproven — run: $0 drill)"
  fi

  # Off-site.
  if [[ -n "${WEISSMAN_DR_OFFSITE_URL:-}" ]]; then
    echo "off-site target   : ${WEISSMAN_DR_OFFSITE_URL}"
    bash "${ROOT}/scripts/dr_offsite_sync.sh" verify 2>&1 | sed 's/^\[dr-offsite\] /  /'
  else
    echo "off-site target   : NONE ⚠  (no geographic redundancy — set WEISSMAN_DR_OFFSITE_URL)"
  fi

  echo "objectives        : RPO ≤ ${RPO_MINUTES}m,  RTO ≤ ${RTO_HOURS}h"
  echo "======================================================================"
}

CMD="${1:-status}"; shift || true
case "$CMD" in
  cycle)    cmd_cycle "$@" ;;
  drill)    cmd_drill "$@" ;;
  restore)  cmd_restore "$@" ;;
  status)   cmd_status "$@" ;;
  selftest) wz_crypto_selftest ;;
  *) echo "usage: $0 {cycle|drill|restore <dir> [--target-time T] [--local] [--start]|status|selftest}" >&2; exit 1 ;;
esac
