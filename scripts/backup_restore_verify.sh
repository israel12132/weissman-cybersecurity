#!/usr/bin/env bash
# PITR restore-VERIFICATION — proves a backup is actually RECOVERABLE, not merely present.
#
# `backup_pitr_setup.sh verify` only lists WAL segments + base backups (existence != recovery).
# This script restores the latest pg_basebackup into a throwaway Postgres, lets it recover,
# runs a sanity query, and only then reports success + emits a freshness metric. Run it
# nightly and gate go-live on a recent success.
#
# Requires: Docker (default) OR set WEISSMAN_RESTORE_USE_LOCAL=1 with local pg_ctl/initdb.
#
# Usage:
#   export WEISSMAN_PITR_BASE_DIR=/var/backups/weissman/base   # dir holding base_<stamp>/ + latest symlink
#   ./scripts/backup_restore_verify.sh
#
# Optional:
#   WEISSMAN_RESTORE_PG_IMAGE       (default: pgvector/pgvector:pg16 — matches production)
#   WEISSMAN_RESTORE_DB             (default: weissman)
#   WEISSMAN_METRICS_TEXTFILE_DIR   node_exporter textfile-collector dir for the success metric
#   WEISSMAN_PUSHGATEWAY_URL        Prometheus Pushgateway base URL (alternative to textfile)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE_DIR="${WEISSMAN_PITR_BASE_DIR:-/var/backups/weissman/base}"
PG_IMAGE="${WEISSMAN_RESTORE_PG_IMAGE:-pgvector/pgvector:pg16}"
DB_NAME="${WEISSMAN_RESTORE_DB:-weissman}"
CT_NAME="weissman-restore-verify-$$"
WORK=""

log() { echo "[restore-verify] $*"; }
fail() { echo "[restore-verify] FAIL: $*" >&2; exit 1; }

cleanup() {
  if command -v docker >/dev/null 2>&1; then
    docker rm -f "$CT_NAME" >/dev/null 2>&1 || true
  fi
  [[ -n "$WORK" && -d "$WORK" ]] && rm -rf "$WORK" || true
}
trap cleanup EXIT

emit_metrics() {
  local rows="$1" now
  now="$(date -u +%s)"
  # node_exporter textfile collector (atomic write via temp+mv).
  if [[ -n "${WEISSMAN_METRICS_TEXTFILE_DIR:-}" && -d "${WEISSMAN_METRICS_TEXTFILE_DIR}" ]]; then
    local out="${WEISSMAN_METRICS_TEXTFILE_DIR}/backup_restore_verify.prom"
    {
      echo "# HELP weissman_backup_restore_verify_success_timestamp Unix time of last successful PITR restore verification."
      echo "# TYPE weissman_backup_restore_verify_success_timestamp gauge"
      echo "weissman_backup_restore_verify_success_timestamp ${now}"
      echo "# HELP weissman_backup_restore_verify_rows Migration rows observed in the restored cluster."
      echo "# TYPE weissman_backup_restore_verify_rows gauge"
      echo "weissman_backup_restore_verify_rows ${rows}"
    } > "${out}.tmp" && mv "${out}.tmp" "${out}"
    log "wrote metric → ${out}"
  fi
  # Optional Pushgateway.
  if [[ -n "${WEISSMAN_PUSHGATEWAY_URL:-}" ]] && command -v curl >/dev/null 2>&1; then
    printf 'weissman_backup_restore_verify_success_timestamp %s\nweissman_backup_restore_verify_rows %s\n' "$now" "$rows" \
      | curl -sf --data-binary @- "${WEISSMAN_PUSHGATEWAY_URL%/}/metrics/job/weissman_backup_restore_verify" \
      && log "pushed metric → Pushgateway" || log "WARN: Pushgateway push failed"
  fi
  # Local success marker (read by go_live_check.sh).
  echo "$now" > "${BASE_DIR}/.last_restore_verify_ok" 2>/dev/null || true
}

# --- Locate the latest base backup ---
[[ -d "$BASE_DIR" ]] || fail "base dir not found: $BASE_DIR"
LATEST=""
if [[ -L "${BASE_DIR}/latest" ]]; then
  LATEST="$(readlink -f "${BASE_DIR}/latest")"
else
  LATEST="$(find "$BASE_DIR" -maxdepth 1 -type d -name 'base_*' 2>/dev/null | sort | tail -1)"
fi
[[ -n "$LATEST" && -d "$LATEST" ]] || fail "no base backup found under $BASE_DIR (run backup_pitr_setup.sh base)"
[[ -f "${LATEST}/base.tar.gz" ]] || fail "restore expects a compressed tar base backup (base.tar.gz) in $LATEST"
log "restoring from: $LATEST"

# --- Extract into a throwaway data dir ---
WORK="$(mktemp -d)"
DATADIR="${WORK}/pgdata"
mkdir -p "${DATADIR}/pg_wal"
tar -xzf "${LATEST}/base.tar.gz" -C "$DATADIR"
# With `pg_basebackup -X stream` the required WAL ships as pg_wal.tar.gz — extract it so the
# restored cluster can reach a consistent state on start (crash recovery, no archive needed).
[[ -f "${LATEST}/pg_wal.tar.gz" ]] && tar -xzf "${LATEST}/pg_wal.tar.gz" -C "${DATADIR}/pg_wal"

if [[ "${WEISSMAN_RESTORE_USE_LOCAL:-0}" == "1" ]]; then
  # Local-binaries path (no Docker).
  command -v pg_ctl >/dev/null 2>&1 || fail "WEISSMAN_RESTORE_USE_LOCAL=1 but pg_ctl not found"
  PORT="${WEISSMAN_RESTORE_PORT:-55432}"
  chmod 700 "$DATADIR"
  log "starting local postgres on 127.0.0.1:${PORT}"
  pg_ctl -D "$DATADIR" -o "-p ${PORT} -c listen_addresses=127.0.0.1" -w -t 60 start \
    || { cat "${DATADIR}/log"/* 2>/dev/null || true; fail "cluster did not start"; }
  ROWS="$(psql "host=127.0.0.1 port=${PORT} dbname=${DB_NAME} user=postgres" -tAc \
    'SELECT count(*) FROM _sqlx_migrations' 2>/dev/null | tr -d '[:space:]')" || true
  pg_ctl -D "$DATADIR" -w -t 30 stop || true
else
  command -v docker >/dev/null 2>&1 || fail "Docker not available (set WEISSMAN_RESTORE_USE_LOCAL=1 to use local pg_ctl)"
  # The official entrypoint skips initdb when PG_VERSION exists and just starts the cluster;
  # it must be owned by the in-image postgres user (uid 999). chown from a root container so
  # this works even when the caller is unprivileged (e.g. CI runners), falling back to a
  # direct chown when we are root.
  docker run --rm --entrypoint chown -v "${DATADIR}:/data" "$PG_IMAGE" -R 999:999 /data >/dev/null 2>&1 \
    || chown -R 999:999 "$DATADIR" 2>/dev/null || true
  chmod 700 "$DATADIR" 2>/dev/null || true
  log "starting $PG_IMAGE on the restored data dir"
  docker run -d --name "$CT_NAME" \
    -v "${DATADIR}:/var/lib/postgresql/data" \
    "$PG_IMAGE" >/dev/null \
    || fail "could not start restore container"

  # Wait for recovery to finish + accept connections.
  ready=0
  for _ in $(seq 1 60); do
    if docker exec -u postgres "$CT_NAME" pg_isready -q 2>/dev/null; then ready=1; break; fi
    sleep 2
  done
  [[ "$ready" == "1" ]] || { docker logs "$CT_NAME" 2>&1 | tail -30; fail "restored cluster never became ready"; }

  ROWS="$(docker exec -u postgres "$CT_NAME" psql -tAc \
    'SELECT count(*) FROM _sqlx_migrations' "$DB_NAME" 2>/dev/null | tr -d '[:space:]')" || true
fi

# --- Assert the restored cluster is real ---
[[ "$ROWS" =~ ^[0-9]+$ ]] || fail "sanity query returned no numeric result — restore is not usable"
[[ "$ROWS" -gt 0 ]] || fail "restored cluster has 0 applied migrations — not a real Weissman DB"

log "OK — restored cluster healthy: ${ROWS} applied migrations in _sqlx_migrations"
emit_metrics "$ROWS"
log "restore verification PASSED"
