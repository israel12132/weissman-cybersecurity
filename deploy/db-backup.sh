#!/usr/bin/env bash
# Scheduled logical backups for the docker-compose production path.
#
# The recommended docker-compose stack ran a single Postgres container with NO
# automated backups: one disk failure or a bad auto-migration (migrations run at
# boot) was unrecoverable. This service takes a periodic `pg_dump` (custom format),
# verifies each archive is actually readable, keeps a bounded history, and logs a
# freshness line so a monitor / operator can alert on staleness.
#
# It is a LOGICAL backup (pg_dump), not PITR/WAL — good enough to recover the
# recommended single-node compose deployment to the last cycle. For continuous PITR,
# cross-region DR and a 99.95% SLA, use the Kubernetes/CNPG stack and the encrypted
# PITR toolchain (scripts/dr_orchestrator.sh, deploy/k8s/backup-cronjob.yaml).
#
# Runs inside a pgvector/pgvector:pg16 container (version-matched pg_dump) on the
# compose network; see the `db-backup` service in docker-compose.prod.yml.
#
# Env (all optional; defaults suit the compose stack):
#   PGHOST                        Postgres host             (default: postgres)
#   PGUSER / POSTGRES_USER        superuser role            (default: postgres)
#   POSTGRES_DB                   database to dump           (default: weissman)
#   PGPASSWORD                    superuser password         (required by pg_dump)
#   WEISSMAN_BACKUP_DIR           output directory           (default: /backups)
#   WEISSMAN_BACKUP_INTERVAL_SECONDS  seconds between cycles (default: 86400 = daily)
#   WEISSMAN_BACKUP_RETENTION     dumps to keep              (default: 14)
#   WEISSMAN_BACKUP_RUN_ONCE      "1" to run one cycle and exit (for cron/testing)
set -uo pipefail

PGHOST="${PGHOST:-postgres}"
PGUSER="${PGUSER:-${POSTGRES_USER:-postgres}}"
DB="${POSTGRES_DB:-weissman}"
DIR="${WEISSMAN_BACKUP_DIR:-/backups}"
INTERVAL="${WEISSMAN_BACKUP_INTERVAL_SECONDS:-86400}"
RETENTION="${WEISSMAN_BACKUP_RETENTION:-14}"
export PGHOST PGUSER

log() { echo "[db-backup] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

run_cycle() {
  mkdir -p "$DIR"
  local ts out
  # Portable UTC timestamp (BusyBox/coreutils both accept this form).
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  out="$DIR/weissman-${ts}.dump"

  log "starting pg_dump of '${DB}' on ${PGHOST} -> ${out}"
  if ! pg_dump -h "$PGHOST" -U "$PGUSER" -d "$DB" -Fc -f "${out}.partial"; then
    log "ERROR: pg_dump failed; leaving previous backups intact"
    rm -f "${out}.partial"
    return 1
  fi

  # Integrity: a valid custom-format archive must have a readable table of contents.
  # This cheaply catches a truncated/corrupt dump before we trust (and rotate on) it.
  if ! pg_restore --list "${out}.partial" >/dev/null 2>&1; then
    log "ERROR: pg_dump produced an unreadable archive (pg_restore --list failed); discarding"
    rm -f "${out}.partial"
    return 1
  fi

  mv "${out}.partial" "$out"
  log "OK backup written: ${out} ($(du -h "$out" | cut -f1))"

  # Retention: keep the newest ${RETENTION}, delete the rest. Never touches non-dumps.
  local stale
  stale="$(ls -1t "$DIR"/weissman-*.dump 2>/dev/null | tail -n +"$((RETENTION + 1))")"
  if [ -n "$stale" ]; then
    echo "$stale" | while IFS= read -r f; do
      [ -n "$f" ] && rm -f "$f" && log "pruned old backup: $f"
    done
  fi
  return 0
}

wait_for_postgres() {
  # Robust regardless of compose depends_on/healthcheck: block until Postgres accepts
  # connections (up to ~2 min) so the first cycle does not fail and then idle a whole
  # interval before retrying.
  local i
  for i in $(seq 1 60); do
    if pg_isready -h "$PGHOST" -U "$PGUSER" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  log "WARNING: Postgres not ready after ~120s; attempting a cycle anyway"
  return 0
}

if [ "${WEISSMAN_BACKUP_RUN_ONCE:-0}" = "1" ]; then
  wait_for_postgres
  run_cycle
  exit $?
fi

log "db-backup started (interval=${INTERVAL}s, retention=${RETENTION}, dir=${DIR})"
while true; do
  run_cycle || log "cycle failed; will retry after interval"
  sleep "$INTERVAL"
done
