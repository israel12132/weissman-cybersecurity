#!/usr/bin/env bash
# PostgreSQL Point-in-Time Recovery (PITR) — WAL archiving + base backup orchestration.
#
# Requires: pg_basebackup, psql, archive_command writable directory.
# For managed Postgres (RDS, Cloud SQL, Azure), use provider PITR instead of this script.
#
# Usage:
#   export DATABASE_URL=postgresql://postgres:pass@host:5432/weissman
#   export WEISSMAN_PITR_ARCHIVE_DIR=/var/backups/weissman/wal
#   export WEISSMAN_PITR_BASE_DIR=/var/backups/weissman/base
#   ./scripts/backup_pitr_setup.sh init     # enable WAL archive settings (superuser)
#   ./scripts/backup_pitr_setup.sh base       # pg_basebackup snapshot
#   ./scripts/backup_pitr_setup.sh verify   # list archives + latest base
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CMD="${1:-verify}"
ARCHIVE_DIR="${WEISSMAN_PITR_ARCHIVE_DIR:-/var/backups/weissman/wal}"
BASE_DIR="${WEISSMAN_PITR_BASE_DIR:-/var/backups/weissman/base}"
RETENTION_DAYS="${WEISSMAN_PITR_RETENTION_DAYS:-14}"

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "error: DATABASE_URL required" >&2
  exit 1
fi

mkdir -p "$ARCHIVE_DIR" "$BASE_DIR"

init_archive() {
  echo "[pitr] Enabling WAL archiving (requires superuser)..."
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<SQL
ALTER SYSTEM SET wal_level = 'replica';
ALTER SYSTEM SET archive_mode = 'on';
ALTER SYSTEM SET archive_command = 'test ! -f ${ARCHIVE_DIR}/%f && cp %p ${ARCHIVE_DIR}/%f';
SELECT pg_reload_conf();
SQL
  echo "[pitr] WAL archive_dir=$ARCHIVE_DIR — restart Postgres if wal_level change requires it."
}

base_backup() {
  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local dest="${BASE_DIR}/base_${stamp}"
  echo "[pitr] pg_basebackup → $dest"
  pg_basebackup -d "$DATABASE_URL" -D "$dest" -Ft -z -P -X stream
  ln -sfn "$dest" "${BASE_DIR}/latest"
  echo "[pitr] base backup complete: $dest"
}

verify() {
  local wal_count base_count
  wal_count="$(find "$ARCHIVE_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
  base_count="$(find "$BASE_DIR" -maxdepth 1 -type d -name 'base_*' 2>/dev/null | wc -l | tr -d ' ')"
  echo "[pitr] archive_dir=$ARCHIVE_DIR wal_segments=$wal_count"
  echo "[pitr] base_dir=$BASE_DIR base_backups=$base_count"
  if [[ -L "${BASE_DIR}/latest" ]]; then
    echo "[pitr] latest_base=$(readlink "${BASE_DIR}/latest")"
  fi
  if [[ "$wal_count" -eq 0 && "$base_count" -eq 0 ]]; then
    echo "WARN: no PITR artifacts yet — run: $0 init && $0 base" >&2
    exit 1
  fi
}

prune() {
  find "$ARCHIVE_DIR" -type f -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
  find "$BASE_DIR" -maxdepth 1 -type d -name 'base_*' -mtime "+${RETENTION_DAYS}" -exec rm -rf {} + 2>/dev/null || true
  echo "[pitr] pruned artifacts older than ${RETENTION_DAYS}d"
}

case "$CMD" in
  init) init_archive ;;
  base) base_backup ;;
  verify) verify ;;
  prune) prune ;;
  *)
    echo "usage: $0 {init|base|verify|prune}" >&2
    exit 1
    ;;
esac
