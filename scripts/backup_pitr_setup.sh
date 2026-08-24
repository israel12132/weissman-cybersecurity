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
#   ./scripts/backup_pitr_setup.sh verify         # list archives + latest base (existence only)
#   ./scripts/backup_pitr_setup.sh verify-restore # actually RESTORE the latest base and prove it
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Read .env so the backup location (and DATABASE_URL) have ONE definition shared with
# backup_restore_verify.sh and go_live_check.sh. Left to per-caller environment, the three
# drifted onto different directories without any of them reporting a problem.
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

CMD="${1:-verify}"
ARCHIVE_DIR="${WEISSMAN_PITR_ARCHIVE_DIR:-/var/backups/weissman/wal}"
BASE_DIR="${WEISSMAN_PITR_BASE_DIR:-/var/backups/weissman/base}"
RETENTION_DAYS="${WEISSMAN_PITR_RETENTION_DAYS:-14}"

# Name of the running Postgres container, when there is one. `base` can take a backup through it
# without any host-side connection at all, so DATABASE_URL is only genuinely required for the
# commands that must issue SQL (`init`).
# Identify Postgres by its COMPOSE SERVICE, never by image alone.
#
# Selecting on `ancestor=pgvector/pgvector:pg16` and taking `head -1` silently backed up the wrong
# cluster: an unrelated throwaway container built from the same image sorted first, so the backup
# reported success while archiving a database with none of Weissman's tables in it. Only the
# restore drill noticed (0 applied migrations). A backup of the wrong database is worse than no
# backup — it looks like protection.
#
# So: match the compose project + service exactly, and if that is not decisive, refuse and make the
# operator name the container rather than guess again.
find_pg_container() {
  if [[ -n "${WEISSMAN_PITR_PG_CONTAINER:-}" ]]; then
    printf '%s' "${WEISSMAN_PITR_PG_CONTAINER}"
    return 0
  fi
  command -v docker >/dev/null 2>&1 || return 0

  local project="${COMPOSE_PROJECT_NAME:-$(basename "$ROOT")}"
  local match
  match="$(docker ps \
             --filter "label=com.docker.compose.project=${project}" \
             --filter 'label=com.docker.compose.service=postgres' \
             --format '{{.Names}}' 2>/dev/null)"
  if [[ "$(wc -l <<<"$match")" -eq 1 && -n "$match" ]]; then
    printf '%s' "$match"
    return 0
  fi

  # No compose labels (plain `docker run`): fall back to the image, but only when it is
  # unambiguous. More than one candidate is exactly the case that produced the wrong backup.
  local candidates n
  candidates="$(docker ps --filter 'ancestor=pgvector/pgvector:pg16' --format '{{.Names}}' 2>/dev/null \
                  | grep -v restore-verify || true)"
  n="$(grep -c . <<<"$candidates" || true)"
  if [[ "$n" -eq 1 ]]; then
    printf '%s' "$(tr -d '\n' <<<"$candidates")"
  elif [[ "$n" -gt 1 ]]; then
    echo "[pitr] ambiguous Postgres container — candidates:" >&2
    sed 's/^/         /' <<<"$candidates" >&2
    echo "       set WEISSMAN_PITR_PG_CONTAINER=<name>; refusing to guess which database to back up" >&2
  fi
}

# `verify`/`prune` only read the backup directory; `base` can fall back to the container. Demanding
# DATABASE_URL for all of them meant a Docker deployment — where it is often not set on the host at
# all, because only the containers ever talk to Postgres — could not run any of them.
if [[ -z "${DATABASE_URL:-}" ]]; then
  case "$CMD" in
    init)
      echo "error: DATABASE_URL required for '$CMD'" >&2
      exit 1
      ;;
    base)
      if [[ -z "$(find_pg_container)" ]]; then
        echo "error: DATABASE_URL required (no running Postgres container to back up through)" >&2
        exit 1
      fi
      ;;
  esac
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
  mkdir -p "$dest"
  echo "[pitr] pg_basebackup → $dest"

  # Capture stderr OUTSIDE $dest. `2>"${dest}/.err"` is opened by the shell before
  # pg_basebackup starts, so the target directory was never empty when it looked —
  # it refused with `directory "..." exists but is not empty` on every single run,
  # whatever the database was doing. That also masked the pg_hba probe below: the
  # fallback only engages on a replication-grant refusal, and this error is not
  # one, so the container path was unreachable too.
  local errfile="${dest}.err"
  local direct_ok=0
  if [[ -n "${DATABASE_URL:-}" ]] && command -v pg_basebackup >/dev/null 2>&1; then
    if pg_basebackup -d "$DATABASE_URL" -D "$dest" -Ft -z -P -X stream 2>"$errfile"; then
      direct_ok=1
      rm -f "$errfile"
    fi
  fi

  if (( direct_ok == 0 )); then
    # A direct replication connection is exactly what the shipped docker-compose stack does NOT
    # allow: Postgres is deliberately not published to the host, and the image's stock pg_hba.conf
    # grants `replication` only over local/127.0.0.1 inside the container. So against the very
    # deployment this repo ships, this command could only ever fail with
    #   FATAL: no pg_hba.conf entry for replication connection from host ...
    # Rather than require loosening pg_hba (widening replication access to take a backup is the
    # wrong trade), run pg_basebackup INSIDE the container against its own loopback and copy the
    # result out. Same physical backup, no configuration change, nothing new exposed.
    # Only a refused *replication grant* justifies falling back. A wrong password or an
    # unreachable host must surface, not be silently retried down another route that happens to
    # trust local connections — that would turn a real credential problem into a green backup.
    if [[ -n "${DATABASE_URL:-}" && -f "$errfile" ]]; then
      local err; err="$(cat "$errfile" 2>/dev/null || true)"
      if ! grep -q 'pg_hba.conf entry for replication' <<<"$err"; then
        echo "[pitr] pg_basebackup failed:" >&2
        printf '%s\n' "$err" >&2
        rm -rf "$dest"
        return 1
      fi
      echo "[pitr] direct replication refused by pg_hba"
    fi
    local ct; ct="$(find_pg_container)"
    if [[ -z "$ct" ]]; then
      echo "[pitr] no replication access and no Postgres container found;" >&2
      echo "       set WEISSMAN_PITR_PG_CONTAINER=<name> or allow replication in pg_hba.conf" >&2
      rm -rf "$dest"
      return 1
    fi
    echo "[pitr] taking the backup inside container '$ct'"
    docker exec -u postgres "$ct" rm -rf /tmp/.pitr_bb >/dev/null 2>&1 || true
    if ! docker exec -u postgres "$ct" \
           pg_basebackup -h 127.0.0.1 -U postgres -D /tmp/.pitr_bb -Ft -z -P -X stream; then
      docker exec -u postgres "$ct" rm -rf /tmp/.pitr_bb >/dev/null 2>&1 || true
      rm -rf "$dest"
      echo "[pitr] in-container pg_basebackup failed" >&2
      return 1
    fi
    docker cp "${ct}:/tmp/.pitr_bb/." "${dest}/" >/dev/null
    docker exec -u postgres "$ct" rm -rf /tmp/.pitr_bb >/dev/null 2>&1 || true
    rm -f "$errfile"
  fi

  # Never let `latest` point at a backup that is missing its payload — the restore drill trusts
  # this symlink, so a truncated run would otherwise become the thing we "verify".
  [[ -s "${dest}/base.tar.gz" ]] || { echo "[pitr] no base.tar.gz produced — discarding $dest" >&2; rm -rf "$dest"; return 1; }
  ln -sfn "$dest" "${BASE_DIR}/latest"
  echo "[pitr] base backup complete: $dest ($(du -sh "$dest" | cut -f1))"
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
  verify-restore) exec "$ROOT/scripts/backup_restore_verify.sh" ;;
  prune) prune ;;
  *)
    echo "usage: $0 {init|base|verify|verify-restore|prune}" >&2
    exit 1
    ;;
esac
