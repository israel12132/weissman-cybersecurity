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

# Envelope encryption engine (age recipient mode). Sourcing it here means both the base backup
# and the WAL archive_command share ONE definition of "are we encrypting, and to whom" — the two
# cannot drift into one being encrypted and the other cleartext. See scripts/lib/backup_crypto.sh.
# shellcheck source=lib/backup_crypto.sh
source "${ROOT}/scripts/lib/backup_crypto.sh"

# Recipients file consumed by the WAL archive_command inside Postgres' own (minimal) environment.
# `init` materialises it from WEISSMAN_BACKUP_AGE_RECIPIENTS(_FILE) so the DB runtime needs no
# Weissman env vars — only this file and the age binary.
PITR_RECIPIENTS_FILE="${WEISSMAN_PITR_RECIPIENTS_FILE:-$(dirname "$ARCHIVE_DIR")/backup-recipients.txt}"
WAL_ARCHIVE_WRAPPER="${ROOT}/scripts/pitr_archive_wal.sh"

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

# Materialise the recipients file from the environment so the archive_command — which runs in
# Postgres' own minimal environment, not the operator's shell — can encrypt without any Weissman
# env vars. Written 0640; public keys are not secret, but we still keep them off world-read.
write_recipients_file() {
  wz_backup_encryption_configured || return 1
  mkdir -p "$(dirname "$PITR_RECIPIENTS_FILE")"
  {
    echo "# Weissman DR/PITR age recipients (public keys). Managed by backup_pitr_setup.sh init."
    echo "# The matching identities (private keys) MUST NOT live on this host — see ENCRYPTED-DR-PITR.md."
    wz_backup_recipients_list
  } > "${PITR_RECIPIENTS_FILE}.part.$$"
  chmod 640 "${PITR_RECIPIENTS_FILE}.part.$$" 2>/dev/null || true
  mv -f "${PITR_RECIPIENTS_FILE}.part.$$" "$PITR_RECIPIENTS_FILE"
  echo "[pitr] recipients written → $PITR_RECIPIENTS_FILE ($(wz_backup_recipients_list | wc -l | tr -d ' ') key(s))"
}

init_archive() {
  echo "[pitr] Enabling WAL archiving (requires superuser)..."

  local archive_cmd
  if wz_backup_encryption_active; then
    write_recipients_file
    # Encrypted, atomic, idempotent WAL archiving via the wrapper. Postgres substitutes %p/%f;
    # everything else is baked in so the DB runtime needs no env. The wrapper fails closed if
    # encryption is unavailable, so WAL never ships in cleartext by accident.
    archive_cmd="${WAL_ARCHIVE_WRAPPER} \"%p\" \"%f\" ${ARCHIVE_DIR} ${PITR_RECIPIENTS_FILE}"
    echo "[pitr] archive_command = ENCRYPTED (age) via $(basename "$WAL_ARCHIVE_WRAPPER")"
    echo "[pitr] NOTE: in a containerised Postgres, mount ${ROOT}/scripts, ${ARCHIVE_DIR} and"
    echo "       ${PITR_RECIPIENTS_FILE} into the DB container and ensure 'age' is on its PATH."
  elif wz_backup_encryption_required; then
    wz_crypto_die "init refused: encryption REQUIRED but no recipients/age configured.
       Set WEISSMAN_BACKUP_AGE_RECIPIENTS(_FILE) before enabling archiving so WAL is never cleartext."
  else
    # Legacy cleartext archiving (dev/CI, or encryption explicitly disabled). Same no-overwrite
    # safety as the upstream Postgres example.
    archive_cmd="test ! -f ${ARCHIVE_DIR}/%f && cp %p ${ARCHIVE_DIR}/%f"
    wz_crypto_warn "archive_command is CLEARTEXT — set WEISSMAN_BACKUP_AGE_RECIPIENTS to encrypt WAL."
  fi

  # archive_command is stored verbatim; single quotes inside must be doubled for the SQL literal.
  local sql_cmd="${archive_cmd//\'/\'\'}"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<SQL
ALTER SYSTEM SET wal_level = 'replica';
ALTER SYSTEM SET archive_mode = 'on';
ALTER SYSTEM SET archive_command = '${sql_cmd}';
SELECT pg_reload_conf();
SQL
  echo "[pitr] WAL archive_dir=$ARCHIVE_DIR — restart Postgres if wal_level change requires it."
}

base_backup() {
  # Fail closed BEFORE pg_basebackup runs: in a required-encryption deployment we must never even
  # produce a cleartext base.tar.gz on disk. In dev/CI (not required) this returns 1 and we
  # continue in cleartext mode — hence `|| true` under `set -e`.
  wz_backup_require_or_die || true

  local stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  local dest="${BASE_DIR}/base_${stamp}"
  mkdir -p "$dest"
  echo "[pitr] pg_basebackup → $dest"

  local direct_ok=0
  if [[ -n "${DATABASE_URL:-}" ]] && command -v pg_basebackup >/dev/null 2>&1; then
    if pg_basebackup -d "$DATABASE_URL" -D "$dest" -Ft -z -P -X stream 2>"${dest}/.err"; then
      direct_ok=1
      rm -f "${dest}/.err"
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
    if [[ -n "${DATABASE_URL:-}" && -f "${dest}/.err" ]]; then
      local err; err="$(cat "${dest}/.err" 2>/dev/null || true)"
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
    rm -f "${dest}/.err"
  fi

  # Never let `latest` point at a backup that is missing its payload — the restore drill trusts
  # this symlink, so a truncated run would otherwise become the thing we "verify". This guard runs
  # on the RAW pg_basebackup output, before encryption, so a failed backup is caught at the source.
  [[ -s "${dest}/base.tar.gz" ]] || { echo "[pitr] no base.tar.gz produced — discarding $dest" >&2; rm -rf "$dest"; return 1; }

  # Encrypt the physical backup in place (base.tar.gz → base.tar.gz.age, pg_wal.tar.gz likewise),
  # then write the keyless integrity + provenance sidecars. On any encryption failure the whole
  # dest is discarded rather than left as a half-encrypted "backup".
  encrypt_base_dir "$dest" || { echo "[pitr] encryption of base backup failed — discarding $dest" >&2; rm -rf "$dest"; return 1; }

  ln -sfn "$dest" "${BASE_DIR}/latest"
  echo "[pitr] base backup complete: $dest ($(du -sh "$dest" | cut -f1))"

  # Emit a freshness metric mirroring the logical-backup gauge, so Grafana/alerts can see the
  # last successful ENCRYPTED base backup independently of the restore drill.
  local ts; ts="$(date -u +%s)"
  if [[ -n "${WEISSMAN_METRICS_TEXTFILE_DIR:-}" && -d "${WEISSMAN_METRICS_TEXTFILE_DIR}" ]]; then
    local enc=0; wz_backup_encryption_active && enc=1
    local out="${WEISSMAN_METRICS_TEXTFILE_DIR}/pitr_base_backup.prom"
    {
      echo "# HELP weissman_pitr_base_backup_success_timestamp Unix time of last successful PITR base backup."
      echo "# TYPE weissman_pitr_base_backup_success_timestamp gauge"
      echo "weissman_pitr_base_backup_success_timestamp ${ts}"
      echo "# HELP weissman_pitr_base_backup_encrypted 1 if the last base backup was encrypted."
      echo "# TYPE weissman_pitr_base_backup_encrypted gauge"
      echo "weissman_pitr_base_backup_encrypted ${enc}"
    } > "${out}.tmp" && mv "${out}.tmp" "${out}"
  fi
}

# Encrypt every physical artifact in a fresh base-backup dir (gzip tar → age), remove the
# cleartext originals, and write SHA256SUMS + MANIFEST.json. When encryption is not active this
# leaves the plaintext artifacts as-is but still records a manifest (encrypted:false) so every
# backup — legacy or encrypted — carries a verifiable inventory.
encrypt_base_dir() {
  local dest="$1"
  # The fail-closed gate already ran at the top of base_backup (before pg_basebackup), so by here
  # either encryption is active or we are legitimately in cleartext dev/CI mode.
  if wz_backup_encryption_active; then
    local f
    for f in base.tar.gz pg_wal.tar.gz; do
      [[ -s "${dest}/${f}" ]] || continue
      wz_encrypt_stream < "${dest}/${f}" > "${dest}/${f}.age.part.$$" || return 1
      [[ -s "${dest}/${f}.age.part.$$" ]] || { rm -f "${dest}/${f}.age.part.$$"; return 1; }
      mv -f "${dest}/${f}.age.part.$$" "${dest}/${f}.age"
      # Prove it decrypts to the exact bytes we started from BEFORE deleting the only cleartext
      # copy — an unopenable "backup" is the worst failure mode, so we never trust encryption we
      # have not just round-tripped, when an identity is available to check with.
      if wz_backup_identity_file >/dev/null 2>&1; then
        if ! wz_decrypt_file "${dest}/${f}.age" | cmp -s - "${dest}/${f}"; then
          echo "[pitr] round-trip verify FAILED for ${f}.age — keeping cleartext, refusing backup" >&2
          rm -f "${dest}/${f}.age"
          return 1
        fi
      fi
      rm -f "${dest}/${f}"
    done
    [[ -s "${dest}/base.tar.gz.age" ]] || { echo "[pitr] no encrypted base produced" >&2; return 1; }
  fi

  local pgver="unknown"
  if [[ -n "${DATABASE_URL:-}" ]]; then
    pgver="$(psql "$DATABASE_URL" -tAc 'SHOW server_version' 2>/dev/null | tr -d '[:space:]' || echo unknown)"
  fi
  wz_write_manifest "$dest" "pg_version=${pgver}" "source=pg_basebackup" "kind=pitr-base"
  return 0
}

verify() {
  local wal_count base_count wal_enc wal_plain
  wal_count="$(find "$ARCHIVE_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
  wal_enc="$(find "$ARCHIVE_DIR" -type f -name '*.age' 2>/dev/null | wc -l | tr -d ' ')"
  wal_plain="$(find "$ARCHIVE_DIR" -type f ! -name '*.age' 2>/dev/null | wc -l | tr -d ' ')"
  base_count="$(find "$BASE_DIR" -maxdepth 1 -type d -name 'base_*' 2>/dev/null | wc -l | tr -d ' ')"
  echo "[pitr] archive_dir=$ARCHIVE_DIR wal_segments=$wal_count (encrypted=$wal_enc plaintext=$wal_plain)"
  echo "[pitr] base_dir=$BASE_DIR base_backups=$base_count"
  if [[ -L "${BASE_DIR}/latest" ]]; then
    local latest; latest="$(readlink -f "${BASE_DIR}/latest")"
    echo "[pitr] latest_base=$latest"
    # Report and integrity-check the latest base.
    if [[ -d "$latest" ]]; then
      if [[ -f "${latest}/base.tar.gz.age" ]]; then echo "[pitr] latest base is ENCRYPTED (base.tar.gz.age)"
      elif [[ -f "${latest}/base.tar.gz" ]]; then echo "[pitr] latest base is CLEARTEXT (base.tar.gz)"; fi
      wz_verify_manifest "$latest" || true
    fi
  fi

  # In an encryption-required deployment, ANY cleartext artifact is a finding, not a warning: it
  # means the archive_command or a base backup leaked the database in the clear.
  if wz_backup_encryption_required; then
    local leak=0
    if [[ "$wal_plain" -gt 0 ]]; then echo "FAIL: ${wal_plain} CLEARTEXT WAL segment(s) in $ARCHIVE_DIR — encryption is REQUIRED" >&2; leak=1; fi
    if compgen -G "${BASE_DIR}"/base_*/base.tar.gz >/dev/null 2>&1; then echo "FAIL: cleartext base.tar.gz present while encryption REQUIRED" >&2; leak=1; fi
    [[ "$leak" -eq 1 ]] && exit 2
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
