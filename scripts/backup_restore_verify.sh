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

# Read .env so the backup location has ONE definition. This script, backup_pitr_setup.sh and
# go_live_check.sh each defaulted to /var/backups/weissman independently, so an operator who
# could not write there (no root) pointed one of them elsewhere via the environment and the
# other two kept reading the empty default — the drill would pass while the gate reported "no
# restore-verify marker", each of them correct about a different directory.
if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

BASE_DIR="${WEISSMAN_PITR_BASE_DIR:-/var/backups/weissman/base}"
PG_IMAGE="${WEISSMAN_RESTORE_PG_IMAGE:-pgvector/pgvector:pg16}"
DB_NAME="${WEISSMAN_RESTORE_DB:-weissman}"
CT_NAME="weissman-restore-verify-$$"
WORK=""

# Envelope decryption engine. A base backup taken by backup_pitr_setup.sh is encrypted
# (base.tar.gz.age); this proves it can actually be DECRYPTED and recovered, not merely that a
# ciphertext exists. Legacy plaintext base.tar.gz (CI, pre-encryption hosts) still restores —
# wz_decrypt_file passes cleartext through untouched.
# shellcheck source=lib/backup_crypto.sh
source "${ROOT}/scripts/lib/backup_crypto.sh"

log() { echo "[restore-verify] $*"; }
fail() { echo "[restore-verify] FAIL: $*" >&2; exit 1; }

cleanup() {
  if command -v docker >/dev/null 2>&1; then
    docker rm -f "$CT_NAME" >/dev/null 2>&1 || true
  fi
  if [[ -n "$WORK" && -d "$WORK" ]]; then
    # The restored data dir was chown'd to the in-image postgres uid (999) so the official
    # entrypoint would accept it, which leaves an unprivileged caller unable to delete it:
    # `rm -rf` failed with EPERM and the directory survived. This script is meant to run
    # NIGHTLY, so every run leaked another undeletable copy of the whole cluster. Hand it back
    # from a root container first — same trick used to take it away.
    if command -v docker >/dev/null 2>&1 && [[ -d "${WORK}/pgdata" ]]; then
      docker run --rm --entrypoint chown -v "${WORK}:/work" "$PG_IMAGE" \
        -R "$(id -u):$(id -g)" /work >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK" 2>/dev/null || echo "[restore-verify] WARN: could not remove $WORK" >&2
  fi
  # Wipe any age identity we materialised from an inline secret — the private key must not
  # outlive the drill.
  wz_backup_scratch_cleanup 2>/dev/null || true
}
trap cleanup EXIT

emit_metrics() {
  local rows="$1" now enc="${ENCRYPTED_RESTORE:-0}"
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
      echo "# HELP weissman_backup_restore_verify_encrypted 1 if the verified restore decrypted an encrypted backup."
      echo "# TYPE weissman_backup_restore_verify_encrypted gauge"
      echo "weissman_backup_restore_verify_encrypted ${enc}"
    } > "${out}.tmp" && mv "${out}.tmp" "${out}"
    log "wrote metric → ${out}"
  fi
  # Optional Pushgateway.
  if [[ -n "${WEISSMAN_PUSHGATEWAY_URL:-}" ]] && command -v curl >/dev/null 2>&1; then
    printf 'weissman_backup_restore_verify_success_timestamp %s\nweissman_backup_restore_verify_rows %s\nweissman_backup_restore_verify_encrypted %s\n' "$now" "$rows" "$enc" \
      | curl -sf --data-binary @- "${WEISSMAN_PUSHGATEWAY_URL%/}/metrics/job/weissman_backup_restore_verify" \
      && log "pushed metric → Pushgateway" || log "WARN: Pushgateway push failed"
  fi
  # Local success markers (read by go_live_check.sh). The encrypted-specific marker lets the gate
  # require that the drill actually decrypted a backup, not merely restored a cleartext one.
  echo "$now" > "${BASE_DIR}/.last_restore_verify_ok" 2>/dev/null || true
  if [[ "$enc" == 1 ]]; then
    echo "$now" > "${BASE_DIR}/.last_encrypted_restore_verify_ok" 2>/dev/null || true
  fi
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

# Prefer the ENCRYPTED artifact; fall back to legacy cleartext so CI and pre-encryption hosts
# still restore. Whichever exists is the one we prove recoverable.
ENCRYPTED_RESTORE=0
if [[ -f "${LATEST}/base.tar.gz.age" ]]; then
  BASE_ART="${LATEST}/base.tar.gz.age"; ENCRYPTED_RESTORE=1
elif [[ -f "${LATEST}/base.tar.gz" ]]; then
  BASE_ART="${LATEST}/base.tar.gz"
else
  fail "no base backup payload in $LATEST (expected base.tar.gz.age or base.tar.gz)"
fi
WAL_ART=""
if [[ -f "${LATEST}/pg_wal.tar.gz.age" ]]; then WAL_ART="${LATEST}/pg_wal.tar.gz.age"
elif [[ -f "${LATEST}/pg_wal.tar.gz" ]]; then WAL_ART="${LATEST}/pg_wal.tar.gz"; fi

# Keyless integrity gate FIRST: if the backup carries SHA256SUMS, a mismatch means the store was
# altered/truncated — refuse to "restore" a tampered artifact and call it a passing drill.
if ! wz_verify_manifest "$LATEST"; then
  rc=$?
  # rc 2 = no sidecars (legacy backup): allowed, just unproven. rc 1 = real mismatch: hard fail.
  [[ "$rc" == 1 ]] && fail "backup integrity check FAILED for $LATEST — refusing to restore a tampered backup"
fi

if [[ "$ENCRYPTED_RESTORE" == 1 ]]; then
  log "restoring from: $LATEST (ENCRYPTED — proving decrypt + recovery)"
  # A decrypt drill is only meaningful with an identity; without one we cannot prove the DR copy
  # is openable. Refuse to report success on an encrypted backup we could not actually decrypt.
  wz_backup_identity_file >/dev/null 2>&1 || wz_backup_age_bin >/dev/null 2>&1 || \
    fail "encrypted backup but no age binary to decrypt it"
  wz_backup_identity_file >/dev/null 2>&1 || \
    fail "encrypted backup but no identity configured — set WEISSMAN_BACKUP_AGE_IDENTITY_FILE on the restore host to prove recoverability"
else
  log "restoring from: $LATEST (cleartext)"
fi

# --- Extract into a throwaway data dir ---
WORK="$(mktemp -d)"
DATADIR="${WORK}/pgdata"
mkdir -p "${DATADIR}/pg_wal"
# Decrypt-and-extract in one stream — the plaintext tar never lands on disk, only the extracted
# data dir does (which is thrown away). wz_decrypt_file passes cleartext through unchanged.
wz_decrypt_file "$BASE_ART" | tar -xzf - -C "$DATADIR" || fail "decrypt/extract of base backup failed"
# With `pg_basebackup -X stream` the required WAL ships as pg_wal.tar.gz — extract it so the
# restored cluster can reach a consistent state on start (crash recovery, no archive needed).
[[ -n "$WAL_ART" ]] && { wz_decrypt_file "$WAL_ART" | tar -xzf - -C "${DATADIR}/pg_wal" || fail "decrypt/extract of pg_wal failed"; }

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
if [[ "${ENCRYPTED_RESTORE:-0}" == 1 ]]; then
  log "restore verification PASSED (encrypted backup decrypted + recovered)"
else
  log "restore verification PASSED (cleartext backup)"
fi
