#!/usr/bin/env bash
# pitr_archive_wal.sh — the encrypted, atomic, idempotent target for Postgres archive_command.
#
# Postgres invokes archive_command once per finalized WAL segment. Correctness rules that this
# script honours (violating any of them silently loses recoverability):
#
#   1. NEVER return 0 unless the segment is durably, wholly in the archive. Postgres treats a
#      zero exit as "safe to recycle this WAL" — a premature success is unrecoverable data loss.
#   2. NEVER overwrite an already-archived segment with different bytes. A WAL filename maps to
#      fixed content in Postgres, so if the encrypted target already exists we treat it as
#      already-archived and succeed (idempotent) rather than looping forever the way the classic
#      `test ! -f && cp` example does when archive status is lost and replayed.
#   3. Write ATOMICALLY: encrypt to a temp file in the destination dir, fsync, then rename into
#      place. A crash mid-encrypt must never leave a half-written segment that looks archived.
#   4. FAIL CLOSED on encryption: if encryption is required but age/recipients are unavailable,
#      exit non-zero so Postgres RETAINS the WAL and archiving visibly backs up (alertable) —
#      rather than shipping the transaction log of the entire database in cleartext.
#
# Configuration is passed as ARGUMENTS (not env), because Postgres runs archive_command with the
# server's own minimal environment, not the operator's shell. `backup_pitr_setup.sh init` wires
# the full command line.
#
#   archive_command = '/abs/path/scripts/pitr_archive_wal.sh "%p" "%f" <archive_dir> [recipients_file]'
#
#   %p  = path to the WAL file to archive (relative to the data dir; Postgres substitutes it)
#   %f  = WAL file name only
#   archive_dir      = directory the encrypted segment is written to (…/%f.age)
#   recipients_file  = age recipients (public keys); optional if WEISSMAN_BACKUP_AGE_RECIPIENTS set
set -euo pipefail

SRC="${1:-}"
WALNAME="${2:-}"
ARCHIVE_DIR="${3:-${WEISSMAN_PITR_ARCHIVE_DIR:-}}"
RECIPIENTS_FILE="${4:-${WEISSMAN_BACKUP_AGE_RECIPIENTS_FILE:-}}"

log() { printf '[pitr-archive] %s\n' "$*" >&2; }
die() { printf '[pitr-archive] FATAL: %s\n' "$*" >&2; exit 1; }

[[ -n "$SRC" && -n "$WALNAME" ]] || die "usage: $0 <%p src> <%f name> [archive_dir] [recipients_file]"
[[ -f "$SRC" ]] || die "source WAL not found: $SRC"
[[ -n "$ARCHIVE_DIR" ]] || die "archive_dir not provided (arg 3 or WEISSMAN_PITR_ARCHIVE_DIR)"

# Locate the crypto engine relative to this script so a container mount of scripts/ works.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/backup_crypto.sh
source "${SCRIPT_DIR}/lib/backup_crypto.sh"

# Feed the recipients file (if given as an arg) to the crypto engine.
[[ -n "$RECIPIENTS_FILE" ]] && export WEISSMAN_BACKUP_AGE_RECIPIENTS_FILE="$RECIPIENTS_FILE"

mkdir -p "$ARCHIVE_DIR"

# fsync a path best-effort (durability of the archived segment matters more than speed here).
fsync_path() {
  # `sync` on a specific file is a GNU coreutils feature; fall back to a global sync.
  sync "$1" 2>/dev/null || sync 2>/dev/null || true
}

if wz_backup_encryption_active; then
  DEST="${ARCHIVE_DIR}/${WALNAME}.age"
  # Idempotent: an existing, valid encrypted segment of this name is the same segment.
  if [[ -s "$DEST" ]] && wz_backup_is_encrypted_file "$DEST"; then
    log "already archived (encrypted): ${WALNAME}.age"
    exit 0
  fi
  # Refuse to clobber a same-named but non-encrypted/corrupt artifact — make the operator look.
  [[ -e "$DEST" ]] && die "refusing to overwrite existing non-encrypted/partial archive: $DEST"

  TMP="${DEST}.part.$$"
  trap 'rm -f "$TMP"' EXIT
  if ! wz_encrypt_stream < "$SRC" > "$TMP"; then
    die "encryption of WAL ${WALNAME} failed"
  fi
  [[ -s "$TMP" ]] || die "encryption produced empty output for ${WALNAME}"
  fsync_path "$TMP"
  mv -f "$TMP" "$DEST"
  trap - EXIT
  fsync_path "$ARCHIVE_DIR"
  log "archived (encrypted): ${WALNAME}.age"
  exit 0
fi

# --- encryption not active ---------------------------------------------------------------
if wz_backup_encryption_required; then
  die "encryption REQUIRED but not active (no recipients or age missing) — RETAINING WAL ${WALNAME}.
       Postgres will retry; archiving is intentionally stalled to avoid cleartext WAL.
       Wire WEISSMAN_BACKUP_AGE_RECIPIENTS(_FILE) and ensure 'age' is on PATH in the DB runtime."
fi

# Legacy cleartext path (dev/CI, or an operator who explicitly disabled encryption).
DEST="${ARCHIVE_DIR}/${WALNAME}"
if [[ -e "$DEST" ]]; then
  # Match Postgres' documented safety: never overwrite; identical re-archival succeeds.
  if cmp -s "$SRC" "$DEST"; then log "already archived (plain): ${WALNAME}"; exit 0; fi
  die "refusing to overwrite differing archived segment: $DEST"
fi
TMP="${DEST}.part.$$"
trap 'rm -f "$TMP"' EXIT
cp "$SRC" "$TMP"
fsync_path "$TMP"
mv -f "$TMP" "$DEST"
trap - EXIT
fsync_path "$ARCHIVE_DIR"
log "archived (CLEARTEXT — encryption not configured): ${WALNAME}"
exit 0
