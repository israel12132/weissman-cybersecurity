#!/usr/bin/env bash
# pitr_restore_wal.sh — the decrypt counterpart of pitr_archive_wal.sh, used as Postgres'
# restore_command during PITR replay. Postgres calls it once per WAL segment it needs; the
# script fetches the archived segment, DECRYPTS it (age), and writes the cleartext WAL to the
# path Postgres asks for. When replay reaches a segment that was never archived (the end of the
# log), it exits non-zero — the normal, expected signal that tells Postgres recovery is complete.
#
#   restore_command = '/abs/scripts/pitr_restore_wal.sh <archive_dir> <identity_file> "%f" "%p"'
#
#   %f = WAL file name Postgres wants        %p = path Postgres wants it written to
set -euo pipefail

ARCHIVE_DIR="${1:-}"
IDENTITY="${2:-}"
WALNAME="${3:-}"
DEST="${4:-}"

log() { printf '[pitr-restore] %s\n' "$*" >&2; }
die() { printf '[pitr-restore] FATAL: %s\n' "$*" >&2; exit 1; }

[[ -n "$ARCHIVE_DIR" && -n "$WALNAME" && -n "$DEST" ]] || die "usage: $0 <archive_dir> <identity_file> <%f> <%p>"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/backup_crypto.sh
source "${SCRIPT_DIR}/lib/backup_crypto.sh"

# Let the crypto engine find the identity from the arg (restore host holds the private key).
[[ -n "$IDENTITY" ]] && export WEISSMAN_BACKUP_AGE_IDENTITY_FILE="$IDENTITY"

enc="${ARCHIVE_DIR%/}/${WALNAME}.age"
plain="${ARCHIVE_DIR%/}/${WALNAME}"

if [[ -f "$enc" ]]; then
  # Atomic: decrypt to a temp then rename, so a killed replay never leaves a partial WAL that
  # Postgres would treat as complete.
  tmp="${DEST}.part.$$"
  trap 'rm -f "$tmp"' EXIT
  wz_decrypt_file "$enc" > "$tmp" || die "decrypt failed for ${WALNAME}"
  mv -f "$tmp" "$DEST"
  trap - EXIT
  log "restored (decrypted): ${WALNAME}"
  exit 0
elif [[ -f "$plain" ]]; then
  cp -f "$plain" "$DEST"
  log "restored (cleartext): ${WALNAME}"
  exit 0
fi

# Not found: the standard end-of-archive signal. Non-zero, but not an error to shout about.
exit 1
