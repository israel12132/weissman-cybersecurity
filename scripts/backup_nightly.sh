#!/usr/bin/env bash
# Nightly backup + PROOF of recoverability, as one cron entry.
#
# Taking a backup and verifying it are separate scripts on purpose (verification restores into a
# throwaway cluster and is slow), but scheduling only the first is how a stack ends up with a
# directory full of archives nobody has ever restored. This runs both, in order, and fails loudly
# if either step does — cron mails the output.
#
# Install (already done on this host by the launch prep):
#   15 3 * * *  /home/israel/weissman-cybersecurity/scripts/backup_nightly.sh >> ~/weissman-backups/nightly.log 2>&1
#
# Reads WEISSMAN_PITR_* from .env, so the location is defined in exactly one place.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# cron runs with a minimal PATH that usually lacks docker and the postgres client binaries.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

BASE_DIR="${WEISSMAN_PITR_BASE_DIR:-/var/backups/weissman/base}"

# The restore drill extracts a full copy of the cluster into $TMPDIR. On this host /tmp is a tmpfs
# sized in RAM and has been observed at 100% full, which would fail the drill for reasons that have
# nothing to do with the backup. Keep the scratch space next to the backups, on real disk.
export TMPDIR="${WEISSMAN_PITR_WORK_DIR:-${BASE_DIR%/base}/.work}"
mkdir -p "$TMPDIR"

stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }
echo "=== [$(stamp)] weissman nightly backup ==="

echo "--- base backup ---"
bash scripts/backup_pitr_setup.sh base

echo "--- prune (retention ${WEISSMAN_PITR_RETENTION_DAYS:-14}d) ---"
bash scripts/backup_pitr_setup.sh prune || echo "WARN: prune failed (non-fatal)"

# The point of the whole job. A base backup that cannot be restored is not a backup, and the only
# way to know is to restore it.
echo "--- restore verification ---"
bash scripts/backup_restore_verify.sh

echo "=== [$(stamp)] nightly backup OK ==="
