#!/usr/bin/env bash
# dr_crypto_selftest.sh — end-to-end proof of the encrypted DR/PITR pipeline WITHOUT a database.
#
# Everything here is real: a real age keypair, real ChaCha20-Poly1305 ciphertext, real tar
# round-trips, real SHA256SUMS integrity, real off-site replication (local backend). The one
# thing it does NOT do is spin up Postgres — the live restore into a cluster is covered by the
# `backup-restore-verify` job in .github/workflows/nightly-e2e.yml. This test guards the crypto,
# archiving, integrity, off-site, and recovery-preparation logic so a regression there fails CI
# fast instead of at 3am during a real disaster.
#
# Run: scripts/tests/dr_crypto_selftest.sh        (exit 0 = all green)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=../lib/backup_crypto.sh
source "${ROOT}/scripts/lib/backup_crypto.sh"

PASS=0 FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
sect() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

command -v age >/dev/null 2>&1 || { echo "age not installed — cannot run DR crypto selftest"; exit 1; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
age-keygen -o "$WORK/id.txt" 2>"$WORK/kg.err"
PUB="$(grep -oE 'age1[a-z0-9]+' "$WORK/kg.err" | head -1)"
export WEISSMAN_BACKUP_AGE_RECIPIENTS="$PUB"
export WEISSMAN_BACKUP_AGE_IDENTITY_FILE="$WORK/id.txt"
export WEISSMAN_BACKUP_REQUIRE_ENCRYPTION=1

# ------------------------------------------------------------------------------------------
sect "1. crypto engine self-test (round-trip, AEAD tamper, SHA256SUMS, fail-closed)"
if wz_crypto_selftest >/dev/null 2>&1; then ok "engine self-test"; else bad "engine self-test"; fi

# ------------------------------------------------------------------------------------------
sect "2. encrypted WAL archive_command wrapper"
mkdir -p "$WORK/wal_src" "$WORK/archive"
printf '%s\n' "$PUB" > "$WORK/recips.txt"
head -c 16384 /dev/urandom > "$WORK/wal_src/000000010000000000000001"
if scripts/pitr_archive_wal.sh "$WORK/wal_src/000000010000000000000001" 000000010000000000000001 "$WORK/archive" "$WORK/recips.txt" >/dev/null 2>&1 \
   && wz_backup_is_encrypted_file "$WORK/archive/000000010000000000000001.age"; then ok "WAL encrypted on archive"; else bad "WAL encrypted on archive"; fi
# idempotent re-run
if scripts/pitr_archive_wal.sh "$WORK/wal_src/000000010000000000000001" 000000010000000000000001 "$WORK/archive" "$WORK/recips.txt" >/dev/null 2>&1; then ok "archive idempotent re-run"; else bad "archive idempotent re-run"; fi
# fail-closed: required but no recipients (unset the inline env recipients so only the empty file remains)
if ! ( unset WEISSMAN_BACKUP_AGE_RECIPIENTS
       WEISSMAN_BACKUP_REQUIRE_ENCRYPTION=1 scripts/pitr_archive_wal.sh "$WORK/wal_src/000000010000000000000001" 00000002 "$WORK/archive" /nope.txt ) >/dev/null 2>&1; then
  ok "archive fails closed without recipients"
else
  bad "archive should have failed closed"
fi
# WAL decrypt round-trip
if scripts/pitr_restore_wal.sh "$WORK/archive" "$WORK/id.txt" 000000010000000000000001 "$WORK/wal_out" >/dev/null 2>&1 \
   && cmp -s "$WORK/wal_src/000000010000000000000001" "$WORK/wal_out"; then ok "WAL restore_command decrypts to original"; else bad "WAL restore_command round-trip"; fi

# ------------------------------------------------------------------------------------------
sect "3. encrypted base backup dir + integrity"
BASE="$WORK/base/base_20260101T000000Z"; mkdir -p "$BASE"
# pg_basebackup -Ft writes the data-dir CONTENTS at the tar root (no leading pgdata/), so the seed
# tar mirrors that: PG_VERSION is at the top level, extracted straight into the target data dir.
mkdir -p "$WORK/seed"; echo 16 > "$WORK/seed/PG_VERSION"
tar -czf "$WORK/full.tar.gz" -C "$WORK/seed" .
wz_encrypt_stream < "$WORK/full.tar.gz" > "$BASE/base.tar.gz.age"
wz_write_manifest "$BASE" pg_version=16 kind=pitr-base >/dev/null 2>&1
if wz_backup_is_encrypted_file "$BASE/base.tar.gz.age"; then ok "base payload encrypted"; else bad "base payload encrypted"; fi
if wz_verify_manifest "$BASE" >/dev/null 2>&1; then ok "SHA256SUMS + manifest verify"; else bad "manifest verify"; fi
# tamper → must fail
cp -r "$BASE" "$WORK/tamper"; printf 'X' >> "$WORK/tamper/base.tar.gz.age"
if ! wz_verify_manifest "$WORK/tamper" >/dev/null 2>&1; then ok "tamper detected by integrity check"; else bad "tamper NOT detected"; fi

# ------------------------------------------------------------------------------------------
sect "4. restore path: decrypt + extract (no plaintext tar on disk)"
ln -sfn "$BASE" "$WORK/base/latest"
RD="$WORK/restore_data"; mkdir -p "$RD"
if wz_decrypt_file "$BASE/base.tar.gz.age" | tar -xzf - -C "$RD" && [[ -f "$RD/PG_VERSION" ]]; then ok "decrypt|tar extract recovers data dir"; else bad "decrypt|tar extract"; fi
# encrypted but no identity → refuse
if ! ( unset WEISSMAN_BACKUP_AGE_IDENTITY_FILE; wz_decrypt_file "$BASE/base.tar.gz.age" >/dev/null 2>&1 ); then ok "refuses to decrypt without identity"; else bad "decrypted without identity"; fi

# ------------------------------------------------------------------------------------------
sect "5. off-site replication (local backend) + cleartext guard"
export WEISSMAN_PITR_BASE_DIR="$WORK/base" WEISSMAN_PITR_ARCHIVE_DIR="$WORK/archive"
export WEISSMAN_DR_OFFSITE_URL="file://$WORK/offsite"
if scripts/dr_offsite_sync.sh push >/dev/null 2>&1; then ok "off-site push"; else bad "off-site push"; fi
PULLED="$(scripts/dr_offsite_sync.sh pull "$WORK/pulled" 2>/dev/null | tail -1)"
if [[ -n "$PULLED" ]] && wz_verify_manifest "$PULLED" >/dev/null 2>&1; then ok "off-site pull + integrity"; else bad "off-site pull + integrity"; fi
# guard: a cleartext base must be refused on push
echo leak > "$BASE/base.tar.gz"
if ! scripts/dr_offsite_sync.sh push >/dev/null 2>&1; then ok "push refuses cleartext payload"; else bad "push shipped cleartext"; fi
rm -f "$BASE/base.tar.gz"

# ------------------------------------------------------------------------------------------
sect "6. orchestrator recovery preparation (restore --local)"
OUT="$(scripts/dr_orchestrator.sh restore "$WORK/reco" --local --target-time '2026-01-01 12:00:00+00' 2>&1)"
if [[ -f "$WORK/reco/pgdata/PG_VERSION" && -f "$WORK/reco/pgdata/recovery.signal" ]] \
   && grep -q "recovery_target_time" "$WORK/reco/pgdata/postgresql.auto.conf" \
   && grep -q "pitr_restore_wal.sh" "$WORK/reco/pgdata/postgresql.auto.conf"; then
  ok "recovery data dir + encrypted restore_command prepared"
else
  bad "recovery preparation"; echo "$OUT" | sed 's/^/      /'
fi

# ------------------------------------------------------------------------------------------
printf '\n\033[1m== summary ==\033[0m  %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
