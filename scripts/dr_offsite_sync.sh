#!/usr/bin/env bash
# dr_offsite_sync.sh — replicate ENCRYPTED PITR artifacts to off-site storage, and pull them back.
#
# WHY OFF-SITE IS THE OTHER HALF OF DR
# ------------------------------------
# Encryption protects the CONFIDENTIALITY of a backup. Off-site replication protects its
# AVAILABILITY: a base backup that only ever exists on the same host (or same volume, or same
# region) as the database dies with it — a datacentre fire, a region outage, a ransomware event
# that reaches the backup mount, and there is nothing to restore from. This ships the encrypted
# artifacts to an independent failure domain, and pulls them back during a restore.
#
# It NEVER uploads cleartext when encryption is required. The upload is guarded per-file by the
# age magic check (wz_backup_assert_encrypted): a mis-wired pipeline that produced a plaintext
# base backup is refused here rather than leaking the database to a bucket.
#
# BACKENDS (auto-detected from the URL scheme; override with WEISSMAN_DR_OFFSITE_BACKEND)
#   local | file://PATH   → cp/rsync to a mounted secondary volume / NFS (on-prem DR target)
#   s3://BUCKET/PREFIX     → aws s3        (AWS S3, or any S3-compatible via AWS_ENDPOINT_URL)
#   gs://BUCKET/PREFIX     → gcloud storage / gsutil  (Google Cloud Storage)
#   rclone:REMOTE:PATH     → rclone        (any of rclone's 70+ providers)
#   mc:ALIAS/BUCKET/PREFIX → mc            (MinIO client)
#
# IMMUTABILITY (ransomware resistance)
#   Configure the bucket for Object Lock / versioning (S3, GCS retention, MinIO WORM) so an
#   attacker who reaches these credentials still cannot delete or overwrite history. With a
#   locked bucket, retention is enforced by the PROVIDER — set WEISSMAN_DR_OFFSITE_IMMUTABLE=1
#   to make `prune` a no-op here and defer to the bucket's lifecycle policy. See ENCRYPTED-DR-PITR.md.
#
# USAGE
#   dr_offsite_sync.sh push            # upload BASE_DIR base backups + ARCHIVE_DIR WAL (encrypted)
#   dr_offsite_sync.sh pull <dest>     # download the latest base + its SHA256SUMS/manifest into <dest>
#   dr_offsite_sync.sh pull-wal <dest> # download all archived WAL segments into <dest>
#   dr_offsite_sync.sh verify          # list remote, report counts + newest base
#   dr_offsite_sync.sh prune           # apply retention remotely (skipped if IMMUTABLE)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a; # shellcheck disable=SC1091
  source .env; set +a
fi

# shellcheck source=lib/backup_crypto.sh
source "${ROOT}/scripts/lib/backup_crypto.sh"

CMD="${1:-verify}"
ARCHIVE_DIR="${WEISSMAN_PITR_ARCHIVE_DIR:-/var/backups/weissman/wal}"
BASE_DIR="${WEISSMAN_PITR_BASE_DIR:-/var/backups/weissman/base}"
OFFSITE_URL="${WEISSMAN_DR_OFFSITE_URL:-}"
RETENTION_DAYS="${WEISSMAN_DR_OFFSITE_RETENTION_DAYS:-${WEISSMAN_PITR_RETENTION_DAYS:-30}}"
IMMUTABLE="${WEISSMAN_DR_OFFSITE_IMMUTABLE:-0}"

log()  { printf '[dr-offsite] %s\n' "$*" >&2; }
die()  { printf '[dr-offsite] FATAL: %s\n' "$*" >&2; exit 1; }

[[ -n "$OFFSITE_URL" ]] || die "WEISSMAN_DR_OFFSITE_URL not set (e.g. s3://bucket/weissman, gs://…, rclone:remote:path, file:///mnt/dr)"

# --- backend detection -------------------------------------------------------------------
detect_backend() {
  if [[ -n "${WEISSMAN_DR_OFFSITE_BACKEND:-}" ]]; then printf '%s' "$WEISSMAN_DR_OFFSITE_BACKEND"; return; fi
  case "$OFFSITE_URL" in
    s3://*)      printf 's3' ;;
    gs://*)      printf 'gcs' ;;
    rclone:*)    printf 'rclone' ;;
    mc:*)        printf 'mc' ;;
    file://*|/*) printf 'local' ;;
    *)           die "cannot infer backend from URL '$OFFSITE_URL' — set WEISSMAN_DR_OFFSITE_BACKEND" ;;
  esac
}
BACKEND="$(detect_backend)"

# Normalise the base path for each backend (strip scheme where the CLI wants a bare path).
offsite_base() {
  case "$BACKEND" in
    local)  printf '%s' "${OFFSITE_URL#file://}" ;;
    rclone) printf '%s' "${OFFSITE_URL#rclone:}" ;;
    mc)     printf '%s' "${OFFSITE_URL#mc:}" ;;
    *)      printf '%s' "$OFFSITE_URL" ;;
  esac
}
OFF="$(offsite_base)"; OFF="${OFF%/}"

need() { command -v "$1" >/dev/null 2>&1 || die "backend '$BACKEND' needs '$1' on PATH"; }

# --- backend primitives ------------------------------------------------------------------
# put <local_file> <remote_relpath>
offsite_put() {
  local src="$1" rel="$2"
  case "$BACKEND" in
    local)  need cp; mkdir -p "$(dirname "${OFF}/${rel}")"; cp -f "$src" "${OFF}/${rel}" ;;
    s3)     need aws; aws s3 cp --only-show-errors "$src" "${OFF}/${rel}" ;;
    gcs)    if command -v gcloud >/dev/null 2>&1; then gcloud storage cp "$src" "${OFF}/${rel}"; else need gsutil; gsutil -q cp "$src" "${OFF}/${rel}"; fi ;;
    rclone) need rclone; rclone copyto "$src" "${OFF}/${rel}" ;;
    mc)     need mc; mc -q cp "$src" "${OFF}/${rel}" ;;
  esac
}
# get <remote_relpath> <local_file>
offsite_get() {
  local rel="$1" dst="$2"; mkdir -p "$(dirname "$dst")"
  case "$BACKEND" in
    local)  need cp; cp -f "${OFF}/${rel}" "$dst" ;;
    s3)     need aws; aws s3 cp --only-show-errors "${OFF}/${rel}" "$dst" ;;
    gcs)    if command -v gcloud >/dev/null 2>&1; then gcloud storage cp "${OFF}/${rel}" "$dst"; else need gsutil; gsutil -q cp "${OFF}/${rel}" "$dst"; fi ;;
    rclone) need rclone; rclone copyto "${OFF}/${rel}" "$dst" ;;
    mc)     need mc; mc -q cp "${OFF}/${rel}" "$dst" ;;
  esac
}
# list <remote_prefix>  → prints remote-relative paths under the prefix, one per line
offsite_list() {
  local prefix="$1"
  case "$BACKEND" in
    local)  ( cd "$OFF" 2>/dev/null && find "${prefix#/}" -type f 2>/dev/null ) || true ;;
    s3)     need aws; aws s3 ls --recursive "${OFF}/${prefix}" 2>/dev/null | awk '{print $4}' ;;
    gcs)    if command -v gcloud >/dev/null 2>&1; then gcloud storage ls -r "${OFF}/${prefix}**" 2>/dev/null | sed "s#^${OFF}/##"; else need gsutil; gsutil ls -r "${OFF}/${prefix}**" 2>/dev/null | sed "s#^${OFF}/##"; fi ;;
    rclone) need rclone; rclone lsf -R "${OFF}/${prefix}" 2>/dev/null | sed "s#^#${prefix}#" ;;
    mc)     need mc; mc -q ls --recursive "${OFF}/${prefix}" 2>/dev/null | awk '{print $NF}' ;;
  esac
}
# exists <remote_relpath>
offsite_exists() {
  local rel="$1"
  case "$BACKEND" in
    local)  [[ -f "${OFF}/${rel}" ]] ;;
    *)      offsite_list "$rel" | grep -q . ;;
  esac
}

# --- push --------------------------------------------------------------------------------
# Upload every base-backup directory and every WAL segment, guarding against cleartext. Already-
# present objects are skipped (idempotent, cheap re-runs). Uploads MANIFEST/SHA256SUMS last so a
# base directory is never "complete" off-site before its payload is.
push() {
  local uploaded=0 skipped=0 dir name rel f
  log "push → ${BACKEND}:${OFF} (retention ${RETENTION_DAYS}d, immutable=${IMMUTABLE})"

  # Base backups.
  if [[ -d "$BASE_DIR" ]]; then
    while IFS= read -r dir; do
      [[ -d "$dir" ]] || continue
      name="$(basename "$dir")"
      # Payload files first, sidecars last.
      local -a payload=() sidecar=()
      while IFS= read -r f; do
        case "$(basename "$f")" in
          MANIFEST.json|MANIFEST.json.sha256|SHA256SUMS) sidecar+=( "$f" ) ;;
          *) payload+=( "$f" ) ;;
        esac
      done < <(find "$dir" -maxdepth 1 -type f | sort)
      for f in "${payload[@]}" "${sidecar[@]}"; do
        [[ -e "$f" ]] || continue
        # Guard: never ship cleartext DB payload when encryption is required. Sidecars are safe.
        case "$(basename "$f")" in
          MANIFEST.json|MANIFEST.json.sha256|SHA256SUMS) : ;;
          *) if wz_backup_encryption_required; then wz_backup_assert_encrypted "$f" >/dev/null; fi ;;
        esac
        rel="base/${name}/$(basename "$f")"
        if offsite_exists "$rel"; then skipped=$((skipped+1)); continue; fi
        offsite_put "$f" "$rel" && uploaded=$((uploaded+1))
      done
    done < <(find "$BASE_DIR" -maxdepth 1 -type d -name 'base_*' | sort)
  fi

  # WAL segments (encrypted *.age when encryption is active; guard the cleartext case).
  if [[ -d "$ARCHIVE_DIR" ]]; then
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      if wz_backup_encryption_required && [[ "$f" != *.age ]]; then
        die "refusing to upload cleartext WAL segment while encryption REQUIRED: $f"
      fi
      rel="wal/$(basename "$f")"
      if offsite_exists "$rel"; then skipped=$((skipped+1)); continue; fi
      offsite_put "$f" "$rel" && uploaded=$((uploaded+1))
    done < <(find "$ARCHIVE_DIR" -maxdepth 1 -type f | sort)
  fi

  log "push complete: ${uploaded} uploaded, ${skipped} already present"
  emit_push_metric "$uploaded"
}

# --- pull (latest base) ------------------------------------------------------------------
newest_remote_base() {
  # base_<UTC stamp> sorts lexicographically by time, so the last one is newest.
  offsite_list "base/" | sed -n 's#^base/\(base_[^/]*\)/.*#\1#p' | LC_ALL=C sort -u | tail -1
}

pull() {
  local dest="${1:-}"; [[ -n "$dest" ]] || die "usage: $0 pull <dest-dir>"
  local base; base="$(newest_remote_base)"
  [[ -n "$base" ]] || die "no base backup found off-site under ${OFF}/base/"
  local out="${dest%/}/${base}"; mkdir -p "$out"
  log "pull base '${base}' → ${out}"
  local rel f
  while IFS= read -r rel; do
    [[ -n "$rel" ]] || continue
    f="$(basename "$rel")"
    offsite_get "$rel" "${out}/${f}"
  done < <(offsite_list "base/${base}/")
  # Prove what we fetched matches its recorded checksums before anyone tries to restore it.
  if ! wz_verify_manifest "$out"; then
    local rc=$?; [[ "$rc" == 1 ]] && die "integrity check FAILED on pulled base ${base} — off-site copy is corrupt/tampered"
  fi
  printf '%s\n' "$out"
}

pull_wal() {
  local dest="${1:-}"; [[ -n "$dest" ]] || die "usage: $0 pull-wal <dest-dir>"
  mkdir -p "$dest"
  local rel n=0
  while IFS= read -r rel; do
    [[ "$rel" == wal/* ]] || continue
    offsite_get "$rel" "${dest%/}/$(basename "$rel")"; n=$((n+1))
  done < <(offsite_list "wal/")
  log "pulled ${n} WAL segment(s) → ${dest}"
}

# --- verify ------------------------------------------------------------------------------
verify() {
  local bases wals newest
  bases="$(offsite_list "base/" | sed -n 's#^base/\(base_[^/]*\)/.*#\1#p' | sort -u | wc -l | tr -d ' ')"
  wals="$(offsite_list "wal/" | grep -c . || true)"
  newest="$(newest_remote_base || true)"
  log "backend=${BACKEND} target=${OFF}"
  log "off-site base backups: ${bases}   WAL objects: ${wals}   newest base: ${newest:-<none>}"
  if [[ "${bases:-0}" -eq 0 ]]; then
    echo "WARN: no base backups off-site yet — run: $0 push" >&2
    return 1
  fi
  # Confirm the newest base is fully formed off-site (payload + SHA256SUMS present).
  if [[ -n "$newest" ]]; then
    offsite_exists "base/${newest}/SHA256SUMS" || log "WARN: newest base ${newest} has no SHA256SUMS off-site (incomplete upload?)"
  fi
}

# --- prune -------------------------------------------------------------------------------
prune() {
  if [[ "$IMMUTABLE" == "1" ]]; then
    log "IMMUTABLE=1 — retention is enforced by the bucket's Object-Lock/lifecycle policy; client prune skipped"
    return 0
  fi
  case "$BACKEND" in
    local)
      find "${OFF}/base" -maxdepth 1 -type d -name 'base_*' -mtime "+${RETENTION_DAYS}" -exec rm -rf {} + 2>/dev/null || true
      find "${OFF}/wal" -type f -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true
      log "pruned local off-site artifacts older than ${RETENTION_DAYS}d"
      ;;
    *)
      log "NOTE: remote prune for backend '${BACKEND}' should be enforced by a bucket lifecycle rule."
      log "      Configure a ${RETENTION_DAYS}-day expiration on the bucket, or set WEISSMAN_DR_OFFSITE_IMMUTABLE=1."
      ;;
  esac
}

emit_push_metric() {
  local uploaded="$1" now; now="$(date -u +%s)"
  [[ -n "${WEISSMAN_METRICS_TEXTFILE_DIR:-}" && -d "${WEISSMAN_METRICS_TEXTFILE_DIR}" ]] || return 0
  local out="${WEISSMAN_METRICS_TEXTFILE_DIR}/dr_offsite_push.prom"
  {
    echo "# HELP weissman_dr_offsite_push_success_timestamp Unix time of last successful off-site DR push."
    echo "# TYPE weissman_dr_offsite_push_success_timestamp gauge"
    echo "weissman_dr_offsite_push_success_timestamp ${now}"
    echo "# HELP weissman_dr_offsite_push_uploaded_objects Objects uploaded in the last push."
    echo "# TYPE weissman_dr_offsite_push_uploaded_objects gauge"
    echo "weissman_dr_offsite_push_uploaded_objects ${uploaded}"
  } > "${out}.tmp" && mv "${out}.tmp" "${out}"
}

case "$CMD" in
  push)      push ;;
  pull)      pull "${2:-}" ;;
  pull-wal)  pull_wal "${2:-}" ;;
  verify)    verify ;;
  prune)     prune ;;
  *) echo "usage: $0 {push|pull <dest>|pull-wal <dest>|verify|prune}" >&2; exit 1 ;;
esac
