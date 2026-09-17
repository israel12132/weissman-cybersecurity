# shellcheck shell=bash
# backup_crypto.sh — envelope encryption engine for Weissman DR/PITR artifacts.
#
# WHY THIS EXISTS
# --------------
# A base backup or a WAL segment written to disk (or shipped to object storage) is a
# verbatim copy of the entire database — every credential, finding, and customer record.
# `scripts/backup_pitr_setup.sh` and the CNPG object store both wrote those artifacts in
# CLEARTEXT. That means the security boundary of the whole platform silently collapsed onto
# the file permissions of a backup directory and the access policy of a bucket: anyone who
# could read `/var/backups` or list the bucket had the database. Volume-level encryption-at-
# rest does not close this — it protects a stolen disk, not a backup file copied out by a
# process, a leaked bucket object, or a compromised backup host.
#
# THE DESIGN — ASYMMETRIC, HOST CANNOT DECRYPT ITS OWN BACKUPS
# -----------------------------------------------------------
# We encrypt every artifact with `age` (https://age-encryption.org) in RECIPIENT mode:
# the backup host holds only PUBLIC keys (recipients) and can therefore only ever ENCRYPT.
# The X25519 private key (the age "identity") that can DECRYPT is never present on the
# production/backup host in normal operation — it lives offline, in a vault/KMS, or on a
# separate DR host that performs restore drills. Consequences:
#
#   * A ransomware actor or insider on the database host can read live data, but CANNOT
#     read historical backups — they never hold the decryption key. Exfiltrating the whole
#     backup history becomes impossible from that vantage point.
#   * age is authenticated (ChaCha20-Poly1305 under an X25519-wrapped file key), so an
#     attacker who can WRITE to the backup store cannot tamper with an artifact without the
#     next restore failing loudly — silent corruption of the DR copy is detected.
#   * Multiple recipients are supported: encrypt to an operations key AND a break-glass key
#     held by a second custodian, so no single lost key destroys recoverability.
#
# This mirrors the platform's existing at-rest convention (AES-256-GCM envelopes in
# fingerprint_engine/src/soar/integrations_vault.rs) — authenticated encryption, versioned
# envelopes, key material never logged, fail-closed in production — applied to the one place
# it was missing.
#
# WHY age AND NOT hand-rolled openssl
# -----------------------------------
# `openssl enc -aes-256-gcm` is explicitly not stream-safe from the CLI (single AEAD
# invocation over unbounded input, no chunked tag handling) and CTR-without-a-MAC is
# unauthenticated. Rolling encrypt-then-MAC over a pipe in bash is exactly the kind of
# bespoke crypto a security product must not ship. `age` is small, audited, streaming,
# non-interactive in recipient mode, and purpose-built for file/stream encryption. `rage`
# (the Rust implementation) is a drop-in via WEISSMAN_BACKUP_AGE_BIN.
#
# SOURCING CONTRACT
# -----------------
# This file is meant to be `source`d. It defines functions and touches no global state at
# source time beyond constants. Callers keep their own `set -euo pipefail`. Functions that
# can legitimately "say no" (encryption not configured, recipient missing) return non-zero
# rather than exiting, EXCEPT wz_backup_require_or_die which is the one deliberate fail-closed
# gate.
#
# ENVIRONMENT
# -----------
#   WEISSMAN_BACKUP_AGE_RECIPIENTS       space/comma/newline-separated age PUBLIC keys (age1...)
#   WEISSMAN_BACKUP_AGE_RECIPIENTS_FILE  path to a recipients file (one age1... per line, # comments)
#   WEISSMAN_BACKUP_AGE_IDENTITY_FILE    path to the age IDENTITY (private key) — RESTORE side only
#   WEISSMAN_BACKUP_AGE_IDENTITY         inline identity (K8s secret env) — written to a 0600 temp, zeroized
#   WEISSMAN_BACKUP_REQUIRE_ENCRYPTION   1=fail closed if encryption unavailable; 0=allow plaintext.
#                                        Default: 1 when the environment looks like production, else 0.
#   WEISSMAN_BACKUP_AGE_BIN              age binary (default: age; may be rage)
#   WEISSMAN_ENV / APP_ENV / ENVIRONMENT used only to auto-derive the REQUIRE default

# Guard against double-sourcing (multiple scripts may pull this in transitively).
if [[ -n "${_WZ_BACKUP_CRYPTO_SOURCED:-}" ]]; then
  return 0 2>/dev/null || true
fi
_WZ_BACKUP_CRYPTO_SOURCED=1

# Envelope/sidecar schema version. Bump only on a breaking layout change so a restorer built
# for v1 refuses a v2 artifact rather than misreading it.
readonly WZ_BACKUP_ENVELOPE_VERSION="wzdr1"

# Files the engine writes for out-of-band cleanup (inline identities materialised to disk).
_WZ_BACKUP_SCRATCH=()

wz_crypto_log()  { printf '[dr-crypto] %s\n' "$*" >&2; }
wz_crypto_warn() { printf '[dr-crypto] WARN: %s\n' "$*" >&2; }
wz_crypto_die()  { printf '[dr-crypto] FATAL: %s\n' "$*" >&2; exit 1; }

# --- binary resolution -------------------------------------------------------------------

wz_backup_age_bin() {
  local bin="${WEISSMAN_BACKUP_AGE_BIN:-age}"
  if command -v "$bin" >/dev/null 2>&1; then
    printf '%s' "$bin"
    return 0
  fi
  return 1
}

# --- environment / policy ----------------------------------------------------------------

# True when the deployment looks like production, used only to pick the REQUIRE default.
_wz_backup_looks_production() {
  local e
  for e in "${WEISSMAN_ENV:-}" "${APP_ENV:-}" "${ENVIRONMENT:-}" "${WEISSMAN_ENVIRONMENT:-}"; do
    case "${e,,}" in
      prod|production|live) return 0 ;;
    esac
  done
  return 1
}

# Resolve the encryption-required policy: explicit env wins; otherwise default to ON in
# production and OFF elsewhere so dev/CI keep their existing plaintext round-trip while a
# real deployment fails closed the moment encryption is not wired up.
wz_backup_encryption_required() {
  case "${WEISSMAN_BACKUP_REQUIRE_ENCRYPTION:-}" in
    1|true|TRUE|yes|on)   return 0 ;;
    0|false|FALSE|no|off) return 1 ;;
  esac
  _wz_backup_looks_production && return 0
  return 1
}

# --- recipients (encrypt side) -----------------------------------------------------------

# Print each configured recipient public key on its own line. Sources, in order:
#   WEISSMAN_BACKUP_AGE_RECIPIENTS_FILE (path) then WEISSMAN_BACKUP_AGE_RECIPIENTS (inline list).
# Only well-formed age/ssh recipients are emitted; anything else is dropped with a warning so a
# typo cannot silently reduce the recipient set to empty and fall through to plaintext.
wz_backup_recipients_list() {
  local emitted=0 line tok
  if [[ -n "${WEISSMAN_BACKUP_AGE_RECIPIENTS_FILE:-}" && -f "${WEISSMAN_BACKUP_AGE_RECIPIENTS_FILE}" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="$(printf '%s' "$line" | tr -d '[:space:]')"
      [[ -z "$line" ]] && continue
      if [[ "$line" == age1* || "$line" == ssh-* ]]; then printf '%s\n' "$line"; emitted=1; fi
    done < "${WEISSMAN_BACKUP_AGE_RECIPIENTS_FILE}"
  fi
  if [[ -n "${WEISSMAN_BACKUP_AGE_RECIPIENTS:-}" ]]; then
    for tok in ${WEISSMAN_BACKUP_AGE_RECIPIENTS//,/ }; do
      [[ -z "$tok" ]] && continue
      if [[ "$tok" == age1* || "$tok" == ssh-* ]]; then printf '%s\n' "$tok"; emitted=1
      else wz_crypto_warn "ignoring malformed recipient (not age1.../ssh-...): ${tok:0:12}…"; fi
    done
  fi
  [[ "$emitted" == 1 ]]
}

# True when at least one valid recipient is configured (i.e. we CAN encrypt).
wz_backup_encryption_configured() {
  wz_backup_recipients_list >/dev/null 2>&1
}

# True when we are actually going to encrypt: configured AND the age binary is present.
wz_backup_encryption_active() {
  wz_backup_encryption_configured || return 1
  wz_backup_age_bin >/dev/null 2>&1 || return 1
  return 0
}

# The one fail-closed gate. Call this at the top of any backup that must not silently produce
# cleartext. When encryption is REQUIRED it dies with actionable guidance unless encryption is
# actually active; when not required it just reports the mode and continues (return 1).
wz_backup_require_or_die() {
  if wz_backup_encryption_active; then
    local n; n="$(wz_backup_recipients_list | wc -l | tr -d ' ')"
    wz_crypto_log "encryption ACTIVE — age recipient mode, ${n} recipient(s), envelope ${WZ_BACKUP_ENVELOPE_VERSION}"
    return 0
  fi
  if wz_backup_encryption_required; then
    if ! wz_backup_age_bin >/dev/null 2>&1; then
      wz_crypto_die "encryption REQUIRED but '${WEISSMAN_BACKUP_AGE_BIN:-age}' is not installed.
       Install age (https://github.com/FiloSottile/age) or set WEISSMAN_BACKUP_AGE_BIN.
       Refusing to write a cleartext backup of the database."
    fi
    wz_crypto_die "encryption REQUIRED but no recipients configured.
       Set WEISSMAN_BACKUP_AGE_RECIPIENTS or WEISSMAN_BACKUP_AGE_RECIPIENTS_FILE to one or more
       age PUBLIC keys (age1...). Generate a keypair OFFLINE with 'age-keygen' and keep the
       identity (private key) off this host. Refusing to write a cleartext backup."
  fi
  wz_crypto_warn "encryption NOT active and not required (dev/CI mode) — artifacts will be CLEARTEXT."
  return 1
}

# --- file-naming helpers -----------------------------------------------------------------

# Suffix to append to an artifact name for the active mode: ".age" when encrypting, "" when not.
# Callers compose destination names as "base.tar$(wz_backup_ext)".
wz_backup_ext() {
  if wz_backup_encryption_active; then printf '.age'; else printf ''; fi
}

# True if a path is an encrypted artifact, by the age file magic (the ASCII banner every age
# file begins with). Extension is not trusted — a mislabelled file is judged by its bytes.
wz_backup_is_encrypted_file() {
  local f="$1"
  [[ -f "$f" ]] || return 1
  [[ "$(head -c 21 "$f" 2>/dev/null)" == "age-encryption.org/v1" ]]
}

# Fail if a file that MUST be encrypted is not. Used by the offsite guard: never upload
# cleartext when encryption is required. Returns 1 (not fatal) when encryption is not required.
wz_backup_assert_encrypted() {
  local f="$1"
  if wz_backup_is_encrypted_file "$f"; then return 0; fi
  if wz_backup_encryption_required; then
    wz_crypto_die "refusing to handle cleartext artifact where encryption is REQUIRED: $f"
  fi
  return 1
}

# --- encryption / decryption streams -----------------------------------------------------

# Build the `age -r <key>` recipient argument vector into the caller's named array (bash
# dynamic scope). Returns 1 if there are no recipients.
_wz_backup_recipient_args() {
  local __out="$1"
  local -a acc=()
  local r
  while IFS= read -r r; do
    [[ -z "$r" ]] && continue
    acc+=( -r "$r" )
  done < <(wz_backup_recipients_list)
  [[ ${#acc[@]} -gt 0 ]] || return 1
  eval "$__out=(\"\${acc[@]}\")"
  return 0
}

# stdin -> stdout, encrypting when active, else pass-through. Streaming; safe for large input.
wz_encrypt_stream() {
  if wz_backup_encryption_active; then
    local bin; bin="$(wz_backup_age_bin)"
    local -a rargs
    _wz_backup_recipient_args rargs || wz_crypto_die "no recipients for wz_encrypt_stream"
    "$bin" "${rargs[@]}"
  else
    cat
  fi
}

# Encrypt stdin to a destination file ATOMICALLY (temp + mv), and print the SHA-256 of the
# bytes actually written to stdout. Never leaves a partial file at $dest — a crashed
# encryption cannot be mistaken for a good artifact.
wz_encrypt_to_file() {
  local dest="$1"
  local tmp="${dest}.part.$$"
  if wz_encrypt_stream > "$tmp"; then
    [[ -s "$tmp" ]] || { rm -f "$tmp"; wz_crypto_die "encryption produced an empty file for $dest"; }
    mv -f "$tmp" "$dest"
    sha256sum "$dest" | awk '{print $1}'
    return 0
  fi
  rm -f "$tmp"
  wz_crypto_die "encryption failed writing $dest"
}

# Resolve an age identity FILE for decryption, materialising an inline identity to a private
# 0600 temp when only WEISSMAN_BACKUP_AGE_IDENTITY is set. Prints the path. Register cleanup
# with wz_backup_scratch_cleanup (call it from your EXIT trap).
wz_backup_identity_file() {
  if [[ -n "${WEISSMAN_BACKUP_AGE_IDENTITY_FILE:-}" && -f "${WEISSMAN_BACKUP_AGE_IDENTITY_FILE}" ]]; then
    printf '%s' "${WEISSMAN_BACKUP_AGE_IDENTITY_FILE}"
    return 0
  fi
  if [[ -n "${WEISSMAN_BACKUP_AGE_IDENTITY:-}" ]]; then
    local t; t="$(mktemp "${TMPDIR:-/tmp}/wz-age-id.XXXXXX")"
    chmod 600 "$t"
    printf '%s\n' "${WEISSMAN_BACKUP_AGE_IDENTITY}" > "$t"
    _WZ_BACKUP_SCRATCH+=( "$t" )
    printf '%s' "$t"
    return 0
  fi
  return 1
}

# Remove any materialised secrets. Best-effort zeroize before unlink.
wz_backup_scratch_cleanup() {
  local f
  for f in "${_WZ_BACKUP_SCRATCH[@]:-}"; do
    [[ -n "$f" && -f "$f" ]] || continue
    dd if=/dev/zero of="$f" bs=1 count="$(wc -c < "$f" 2>/dev/null || echo 0)" conv=notrunc >/dev/null 2>&1 || true
    rm -f "$f" 2>/dev/null || true
  done
  _WZ_BACKUP_SCRATCH=()
}

# Decrypt a file to stdout. Transparent for cleartext inputs (legacy .gz backups and CI), so a
# mixed store part-migrated to encryption still restores. Requires an identity for encrypted
# inputs and fails loudly if none is available — a restore that cannot decrypt must not be
# mistaken for "nothing to do".
wz_decrypt_file() {
  local src="$1"
  [[ -f "$src" ]] || wz_crypto_die "wz_decrypt_file: not found: $src"
  if wz_backup_is_encrypted_file "$src"; then
    local bin; bin="$(wz_backup_age_bin)" || wz_crypto_die "encrypted artifact but age binary missing: $src"
    local id; id="$(wz_backup_identity_file)" || wz_crypto_die "encrypted artifact but no identity configured to decrypt: $src
       Provide WEISSMAN_BACKUP_AGE_IDENTITY_FILE (the age private key) on the restore host."
    "$bin" -d -i "$id" "$src"
  else
    cat "$src"
  fi
}

# --- integrity + provenance sidecars -----------------------------------------------------
#
# For a base-backup directory we write:
#   SHA256SUMS            standard `<hash>␠␠<name>` lines — the tamper oracle, verified with
#                         the stock `sha256sum -c`. Keyless: the offsite layer and the restorer
#                         confirm they hold exactly the produced bytes WITHOUT any decryption
#                         key. age already authenticates ciphertext on decrypt; this catches
#                         truncation/substitution before a restore is even attempted.
#   MANIFEST.json         human/machine metadata: envelope version, algorithm, recipients
#                         (public keys are not secret), host, caller kv pairs.
#   MANIFEST.json.sha256  sidecar over the manifest so an edited manifest is detected.
#
# Verification leans on `sha256sum -c` rather than re-parsing JSON, so integrity never depends
# on a bespoke JSON scanner or a jq install on the restore host.
#
# Usage: wz_write_manifest <dir> [key=value ...]   (extra kv pairs are merged as metadata)
wz_write_manifest() {
  local dir="$1"; shift || true
  [[ -d "$dir" ]] || wz_crypto_die "wz_write_manifest: not a dir: $dir"
  local created; created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local encrypted="false"; wz_backup_encryption_active && encrypted="true"
  local algo="none"; [[ "$encrypted" == "true" ]] && algo="age/X25519-ChaCha20Poly1305"

  # SHA256SUMS — written from inside $dir so names are relative and `sha256sum -c` works from
  # that dir wherever the tree is later moved or fetched to.
  local sums_tmp="${dir}/SHA256SUMS.part.$$"
  ( cd "$dir" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' ! -name 'MANIFEST.json*' -printf '%P\n' \
      | LC_ALL=C sort | xargs -r -d '\n' sha256sum ) > "$sums_tmp"
  mv -f "$sums_tmp" "${dir}/SHA256SUMS"

  # MANIFEST.json metadata.
  local recips_json="[]"
  if wz_backup_encryption_configured; then
    recips_json="$(wz_backup_recipients_list | awk 'BEGIN{printf "["} {printf "%s\"%s\"", (NR>1?",":""), $0} END{printf "]"}')"
  fi

  local files_json="" f name bytes sha enc
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    name="$(basename "$f")"
    case "$name" in SHA256SUMS*|MANIFEST.json*) continue ;; esac
    bytes="$(wc -c < "$f" | tr -d ' ')"
    sha="$(sha256sum "$f" | awk '{print $1}')"
    enc="false"; wz_backup_is_encrypted_file "$f" && enc="true"
    files_json+="$(printf '%s{"name":"%s","bytes":%s,"sha256":"%s","encrypted":%s}' \
      "${files_json:+,}" "$name" "$bytes" "$sha" "$enc")"
  done < <(find "$dir" -maxdepth 1 -type f | sort)

  local extra_json="" kv k v
  for kv in "$@"; do
    k="${kv%%=*}"; v="${kv#*=}"
    extra_json+="$(printf '%s"%s":"%s"' "${extra_json:+,}" "$k" "$v")"
  done

  local out="${dir}/MANIFEST.json" tmp="${dir}/MANIFEST.json.part.$$"
  {
    printf '{\n'
    printf '  "envelope_version": "%s",\n' "$WZ_BACKUP_ENVELOPE_VERSION"
    printf '  "created_utc": "%s",\n' "$created"
    printf '  "encrypted": %s,\n' "$encrypted"
    printf '  "algorithm": "%s",\n' "$algo"
    printf '  "recipients": %s,\n' "$recips_json"
    printf '  "host": "%s",\n' "$(hostname 2>/dev/null || echo unknown)"
    printf '  "sha256sums": "SHA256SUMS",\n'
    printf '  "files": [%s]' "$files_json"
    [[ -n "$extra_json" ]] && printf ',\n  "metadata": {%s}' "$extra_json"
    printf '\n}\n'
  } > "$tmp"
  mv -f "$tmp" "$out"
  sha256sum "$out" | awk '{print $1}' > "${out}.sha256"
  wz_crypto_log "manifest + SHA256SUMS written: $dir"
}

# Verify a directory's integrity: every artifact matches SHA256SUMS (via the stock tool) and
# the manifest matches its sidecar. Keyless — proves the store was not tampered with,
# independent of whether the caller can decrypt. Returns 0 OK, 1 mismatch, 2 no sidecars
# (legacy backup predating this engine — caller decides whether that is acceptable).
wz_verify_manifest() {
  local dir="$1"
  local sums="${dir}/SHA256SUMS"
  local man="${dir}/MANIFEST.json"
  if [[ ! -f "$sums" ]]; then
    wz_crypto_warn "no SHA256SUMS in $dir (legacy backup?) — cannot prove integrity"
    return 2
  fi
  local rc=0
  if ! ( cd "$dir" && sha256sum -c --strict SHA256SUMS ) >/dev/null 2>&1; then
    wz_crypto_warn "SHA256SUMS verification FAILED in $dir — an artifact was altered/truncated"
    ( cd "$dir" && sha256sum -c SHA256SUMS 2>&1 | grep -v ': OK$' >&2 ) || true
    rc=1
  fi
  if [[ -f "$man" && -f "${man}.sha256" ]]; then
    local want got
    want="$(tr -d '[:space:]' < "${man}.sha256")"
    got="$(sha256sum "$man" | awk '{print $1}')"
    [[ "$want" == "$got" ]] || { wz_crypto_warn "MANIFEST.json checksum mismatch in $dir — manifest was altered"; rc=1; }
  fi
  [[ "$rc" == 0 ]] && wz_crypto_log "integrity OK ($dir)"
  return "$rc"
}

# --- self-test (run by scripts/tests/dr_crypto_selftest.sh) ------------------------------

# Proves the round-trip in THIS environment: keygen -> encrypt -> decrypt -> byte-equal, plus
# AEAD tamper detection, SHA256SUMS tamper detection, and the fail-closed guard. Returns 0 OK.
wz_crypto_selftest() {
  wz_backup_age_bin >/dev/null 2>&1 || { wz_crypto_warn "selftest: age not installed"; return 1; }
  local work; work="$(mktemp -d)"
  local rc=0
  (
    set -e
    age-keygen -o "$work/id.txt" 2>"$work/kg.err"
    local pub; pub="$(grep -oE 'age1[a-z0-9]+' "$work/kg.err" | head -1)"
    [[ -n "$pub" ]] || { echo "selftest: no public key from keygen" >&2; exit 1; }

    export WEISSMAN_BACKUP_AGE_RECIPIENTS="$pub"
    export WEISSMAN_BACKUP_AGE_IDENTITY_FILE="$work/id.txt"

    head -c 1048576 /dev/urandom > "$work/plain.bin"
    wz_backup_encryption_active || { echo "selftest: encryption not active with a valid recipient" >&2; exit 1; }
    wz_encrypt_stream < "$work/plain.bin" > "$work/ct.age"
    wz_backup_is_encrypted_file "$work/ct.age" || { echo "selftest: ciphertext not recognised as age" >&2; exit 1; }
    wz_decrypt_file "$work/ct.age" > "$work/rt.bin"
    cmp -s "$work/plain.bin" "$work/rt.bin" || { echo "selftest: round-trip mismatch" >&2; exit 1; }

    # AEAD tamper detection: flip a byte in the ciphertext; decrypt MUST fail.
    printf '\x00' | dd of="$work/ct.age" bs=1 seek=200 count=1 conv=notrunc >/dev/null 2>&1 || true
    if wz_decrypt_file "$work/ct.age" >/dev/null 2>&1; then
      echo "selftest: tampered ciphertext decrypted — AEAD not enforced" >&2; exit 1
    fi

    # SHA256SUMS tamper detection.
    mkdir -p "$work/mani"
    echo "hello" | wz_encrypt_stream > "$work/mani/base.tar.age"
    wz_write_manifest "$work/mani" pg_version=test
    wz_verify_manifest "$work/mani" || { echo "selftest: fresh manifest failed to verify" >&2; exit 1; }
    printf 'X' >> "$work/mani/base.tar.age"
    if wz_verify_manifest "$work/mani" 2>/dev/null; then
      echo "selftest: manifest verify passed after tamper" >&2; exit 1
    fi

    # Fail-closed guard: required + no recipients must die.
    ( unset WEISSMAN_BACKUP_AGE_RECIPIENTS
      export WEISSMAN_BACKUP_REQUIRE_ENCRYPTION=1
      wz_backup_require_or_die ) >/dev/null 2>&1 && { echo "selftest: require_or_die did not fail closed" >&2; exit 1; }
    exit 0
  )
  rc=$?
  rm -rf "$work"
  [[ "$rc" == 0 ]] && wz_crypto_log "SELFTEST PASSED (encrypt/decrypt, AEAD tamper, SHA256SUMS, fail-closed)"
  return "$rc"
}
