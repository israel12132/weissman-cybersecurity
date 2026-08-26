#!/usr/bin/env bash
# Verify Docker build contexts include every compile-time / build-time path.
# Usage: ./scripts/verify_docker_build_integrity.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0
ok() { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }

section() { echo ""; echo "== $1 =="; }

section "Required repo paths"
for path in \
  shared/engine_ui_manifests.json \
  shared/engine_requirements.json \
  Cargo.toml \
  Cargo.lock \
  fuzz_core/Cargo.toml \
  fingerprint_engine/Cargo.toml \
  backend/weissman-server/Cargo.toml \
  crates/weissman-worker/Cargo.toml \
  crates/weissman-ast-cap/Cargo.toml \
  crates/weissman-ui-provenance/Cargo.toml \
  crates/weissman-db/migrations \
  scripts/build-ast-cap-wasm.sh \
  scripts/build-ui-provenance-wasm.sh \
  scripts/generate_engine_param_defs.mjs \
  deploy/backend.Dockerfile \
  deploy/frontend.Dockerfile \
  deploy/oast.Dockerfile \
  deploy/nginx-gateway.conf
do
  [[ -e "$path" ]] && ok "exists $path" || bad "missing $path"
done

section "backend.Dockerfile COPY coverage"
for token in fuzz_core fingerprint_engine backend crates scripts shared; do
  if grep -q "COPY ${token}" deploy/backend.Dockerfile; then
    ok "backend COPY $token"
  else
    bad "backend.Dockerfile missing COPY $token"
  fi
done

section "frontend.Dockerfile COPY coverage"
for token in shared scripts backend fingerprint_engine crates; do
  if grep -q "${token}" deploy/frontend.Dockerfile; then
    ok "frontend references $token"
  else
    bad "frontend.Dockerfile missing $token"
  fi
done

section "oast.Dockerfile COPY coverage"
for token in fuzz_core fingerprint_engine backend crates shared; do
  if grep -q "COPY ${token}" deploy/oast.Dockerfile; then
    ok "oast COPY $token"
  else
    bad "oast.Dockerfile missing COPY $token"
  fi
done

section "Runtime agent binary wiring"
if grep -q 'COPY --from=build /build/target/release/weissman-agent' deploy/backend.Dockerfile; then
  ok "backend copies weissman-agent from build stage"
else
  bad "backend.Dockerfile must COPY --from=build weissman-agent (not cp from /build in runtime)"
fi

section "include_str! external paths (fingerprint_engine)"
while IFS= read -r line; do
  if [[ "$line" =~ include_str!\(\"([^\"]+)\"\) ]]; then
    rel="${BASH_REMATCH[1]}"
    # Paths are relative to the .rs file; only flag repo-root shared/ assets.
    if [[ "$rel" == *shared/* ]]; then
      base="$(basename "$rel")"
      [[ -f "shared/$base" ]] && ok "shared asset $base" || bad "missing shared/$base for $line"
    fi
  fi
done < <(grep -rh 'include_str!' fingerprint_engine/src --include='*.rs' || true)

section "Workspace members on disk"
while IFS= read -r member; do
  [[ -f "${member}/Cargo.toml" ]] && ok "workspace member $member" || bad "workspace member missing: $member"
done < <(grep -E '^\s+".*"' Cargo.toml | tr -d '," ' | grep -v '^\[workspace\]' | grep '/' || true)

section "SQL migration mirror (fingerprint_engine ↔ weissman-db)"
# Live backend embeds crates/weissman-db/migrations at compile time. A file that exists
# only in fingerprint_engine/migrations is applied by host/sqlx CLI runs, then Docker
# boot dies with sqlx VersionMissing (20260818120000_clients_sector.sql).
if bash "$ROOT/scripts/check-migration-sync.sh"; then
  ok "migration trees byte-synced"
else
  bad "migration trees drifted — live backend will crash: previously applied but missing in resolved migrations"
fi

echo ""
if [[ "$fail" -ne 0 ]]; then
  echo "Docker build integrity check FAILED."
  exit 1
fi
echo "Docker build integrity check passed."
