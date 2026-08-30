#!/usr/bin/env bash
# Sign a Weissman dual-control request (same canonical string as Axum).
# Usage:
#   WEISSMAN_PROXY_SIGNING_SECRET=... \
#     ./scripts/sign_weissman_proxy_header.sh POST /api/containment/execute \
#       "$CONFIRM" "$APPROVE"
set -euo pipefail
secret="${WEISSMAN_PROXY_SIGNING_SECRET:?set WEISSMAN_PROXY_SIGNING_SECRET}"
method="${1:?method}"
path="${2:?path}"
confirm="${3:-}"
approve="${4:-}"
ts="$(date +%s)"
canonical="v1:${ts}"$'\n'"${method}"$'\n'"${path}"$'\n'"${confirm}"$'\n'"${approve}"
hex="$(printf '%s' "$canonical" | openssl dgst -sha256 -hmac "$secret" -hex | awk '{print $NF}')"
echo "X-Weissman-Proxy-Signature: t=${ts},v1=${hex}"
