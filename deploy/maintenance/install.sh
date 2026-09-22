#!/usr/bin/env bash
# deploy/maintenance/install.sh — build the maintenance page and install it for the
# host gateway (nginx / Caddy on a systemd host). Kubernetes uses the generated
# ConfigMap instead; Cloudflare uses assets.generated.mjs.
#
#   sudo deploy/maintenance/install.sh [--no-build]
#
#   WEISSMAN_MAINTENANCE_ROOT       where dist/ is installed   (default /opt/weissman/maintenance)
#   WEISSMAN_MAINTENANCE_STATE_DIR  maintenance.on/status.json (default $ROOT/state)
#   WEISSMAN_MAINTENANCE_OWNER      owner[:group] for the state dir, e.g. weissman:www-data
#
# The gateway serves ROOT at /maintenance/ (index.html, he/index.html, maintenance.js,
# api.json) and STATE_DIR/status.json at /maintenance/status.json. The page appears
# automatically when the origin is out; the state dir is only for announced windows.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${WEISSMAN_MAINTENANCE_ROOT:-/opt/weissman/maintenance}"
STATE_DIR="${WEISSMAN_MAINTENANCE_STATE_DIR:-$ROOT/state}"
OWNER="${WEISSMAN_MAINTENANCE_OWNER:-}"
BUILD=1
for a in "$@"; do
  case "$a" in
    --no-build) BUILD=0 ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install.sh: unknown option $a" >&2; exit 2 ;;
  esac
done

if [ $BUILD -eq 1 ]; then
  command -v node >/dev/null 2>&1 || { echo "install.sh: node >= 22 is required to build" >&2; exit 2; }
  node "$HERE/build.mjs"
else
  node "$HERE/build.mjs" --check || { echo "install.sh: dist/ is stale — run without --no-build" >&2; exit 1; }
fi

for f in index.html he/index.html maintenance.js api.json status.example.json; do
  [ -f "$HERE/dist/$f" ] || { echo "install.sh: missing $HERE/dist/$f" >&2; exit 1; }
done

install -d -m 0755 "$ROOT" "$ROOT/he"
install -m 0644 "$HERE/dist/index.html"        "$ROOT/index.html"
install -m 0644 "$HERE/dist/he/index.html"     "$ROOT/he/index.html"
install -m 0644 "$HERE/dist/maintenance.js"    "$ROOT/maintenance.js"
install -m 0644 "$HERE/dist/api.json"          "$ROOT/api.json"
install -m 0644 "$HERE/dist/status.example.json" "$ROOT/status.example.json"
install -d -m 0755 "$STATE_DIR"
[ -n "$OWNER" ] && chown "$OWNER" "$STATE_DIR"

cat <<SUMMARY
maintenance page installed
  page root : $ROOT            -> serve at /maintenance/  (fallback on 502/504/connection failure)
  state dir : $STATE_DIR   -> serve status.json at /maintenance/status.json (404 when absent = normal)
  announce  : WEISSMAN_MAINTENANCE_STATE_DIR=$STATE_DIR $HERE/maintenance-mode.sh on --reason "..." --until "..."
The page is automatic; announcing a window is optional.
SUMMARY
