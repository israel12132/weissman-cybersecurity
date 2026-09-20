#!/usr/bin/env bash
# Install or upgrade Weissman systemd units (production).
# Run on the server: sudo bash deploy/systemd/install-weissman-systemd.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/weissman/app}"
ENV_DIR="${ENV_DIR:-/etc/weissman}"
SERVICE_USER="${SERVICE_USER:-weissman}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_FRONTEND="${SKIP_FRONTEND:-0}"

die() { echo "ERROR: $*" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo)"

command -v systemctl >/dev/null 2>&1 || die "systemd not found"

echo "[*] Repo:          $REPO_ROOT"
echo "[*] Install to:    $INSTALL_ROOT"
echo "[*] Service user:  $SERVICE_USER"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  echo "[*] Creating system user $SERVICE_USER"
  useradd --system --home-dir "$INSTALL_ROOT" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" || true
fi

mkdir -p "$INSTALL_ROOT/bin" "$INSTALL_ROOT/frontend/dist" "$ENV_DIR"

if [[ "$SKIP_BUILD" != "1" ]]; then
  command -v cargo >/dev/null 2>&1 || die "cargo not found — install Rust or SKIP_BUILD=1 with binaries in $INSTALL_ROOT/bin/"
  echo "[*] cargo build --release (weissman-server, weissman-worker)"
  (cd "$REPO_ROOT" && cargo build --release -p weissman-server -p weissman-worker)
  install -o root -g root -m 0755 "$REPO_ROOT/target/release/weissman-server" "$INSTALL_ROOT/bin/weissman-server"
  install -o root -g root -m 0755 "$REPO_ROOT/target/release/weissman-worker" "$INSTALL_ROOT/bin/weissman-worker"
else
  echo "[*] SKIP_BUILD=1 — expecting binaries in $INSTALL_ROOT/bin/"
  [[ -x "$INSTALL_ROOT/bin/weissman-server" ]] || die "missing $INSTALL_ROOT/bin/weissman-server"
  [[ -x "$INSTALL_ROOT/bin/weissman-worker" ]] || die "missing $INSTALL_ROOT/bin/weissman-worker"
fi

if [[ "$SKIP_FRONTEND" != "1" ]]; then
  if command -v npm >/dev/null 2>&1; then
    echo "[*] npm run build (frontend)"
    (cd "$REPO_ROOT/frontend" && npm ci && npm run build)
    rsync -a --delete "$REPO_ROOT/frontend/dist/" "$INSTALL_ROOT/frontend/dist/"
  else
    echo "[!] npm not found — copy $REPO_ROOT/frontend/dist/ to $INSTALL_ROOT/frontend/dist/ after building elsewhere"
  fi
else
  echo "[*] SKIP_FRONTEND=1 — leaving $INSTALL_ROOT/frontend/dist unchanged"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_ROOT"

# Continuity ("maintenance") page for the host gateway. deploy/nginx-weissman.conf and
# deploy/Caddyfile serve it from /opt/weissman/maintenance (a sibling of $INSTALL_ROOT) whenever
# the origin cannot answer, and read the optional announced-window flag from its state/ dir.
# The page is automatic, so a problem here must not block the units: it only means the branded
# page is not in place yet. --no-build verifies the committed dist instead of regenerating
# files inside the operator's checkout as root. WEISSMAN_MAINTENANCE_ROOT/_STATE_DIR/_OWNER
# pass through to install.sh.
MAINT_INSTALL="$REPO_ROOT/deploy/maintenance/install.sh"
if [[ -f "$MAINT_INSTALL" ]]; then
  echo "[*] Installing the continuity page → ${WEISSMAN_MAINTENANCE_ROOT:-/opt/weissman/maintenance}"
  if ! bash "$MAINT_INSTALL" --no-build; then
    echo "[!] continuity page not installed (non-fatal) — run: node deploy/maintenance/build.mjs && sudo deploy/maintenance/install.sh"
  fi
else
  echo "[!] deploy/maintenance/install.sh not found — continuity page not installed (the units do not need it)"
fi

UNIT_SRC="$REPO_ROOT/deploy/systemd"
for u in weissman-server.service weissman-worker.service weissman.target; do
  [[ -f "$UNIT_SRC/$u" ]] || die "missing $UNIT_SRC/$u"
  sed -e "s|/opt/weissman/app|$INSTALL_ROOT|g" "$UNIT_SRC/$u" >"/etc/systemd/system/$u.tmp"
  install -o root -g root -m 0644 "/etc/systemd/system/$u.tmp" "/etc/systemd/system/$u"
  rm -f "/etc/systemd/system/$u.tmp"
done

ENV_EXAMPLE="$UNIT_SRC/weissman.env.example"
[[ -f "$ENV_EXAMPLE" ]] || die "missing $ENV_EXAMPLE"
ENV_CREATED=0
if [[ ! -f "$ENV_DIR/weissman.env" ]]; then
  install -o root -g root -m 0600 "$ENV_EXAMPLE" "$ENV_DIR/weissman.env"
  ENV_CREATED=1
fi

systemctl daemon-reload

if [[ "$ENV_CREATED" -eq 1 ]]; then
  echo ""
  echo "[!] Created $ENV_DIR/weissman.env — set DATABASE_URL, WEISSMAN_JWT_SECRET, WEISSMAN_COOKIE_SECURE=1, PORT, then:"
  echo "    sudo systemctl enable --now weissman-server weissman-worker weissman.target"
  echo "    journalctl -u weissman-server -f"
  exit 0
fi

echo ""
echo "[*] Units installed. Start or restart:"
echo "    sudo systemctl enable --now weissman-server weissman-worker weissman.target"
echo "    sudo systemctl restart weissman-server weissman-worker"
echo "    journalctl -u weissman-server -f"
echo "    journalctl -u weissman-worker -f"
