#!/usr/bin/env bash
# =============================================================================
# Weissman — one command, whole stack. Docker-first.
# =============================================================================
# This is the front door: it makes sure the Docker daemon is running (starting it when it is
# installed but down), then hands over to ./start_weissman_live.sh, which owns the stack —
# `.env` bootstrap, `docker compose up -d --build`, migrations, health gate, banner.
#
# There is exactly one architecture here: Postgres 16 (pgvector) · Redis · weissman-server ·
# weissman-worker · Nginx gateway, all on one Compose network, reaching each other by service
# name. Nothing runs as a loose host process, so role separation (weissman_app / weissman_auth
# / weissman_ro) and /api/ask are configured the same way on every machine.
#
# Usage:
#   ./start_weissman.sh                          first boot / re-deploy
#   ./start_weissman.sh --url https://sec.acme.com
#   ./start_weissman.sh stop | status | logs | reset
#   ./start_weissman.sh --help                   full flag list (from start_weissman_live.sh)
#
# Every argument is passed through unchanged.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

log() { printf '[weissman] %s\n' "$*"; }
die() { printf '[weissman] ERROR: %s\n' "$*" >&2; exit 1; }

# shellcheck source=scripts/lib/docker_daemon.sh
. "$ROOT/scripts/lib/docker_daemon.sh"

LIVE="$ROOT/start_weissman_live.sh"
[ -x "$LIVE" ] || die "start_weissman_live.sh is missing or not executable — this launcher only orchestrates it"

# --help must work without a daemon: operators (and the contract tests) read the flag list
# before Docker is even installed.
case "${1:-}" in
  -h|--help) exec "$LIVE" --help ;;
esac

# `stop`, `status` and `logs` all talk to the daemon too, so this runs for every subcommand.
if ! weissman_docker_ensure; then
  die "$(cat <<'EOF'
Docker is required: the whole platform (API, worker, Postgres, Redis, gateway) runs as one
Compose stack. Install Docker 24+ with Compose v2, then re-run:

  https://docs.docker.com/engine/install/

If Docker IS installed, start its daemon and re-run — or set WEISSMAN_DOCKER_AUTOSTART=0 to
tell this launcher not to try starting it for you.
EOF
)"
fi

exec "$LIVE" "$@"
