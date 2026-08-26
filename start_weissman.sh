#!/bin/bash
# =============================================================================
# Weissman — one command, full Docker Compose stack
# =============================================================================
# Starts dockerd if needed, generates .env (role-separated DB URLs + LLM wiring),
# then `docker compose up -d` for:
#   postgres (pgvector/pg16) · redis · weissman-server · weissman-worker · nginx gateway
#
# This is the same production stack as ./start_weissman_live.sh. Use either name.
#
# Usage:
#   ./start_weissman.sh                         # start everything
#   ./start_weissman.sh --url https://sec.example.com
#   ./start_weissman.sh stop | status | logs
#   WEISSMAN_START_DRY_RUN=1 ./start_weissman.sh
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "help" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  exec "$ROOT/start_weissman_live.sh" --help
fi

case "${WEISSMAN_START_DRY_RUN:-0}" in
  1|true|yes|TRUE|YES)
    echo "PLAN compose=docker-compose.yml+docker-compose.prod.yml"
    echo "PLAN up=docker compose up -d"
    echo "PLAN services=postgres,redis,backend,worker,gateway"
    echo "PLAN postgres_image=pgvector/pgvector:pg16"
    echo "PLAN role_urls=DATABASE_URL,WEISSMAN_AUTH_DATABASE_URL,WEISSMAN_READ_ONLY_DATABASE_URL,WEISSMAN_MIGRATE_URL"
    echo "PLAN llm=WEISSMAN_LLM_BASE_URL,WEISSMAN_LLM_API_KEY,WEISSMAN_LLM_MODEL,WEISSMAN_NL_QUERY_MODEL"
    echo "PLAN verify=/api/health,worker,/api/ask"
    echo "PLAN system_ready=1"
    exit 0
    ;;
esac

exec "$ROOT/start_weissman_live.sh" "$@"
