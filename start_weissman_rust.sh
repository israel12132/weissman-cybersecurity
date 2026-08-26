#!/bin/bash
# Same as start_weissman.sh — full stack (Postgres, Redis, API, worker, UI).
exec "$(dirname "$0")/start_weissman.sh" "$@"
